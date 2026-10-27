//! Durable desired listener state and bounded exact operation receipts. A saved
//! enabled flag is not a running socket. Socket work belongs to the live owner;
//! no SQL transaction waits for a bind, TLS handshake or connection drain.

use std::{io, path::Path};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params, types::ValueRef};

use super::{admission, control, invalid_data, peers::open_existing, sqlite_error, valid_id};
use crate::manage::proxy::settings::{Configuration, MAX_BYTES};

const MAX_HISTORY: i64 = 256;

#[derive(Debug, thiserror::Error)]
pub(in crate::manage) enum Error {
    #[error("managed service requires explicit schema migration")]
    UpgradeRequired,
    #[error("managed service configuration changed")]
    RevisionConflict,
    #[error("managed service operation is still pending")]
    Pending,
    #[error("managed service operation does not match")]
    OperationConflict,
}

impl Error {
    pub(in crate::manage) fn io(self) -> io::Error {
        let kind = match self {
            Self::UpgradeRequired => io::ErrorKind::InvalidInput,
            Self::Pending => io::ErrorKind::WouldBlock,
            Self::RevisionConflict | Self::OperationConflict => io::ErrorKind::AlreadyExists,
        };
        io::Error::new(kind, self)
    }
}

/// Persisted configuration revision is monotonically increasing across normal
/// process restarts. It is not the policy revision or a runtime generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct State {
    pub(in crate::manage) revision: u64,
    pub(in crate::manage) enabled: bool,
    pub(in crate::manage) configuration: Option<Configuration>,
}

/// Only fixed public result classes survive. Applied means that particular
/// operation reached its desired state then, not that a socket is live now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::manage) enum Outcome {
    Pending,
    Applied,
    Failed,
    Interrupted,
}

impl Outcome {
    fn text(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
        }
    }
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "applied" => Ok(Self::Applied),
            "failed" => Ok(Self::Failed),
            "interrupted" => Ok(Self::Interrupted),
            _ => Err(corrupt()),
        }
    }
}

/// Exact receipt namespace includes its revision, random request identity and
/// real administrator. Expired receipts are not replayed: their old expected
/// revision can never become current again. A process restart interrupts a
/// pending receipt rather than claiming the original socket work succeeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct Receipt {
    pub(in crate::manage) state: State,
    pub(in crate::manage) request_id: String,
    pub(in crate::manage) administrator_id: String,
    pub(in crate::manage) owner_epoch: u64,
    pub(in crate::manage) outcome: Outcome,
}

/// Assertions are not authority. The authenticated administrator, node and
/// current local ownership are checked in the same immediate transaction.
pub(in crate::manage) struct Request {
    pub(in crate::manage) assertion: admission::Assertion,
    pub(in crate::manage) expected_revision: u64,
    pub(in crate::manage) request_id: String,
    pub(in crate::manage) enabled: bool,
    pub(in crate::manage) configuration: Configuration,
}

pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection
        .execute_batch(
            "CREATE TABLE proxy_service_state(
           singleton INTEGER PRIMARY KEY CHECK(singleton=1),
           revision INTEGER NOT NULL CHECK(revision>=1),
           enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),
           configuration BLOB CHECK(length(configuration) BETWEEN 1 AND 8192),
           CHECK(configuration IS NOT NULL OR (revision=1 AND enabled=0))
         ) STRICT;
         INSERT INTO proxy_service_state VALUES(1,1,0,NULL);
         CREATE TABLE proxy_service_operations(
           revision INTEGER PRIMARY KEY CHECK(revision>=2),
           request_id TEXT NOT NULL CHECK(length(request_id)=22),
           administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
           owner_epoch INTEGER NOT NULL CHECK(owner_epoch>=1),
           enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),
           configuration BLOB NOT NULL CHECK(length(configuration) BETWEEN 1 AND 8192),
           outcome TEXT NOT NULL CHECK(outcome IN('pending','applied','failed','interrupted'))
         ) STRICT;",
        )
        .map_err(|e| sqlite_error("cannot create managed service settings", e))
}

pub(super) fn validate_schema(connection: &Connection, version: u32) -> io::Result<()> {
    if version >= 27 {
        let state = read_in(connection)?;
        let (count, pending, oldest, latest): (i64, i64, Option<i64>, Option<i64>) = connection.query_row(
            "SELECT count(*),coalesce(sum(outcome='pending'),0),min(revision),max(revision) FROM proxy_service_operations",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).map_err(|e| sqlite_error("cannot inspect managed service receipts", e))?;
        let current = state.revision;
        let retained = (current - 1).min(MAX_HISTORY as u64);
        if !(0..=MAX_HISTORY).contains(&count)
            || !(0..=1).contains(&pending)
            || if current == 1 {
                count != 0
            } else {
                latest != i64::try_from(current).ok()
                    || count != i64::try_from(retained).map_err(|_| corrupt())?
                    || oldest != i64::try_from(current - retained + 1).ok()
            }
        {
            return Err(corrupt());
        }
        if let Some(latest) = latest {
            let receipt = receipt_in(connection, latest as u64)?.ok_or_else(corrupt)?;
            if receipt.state != state {
                return Err(corrupt());
            }
            if pending != 0 && receipt.outcome != Outcome::Pending {
                return Err(corrupt());
            }
        }
        Ok(())
    } else {
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name IN('proxy_service_state','proxy_service_operations'))",
            [], |r| r.get(0),
        ).map_err(|e| sqlite_error("cannot inspect legacy service settings", e))?;
        if present { Err(corrupt()) } else { Ok(()) }
    }
}

fn require_current(connection: &Connection) -> io::Result<()> {
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| sqlite_error("cannot inspect service settings version", e))?;
    if version < 27 {
        return Err(Error::UpgradeRequired.io());
    }
    Ok(())
}

fn bytes(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Vec<u8>> {
    match row.get_ref(index)? {
        ValueRef::Blob(value) if !value.is_empty() && value.len() <= MAX_BYTES => {
            Ok(value.to_vec())
        }
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn read_in(connection: &Connection) -> io::Result<State> {
    let (count, revision, enabled): (i64, i64, i64) = connection.query_row(
        "SELECT count(*),coalesce(min(revision),0),coalesce(min(enabled),-1) FROM proxy_service_state",
        [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).map_err(|e| sqlite_error("cannot read managed service settings", e))?;
    if count != 1 || revision < 1 || !matches!(enabled, 0 | 1) {
        return Err(corrupt());
    }
    let configuration: Option<Vec<u8>> = connection
        .query_row(
            "SELECT configuration FROM proxy_service_state WHERE singleton=1",
            [],
            |row| {
                if matches!(row.get_ref(0)?, ValueRef::Null) {
                    Ok(None)
                } else {
                    bytes(row, 0).map(Some)
                }
            },
        )
        .map_err(|e| sqlite_error("cannot read managed service configuration", e))?;
    let configuration = configuration
        .map(|b| Configuration::decode(&b).map_err(|_| corrupt()))
        .transpose()?;
    if configuration.is_none() && (revision != 1 || enabled != 0) {
        return Err(corrupt());
    }
    Ok(State {
        revision: revision as u64,
        enabled: enabled == 1,
        configuration,
    })
}

fn receipt_in(connection: &Connection, revision: u64) -> io::Result<Option<Receipt>> {
    let revision_sql = i64::try_from(revision).map_err(|_| corrupt())?;
    let row = connection.query_row(
        "SELECT request_id,administrator_id,owner_epoch,enabled,configuration,outcome FROM proxy_service_operations WHERE revision=?1",
        [revision_sql], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,bytes(r,4)?,r.get::<_,String>(5)?)),
    ).optional().map_err(|e| sqlite_error("cannot read managed service receipt", e))?;
    row.map(
        |(request_id, administrator_id, epoch, enabled, configuration, outcome)| {
            if revision < 2
                || !valid_id(&request_id)
                || !valid_id(&administrator_id)
                || epoch < 1
                || !matches!(enabled, 0 | 1)
            {
                return Err(corrupt());
            }
            Ok(Receipt {
                state: State {
                    revision,
                    enabled: enabled == 1,
                    configuration: Some(
                        Configuration::decode(&configuration).map_err(|_| corrupt())?,
                    ),
                },
                request_id,
                administrator_id,
                owner_epoch: epoch as u64,
                outcome: Outcome::parse(&outcome)?,
            })
        },
    )
    .transpose()
}

pub(in crate::manage) fn read(directory: &Path) -> io::Result<State> {
    let connection = open_existing(directory, false)?;
    require_current(&connection)?;
    read_in(&connection)
}

/// Directory-bound activation metadata after actual readiness. No sockets are
/// created here; the native owner still retains the writer until publication.
pub(in crate::manage) fn record_applied(
    directory: &Path,
    gate: &super::UpdateGuard,
    revision: u64,
) -> io::Result<()> {
    gate.ensure(directory)?;
    super::users::record_applied(directory, revision)
}

/// Offline snapshots additionally validate every retained original receipt.
/// Routine opens inspect only aggregate bounds and the latest exact state.
pub(in crate::manage::store) fn validate_snapshot(connection: &Connection) -> io::Result<()> {
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| sqlite_error("cannot inspect service snapshot version", e))?;
    if version < 27 {
        return Ok(());
    }
    validate_schema(connection, version)?;
    let mut statement = connection
        .prepare("SELECT revision FROM proxy_service_operations ORDER BY revision LIMIT 257")
        .map_err(|e| sqlite_error("cannot inspect service snapshot history", e))?;
    let rows = statement
        .query_map([], |r| r.get::<_, i64>(0))
        .map_err(|e| sqlite_error("cannot read service snapshot history", e))?;
    for (index, revision) in rows.enumerate() {
        if index >= MAX_HISTORY as usize {
            return Err(corrupt());
        }
        let revision = u64::try_from(
            revision.map_err(|e| sqlite_error("cannot decode service snapshot revision", e))?,
        )
        .map_err(|_| corrupt())?;
        receipt_in(connection, revision)?.ok_or_else(corrupt)?;
    }
    Ok(())
}

/// Admit an exact local intent or recover only that actor's identical receipt.
/// The boolean identifies first acceptance; duplicate reads never bind sockets.
/// Caller retains the coordinator writer, author and update guard through commit.
pub(in crate::manage) fn accept(
    directory: &Path,
    guard: &super::UpdateGuard,
    administrator: &str,
    request: &Request,
) -> io::Result<(Receipt, bool)> {
    guard.ensure(directory)?;
    if !valid_id(&request.request_id) || request.expected_revision == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid service operation",
        ));
    }
    let configuration = request.configuration.encode()?;
    let revision = request
        .expected_revision
        .checked_add(1)
        .filter(|r| *r <= i64::MAX as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "service revision exhausted"))?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin managed service change", e))?;
    require_current(&transaction)?;
    control::check_administrator(&transaction, administrator)?;
    admission::assert_local_in(&transaction, &request.assertion)?;
    let expected = State {
        revision,
        enabled: request.enabled,
        configuration: Some(request.configuration.clone()),
    };
    if let Some(original) = receipt_in(&transaction, revision)? {
        if original.request_id != request.request_id
            || original.administrator_id != administrator
            || original.owner_epoch != request.assertion.epoch
            || original.state != expected
        {
            return Err(Error::OperationConflict.io());
        }
        return Ok((original, false));
    }
    if read_in(&transaction)?.revision != request.expected_revision {
        return Err(Error::RevisionConflict.io());
    }
    let pending: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM proxy_service_operations WHERE outcome='pending')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot inspect pending service operation", e))?;
    if pending {
        return Err(Error::Pending.io());
    }
    transaction.execute("UPDATE proxy_service_state SET revision=?1,enabled=?2,configuration=?3 WHERE singleton=1",params![revision as i64,request.enabled,&configuration])
        .map_err(|e|sqlite_error("cannot save desired service state",e))?;
    transaction
        .execute(
            "INSERT INTO proxy_service_operations VALUES(?1,?2,?3,?4,?5,?6,'pending')",
            params![
                revision as i64,
                request.request_id,
                administrator,
                request.assertion.epoch as i64,
                request.enabled,
                &configuration
            ],
        )
        .map_err(|e| sqlite_error("cannot save service operation", e))?;
    let cutoff = revision.saturating_sub(MAX_HISTORY as u64);
    transaction
        .execute(
            "DELETE FROM proxy_service_operations WHERE revision<=?1",
            [cutoff as i64],
        )
        .map_err(|e| sqlite_error("cannot retain bounded service history", e))?;
    transaction
        .commit()
        .map_err(|e| sqlite_error("cannot commit managed service change", e))?;
    Ok((
        Receipt {
            state: expected,
            request_id: request.request_id.clone(),
            administrator_id: administrator.into(),
            owner_epoch: request.assertion.epoch,
            outcome: Outcome::Pending,
        },
        true,
    ))
}

/// Finish only the original pending operation. Repeated identical completion
/// is idempotent; another actor/revision/result cannot adopt or rewrite it.
pub(in crate::manage) fn finish(
    directory: &Path,
    guard: &super::UpdateGuard,
    original: &Receipt,
    outcome: Outcome,
) -> io::Result<Receipt> {
    guard.ensure(directory)?;
    if outcome == Outcome::Pending {
        return Err(corrupt());
    }
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin service result", e))?;
    require_current(&transaction)?;
    let current = receipt_in(&transaction, original.state.revision)?
        .ok_or_else(|| Error::OperationConflict.io())?;
    if current.state != original.state
        || current.request_id != original.request_id
        || current.administrator_id != original.administrator_id
        || current.owner_epoch != original.owner_epoch
        || current.outcome != Outcome::Pending && current.outcome != outcome
    {
        return Err(Error::OperationConflict.io());
    }
    transaction
        .execute(
            "UPDATE proxy_service_operations SET outcome=?1 WHERE revision=?2",
            params![outcome.text(), original.state.revision as i64],
        )
        .map_err(|e| sqlite_error("cannot save service result", e))?;
    transaction
        .commit()
        .map_err(|e| sqlite_error("cannot commit service result", e))?;
    Ok(Receipt { outcome, ..current })
}

/// Startup interrupts, never completes/replays an old pending command. Desired
/// settings remain available for a separately observed process reconciliation.
pub(in crate::manage) fn interrupt(directory: &Path, guard: &super::UpdateGuard) -> io::Result<()> {
    guard.ensure(directory)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin service startup reconciliation", e))?;
    require_current(&transaction)?;
    transaction
        .execute(
            "UPDATE proxy_service_operations SET outcome='interrupted' WHERE outcome='pending'",
            [],
        )
        .map_err(|e| sqlite_error("cannot interrupt old service operation", e))?;
    transaction
        .commit()
        .map_err(|e| sqlite_error("cannot commit service startup reconciliation", e))
}

/// Recheck the real current administrator/owner even for historical results.
pub(in crate::manage) fn exact(
    directory: &Path,
    administrator: &str,
    assertion: &admission::Assertion,
    revision: u64,
    request_id: &str,
) -> io::Result<Receipt> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|e| sqlite_error("cannot begin service receipt snapshot", e))?;
    require_current(&transaction)?;
    control::check_administrator(&transaction, administrator)?;
    admission::assert_local_in(&transaction, assertion)?;
    let receipt = receipt_in(&transaction, revision)?
        .filter(|r| {
            r.request_id == request_id
                && r.administrator_id == administrator
                && r.owner_epoch == assertion.epoch
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "service operation not found"))?;
    Ok(receipt)
}

#[cfg(test)]
pub(in crate::manage) fn require_unused_for_test(connection: &Connection) -> io::Result<()> {
    super::secrets::require_unused_for_test(connection)?;
    let state = read_in(connection)?;
    let count: i64 = connection
        .query_row("SELECT count(*) FROM proxy_service_operations", [], |r| {
            r.get(0)
        })
        .map_err(|e| sqlite_error("cannot inspect service fixture receipts", e))?;
    if state.revision != 1 || state.enabled || state.configuration.is_some() || count != 0 {
        return Err(corrupt());
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::manage) fn remove_schema_for_test(connection: &Connection) -> io::Result<()> {
    super::secrets::project_legacy_for_test(connection)?;
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='proxy_service_state')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot inspect service fixture", e))?;
    if exists {
        require_unused_for_test(connection)?;
        connection
            .execute_batch("DROP TABLE proxy_service_operations; DROP TABLE proxy_service_state;")
            .map_err(|e| sqlite_error("cannot reconstruct pre-service fixture", e))?;
    }
    Ok(())
}

fn corrupt() -> io::Error {
    invalid_data("managed service settings are malformed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::{
        proxy::{ListenerView, Protocol},
        store,
    };

    struct Fixture {
        root: std::path::PathBuf,
        directory: std::path::PathBuf,
        node: String,
        administrator: String,
    }

    impl Fixture {
        fn new() -> io::Result<Self> {
            let root = std::env::temp_dir()
                .join(format!("vproxy-service-settings-{}", store::random_id()?));
            crate::manage::files::create_directory(&root)?;
            let directory = root.join("state");
            let node = store::initialize(
                &directory,
                "service fixture",
                "admin",
                "fixture verifier, not a usable login",
            )?
            .node_id;
            let connection = open_existing(&directory, false)?;
            let administrator = connection
                .query_row("SELECT id FROM administrators", [], |r| r.get(0))
                .map_err(io::Error::other)?;
            Ok(Self {
                root,
                directory,
                node,
                administrator,
            })
        }
        fn request(&self, expected_revision: u64) -> io::Result<Request> {
            Ok(Request {
                assertion: admission::Assertion {
                    node_id: self.node.clone(),
                    epoch: 1,
                },
                expected_revision,
                request_id: store::random_id()?,
                enabled: true,
                configuration: Configuration {
                    workers: 1,
                    concurrent: 512,
                    connect_timeout: 10,
                    listeners: vec![ListenerView {
                        protocol: Protocol::Http,
                        bind: "127.0.0.1:18080".parse().map_err(io::Error::other)?,
                        public_address: Some("proxy.example:18080".into()),
                    }],
                },
            })
        }
        fn accept(&self, request: &Request) -> io::Result<(Receipt, bool)> {
            accept(
                &self.directory,
                &store::update_lock(&self.directory)?,
                &self.administrator,
                request,
            )
        }
        fn finish(&self, receipt: &Receipt, outcome: Outcome) -> io::Result<Receipt> {
            finish(
                &self.directory,
                &store::update_lock(&self.directory)?,
                receipt,
                outcome,
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn persistent_service_intents_distinguish_saved_applied_restart_and_exact_actor()
    -> io::Result<()> {
        let f = Fixture::new()?;
        assert_eq!(
            read(&f.directory)?,
            State {
                revision: 1,
                enabled: false,
                configuration: None
            }
        );
        let request = f.request(1)?;
        let (first, accepted) = f.accept(&request)?;
        assert!(accepted);
        assert_eq!(first.outcome, Outcome::Pending);
        assert_eq!(read(&f.directory)?, first.state);
        assert_eq!(f.accept(&request)?, (first.clone(), false));
        assert_eq!(
            f.accept(&f.request(2)?)
                .expect_err("another operation blocked")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let mut changed = f.request(1)?;
        changed.request_id = request.request_id.clone();
        changed.configuration.concurrent = 513;
        assert!(f.accept(&changed).is_err());
        let applied = f.finish(&first, Outcome::Applied)?;
        assert_eq!(f.finish(&first, Outcome::Applied)?, applied);
        assert!(f.finish(&first, Outcome::Failed).is_err());
        assert_eq!(f.accept(&request)?, (applied.clone(), false));
        assert_eq!(
            exact(
                &f.directory,
                &f.administrator,
                &request.assertion,
                2,
                &request.request_id
            )?,
            applied
        );
        assert!(
            exact(
                &f.directory,
                &f.administrator,
                &request.assertion,
                2,
                &store::random_id()?
            )
            .is_err()
        );
        assert!(
            exact(
                &f.directory,
                &store::random_id()?,
                &request.assertion,
                2,
                &request.request_id
            )
            .is_err()
        );

        let mut stop = f.request(2)?;
        stop.enabled = false;
        let (pending, _) = f.accept(&stop)?;
        interrupt(&f.directory, &store::update_lock(&f.directory)?)?;
        let interrupted = exact(
            &f.directory,
            &f.administrator,
            &stop.assertion,
            3,
            &stop.request_id,
        )?;
        assert_eq!(interrupted.outcome, Outcome::Interrupted);
        assert_eq!(read(&f.directory)?, pending.state);
        assert!(!interrupted.state.enabled);
        assert!(interrupted.state.configuration.is_some());
        assert_eq!(f.accept(&stop)?, (interrupted, false));
        assert!(f.finish(&pending, Outcome::Applied).is_err());
        Ok(())
    }

    #[test]
    fn service_intents_recheck_administrator_node_epoch_owner_and_reject_storage_corruption()
    -> io::Result<()> {
        let f = Fixture::new()?;
        let mut request = f.request(1)?;
        assert!(
            accept(
                &f.directory,
                &store::update_lock(&f.directory)?,
                &store::random_id()?,
                &request
            )
            .is_err()
        );
        request.assertion.node_id = store::random_id()?;
        assert!(f.accept(&request).is_err());
        request.assertion.node_id = f.node.clone();
        request.assertion.epoch = 2;
        assert!(f.accept(&request).is_err());
        let connection = open_existing(&f.directory, true)?;
        let peer = store::random_id()?;
        connection
            .execute(
                "INSERT INTO peers VALUES(?1,'test controller',1,1)",
                [&peer],
            )
            .map_err(io::Error::other)?;
        connection
            .execute(
                "UPDATE control_ownership SET controller_node_id=?1,epoch=2 WHERE singleton=1",
                [&peer],
            )
            .map_err(io::Error::other)?;
        assert!(f.accept(&request).is_err());
        assert_eq!(read(&f.directory)?.revision, 1);
        connection
            .execute(
                "UPDATE control_ownership SET controller_node_id=NULL,epoch=3 WHERE singleton=1",
                [],
            )
            .map_err(io::Error::other)?;
        request.assertion.epoch = 3;
        let (receipt, _) = f.accept(&request)?;
        f.finish(&receipt, Outcome::Applied)?;
        let mut malformed = request.configuration.encode()?;
        malformed.push(b' ');
        connection
            .execute(
                "UPDATE proxy_service_state SET configuration=?1",
                [&malformed],
            )
            .map_err(io::Error::other)?;
        assert!(store::inspect(&f.directory).is_err());
        Ok(())
    }

    #[test]
    fn service_history_is_bounded_and_pruned_revision_cannot_replay() -> io::Result<()> {
        let f = Fixture::new()?;
        let first = f.request(1)?;
        let (receipt, _) = f.accept(&first)?;
        f.finish(&receipt, Outcome::Applied)?;
        for expected in 2..=(MAX_HISTORY as u64 + 3) {
            let (receipt, _) = f.accept(&f.request(expected)?)?;
            f.finish(&receipt, Outcome::Applied)?;
        }
        let connection = open_existing(&f.directory, false)?;
        let count: i64 = connection
            .query_row("SELECT count(*) FROM proxy_service_operations", [], |r| {
                r.get(0)
            })
            .map_err(io::Error::other)?;
        assert_eq!(count, MAX_HISTORY);
        let before = read(&f.directory)?;
        assert!(f.accept(&first).is_err());
        assert_eq!(
            exact(
                &f.directory,
                &f.administrator,
                &first.assertion,
                2,
                &first.request_id
            )
            .expect_err("expired original receipt")
            .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(read(&f.directory)?, before);
        Ok(())
    }

    #[test]
    fn schema26_migration_preserves_identity_and_backup_while_new_settings_stay_disabled()
    -> io::Result<()> {
        let f = Fixture::new()?;
        let connection = open_existing(&f.directory, true)?;
        store::recovery::restore_schema_twenty_six_for_test(&connection)?;
        drop(connection);
        assert_eq!(store::inspect(&f.directory)?.schema_version, 26);
        assert!(read(&f.directory).is_err());
        let backup = f.root.join("before-service.sqlite3");
        let after = store::migrate(&f.directory, &backup)?;
        assert_eq!(after.schema_version, store::SCHEMA_VERSION);
        assert_eq!(after.node_id, f.node);
        assert_eq!(
            read(&f.directory)?,
            State {
                revision: 1,
                enabled: false,
                configuration: None
            }
        );
        let old = Connection::open_with_flags(&backup, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(io::Error::other)?;
        assert_eq!(
            old.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                .map_err(io::Error::other)?,
            26
        );
        assert_eq!(
            old.query_row("SELECT id FROM administrators", [], |r| r
                .get::<_, String>(0))
                .map_err(io::Error::other)?,
            f.administrator
        );
        assert!(
            !old.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='proxy_service_state')",
                [],
                |r| r.get::<_, bool>(0)
            )
            .map_err(io::Error::other)?
        );
        let package = f.root.join("backup-v27");
        let manifest = store::create_backup(&f.directory, &package)?;
        assert_eq!(store::verify_backup(&package)?, manifest);
        for revision in 1..=2 {
            let (receipt, _) = f.accept(&f.request(revision)?)?;
            f.finish(&receipt, Outcome::Applied)?;
        }
        let populated = f.root.join("backup-configured");
        let manifest = store::create_backup(&f.directory, &populated)?;
        assert_eq!(store::verify_backup(&populated)?, manifest);
        let connection = open_existing(&f.directory, true)?;
        connection.execute("UPDATE proxy_service_operations SET request_id='!!!!!!!!!!!!!!!!!!!!!!' WHERE revision=2",[])
        .map_err(io::Error::other)?;
        // Routine state remains readable; a historical malformed receipt cannot
        // be blessed by a completed backup just because the latest row is valid.
        assert_eq!(read(&f.directory)?.revision, 3);
        assert!(store::create_backup(&f.directory, &f.root.join("bad-history-backup")).is_err());
        Ok(())
    }

    #[test]
    fn service_configuration_separates_tcp_udp_binds_and_checks_canonical_saved_bytes()
    -> io::Result<()> {
        let f = Fixture::new()?;
        let mut config = f.request(1)?.configuration;
        let bytes = config.encode()?;
        assert_eq!(Configuration::decode(&bytes)?, config);
        config.listeners.push(config.listeners[0].clone());
        assert!(config.validate().is_err());
        config.listeners[1].protocol = Protocol::Socks5;
        assert!(config.validate().is_err());
        config.listeners[1].protocol = Protocol::Masque;
        assert!(config.validate().is_ok());
        config.listeners[1].public_address = Some("user:secret@proxy.example:18080".into());
        assert!(config.validate().is_err());
        let mut malformed = bytes;
        malformed.push(b'\n');
        assert!(Configuration::decode(&malformed).is_err());
        Ok(())
    }
}
