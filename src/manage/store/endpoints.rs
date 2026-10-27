//! Durable public-address declarations, never instructions to bind a socket.
//!
//! The inventory is supplied by this process's validated startup configuration.
//! Only an identity tuple and its explicit override survive restart. Detached
//! overrides remain visible and removable; startup never silently removes them.

use std::{collections::HashSet, io, net::SocketAddr, path::Path};

use rusqlite::{Connection, TransactionBehavior, params, types::ValueRef};
use serde::{Deserialize, Serialize};

use super::{
    invalid_data, peers::open_existing, read_overview, sqlite_error, users::Actor, valid_id,
};
use crate::manage::proxy::Protocol;

pub(in crate::manage) const MAX_OVERRIDES: usize = 256;
const MAX_AUDIT: i64 = 16_384;

/// Business rejections can enter a bounded remote receipt without exposing
/// SQLite diagnostics or confusing metadata revision with access policy.
#[derive(Debug, thiserror::Error)]
pub(in crate::manage) enum Error {
    #[error("invalid public endpoint mutation")]
    InvalidEndpoint,
    #[error("endpoint metadata revision changed")]
    RevisionConflict,
    #[error("endpoint startup configuration changed")]
    GenerationConflict,
    #[error("endpoint override capacity is exhausted")]
    Capacity,
    #[error("endpoint management requires explicit schema migration")]
    UpgradeRequired,
}

impl Error {
    pub(in crate::manage) const fn code(&self) -> &'static str {
        match self {
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::RevisionConflict => "endpoint_revision_changed",
            Self::GenerationConflict => "endpoint_configuration_changed",
            Self::Capacity => "endpoint_capacity",
            Self::UpgradeRequired => "management_upgrade_required",
        }
    }
}

/// Immutable startup identity and its optional file-configured default. This
/// value is never loaded from the endpoint tables to create a listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct ListenerKey {
    pub(in crate::manage) id: String,
    pub(in crate::manage) protocol: Protocol,
    pub(in crate::manage) bind: SocketAddr,
    pub(in crate::manage) configured_public_address: Option<String>,
}

/// At most sixteen already-validated configured listeners. The digest includes
/// their defaults as well as their identities, independently of array order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct Inventory {
    pub(in crate::manage) digest: String,
    pub(in crate::manage) listeners: Vec<ListenerKey>,
}

/// Inherit uses the current startup default; Hidden explicitly suppresses it,
/// including after restart. Custom contains a credential-free authority only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::manage) enum AddressSelection {
    Inherit,
    Custom { public_address: String },
    Hidden,
}

/// One mutation selected against a separately supplied revision and inventory
/// digest. The request does not get to supply an actor or identity tuple.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Change {
    pub(in crate::manage) listener_id: String,
    pub(in crate::manage) selection: AddressSelection,
}

/// Saved descriptive identity, not runtime configuration. Inherit has no row;
/// removing a row does not reset the singleton's monotonically increasing CAS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct Override {
    pub(in crate::manage) listener_id: String,
    pub(in crate::manage) protocol: Protocol,
    pub(in crate::manage) bind: SocketAddr,
    pub(in crate::manage) selection: AddressSelection,
}

/// A bounded snapshot. Empty digest is permitted only for a fresh revision-one
/// singleton with no overrides or audit. Every configured digest is lower hex.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct State {
    pub(in crate::manage) revision: u64,
    pub(in crate::manage) digest: String,
    pub(in crate::manage) overrides: Vec<Override>,
}

/// Create the empty v15 namespace inside initialization or backed-up migration.
/// Audit sequence is the permanent metadata revision, so pruning cannot reuse
/// an old sequence and startup configuration changes may leave harmless gaps.
pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection.execute_batch(
        "CREATE TABLE endpoint_state (
           singleton INTEGER PRIMARY KEY CHECK(singleton=1),
           revision INTEGER NOT NULL CHECK(revision>=1),
           digest TEXT NOT NULL CHECK(digest='' OR (length(digest)=64 AND digest NOT GLOB '*[^0-9a-f]*')),
           CHECK(digest<>'' OR revision=1)
         ) STRICT;
         INSERT INTO endpoint_state VALUES(1,1,'');
         CREATE TABLE endpoint_overrides (
           listener_id TEXT PRIMARY KEY NOT NULL CHECK(length(listener_id)=22),
           protocol TEXT NOT NULL CHECK(protocol IN('http','https','socks5','masque','auto')),
           bind TEXT NOT NULL CHECK(length(bind) BETWEEN 3 AND 80),
           selection TEXT NOT NULL CHECK(selection IN('custom','hidden')),
           public_address TEXT,
           CHECK((selection='custom' AND public_address IS NOT NULL AND length(public_address) BETWEEN 1 AND 259)
              OR (selection='hidden' AND public_address IS NULL)),
           UNIQUE(protocol,bind)
         ) STRICT;
         CREATE TABLE endpoint_audit (
           sequence INTEGER PRIMARY KEY CHECK(sequence>=2),
           entry TEXT NOT NULL CHECK(entry IN('local_management','node_management')),
           administrator_id TEXT REFERENCES administrators(id) ON DELETE RESTRICT,
           controller_node_id TEXT REFERENCES peers(node_id) ON DELETE RESTRICT,
           controller_epoch INTEGER CHECK(controller_epoch>=1),
           command_id INTEGER CHECK(command_id>=1),
           source_administrator_id TEXT CHECK(length(source_administrator_id)=22),
           listener_id TEXT NOT NULL CHECK(length(listener_id)=22),
           selection TEXT NOT NULL CHECK(selection IN('inherit','custom','hidden')),
           CHECK((entry='local_management' AND administrator_id IS NOT NULL AND controller_node_id IS NULL
               AND controller_epoch IS NULL AND command_id IS NULL AND source_administrator_id IS NULL)
             OR (entry='node_management' AND administrator_id IS NULL AND controller_node_id IS NOT NULL
               AND controller_epoch IS NOT NULL AND command_id IS NOT NULL AND source_administrator_id IS NOT NULL))
         ) STRICT;"
    ).map_err(|error| sqlite_error("cannot create public endpoint metadata", error))
}

/// Check only this namespace without calling read_overview recursively. Legacy
/// schemas must not carry a v15 table under a lowered user_version.
pub(super) fn validate_schema(connection: &Connection, version: u32) -> io::Result<()> {
    if version >= 15 {
        read_in(connection).map(|_| ())
    } else {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name IN('endpoint_state','endpoint_overrides','endpoint_audit'))",
            [], |row| row.get(0),
        ).map_err(|error| sqlite_error("cannot inspect legacy endpoint namespace", error))?;
        if exists {
            return Err(invalid_data(
                "public endpoint metadata disagrees with the schema version",
            ));
        }
        Ok(())
    }
}

/// Read a single bounded SQL snapshot; callers that need a coherent inventory
/// must retain the corresponding immutable startup value themselves.
pub(in crate::manage) fn read(directory: &Path) -> io::Result<State> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin endpoint metadata snapshot", error))?;
    require_current(&transaction)?;
    read_in(&transaction)
}

/// Offline/startup reconciliation while the caller retains the process author.
/// The supplied update guard is directory-bound; Pending recovery fails before
/// SQL mutation. No endpoint inventory is inferred from the saved table.
pub(in crate::manage) fn configure(
    directory: &Path,
    guard: &super::UpdateGuard,
    inventory: &Inventory,
) -> io::Result<State> {
    guard.ensure(directory)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin endpoint configuration", error))?;
    let state = sync_inventory(&transaction, inventory)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit endpoint configuration", error))?;
    Ok(state)
}

/// Only a live management coordinator may call this while retaining its author
/// and worker permit. The authenticated administrator and local owner are
/// rechecked inside this mutation transaction; a caller-supplied ID is not
/// authorization. Unknown commit outcomes must be inspected, never replayed.
pub(in crate::manage) fn change_local(
    directory: &Path,
    guard: &super::UpdateGuard,
    administrator: &str,
    expected_revision: u64,
    expected_digest: &str,
    inventory: &Inventory,
    change: &Change,
) -> io::Result<State> {
    guard.ensure(directory)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin endpoint declaration", error))?;
    let state = change_local_in(
        &transaction,
        administrator,
        expected_revision,
        expected_digest,
        inventory,
        change,
    )?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit endpoint declaration", error))?;
    Ok(state)
}

/// Recheck the administrator, current owner and metadata CAS in the caller's
/// transaction. This core never commits or publishes proxy policy. Successful
/// no-ops still advance metadata revision and audit, as ordinary declarations do.
pub(in crate::manage) fn change_local_in(
    transaction: &rusqlite::Transaction<'_>,
    administrator: &str,
    expected_revision: u64,
    expected_digest: &str,
    inventory: &Inventory,
    change: &Change,
) -> io::Result<State> {
    require_current(transaction)?;
    let exists: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM administrators WHERE id=?1)",
            [administrator],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot verify endpoint administrator", error))?;
    if !valid_id(administrator) || !exists {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "endpoint administrator is not authorized",
        ));
    }
    super::control::require_local(transaction)?;
    apply_in(
        transaction,
        inventory,
        expected_revision,
        expected_digest,
        change,
        Actor::Local(administrator),
    )
}

/// Typed row validation also runs on immutable backup connections: SQLite's
/// read-only CHECK handling must not be the only validation of these values.
pub(in crate::manage) fn read_in(connection: &Connection) -> io::Result<State> {
    let count: i64 = connection
        .query_row("SELECT count(*) FROM endpoint_state", [], |row| row.get(0))
        .map_err(|error| sqlite_error("cannot count endpoint metadata state", error))?;
    if count != 1 {
        return Err(corrupt());
    }
    let mut state_statement = connection
        .prepare("SELECT revision,digest FROM endpoint_state WHERE singleton=1")
        .map_err(|error| sqlite_error("cannot prepare endpoint metadata state", error))?;
    let mut state_rows = state_statement
        .query([])
        .map_err(|error| sqlite_error("cannot read endpoint metadata state", error))?;
    let state_row = state_rows
        .next()
        .map_err(|error| sqlite_error("cannot read endpoint metadata state", error))?
        .ok_or_else(corrupt)?;
    let revision: i64 = state_row
        .get(0)
        .map_err(|error| sqlite_error("cannot decode endpoint metadata revision", error))?;
    let digest = text(state_row, 1, 64)?;
    let revision = u64::try_from(revision)
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(corrupt)?;
    if !digest.is_empty() && !valid_digest(&digest) {
        return Err(corrupt());
    }
    let node: String = connection
        .query_row(
            "SELECT node_id FROM node_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot inspect endpoint node identity", error))?;
    if !valid_id(&node) {
        return Err(corrupt());
    }
    let mut statement = connection.prepare(
        "SELECT listener_id,protocol,bind,selection,public_address FROM endpoint_overrides ORDER BY listener_id LIMIT 257",
    ).map_err(|error| sqlite_error("cannot prepare endpoint overrides", error))?;
    let mut rows = statement
        .query([])
        .map_err(|error| sqlite_error("cannot read endpoint overrides", error))?;
    let mut overrides = Vec::new();
    let mut identities = HashSet::new();
    let mut tuples = HashSet::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| sqlite_error("cannot read endpoint override", error))?
    {
        if overrides.len() == MAX_OVERRIDES {
            return Err(corrupt());
        }
        let listener_id = text(row, 0, 22)?;
        let protocol = protocol(&text(row, 1, 6)?)?;
        let bind_text = text(row, 2, 80)?;
        let bind = bind_text.parse::<SocketAddr>().map_err(|_| corrupt())?;
        if bind.port() == 0
            || bind.to_string() != bind_text
            || !valid_id(&listener_id)
            || crate::manage::proxy::endpoint_id(&node, protocol, bind) != listener_id
            || !identities.insert(listener_id.clone())
            || !tuples.insert((protocol_name(protocol), bind))
        {
            return Err(corrupt());
        }
        let selection = match text(row, 3, 6)?.as_str() {
            "custom" => {
                let value = text(row, 4, 259)?;
                if crate::manage::proxy::public_address(&value).ok().as_deref()
                    != Some(value.as_str())
                {
                    return Err(corrupt());
                }
                AddressSelection::Custom {
                    public_address: value,
                }
            }
            "hidden"
                if matches!(
                    row.get_ref(4)
                        .map_err(|error| sqlite_error("cannot decode hidden endpoint", error))?,
                    ValueRef::Null
                ) =>
            {
                AddressSelection::Hidden
            }
            _ => return Err(corrupt()),
        };
        overrides.push(Override {
            listener_id,
            protocol,
            bind,
            selection,
        });
    }
    let (audit_count, first, last): (i64, Option<i64>, Option<i64>) = connection
        .query_row(
            "SELECT count(*),min(sequence),max(sequence) FROM endpoint_audit",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| sqlite_error("cannot inspect endpoint audit high water", error))?;
    if !(0..=MAX_AUDIT).contains(&audit_count)
        || first.is_some_and(|n| n < 2)
        || last.is_some_and(|n| u64::try_from(n).map_or(true, |n| n > revision))
        || digest.is_empty() && (revision != 1 || !overrides.is_empty() || audit_count != 0)
    {
        return Err(corrupt());
    }
    Ok(State {
        revision,
        digest,
        overrides,
    })
}

/// Record the current inventory digest before exposing management listeners.
/// Caller owns author/update and an immediate transaction. Changing startup
/// configuration invalidates prior CAS but never applies an old override to a
/// different identity, deletes detached rows, or alters proxy access policy.
pub(in crate::manage) fn sync_inventory(
    connection: &Connection,
    inventory: &Inventory,
) -> io::Result<State> {
    require_transaction(connection)?;
    super::recovery::require_writable(connection)?;
    let node = require_current(connection)?;
    inventory.validate(&node)?;
    let before = read_in(connection)?;
    validate_attached(&before, inventory)?;
    if before.digest == inventory.digest {
        return Ok(before);
    }
    let next = increment(before.revision)?;
    save_state(connection, &before, next, &inventory.digest)?;
    saved_state(connection, next, &inventory.digest)
}

/// Apply inside the caller's authorized immediate transaction/savepoint. The
/// actor/owner must be verified in that same transaction, not request JSON.
/// A detached row can only return to Inherit. Successful no-ops consume a
/// revision too; deletion never resets the permanent CAS/audit high water.
pub(super) fn apply_in(
    connection: &Connection,
    inventory: &Inventory,
    expected_revision: u64,
    expected_digest: &str,
    change: &Change,
    actor: Actor<'_>,
) -> io::Result<State> {
    require_transaction(connection)?;
    super::recovery::require_writable(connection)?;
    let node = require_current(connection)?;
    inventory.validate(&node)?;
    let before = read_in(connection)?;
    validate_attached(&before, inventory)?;
    if sql_revision(expected_revision).is_err()
        || !valid_digest(expected_digest)
        || !valid_id(&change.listener_id)
    {
        return Err(rejected(Error::InvalidEndpoint));
    }
    if before.digest != expected_digest || inventory.digest != expected_digest {
        return Err(rejected(Error::GenerationConflict));
    }
    if before.revision != expected_revision {
        return Err(rejected(Error::RevisionConflict));
    }
    let configured = inventory
        .listeners
        .iter()
        .find(|listener| listener.id == change.listener_id);
    let saved = before
        .overrides
        .iter()
        .find(|saved| saved.listener_id == change.listener_id);
    if configured.is_none()
        && (saved.is_none() || !matches!(change.selection, AddressSelection::Inherit))
    {
        return Err(rejected(Error::InvalidEndpoint));
    }
    let next = increment(before.revision)?;
    let (mode, address) = match &change.selection {
        AddressSelection::Inherit => ("inherit", None),
        AddressSelection::Hidden => ("hidden", None),
        AddressSelection::Custom { public_address } => (
            "custom",
            Some(
                crate::manage::proxy::public_address(public_address)
                    .map_err(|_| rejected(Error::InvalidEndpoint))?,
            ),
        ),
    };
    if mode == "inherit" {
        let changed = connection
            .execute(
                "DELETE FROM endpoint_overrides WHERE listener_id=?1",
                [&change.listener_id],
            )
            .map_err(|error| sqlite_error("cannot clear endpoint override", error))?;
        if changed != usize::from(saved.is_some()) {
            return Err(corrupt());
        }
    } else {
        let listener = configured.ok_or_else(|| rejected(Error::InvalidEndpoint))?;
        if saved.is_none() && before.overrides.len() == MAX_OVERRIDES {
            return Err(rejected(Error::Capacity));
        }
        let changed = connection.execute(
            "INSERT INTO endpoint_overrides(listener_id,protocol,bind,selection,public_address) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(listener_id) DO UPDATE SET selection=excluded.selection,public_address=excluded.public_address",
            params![listener.id, protocol_name(listener.protocol), listener.bind.to_string(), mode, address],
        ).map_err(|error| sqlite_error("cannot save endpoint override", error))?;
        if changed != 1 {
            return Err(corrupt());
        }
    }
    save_state(connection, &before, next, expected_digest)?;
    audit(connection, actor, next, &change.listener_id, mode)?;
    saved_state(connection, next, expected_digest)
}

fn saved_state(connection: &Connection, revision: u64, digest: &str) -> io::Result<State> {
    let state = read_in(connection)?;
    if state.revision != revision || state.digest != digest {
        return Err(corrupt());
    }
    Ok(state)
}

fn validate_attached(state: &State, inventory: &Inventory) -> io::Result<()> {
    for saved in &state.overrides {
        if let Some(current) = inventory
            .listeners
            .iter()
            .find(|listener| listener.id == saved.listener_id)
            && (protocol_name(saved.protocol) != protocol_name(current.protocol)
                || saved.bind != current.bind)
        {
            return Err(invalid_data(
                "endpoint identity collided with a different configured listener",
            ));
        }
    }
    Ok(())
}

fn save_state(connection: &Connection, before: &State, next: u64, digest: &str) -> io::Result<()> {
    let changed = connection.execute(
        "UPDATE endpoint_state SET revision=?1,digest=?2 WHERE singleton=1 AND revision=?3 AND digest=?4",
        params![sql_revision(next)?, digest, sql_revision(before.revision)?, before.digest],
    ).map_err(|error| sqlite_error("cannot save endpoint metadata revision", error))?;
    if changed != 1 {
        return Err(rejected(Error::RevisionConflict));
    }
    Ok(())
}

fn audit(
    connection: &Connection,
    actor: Actor<'_>,
    revision: u64,
    listener: &str,
    selection: &str,
) -> io::Result<()> {
    let (entry, administrator, controller, epoch, command, source) = match actor {
        Actor::Automation { .. } => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "automation endpoint changes are not authorized",
            ));
        }
        Actor::Local(id) => ("local_management", Some(id), None, None, None, None),
        Actor::Remote {
            node_id,
            epoch,
            command_id,
            source_administrator_id,
        } => (
            "node_management",
            None,
            Some(node_id),
            Some(sql_revision(epoch)?),
            Some(sql_revision(command_id)?),
            Some(source_administrator_id),
        ),
    };
    let changed = connection.execute(
        "INSERT INTO endpoint_audit(sequence,entry,administrator_id,controller_node_id,controller_epoch,command_id,source_administrator_id,listener_id,selection) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![sql_revision(revision)?, entry, administrator, controller, epoch, command, source, listener, selection],
    ).map_err(|error| sqlite_error("cannot record endpoint mutation actor", error))?;
    if changed != 1 {
        return Err(corrupt());
    }
    connection.execute("DELETE FROM endpoint_audit WHERE sequence NOT IN(SELECT sequence FROM endpoint_audit ORDER BY sequence DESC LIMIT 16384)", [])
        .map_err(|error| sqlite_error("cannot retain bounded endpoint audit", error))?;
    Ok(())
}

fn require_current(connection: &Connection) -> io::Result<String> {
    let overview = read_overview(connection)?;
    if overview.schema_version < 15 {
        return Err(rejected(Error::UpgradeRequired));
    }
    Ok(overview.node_id)
}
fn require_transaction(connection: &Connection) -> io::Result<()> {
    if connection.is_autocommit() {
        return Err(invalid_input(
            "endpoint writes require a caller-owned transaction",
        ));
    }
    Ok(())
}
fn text(row: &rusqlite::Row<'_>, column: usize, maximum: usize) -> io::Result<String> {
    match row
        .get_ref(column)
        .map_err(|error| sqlite_error("cannot decode endpoint metadata value", error))?
    {
        ValueRef::Text(bytes) if bytes.len() <= maximum => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| corrupt()),
        _ => Err(corrupt()),
    }
}
fn protocol(value: &str) -> io::Result<Protocol> {
    match value {
        "http" => Ok(Protocol::Http),
        "https" => Ok(Protocol::Https),
        "socks5" => Ok(Protocol::Socks5),
        "masque" => Ok(Protocol::Masque),
        "auto" => Ok(Protocol::Auto),
        _ => Err(corrupt()),
    }
}
fn protocol_name(value: Protocol) -> &'static str {
    match value {
        Protocol::Http => "http",
        Protocol::Https => "https",
        Protocol::Socks5 => "socks5",
        Protocol::Masque => "masque",
        Protocol::Auto => "auto",
    }
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn sql_revision(value: u64) -> io::Result<i64> {
    i64::try_from(value)
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| invalid_input("endpoint revision must be positive and fit SQLite"))
}
fn increment(value: u64) -> io::Result<u64> {
    value
        .checked_add(1)
        .filter(|next| i64::try_from(*next).is_ok())
        .ok_or_else(|| rejected(Error::RevisionConflict))
}
fn corrupt() -> io::Error {
    invalid_data("public endpoint metadata is malformed")
}
fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn rejected(error: Error) -> io::Error {
    io::Error::new(
        match error {
            Error::InvalidEndpoint => io::ErrorKind::InvalidInput,
            Error::UpgradeRequired => io::ErrorKind::Unsupported,
            _ => io::ErrorKind::AlreadyExists,
        },
        error,
    )
}

/// Reconstruct an actual old fixture, never called by production downgrade.
#[cfg(test)]
pub(in crate::manage::store) fn remove_schema_for_test(connection: &Connection) -> io::Result<()> {
    connection.execute_batch("DROP TABLE IF EXISTS endpoint_audit; DROP TABLE IF EXISTS endpoint_overrides; DROP TABLE IF EXISTS endpoint_state;")
        .map_err(|error| sqlite_error("cannot reconstruct pre-endpoint fixture", error))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::manage::store::{
        self, DATABASE_NAME, OpenFlags, TransactionBehavior, configure, open,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Owns a random private directory; no operator-selected path is removed.
    struct Fixture {
        directory: PathBuf,
        node: String,
        administrator: String,
    }
    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory =
                std::env::temp_dir().join(format!("vproxy-endpoints-{}", store::random_id()?));
            let overview =
                store::initialize(&directory, "endpoint fixture", "admin", "fixture PHC")?;
            let connection = open_existing(&directory, false)?;
            let administrator = connection
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)?;
            Ok(Self {
                directory,
                node: overview.node_id,
                administrator,
            })
        }
        fn raw(&self) -> io::Result<Connection> {
            let connection = open(
                &self.directory.join(DATABASE_NAME),
                OpenFlags::SQLITE_OPEN_READ_WRITE,
            )?;
            configure(&connection)?;
            Ok(connection)
        }
        fn inventory(&self, ports: &[u16]) -> io::Result<Inventory> {
            let listeners = ports
                .iter()
                .map(|port| {
                    let bind = SocketAddr::from(([127, 0, 0, 1], *port));
                    Ok(ListenerKey {
                        id: crate::manage::proxy::endpoint_id(&self.node, Protocol::Http, bind),
                        protocol: Protocol::Http,
                        bind,
                        configured_public_address: Some(format!("default.example:{port}")),
                    })
                })
                .collect::<io::Result<Vec<_>>>()?;
            Inventory::new(&self.node, listeners)
        }
        fn configure(&self, inventory: &Inventory) -> io::Result<State> {
            super::configure(
                &self.directory,
                &store::update_lock(&self.directory)?,
                inventory,
            )
        }
        fn change(
            &self,
            state: &State,
            inventory: &Inventory,
            id: &str,
            selection: AddressSelection,
        ) -> io::Result<State> {
            change_local(
                &self.directory,
                &store::update_lock(&self.directory)?,
                &self.administrator,
                state.revision,
                &state.digest,
                inventory,
                &Change {
                    listener_id: id.into(),
                    selection,
                },
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
    fn code(error: &io::Error) -> Option<&'static str> {
        error
            .get_ref()
            .and_then(|error| error.downcast_ref::<Error>())
            .map(Error::code)
    }

    #[test]
    fn declarations_persist_and_config_reordering_preserves_identity_without_policy_changes()
    -> TestResult {
        let fixture = Fixture::new()?;
        let inventory = fixture.inventory(&[18080, 18081])?;
        let state = fixture.configure(&inventory)?;
        assert_eq!(state.revision, 2);
        let id = &inventory.listeners[0].id;
        let state = fixture.change(
            &state,
            &inventory,
            id,
            AddressSelection::Custom {
                public_address: "PROXY.Example:443".into(),
            },
        )?;
        assert_eq!(
            state.overrides[0].selection,
            AddressSelection::Custom {
                public_address: "proxy.example:443".into()
            }
        );
        assert_eq!(read(&fixture.directory)?.revision, state.revision);
        let reordered = fixture.inventory(&[18081, 18080])?;
        assert_eq!(reordered.digest, inventory.digest);
        assert_eq!(fixture.configure(&reordered)?.revision, state.revision);
        let hidden = fixture.change(&state, &reordered, id, AddressSelection::Hidden)?;
        assert_eq!(
            read(&fixture.directory)?.overrides[0].selection,
            AddressSelection::Hidden
        );
        let cleared = fixture.change(&hidden, &reordered, id, AddressSelection::Inherit)?;
        assert!(cleared.overrides.is_empty());
        assert!(cleared.revision > hidden.revision);
        assert_eq!(
            code(
                &fixture
                    .change(&state, &reordered, id, AddressSelection::Hidden)
                    .err()
                    .unwrap()
            ),
            Some("endpoint_revision_changed")
        );
        let connection = fixture.raw()?;
        let policy: (i64, Option<i64>) = connection.query_row(
            "SELECT revision,applied_revision FROM proxy_policy_state",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(policy, (1, None));
        let audit: (i64, String) = connection.query_row(
            "SELECT count(*),min(administrator_id) FROM endpoint_audit",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(audit, (3, fixture.administrator.clone()));
        assert_eq!(store::inspect(&fixture.directory)?.node_id, fixture.node);
        Ok(())
    }

    #[test]
    fn detached_entries_only_allow_explicit_cleanup_with_current_configuration_cas() -> TestResult {
        let fixture = Fixture::new()?;
        let old = fixture.inventory(&[18080])?;
        let state = fixture.configure(&old)?;
        let state = fixture.change(&state, &old, &old.listeners[0].id, AddressSelection::Hidden)?;
        let current = fixture.inventory(&[18081])?;
        let synchronized = fixture.configure(&current)?;
        assert_eq!(synchronized.overrides.len(), 1);
        assert_eq!(synchronized.overrides[0].bind, old.listeners[0].bind);
        assert_eq!(
            code(
                &fixture
                    .change(
                        &state,
                        &old,
                        &old.listeners[0].id,
                        AddressSelection::Inherit
                    )
                    .err()
                    .unwrap()
            ),
            Some("endpoint_configuration_changed")
        );
        assert_eq!(
            code(
                &fixture
                    .change(
                        &synchronized,
                        &current,
                        &old.listeners[0].id,
                        AddressSelection::Hidden
                    )
                    .err()
                    .unwrap()
            ),
            Some("invalid_endpoint")
        );
        let cleared = fixture.change(
            &synchronized,
            &current,
            &old.listeners[0].id,
            AddressSelection::Inherit,
        )?;
        assert!(cleared.overrides.is_empty());
        assert!(cleared.revision > synchronized.revision);
        assert_eq!(
            code(
                &fixture
                    .change(
                        &cleared,
                        &current,
                        &old.listeners[0].id,
                        AddressSelection::Inherit
                    )
                    .err()
                    .unwrap()
            ),
            Some("invalid_endpoint")
        );
        Ok(())
    }

    #[test]
    fn local_mutations_recheck_administrator_and_current_owner() -> TestResult {
        let fixture = Fixture::new()?;
        let inventory = fixture.inventory(&[18080])?;
        let state = fixture.configure(&inventory)?;
        let change = Change {
            listener_id: inventory.listeners[0].id.clone(),
            selection: AddressSelection::Hidden,
        };
        let bad = change_local(
            &fixture.directory,
            &store::update_lock(&fixture.directory)?,
            &store::random_id()?,
            state.revision,
            &state.digest,
            &inventory,
            &change,
        )
        .err()
        .unwrap();
        assert_eq!(bad.kind(), io::ErrorKind::PermissionDenied);
        let peer = store::random_id()?;
        store::register_peer(
            &fixture.directory,
            &peer,
            "controller",
            b"fixture certificate",
            "controller.invalid",
            None,
        )?;
        store::set_owner(
            &fixture.directory,
            &store::update_lock(&fixture.directory)?,
            &fixture.administrator,
            1,
            Some(&peer),
        )?;
        assert!(
            fixture
                .change(
                    &state,
                    &inventory,
                    &change.listener_id,
                    AddressSelection::Hidden
                )
                .is_err()
        );
        assert_eq!(read(&fixture.directory)?.revision, state.revision);
        assert!(read(&fixture.directory)?.overrides.is_empty());
        Ok(())
    }

    #[test]
    fn capacity_and_revision_exhaustion_do_not_rebind_or_reset_saved_entries() -> TestResult {
        let fixture = Fixture::new()?;
        let inventory = fixture.inventory(&[18080])?;
        let state = fixture.configure(&inventory)?;
        let connection = fixture.raw()?;
        for port in 20000..20256 {
            let bind = SocketAddr::from(([127, 0, 0, 1], port));
            let id = crate::manage::proxy::endpoint_id(&fixture.node, Protocol::Http, bind);
            connection.execute(
                "INSERT INTO endpoint_overrides VALUES(?1,'http',?2,'hidden',NULL)",
                params![id, bind.to_string()],
            )?;
        }
        assert_eq!(
            code(
                &fixture
                    .change(
                        &state,
                        &inventory,
                        &inventory.listeners[0].id,
                        AddressSelection::Hidden
                    )
                    .err()
                    .unwrap()
            ),
            Some("endpoint_capacity")
        );
        let full = read(&fixture.directory)?;
        assert_eq!(full.overrides.len(), MAX_OVERRIDES);
        let cleared = fixture.change(
            &full,
            &inventory,
            &full.overrides[0].listener_id,
            AddressSelection::Inherit,
        )?;
        assert_eq!(cleared.overrides.len(), MAX_OVERRIDES - 1);
        let saved = fixture.change(
            &cleared,
            &inventory,
            &inventory.listeners[0].id,
            AddressSelection::Hidden,
        )?;
        connection.execute("UPDATE endpoint_state SET revision=?1", [i64::MAX])?;
        let exhausted = read(&fixture.directory)?;
        assert_eq!(
            code(
                &fixture
                    .change(
                        &exhausted,
                        &inventory,
                        &inventory.listeners[0].id,
                        AddressSelection::Inherit
                    )
                    .err()
                    .unwrap()
            ),
            Some("endpoint_revision_changed")
        );
        assert_eq!(read(&fixture.directory)?.revision, i64::MAX as u64);
        assert_eq!(
            read(&fixture.directory)?.overrides.len(),
            saved.overrides.len()
        );
        Ok(())
    }

    #[test]
    fn audit_failures_roll_back_override_and_revision_together() -> TestResult {
        for trigger in [
            "CREATE TRIGGER fail_audit BEFORE INSERT ON endpoint_audit BEGIN SELECT RAISE(ABORT,'fixture'); END;",
            "CREATE TRIGGER fail_audit BEFORE INSERT ON endpoint_audit BEGIN SELECT RAISE(IGNORE); END;",
            "CREATE TABLE deferred_endpoint_guard(id TEXT REFERENCES administrators(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_audit AFTER INSERT ON endpoint_audit BEGIN INSERT INTO deferred_endpoint_guard VALUES('missing'); END;",
        ] {
            let fixture = Fixture::new()?;
            let inventory = fixture.inventory(&[18080])?;
            let state = fixture.configure(&inventory)?;
            fixture.raw()?.execute_batch(trigger)?;
            assert!(
                fixture
                    .change(
                        &state,
                        &inventory,
                        &inventory.listeners[0].id,
                        AddressSelection::Hidden
                    )
                    .is_err()
            );
            let after = read(&fixture.directory)?;
            assert_eq!(after.revision, state.revision);
            assert!(after.overrides.is_empty());
        }
        Ok(())
    }

    #[test]
    fn typed_rows_reject_bad_canonical_values_and_legacy_namespace_downgrade() -> TestResult {
        for sql in [
            "PRAGMA ignore_check_constraints=ON; UPDATE endpoint_state SET digest='',revision=2;",
            "PRAGMA ignore_check_constraints=ON; UPDATE endpoint_state SET revision=-1;",
            "PRAGMA ignore_check_constraints=ON; UPDATE endpoint_state SET digest='bad';",
            "PRAGMA ignore_check_constraints=ON; UPDATE endpoint_overrides SET bind='127.0.0.1:08080';",
            "UPDATE endpoint_overrides SET listener_id='AAAAAAAAAAAAAAAAAAAAAA';",
            "PRAGMA ignore_check_constraints=ON; UPDATE endpoint_overrides SET public_address='proxy.example:443';",
            "PRAGMA user_version=14;",
        ] {
            let fixture = Fixture::new()?;
            let inventory = fixture.inventory(&[18080])?;
            let state = fixture.configure(&inventory)?;
            fixture.change(
                &state,
                &inventory,
                &inventory.listeners[0].id,
                AddressSelection::Hidden,
            )?;
            fixture.raw()?.execute_batch(sql)?;
            assert!(read(&fixture.directory).is_err(), "{sql}");
            assert!(store::inspect(&fixture.directory).is_err(), "{sql}");
        }
        Ok(())
    }

    #[test]
    fn pending_recovery_rejects_bootstrap_and_direct_transaction_mutations() -> TestResult {
        let fixture = Fixture::new()?;
        fixture.raw()?.execute("UPDATE recovery_state SET kind='restored',phase='pending_review',recovery_id=?1,source_node_id=?2,source_schema_version=14,source_database_sha256=?3,node_key_sha256=?4,imported_users=0,imported_prefixes=0,imported_addresses=0,imported_pools=0",params![store::random_id()?,store::random_id()?,"0".repeat(64),[1_u8;32].as_slice()])?;
        let inventory = fixture.inventory(&[18080])?;
        assert_eq!(
            fixture.configure(&inventory).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut connection = fixture.raw()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_eq!(
            sync_inventory(&transaction, &inventory)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let change = Change {
            listener_id: inventory.listeners[0].id.clone(),
            selection: AddressSelection::Hidden,
        };
        assert_eq!(
            apply_in(
                &transaction,
                &inventory,
                1,
                &inventory.digest,
                &change,
                Actor::Local(&fixture.administrator)
            )
            .err()
            .unwrap()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(read_in(&transaction)?.revision, 1);
        assert!(read_in(&transaction)?.overrides.is_empty());
        Ok(())
    }
}
