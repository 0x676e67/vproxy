//! Durable last-good node-only traffic imports. A bounded typed full snapshot
//! replaces one row, never adds an already observed absolute value again.

mod codec;

#[cfg(all(test, feature = "witness-journal"))]
pub(super) fn check_progress_for_test(old: &NodeSnapshot, new: &NodeSnapshot) -> io::Result<()> {
    codec::check_progress(old, new)
}

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{io, path::Path};

use super::{
    RemoteAuthorization, UpdateGuard, control, invalid_data, peers, read_overview, sqlite_error,
    traffic::{self, BucketPage, NodeSnapshot, Resolution, Scope, Totals},
    valid_id,
};

const MAX_BYTES: usize = 32 * 1024;
const MAX_TIME: u64 = 9_007_199_254_740_991;

/// A validated, already-persisted quarantine rejects before any SQL mutation.
/// Source can return this business result after a fresh read-only observation;
/// unrelated InvalidData errors still represent corruption or uncertainty.
#[derive(Debug, thiserror::Error)]
#[error("remote traffic source is quarantined")]
pub(super) struct Quarantined;

/// Cache provenance is separate from the child's cumulative data; neither a
/// recent HTTP success nor an enabled local target proves its proxy is active.
pub(in crate::manage) struct Source {
    pub(in crate::manage) target_revision: u64,
    pub(in crate::manage) last_success_at: Option<u64>,
    pub(in crate::manage) error: Option<Failure>,
    pub(in crate::manage) authorization_revision: Option<u64>,
    /// Only an authorized same-transaction continuity conflict may set this.
    /// Transport/decode failures cannot quarantine a previously trusted source.
    pub(in crate::manage) quarantined: bool,
}

pub(in crate::manage) struct Cached {
    pub(in crate::manage) source: Source,
    pub(in crate::manage) snapshot: Option<NodeSnapshot>,
}

/// Current local registration and cache facts from one readonly transaction.
pub(in crate::manage) struct BrowserRead {
    pub(in crate::manage) cache: Cached,
    pub(in crate::manage) target: super::targets::Target,
    pub(in crate::manage) peer_active: bool,
    pub(in crate::manage) authorization_revision: u64,
}

/// Allowlisted diagnostics only; arbitrary remote responses never enter SQL.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::manage) enum Failure {
    Unavailable,
    Unsupported,
    NotAuthorized,
    Continuity,
}
impl Failure {
    pub(in crate::manage) const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Unsupported => "unsupported",
            Self::NotAuthorized => "not_authorized",
            Self::Continuity => "continuity_error",
        }
    }
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "unavailable" => Ok(Self::Unavailable),
            "unsupported" => Ok(Self::Unsupported),
            "not_authorized" => Ok(Self::NotAuthorized),
            "continuity_error" => Ok(Self::Continuity),
            _ => Err(invalid_data("invalid remote traffic failure")),
        }
    }
}

/// Schema8 stores at most one canonical <=32KiB snapshot per configured peer
/// (target capacity128). This is a fixed typed cache, not an arbitrary JSON/KV
/// store; no credentials, response text or live uncheckpointed values enter it.
pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection.execute_batch("ALTER TABLE traffic_state ADD COLUMN retention_at INTEGER CHECK(retention_at>=0);
    CREATE TABLE remote_traffic_sources(
      peer_id TEXT PRIMARY KEY NOT NULL REFERENCES managed_targets(peer_id) ON DELETE RESTRICT,
      target_revision INTEGER NOT NULL CHECK(target_revision>=1),
      meter_epoch TEXT CHECK(meter_epoch IS NULL OR length(meter_epoch)=22),
      cursor INTEGER CHECK(cursor>=0),
      snapshot BLOB CHECK(snapshot IS NULL OR length(snapshot) BETWEEN 1 AND 32768),
      last_success_at INTEGER CHECK(last_success_at>=0),
      error TEXT CHECK(error IN('unavailable','unsupported','not_authorized','continuity_error')),
      authorization_revision INTEGER CHECK(authorization_revision>=1),
      quarantined INTEGER NOT NULL DEFAULT 0 CHECK(quarantined IN(0,1)),
      CHECK(quarantined=0 OR snapshot IS NOT NULL),
      CHECK((snapshot IS NULL AND meter_epoch IS NULL AND cursor IS NULL AND last_success_at IS NULL AND authorization_revision IS NULL)
        OR(snapshot IS NOT NULL AND meter_epoch IS NOT NULL AND cursor IS NOT NULL AND authorization_revision IS NOT NULL))
    ) STRICT;").map_err(|error|sqlite_error("cannot create remote traffic cache",error))
}

/// Shared strict bounds for secure decoders and durable imports.
pub(in crate::manage) fn validate_snapshot(snapshot: &NodeSnapshot) -> io::Result<()> {
    codec::validate(snapshot)
}

/// Export only this node's durable payload under the very same read transaction
/// that checks exact leaf/revision/SAN and current controller ownership.
pub(in crate::manage) fn export_snapshot(
    directory: &Path,
    authorization: &RemoteAuthorization,
) -> io::Result<NodeSnapshot> {
    control::read_snapshot(directory, |connection| {
        require_schema(connection)?;
        control::authorize_in(connection, authorization)?;
        traffic::node_snapshot_in(connection)
    })
}
pub(in crate::manage) fn export_totals(
    directory: &Path,
    authorization: &RemoteAuthorization,
    scope: Scope,
) -> io::Result<Totals> {
    control::read_snapshot(directory, |connection| {
        require_schema(connection)?;
        control::authorize_in(connection, authorization)?;
        traffic::totals_in(connection, scope)
    })
}
pub(in crate::manage) fn export_buckets(
    directory: &Path,
    authorization: &RemoteAuthorization,
    scope: Scope,
    resolution: Resolution,
    after: Option<u64>,
    limit: u32,
) -> io::Result<BucketPage> {
    control::read_snapshot(directory, |connection| {
        require_schema(connection)?;
        control::authorize_in(connection, authorization)?;
        traffic::buckets_in(connection, scope, resolution, after, limit)
    })
}

/// Accept a TLS-proven full snapshot only after rechecking source DER/revision
/// and local target generation in this Immediate FULL transaction. Unknown
/// epochs, lower cursors/quantities and same-cursor conflicts preserve lastgood.
/// The caller retains its owned update gate through cancellation/commit.
pub(in crate::manage) fn import(
    directory: &Path,
    gate: &UpdateGuard,
    authorization: &RemoteAuthorization,
    target_revision: u64,
    snapshot: NodeSnapshot,
    observed_at: Option<u64>,
) -> io::Result<Source> {
    gate.ensure(directory)?;
    let encoded = encode_import(&snapshot, observed_at)?;
    let mut connection = peers::open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sql_error)?;
    let result = import_in(
        &transaction,
        authorization,
        target_revision,
        snapshot,
        observed_at,
        encoded,
    )?;
    transaction.commit().map_err(sql_error)?;
    result
}

/// An authenticated continuity rejection is itself durable quarantine. The
/// outer Result controls transaction failure; the inner result is returned only
/// after the caller commits and, for Source, confirms that quarantine.
pub(super) fn import_in(
    transaction: &Connection,
    authorization: &RemoteAuthorization,
    target_revision: u64,
    snapshot: NodeSnapshot,
    observed_at: Option<u64>,
    encoded: Vec<u8>,
) -> io::Result<io::Result<Source>> {
    require_transaction(transaction)?;
    require_schema(transaction)?;
    check_target(transaction, &authorization.node_id, target_revision)?;
    check_capacity(transaction, &authorization.node_id)?;
    let peer = peers::authorize_in(transaction, &authorization.leaf)?.ok_or_else(denied)?;
    if peer.node_id != authorization.node_id
        || peer.authorization_revision != authorization.authorization_revision
        || super::super::tls::verify_peer_name(&authorization.leaf, &peer.expected_san).is_err()
    {
        return Err(denied());
    }
    if snapshot.status.node_id != authorization.node_id {
        return Err(invalid_data(
            "remote traffic identity differs from verified peer",
        ));
    }
    let previous = read_in(transaction, &authorization.node_id)?;
    if previous.source.quarantined {
        return Err(io::Error::new(io::ErrorKind::InvalidData, Quarantined));
    }
    if let Some(previous) = previous.snapshot
        && codec::check_progress(&previous, &snapshot).is_err()
    {
        // Returning Err before COMMIT would roll the quarantine back. Only
        // this already-authorized path can set it; future high cursors or
        // failed network diagnostics must not silently recover continuity.
        transaction.execute("UPDATE remote_traffic_sources SET quarantined=1,error='continuity_error' WHERE peer_id=?1",[&authorization.node_id]).map_err(sql_error)?;
        return Ok(Err(invalid_data(
            "remote traffic continuity conflict persisted",
        )));
    }
    transaction.execute("INSERT INTO remote_traffic_sources(peer_id,target_revision,meter_epoch,cursor,snapshot,last_success_at,error,authorization_revision) VALUES(?1,?2,?3,?4,?5,?6,NULL,?7) ON CONFLICT(peer_id) DO UPDATE SET target_revision=excluded.target_revision,meter_epoch=excluded.meter_epoch,cursor=excluded.cursor,snapshot=excluded.snapshot,last_success_at=excluded.last_success_at,error=NULL,authorization_revision=excluded.authorization_revision WHERE NOT(remote_traffic_sources.target_revision IS excluded.target_revision AND remote_traffic_sources.meter_epoch IS excluded.meter_epoch AND remote_traffic_sources.cursor IS excluded.cursor AND remote_traffic_sources.snapshot IS excluded.snapshot AND remote_traffic_sources.last_success_at IS excluded.last_success_at AND remote_traffic_sources.error IS NULL AND remote_traffic_sources.authorization_revision IS excluded.authorization_revision)",params![authorization.node_id,sql_number(target_revision)?,snapshot.status.meter_epoch,sql_number(snapshot.status.cursor)?,encoded,observed_at.map(sql_number).transpose()?,sql_number(authorization.authorization_revision)?]).map_err(sql_error)?;
    Ok(Ok(Source {
        target_revision,
        last_success_at: observed_at,
        error: None,
        authorization_revision: Some(authorization.authorization_revision),
        quarantined: false,
    }))
}

/// A failed contact changes diagnostic metadata only. Old snapshot/epoch/cursor
/// remain intact; no network failure can reset data or consume unlimited rows.
pub(in crate::manage) fn failed(
    directory: &Path,
    gate: &UpdateGuard,
    peer: &str,
    target_revision: u64,
    failure: Failure,
) -> io::Result<()> {
    gate.ensure(directory)?;
    let mut connection = peers::open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sql_error)?;
    failed_in(&transaction, peer, target_revision, failure)?;
    transaction.commit().map_err(sql_error)
}

/// Preserve the last-good payload and quarantine while changing only the
/// bounded contact diagnostic. Exact repeats are read-only after validation.
pub(super) fn failed_in(
    transaction: &Connection,
    peer: &str,
    target_revision: u64,
    failure: Failure,
) -> io::Result<()> {
    require_transaction(transaction)?;
    require_schema(transaction)?;
    check_target(transaction, peer, target_revision)?;
    check_capacity(transaction, peer)?;
    transaction.execute("INSERT INTO remote_traffic_sources(peer_id,target_revision,error) VALUES(?1,?2,?3) ON CONFLICT(peer_id) DO UPDATE SET error=CASE WHEN quarantined=1 THEN 'continuity_error' ELSE excluded.error END WHERE remote_traffic_sources.error IS NOT CASE WHEN quarantined=1 THEN 'continuity_error' ELSE excluded.error END",params![peer,sql_number(target_revision)?,failure.code()]).map_err(sql_error)?;
    Ok(())
}

fn require_transaction(connection: &Connection) -> io::Result<()> {
    if connection.is_autocommit() {
        return Err(invalid_data(
            "remote traffic write requires a held transaction",
        ));
    }
    Ok(())
}

pub(super) fn encode_import(
    snapshot: &NodeSnapshot,
    observed_at: Option<u64>,
) -> io::Result<Vec<u8>> {
    if observed_at.is_some_and(|time| time > MAX_TIME) {
        return Err(invalid_data(
            "remote traffic observation time exceeds its wire range",
        ));
    }
    codec::encode(snapshot)
}

/// Reads one bounded last-good snapshot; missing data is None, never fabricated
/// zero traffic. Local administrators may inspect historical paused/revoked
/// sources; only imports/contact require their still-current remote permission.
#[cfg(test)]
pub(in crate::manage) fn get(directory: &Path, peer: &str) -> io::Result<Cached> {
    if !valid_id(peer) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid remote traffic peer",
        ));
    }
    let mut connection = peers::open_existing(directory, false)?;
    let transaction = connection.transaction().map_err(sql_error)?;
    require_schema(&transaction)?;
    let exists: i64 = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_targets WHERE peer_id=?1)",
            [peer],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    if exists != 1 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "remote traffic target is not configured",
        ));
    }
    read_in(&transaction, peer)
}

fn read_in(connection: &Connection, peer: &str) -> io::Result<Cached> {
    let row=connection.query_row("SELECT target_revision,meter_epoch,cursor,snapshot,last_success_at,error,authorization_revision,quarantined FROM remote_traffic_sources WHERE peer_id=?1",[peer],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,Option<String>>(1)?,row.get::<_,Option<i64>>(2)?,row.get::<_,Option<Vec<u8>>>(3)?,row.get::<_,Option<i64>>(4)?,row.get::<_,Option<String>>(5)?,row.get::<_,Option<i64>>(6)?,row.get::<_,i64>(7)?))).optional().map_err(sql_error)?;
    let Some((revision, epoch, cursor, blob, success, error, auth_revision, quarantined)) = row
    else {
        return Ok(Cached {
            source: Source {
                target_revision: 0,
                last_success_at: None,
                error: None,
                authorization_revision: None,
                quarantined: false,
            },
            snapshot: None,
        });
    };
    let revision = positive(revision)?;
    let snapshot = blob.map(|blob| codec::decode(&blob)).transpose()?;
    if snapshot
        .as_ref()
        .map(|snapshot| snapshot.status.node_id.as_str())
        .is_some_and(|id| id != peer)
        || snapshot
            .as_ref()
            .map(|snapshot| snapshot.status.meter_epoch.as_str())
            != epoch.as_deref()
        || snapshot.as_ref().map(|snapshot| snapshot.status.cursor)
            != cursor.map(nonnegative).transpose()?
        || snapshot.is_none() && success.is_some()
        || snapshot.is_some() != auth_revision.is_some()
        || ![0, 1].contains(&quarantined)
        || quarantined == 1 && (snapshot.is_none() || error.as_deref() != Some("continuity_error"))
    {
        return Err(invalid_data("remote traffic cache provenance is malformed"));
    }
    Ok(Cached {
        source: Source {
            target_revision: revision,
            last_success_at: success
                .map(|time| {
                    let time = nonnegative(time)?;
                    if time > MAX_TIME {
                        return Err(invalid_data(
                            "remote traffic observation time exceeds its wire range",
                        ));
                    }
                    Ok(time)
                })
                .transpose()?,
            error: error.as_deref().map(Failure::parse).transpose()?,
            authorization_revision: auth_revision.map(positive).transpose()?,
            quarantined: quarantined == 1,
        },
        snapshot,
    })
}

/// A source cannot stay 'ready' merely because its target generation did not
/// change while local peer permission/certificate revision was revoked.
pub(in crate::manage) fn browser_read(directory: &Path, peer: &str) -> io::Result<BrowserRead> {
    let mut connection = peers::open_existing(directory, false)?;
    let transaction = connection.transaction().map_err(sql_error)?;
    require_schema(&transaction)?;
    let target = super::targets::get_in(&transaction, peer)?;
    let (active, revision): (i64, i64) = transaction
        .query_row(
            "SELECT active,authorization_revision FROM peers WHERE node_id=?1",
            [peer],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sql_error)?;
    if ![0, 1].contains(&active) {
        return Err(invalid_data("invalid remote traffic peer state"));
    }
    Ok(BrowserRead {
        cache: read_in(&transaction, peer)?,
        target,
        peer_active: active == 1,
        authorization_revision: positive(revision)?,
    })
}

fn require_schema(connection: &Connection) -> io::Result<()> {
    if read_overview(connection)?.schema_version < 8 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "remote traffic requires explicit management schema migration",
        ));
    }
    Ok(())
}

fn check_capacity(connection: &Connection, peer: &str) -> io::Result<()> {
    let count: i64 = connection
        .query_row("SELECT count(*) FROM remote_traffic_sources", [], |row| {
            row.get(0)
        })
        .map_err(sql_error)?;
    let existing: i64 = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM remote_traffic_sources WHERE peer_id=?1)",
            [peer],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    if !(0..=128).contains(&count) || ![0, 1].contains(&existing) || count == 128 && existing == 0 {
        return Err(invalid_data("remote traffic source capacity exceeded"));
    }
    Ok(())
}
fn check_target(connection: &Connection, peer: &str, revision: u64) -> io::Result<()> {
    if !valid_id(peer) || revision == 0 {
        return Err(denied());
    }
    let row=connection.query_row("SELECT revision,active,retired,rollback_detected FROM managed_targets WHERE peer_id=?1",[peer],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?))).optional().map_err(sql_error)?;
    let Some((current, active, retired, rollback)) = row else {
        return Err(denied());
    };
    if ![0, 1].contains(&active) || ![0, 1].contains(&retired) || ![0, 1].contains(&rollback) {
        return Err(invalid_data("remote target state is malformed"));
    }
    if positive(current)? != revision || active != 1 || retired != 0 || rollback != 0 {
        return Err(denied());
    }
    Ok(())
}
fn positive(value: i64) -> io::Result<u64> {
    let value = nonnegative(value)?;
    if value == 0 {
        return Err(invalid_data("remote traffic revision is malformed"));
    }
    Ok(value)
}
fn nonnegative(value: i64) -> io::Result<u64> {
    u64::try_from(value).map_err(|_| invalid_data("remote traffic number is malformed"))
}
fn sql_number(value: u64) -> io::Result<i64> {
    i64::try_from(value).map_err(|_| invalid_data("remote traffic number exceeds SQLite range"))
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "remote traffic source is no longer authorized",
    )
}
fn sql_error(error: rusqlite::Error) -> io::Error {
    sqlite_error("cannot access remote traffic cache", error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        manage::store::{
            self, random_id,
            traffic::{Status, Window},
        },
        traffic::Snapshot,
    };
    use std::{path::PathBuf, sync::Arc};

    struct Fixture {
        directory: PathBuf,
        administrator: String,
        peer: String,
        epoch: String,
        leaf: Arc<[u8]>,
    }
    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory =
                std::env::temp_dir().join(format!("vproxy-remote-traffic-{}", random_id()?));
            store::initialize(&directory, "importer", "admin", "private fixture PHC")?;
            let connection = peers::open_existing(&directory, false)?;
            let administrator: String = connection
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(sql_error)?;
            let peer = random_id()?;
            let epoch = random_id()?;
            let certificate = rcgen::generate_simple_self_signed(vec!["source.example".into()])
                .map_err(io::Error::other)?;
            let leaf: Arc<[u8]> = certificate.cert.der().to_vec().into();
            store::register_peer(&directory, &peer, "source", &leaf, "source.example", None)?;
            super::super::targets::configure(
                &directory,
                &administrator,
                &peer,
                None,
                "https://source.example",
                true,
                None,
            )?;
            Ok(Self {
                directory,
                administrator,
                peer,
                epoch,
                leaf,
            })
        }
        fn proof(&self) -> RemoteAuthorization {
            RemoteAuthorization {
                node_id: self.peer.clone(),
                authorization_revision: 1,
                leaf: self.leaf.clone(),
            }
        }
        fn snapshot(&self, cursor: u64, bytes: u64) -> NodeSnapshot {
            let value = Snapshot {
                upload: bytes,
                download: bytes / 2,
                saturated: false,
            };
            let windows = |id| {
                vec![Window {
                    window_id: id,
                    values: [Some(value), None, None],
                }]
            };
            NodeSnapshot {
                status: Status {
                    node_id: self.peer.clone(),
                    meter_epoch: self.epoch.clone(),
                    run_id: Some(self.epoch.clone()),
                    cursor,
                    clean: false,
                    loss_possible: false,
                    history_gap: false,
                    time_uncertain: false,
                    last_checkpoint_at: Some(65_000),
                    meter_started_at: Some(60_000),
                },
                totals: [
                    value,
                    Snapshot {
                        upload: 0,
                        download: 0,
                        saturated: false,
                    },
                    Snapshot {
                        upload: 0,
                        download: 0,
                        saturated: false,
                    },
                ],
                minute: windows(60_000),
                hour: windows(0),
                day: windows(0),
                floors: [Some(0); 3],
            }
        }
        fn import(&self, snapshot: NodeSnapshot) -> io::Result<Source> {
            import(
                &self.directory,
                &store::update_lock(&self.directory)?,
                &self.proof(),
                1,
                snapshot,
                Some(70_000),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn absolute_import_is_idempotent_restart_safe_and_never_part_of_local_node() -> io::Result<()> {
        let fixture = Fixture::new()?;
        assert!(get(&fixture.directory, &fixture.peer)?.snapshot.is_none());
        fixture.import(fixture.snapshot(1, 10))?;
        fixture.import(fixture.snapshot(1, 10))?;
        fixture.import(fixture.snapshot(2, 15))?;
        let loaded = get(&fixture.directory, &fixture.peer)?;
        assert_eq!(loaded.snapshot.unwrap().totals[0].upload, 15);
        assert_eq!(loaded.source.last_success_at, Some(70_000));
        assert!(loaded.source.error.is_none());
        let local = traffic::totals(&fixture.directory, Scope::Node)?;
        assert!(
            local
                .items
                .iter()
                .all(|item| item.value.upload == 0 && item.value.download == 0)
        );
        let gate = store::update_lock(&fixture.directory)?;
        failed(
            &fixture.directory,
            &gate,
            &fixture.peer,
            1,
            Failure::Unavailable,
        )?;
        let loaded = get(&fixture.directory, &fixture.peer)?;
        assert_eq!(loaded.snapshot.unwrap().status.cursor, 2);
        assert!(loaded.source.error == Some(Failure::Unavailable));
        failed(
            &fixture.directory,
            &gate,
            &fixture.peer,
            1,
            Failure::Continuity,
        )?;
        // A transport/decoder's classification alone is not authorized proof of a
        // persisted regression and must not poison the sticky quarantine bit.
        assert!(!get(&fixture.directory, &fixture.peer)?.source.quarantined);
        drop(gate);
        fixture.import(fixture.snapshot(2, 15))?;
        assert!(
            get(&fixture.directory, &fixture.peer)?
                .source
                .error
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn epoch_cursor_counter_and_same_cursor_conflicts_preserve_lastgood() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.import(fixture.snapshot(2, 15))?;
        for mut candidate in [
            fixture.snapshot(1, 15),
            fixture.snapshot(2, 16),
            fixture.snapshot(3, 14),
        ] {
            assert!(codec::check_progress(&fixture.snapshot(2, 15), &candidate).is_err());
            candidate = fixture.snapshot(3, 16);
            candidate.status.meter_epoch = random_id()?;
            assert!(codec::check_progress(&fixture.snapshot(2, 15), &candidate).is_err());
        }
        let mut missing = fixture.snapshot(3, 16);
        missing.minute.clear();
        missing.status.history_gap = true;
        assert!(codec::check_progress(&fixture.snapshot(2, 15), &missing).is_err()); // missing is not a deletion proof
        let mut missing = fixture.snapshot(3, 16);
        missing.minute.clear();
        missing.floors[0] = Some(60_000);
        missing.status.history_gap = true;
        assert!(codec::check_progress(&fixture.snapshot(2, 15), &missing).is_err()); // equal floor still retained
        let mut retained = fixture.snapshot(3, 16);
        retained.minute.clear();
        retained.floors[0] = Some(120_000);
        retained.status.history_gap = true;
        fixture.import(retained)?;
        let loaded = get(&fixture.directory, &fixture.peer)?.snapshot.unwrap();
        assert_eq!(loaded.status.cursor, 3);
        assert_eq!(loaded.totals[0].upload, 16);
        assert!(loaded.minute.is_empty());
        // Once a fully authorized source actually regresses, even a later higher
        // cursor cannot silently unquarantine it or overwrite the last good facts.
        assert!(fixture.import(fixture.snapshot(2, 15)).is_err());
        assert!(get(&fixture.directory, &fixture.peer)?.source.quarantined);
        assert!(fixture.import(fixture.snapshot(4, 17)).is_err());
        let gate = store::update_lock(&fixture.directory)?;
        failed(
            &fixture.directory,
            &gate,
            &fixture.peer,
            1,
            Failure::Unavailable,
        )?;
        let blocked = get(&fixture.directory, &fixture.peer)?;
        assert!(blocked.source.quarantined && blocked.source.error == Some(Failure::Continuity));
        assert_eq!(blocked.snapshot.unwrap().status.cursor, 3);
        Ok(())
    }

    #[test]
    fn exact_leaf_revision_and_target_generation_are_rechecked_at_commit() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.import(fixture.snapshot(1, 10))?;
        let gate = store::update_lock(&fixture.directory)?;
        let mut proof = fixture.proof();
        proof.authorization_revision = 2;
        assert!(
            import(
                &fixture.directory,
                &gate,
                &proof,
                1,
                fixture.snapshot(2, 11),
                Some(71_000)
            )
            .is_err()
        );
        proof = fixture.proof();
        proof.leaf = Arc::from(b"not a TLS leaf".as_slice());
        assert!(
            import(
                &fixture.directory,
                &gate,
                &proof,
                1,
                fixture.snapshot(2, 11),
                Some(71_000)
            )
            .is_err()
        );
        drop(gate);
        super::super::targets::configure(
            &fixture.directory,
            &fixture.administrator,
            &fixture.peer,
            Some(1),
            "https://source.example:8443",
            true,
            None,
        )?;
        assert!(fixture.import(fixture.snapshot(2, 11)).is_err());
        let gate = store::update_lock(&fixture.directory)?;
        import(
            &fixture.directory,
            &gate,
            &fixture.proof(),
            2,
            fixture.snapshot(2, 11),
            Some(71_000),
        )?;
        drop(gate);
        store::revoke_certificate(&fixture.directory, &fixture.leaf, 1)?;
        let gate = store::update_lock(&fixture.directory)?;
        assert!(
            import(
                &fixture.directory,
                &gate,
                &fixture.proof(),
                2,
                fixture.snapshot(3, 12),
                Some(72_000)
            )
            .is_err()
        );
        assert_eq!(
            get(&fixture.directory, &fixture.peer)?
                .snapshot
                .unwrap()
                .totals[0]
                .upload,
            11
        );
        let browser = browser_read(&fixture.directory, &fixture.peer)?;
        assert_eq!(browser.authorization_revision, 2);
        assert_eq!(browser.cache.source.authorization_revision, Some(1));
        Ok(())
    }

    #[test]
    fn failed_schema_eight_migration_does_not_leave_retention_column_or_drop_old_state()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let before = traffic::restore(&fixture.directory)?.status;
        let connection = peers::open_existing(&fixture.directory, true)?;
        super::super::control::reconstruct_v8(&connection)?;
        connection.execute_batch("DROP TABLE remote_traffic_sources; ALTER TABLE traffic_state DROP COLUMN retention_at; PRAGMA user_version=7; CREATE TABLE remote_traffic_sources(operator_fixture TEXT);").map_err(sql_error)?;
        let backup = fixture.directory.join("failed-schema8.sqlite3");
        assert!(store::migrate(&fixture.directory, &backup).is_err());
        assert_eq!(store::inspect(&fixture.directory)?.schema_version, 7);
        assert_eq!(
            traffic::restore(&fixture.directory)?.status.meter_epoch,
            before.meter_epoch
        );
        let columns: i64 = connection
            .query_row(
                "SELECT count(*) FROM pragma_table_info('traffic_state') WHERE name='retention_at'",
                [],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        assert_eq!(columns, 0);
        assert_eq!(
            store::read_overview(&Connection::open(backup).map_err(sql_error)?)?.schema_version,
            7
        );
        Ok(())
    }

    #[test]
    fn maximum_cache_is_bounded_and_malformed_shapes_fail_closed() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let mut maximum = fixture.snapshot(1, u64::MAX);
        maximum.totals = [Snapshot {
            upload: u64::MAX,
            download: u64::MAX,
            saturated: true,
        }; 3];
        let windows = |count: u64, width: u64| {
            (0..count)
                .map(|index| Window {
                    window_id: index * width,
                    values: [Some(maximum.totals[0]); 3],
                })
                .collect()
        };
        maximum.minute = windows(60, 60_000);
        maximum.hour = windows(48, 3_600_000);
        maximum.day = windows(30, 86_400_000);
        let bytes = codec::encode(&maximum)?;
        assert!(bytes.len() <= MAX_BYTES);
        assert_eq!(codec::encode(&codec::decode(&bytes)?)?, bytes);
        maximum.minute[1].window_id = 0;
        assert!(validate_snapshot(&maximum).is_err());
        let mut double_counted = fixture.snapshot(1, 10);
        double_counted.minute.push(Window {
            window_id: 120_000,
            values: double_counted.minute[0].values,
        });
        assert!(validate_snapshot(&double_counted).is_err());
        double_counted.totals[0].saturated = true;
        assert!(validate_snapshot(&double_counted).is_ok());
        assert!(codec::decode(&vec![b' '; MAX_BYTES + 1]).is_err());
        fixture.import(fixture.snapshot(1, 10))?;
        let gate = store::update_lock(&fixture.directory)?;
        assert!(
            import(
                &fixture.directory,
                &gate,
                &fixture.proof(),
                1,
                fixture.snapshot(2, 11),
                Some(MAX_TIME + 1)
            )
            .is_err()
        );
        assert_eq!(
            get(&fixture.directory, &fixture.peer)?
                .snapshot
                .unwrap()
                .status
                .cursor,
            1
        );
        drop(gate);
        let connection = peers::open_existing(&fixture.directory, true)?;
        connection
            .execute(
                "UPDATE remote_traffic_sources SET last_success_at=?1",
                [i64::try_from(MAX_TIME + 1).unwrap()],
            )
            .map_err(sql_error)?;
        assert!(browser_read(&fixture.directory, &fixture.peer).is_err());
        connection
            .execute(
                "UPDATE remote_traffic_sources SET last_success_at=70000",
                [],
            )
            .map_err(sql_error)?;
        connection
            .execute(
                "UPDATE remote_traffic_sources SET snapshot=?1",
                [b"{\"version\":1}".as_slice()],
            )
            .map_err(sql_error)?;
        assert!(get(&fixture.directory, &fixture.peer).is_err());
        Ok(())
    }

    #[test]
    fn schema_seven_migration_preserves_traffic_epoch_marker_and_consistent_backup()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let before = traffic::restore(&fixture.directory)?.status;
        let gate = store::update_lock(&fixture.directory)?;
        let run = traffic::start_run(
            &fixture.directory,
            &gate,
            &before.meter_epoch,
            before.cursor,
            Some(60_000),
        )?
        .status;
        traffic::checkpoint(
            &fixture.directory,
            &gate,
            run.run_id.as_deref().unwrap(),
            Some(65_000),
            &[],
            &[],
        )?;
        drop(gate);
        let connection = peers::open_existing(&fixture.directory, true)?;
        super::super::control::reconstruct_v8(&connection)?;
        connection.execute_batch("DROP TABLE remote_traffic_sources; ALTER TABLE traffic_state DROP COLUMN retention_at; PRAGMA user_version=7;").map_err(sql_error)?;
        let old = traffic::restore(&fixture.directory)?.status;
        let backup = fixture.directory.join("before-schema8.sqlite3");
        assert_eq!(
            store::migrate(&fixture.directory, &backup)?.schema_version,
            store::SCHEMA_VERSION
        );
        let after = traffic::restore(&fixture.directory)?.status;
        assert_eq!(after.meter_epoch, old.meter_epoch);
        assert_eq!(after.cursor, old.cursor);
        assert_eq!(after.run_id, old.run_id);
        assert!(!after.clean);
        assert_eq!(
            store::list_peers(&fixture.directory)?[0].node_id,
            fixture.peer
        );
        assert_eq!(
            store::read_overview(&Connection::open(backup).map_err(sql_error)?)?.schema_version,
            7
        );
        Ok(())
    }
}
