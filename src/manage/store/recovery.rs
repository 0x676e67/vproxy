//! Restore configuration as a new, initially quarantined node, never roll back
//! an existing identity. All writes stay offline and use the existing two gates.

use std::{
    collections::{HashMap, HashSet},
    io::{self, Write},
    path::Path,
};

use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    DATABASE_NAME, backup, configure, invalid_data, open, random_id, read_overview, sqlite_error,
    validate_database, validate_directory,
};
use crate::access::{
    self, PolicyData,
    presets::{PoolPreset, UserPreset},
    routing::{ResourceState, RoutePermission},
};

const CURRENT_SOURCE_VERSIONS: &str = "13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28";
const MAX_SOURCE_IDS: usize = 32_768;
// The history reader accepts at most 16,384 typed rows, each with at most nine
// identity references. Keep the old catalog bound intact and add only this
// explicit metadata budget, not arbitrary payload strings or executable jobs.
const MAX_HISTORY_SOURCE_IDS: usize = 16_384 * 9;
// Each retained episode/event has at most six public observer/source node,
// boot, resource and administrator IDs. Preserve the older independent budgets before adding this
// bounded catalog; arbitrary payload strings never become identity candidates.
const MAX_ALERT_SOURCE_IDS: usize = (super::alerts::history::MAX_ACTIVE
    + super::alerts::history::MAX_CLOSED
    + super::alerts::history::MAX_EVENTS)
    * 6
    + 1;
const ID_ATTEMPTS: usize = 32;

/// Caller-generated fresh node key and CSR. Neither secret key nor its PEM is
/// ever included in status, errors, audit or backup manifests. The store checks
/// the written key's SPKI hash before committing the recovery record.
pub(in crate::manage) struct Identity {
    pub(in crate::manage) key_pem: Zeroizing<String>,
    pub(in crate::manage) request_pem: String,
    pub(in crate::manage) public_key_sha256: [u8; 32],
}

/// Persistent recovery admission. Ready starts no server; PendingTakeover has
/// no activation transition here and requires the later witnessed workflow.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum Phase {
    PendingReview,
    Ready,
    /// A retained-identity copy, not an as-new import. Neither ordinary
    /// finalization nor a successful backup verification can activate it.
    PendingTakeover,
}

/// Non-secret provenance and counts of the imported live-object draft subset.
/// Deleted/retired history, health and all old authorization are excluded.
/// A retained snapshot has zero imported counts: its original objects were not
/// reimported as drafts, and its earlier recovery record lives in the marker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Record {
    pub(in crate::manage) id: String,
    pub(in crate::manage) source_node_id: String,
    pub(in crate::manage) source_schema_version: u32,
    pub(in crate::manage) source_database_sha256: String,
    pub(in crate::manage) phase: Phase,
    pub(in crate::manage) node_key_sha256: [u8; 32],
    pub(in crate::manage) imported_users: u32,
    pub(in crate::manage) imported_prefixes: u32,
    pub(in crate::manage) imported_addresses: u32,
    pub(in crate::manage) imported_pools: u32,
}

/// Native/legacy state has no recovery record. A recovered Ready node retains
/// its record and key pin permanently; finalize never turns it into Native.
#[derive(Debug, Eq, PartialEq)]
pub(in crate::manage) struct Status {
    pub(in crate::manage) node_id: String,
    pub(in crate::manage) schema_version: u32,
    pub(in crate::manage) recovery: Option<Record>,
}

/// Non-secret identity of one newly claimed retained-identity output. Written
/// before copying any SQL pages, then bound to the persistent takeover fence.
/// This is a quarantine marker, never a witness receipt or activation permit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Snapshot {
    format_version: u8,
    pub(in crate::manage) id: String,
    pub(in crate::manage) node_id: String,
    pub(in crate::manage) schema_version: u32,
    pub(in crate::manage) node_key_sha256: [u8; 32],
    /// The SQL singleton becomes the takeover fence. Preserve its previous
    /// provenance here instead of silently discarding an earlier as-new restore.
    #[serde(deserialize_with = "Option::deserialize")]
    previous_recovery: Option<Record>,
    /// Version-two logical commitment to the original source rows and schema,
    /// before this archive's recovery singleton becomes PendingTakeover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::manage) database_content_sha256: Option<String>,
}

impl Snapshot {
    /// Original recovery pin before quarantine, not the archive's mandatory key
    /// pin and not an authority to resume the retained identity.
    #[cfg(feature = "witness-journal")]
    pub(in crate::manage) fn previous_key(&self) -> Option<[u8; 32]> {
        self.previous_recovery
            .as_ref()
            .map(|record| record.node_key_sha256)
    }
}

/// Select a fresh quarantine ID inside the source's locked SQLite snapshot.
/// A reviewed new-identity node must retain its existing key pin. Pending
/// sources cannot be repackaged to obtain a different recovery workflow.
pub(super) fn prepare_snapshot(
    connection: &Connection,
    node_key_sha256: [u8; 32],
) -> io::Result<Snapshot> {
    let status = status_in(connection)?;
    if status.schema_version != super::SCHEMA_VERSION {
        return Err(invalid_data(
            "identity snapshot requires the current schema",
        ));
    }
    if let Some(record) = &status.recovery {
        if record.phase != Phase::Ready {
            return Err(pending());
        }
        if record.node_key_sha256 != node_key_sha256 {
            return Err(invalid_data(
                "snapshot node key does not match its permanent pin",
            ));
        }
    }
    let mut ids = source_ids(connection, status.schema_version)?;
    Ok(Snapshot {
        format_version: 2,
        id: fresh_id(&mut ids)?,
        node_id: status.node_id,
        schema_version: status.schema_version,
        node_key_sha256,
        previous_recovery: status.recovery,
        database_content_sha256: Some(super::content::calculate(connection, None)?),
    })
}

/// Seal only the caller-owned newly copied database, never the source. All
/// existing users, credentials, revocations, owner and counters remain intact;
/// the takeover phase prevents their use until a later witnessed recovery.
pub(super) fn seal_snapshot(
    connection: &mut Connection,
    snapshot: &Snapshot,
    source_database_sha256: &str,
) -> io::Result<()> {
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|error| sqlite_error("cannot configure identity snapshot durability", error))?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin identity snapshot quarantine", error))?;
    let before = status_in(&transaction)?;
    if !snapshot_version(snapshot)
        || !super::valid_id(&snapshot.id)
        || snapshot.id == snapshot.node_id
        || before.node_id != snapshot.node_id
        || before.schema_version != snapshot.schema_version
        || before.schema_version < 24
        || before.recovery != snapshot.previous_recovery
        || before.recovery.as_ref().is_some_and(|record| {
            record.phase != Phase::Ready || record.node_key_sha256 != snapshot.node_key_sha256
        })
    {
        return Err(invalid_data("identity snapshot does not match its source"));
    }
    if let Some(expected) = &snapshot.database_content_sha256
        && super::content::calculate(&transaction, None)? != *expected
    {
        return Err(invalid_data(
            "identity snapshot content does not match its source",
        ));
    }
    let changed = transaction.execute(
        "UPDATE recovery_state SET kind='snapshot',phase='pending_takeover',recovery_id=?1,source_node_id=?2,source_schema_version=?3,source_database_sha256=?4,node_key_sha256=?5,imported_users=0,imported_prefixes=0,imported_addresses=0,imported_pools=0 WHERE singleton=1 AND phase='ready' AND kind IN('native','restored')",
        params![snapshot.id,snapshot.node_id,snapshot.schema_version,source_database_sha256,&snapshot.node_key_sha256[..]],
    ).map_err(|error| sqlite_error("cannot quarantine retained identity", error))?;
    if changed != 1 {
        return Err(corrupt());
    }
    check_snapshot(&transaction, Some(snapshot))?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit identity snapshot quarantine", error))
}

/// Recheck the marker against the SQL fence; file hashes alone must not let a
/// native or ordinary Ready database masquerade as an inert identity snapshot.
pub(super) fn check_snapshot(
    connection: &Connection,
    snapshot: Option<&Snapshot>,
) -> io::Result<()> {
    let status = status_in(connection)?;
    let Some(snapshot) = snapshot else {
        return if status
            .recovery
            .is_some_and(|record| record.phase == Phase::PendingTakeover)
        {
            Err(corrupt())
        } else {
            Ok(())
        };
    };
    let Some(record) = status.recovery else {
        return Err(corrupt());
    };
    if !snapshot_version(snapshot)
        || snapshot.node_id != status.node_id
        || snapshot.schema_version != status.schema_version
        || record.id != snapshot.id
        || record.phase != Phase::PendingTakeover
        || record.node_key_sha256 != snapshot.node_key_sha256
    {
        return Err(corrupt());
    }
    if let Some(previous) = &snapshot.previous_recovery
        && (previous.phase != Phase::Ready
            || !super::valid_id(&previous.id)
            || !super::valid_id(&previous.source_node_id)
            || previous.id == snapshot.id
            || previous.id == snapshot.node_id
            || previous.source_node_id == snapshot.node_id
            || previous.id == previous.source_node_id
            || !(13..=snapshot.schema_version).contains(&previous.source_schema_version)
            || previous.node_key_sha256 != snapshot.node_key_sha256
            || previous.imported_users > 1024
            || previous.imported_prefixes > 256
            || previous.imported_addresses > 1024
            || previous.imported_pools > 128
            || previous.source_database_sha256.len() != 64
            || !previous
                .source_database_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return Err(corrupt());
    }
    Ok(())
}

/// A legacy marker has no logical commitment. Stripping the new field without
/// explicitly reverting to the legacy format is invalid, not an empty proof.
fn snapshot_version(snapshot: &Snapshot) -> bool {
    match (
        snapshot.format_version,
        snapshot.database_content_sha256.as_deref(),
    ) {
        (1, None) => true,
        (2, Some(hash)) => snapshot.schema_version >= 25 && crate::manage::witness::digest(hash),
        _ => false,
    }
}

/// Project just the quarantine bookkeeping back to the checked source row.
/// Called only after check_snapshot validates the actual fence and provenance;
/// all other tables/rows are read unchanged from the caller's SQL snapshot.
pub(super) fn source_recovery_row(snapshot: &Snapshot) -> Vec<rusqlite::types::Value> {
    use rusqlite::types::Value;
    let Some(previous) = &snapshot.previous_recovery else {
        let mut row = vec![
            Value::Integer(1),
            Value::Text("native".into()),
            Value::Text("ready".into()),
        ];
        row.extend(std::iter::repeat_n(Value::Null, 9));
        return row;
    };
    vec![
        Value::Integer(1),
        Value::Text("restored".into()),
        Value::Text("ready".into()),
        Value::Text(previous.id.clone()),
        Value::Text(previous.source_node_id.clone()),
        Value::Integer(i64::from(previous.source_schema_version)),
        Value::Text(previous.source_database_sha256.clone()),
        Value::Blob(previous.node_key_sha256.to_vec()),
        Value::Integer(i64::from(previous.imported_users)),
        Value::Integer(i64::from(previous.imported_prefixes)),
        Value::Integer(i64::from(previous.imported_addresses)),
        Value::Integer(i64::from(previous.imported_pools)),
    ]
}

/// Create the current singleton only in initialization or backed-up migration.
/// A colliding table is an error, never an excuse to erase recovery state.
pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    create_table(connection, "recovery_state", CURRENT_SOURCE_VERSIONS)?;
    connection
        .execute(
            "INSERT INTO recovery_state(singleton,kind,phase) VALUES(1,'native','ready')",
            [],
        )
        .map_err(|error| sqlite_error("cannot initialize management recovery fence", error))?;
    Ok(())
}

/// Widen only the supported source-version vocabulary, preserving every v14..16
/// phase, provenance, count and permanent key pin. The caller owns migration's
/// backup and transaction; Pending is rejected before migration reaches here.
pub(super) fn upgrade_schema(connection: &Connection) -> io::Result<()> {
    let before = record_in(connection)?;
    create_table(connection, "recovery_state_v17", CURRENT_SOURCE_VERSIONS)?;
    connection.execute_batch("INSERT INTO recovery_state_v17 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_v17 RENAME TO recovery_state;")
        .map_err(|error|sqlite_error("cannot upgrade recovery provenance versions",error))?;
    if record_in(connection)? != before {
        return Err(corrupt());
    }
    Ok(())
}

/// Widen a schema19 fence without changing its phase, provenance or key pin.
/// The caller retains the migration transaction and old-file backup. An
/// existing temporary table is a conflict, not permission to overwrite it.
pub(super) fn migrate_nineteen(connection: &Connection) -> io::Result<()> {
    let before = record_in(connection)?;
    create_table(connection, "recovery_state_v20", CURRENT_SOURCE_VERSIONS)?;
    connection.execute_batch("INSERT INTO recovery_state_v20 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_v20 RENAME TO recovery_state;")
        .map_err(|error|sqlite_error("cannot upgrade schema nineteen recovery provenance",error))?;
    if record_in(connection)? != before {
        return Err(corrupt());
    }
    Ok(())
}

/// Widen only schema20's source-version fence in the migration's transaction.
/// Existing controller history and every provenance/key-pin value stay intact.
pub(super) fn migrate_twenty(connection: &Connection) -> io::Result<()> {
    let before = record_in(connection)?;
    create_table(connection, "recovery_state_v21", CURRENT_SOURCE_VERSIONS)?;
    connection.execute_batch("INSERT INTO recovery_state_v21 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_v21 RENAME TO recovery_state;")
        .map_err(|error| sqlite_error("cannot upgrade schema twenty recovery provenance", error))?;
    if record_in(connection)? != before {
        return Err(corrupt());
    }
    Ok(())
}

/// Preserve schema21's event history and recovery fence while widening only
/// the source-version vocabulary. Migration owns the backup and transaction.
pub(super) fn migrate_twenty_one(connection: &Connection) -> io::Result<()> {
    let before = record_in(connection)?;
    create_table(connection, "recovery_state_v22", CURRENT_SOURCE_VERSIONS)?;
    connection.execute_batch("INSERT INTO recovery_state_v22 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_v22 RENAME TO recovery_state;")
        .map_err(|error| sqlite_error("cannot upgrade schema twenty one recovery provenance", error))?;
    if record_in(connection)? != before {
        return Err(corrupt());
    }
    Ok(())
}

/// Widen schema22 recovery provenance without restoring outbound authority.
/// The surrounding explicit migration retains the old backup and transaction.
pub(super) fn migrate_twenty_two(connection: &Connection) -> io::Result<()> {
    let before = record_in(connection)?;
    create_table(connection, "recovery_state_v23", CURRENT_SOURCE_VERSIONS)?;
    connection.execute_batch("INSERT INTO recovery_state_v23 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_v23 RENAME TO recovery_state;")
        .map_err(|error| sqlite_error("cannot upgrade schema twenty two recovery provenance", error))?;
    if record_in(connection)? != before {
        return Err(corrupt());
    }
    Ok(())
}

/// Add the retained-identity quarantine vocabulary in the caller's backed-up
/// migration transaction. No native/Ready/new-identity record changes meaning.
pub(super) fn migrate_twenty_three(connection: &Connection) -> io::Result<()> {
    let before = record_in(connection)?;
    create_table(connection, "recovery_state_v24", CURRENT_SOURCE_VERSIONS)?;
    connection.execute_batch("INSERT INTO recovery_state_v24 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_v24 RENAME TO recovery_state;")
        .map_err(|error| sqlite_error("cannot upgrade schema twenty three recovery fence", error))?;
    if record_in(connection)? != before {
        return Err(corrupt());
    }
    Ok(())
}

/// Widen schema24 provenance without changing existing quarantine or identity.
/// Called only inside the explicit migration's backed-up write transaction.
pub(super) fn migrate_twenty_four(connection: &Connection) -> io::Result<()> {
    let before = record_in(connection)?;
    create_table(connection, "recovery_state_v25", CURRENT_SOURCE_VERSIONS)?;
    connection.execute_batch("INSERT INTO recovery_state_v25 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_v25 RENAME TO recovery_state;")
        .map_err(|e| sqlite_error("cannot upgrade schema twenty four recovery fence", e))?;
    if record_in(connection)? != before {
        return Err(corrupt());
    }
    Ok(())
}

/// Preserve schema25 identity and quarantine while adding source provenance.
/// The caller owns the original backup and the migration transaction.
pub(super) fn migrate_twenty_five(connection: &Connection) -> io::Result<()> {
    let before = record_in(connection)?;
    create_table(connection, "recovery_state_v26", CURRENT_SOURCE_VERSIONS)?;
    connection.execute_batch("INSERT INTO recovery_state_v26 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_v26 RENAME TO recovery_state;")
        .map_err(|e|sqlite_error("cannot upgrade schema twenty five recovery fence",e))?;
    if record_in(connection)? != before {
        return Err(corrupt());
    }
    Ok(())
}

/// Widen schema26 provenance while preserving identity, quarantine and pins.
/// The caller owns the consistent old backup and the migration transaction.
pub(super) fn migrate_twenty_six(connection: &Connection) -> io::Result<()> {
    let before = record_in(connection)?;
    create_table(connection, "recovery_state_v27", CURRENT_SOURCE_VERSIONS)?;
    connection.execute_batch("INSERT INTO recovery_state_v27 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_v27 RENAME TO recovery_state;")
        .map_err(|e| sqlite_error("cannot upgrade schema twenty six recovery fence", e))?;
    if record_in(connection)? != before {
        return Err(corrupt());
    }
    Ok(())
}

/// Widen schema27 provenance without changing quarantine or identity pins.
pub(super) fn migrate_twenty_seven(connection: &Connection) -> io::Result<()> {
    let before = record_in(connection)?;
    create_table(connection, "recovery_state_v28", CURRENT_SOURCE_VERSIONS)?;
    connection.execute_batch("INSERT INTO recovery_state_v28 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_v28 RENAME TO recovery_state;")
        .map_err(|e| sqlite_error("cannot upgrade schema twenty seven recovery fence", e))?;
    if record_in(connection)? != before {
        return Err(corrupt());
    }
    Ok(())
}

// Both identifier and allowed-version fragments are fixed internal constants,
// never SQL supplied by a backup, browser or command payload.
fn create_table(connection: &Connection, name: &str, versions: &str) -> io::Result<()> {
    // The fixed current vocabulary includes v24; genuine pre-v24 test schemas
    // retain their original CHECKs instead of acquiring future recovery phases.
    let (kinds, phases, retained) = if versions.split(',').any(|version| version == "24") {
        (
            "'native','restored','snapshot'",
            "'pending_review','ready','pending_takeover'",
            "OR(kind='snapshot' AND phase='pending_takeover' AND recovery_id IS NOT NULL AND source_node_id IS NOT NULL AND source_schema_version IS NOT NULL AND source_database_sha256 IS NOT NULL AND node_key_sha256 IS NOT NULL AND imported_users=0 AND imported_prefixes=0 AND imported_addresses=0 AND imported_pools=0)",
        )
    } else {
        ("'native','restored'", "'pending_review','ready'", "")
    };
    connection.execute_batch(&format!(
        "CREATE TABLE {name}(
          singleton INTEGER PRIMARY KEY CHECK(singleton=1),
          kind TEXT NOT NULL CHECK(kind IN({kinds})),
          phase TEXT NOT NULL CHECK(phase IN({phases})),
          recovery_id TEXT CHECK(length(recovery_id)=22),
          source_node_id TEXT CHECK(length(source_node_id)=22),
          source_schema_version INTEGER CHECK(source_schema_version IN({versions})),
          source_database_sha256 TEXT CHECK(length(source_database_sha256)=64 AND source_database_sha256 NOT GLOB '*[^0-9a-f]*'),
          node_key_sha256 BLOB CHECK(length(node_key_sha256)=32),
          imported_users INTEGER CHECK(imported_users BETWEEN 0 AND 1024),
          imported_prefixes INTEGER CHECK(imported_prefixes BETWEEN 0 AND 256),
          imported_addresses INTEGER CHECK(imported_addresses BETWEEN 0 AND 1024),
          imported_pools INTEGER CHECK(imported_pools BETWEEN 0 AND 128),
          CHECK((kind='native' AND phase='ready' AND recovery_id IS NULL AND source_node_id IS NULL
              AND source_schema_version IS NULL AND source_database_sha256 IS NULL AND node_key_sha256 IS NULL
              AND imported_users IS NULL AND imported_prefixes IS NULL AND imported_addresses IS NULL AND imported_pools IS NULL)
            OR (kind='restored' AND phase IN('pending_review','ready') AND recovery_id IS NOT NULL AND source_node_id IS NOT NULL
              AND source_schema_version IS NOT NULL AND source_database_sha256 IS NOT NULL AND node_key_sha256 IS NOT NULL
              AND imported_users IS NOT NULL AND imported_prefixes IS NOT NULL AND imported_addresses IS NOT NULL AND imported_pools IS NOT NULL)
            {retained})
         ) STRICT;"
    )).map_err(|error| sqlite_error("cannot create management recovery fence", error))
}

/// Called from read_overview without calling it back. A v14 row is required;
/// legacy state must not smuggle a recovery row under an older user_version.
pub(super) fn validate_schema(connection: &Connection, version: u32) -> io::Result<()> {
    if version >= 14 {
        record_in(connection).map(|_| ())
    } else {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='recovery_state')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| sqlite_error("cannot inspect legacy recovery namespace", error))?;
        if exists {
            return Err(invalid_data(
                "management recovery fence disagrees with the schema version",
            ));
        }
        Ok(())
    }
}

fn record_in(connection: &Connection) -> io::Result<Option<Record>> {
    let count: i64 = connection
        .query_row("SELECT count(*) FROM recovery_state", [], |row| row.get(0))
        .map_err(|error| sqlite_error("cannot count management recovery state", error))?;
    if count != 1 {
        return Err(corrupt());
    }
    let (kind, phase, id, source, version, hash, key, users, prefixes, addresses, pools) = connection.query_row(
        "SELECT kind,phase,recovery_id,source_node_id,source_schema_version,source_database_sha256,node_key_sha256,imported_users,imported_prefixes,imported_addresses,imported_pools FROM recovery_state WHERE singleton=1", [],
        |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,Option<String>>(2)?,row.get::<_,Option<String>>(3)?,row.get::<_,Option<i64>>(4)?,row.get::<_,Option<String>>(5)?,row.get::<_,Option<Vec<u8>>>(6)?,row.get::<_,Option<i64>>(7)?,row.get::<_,Option<i64>>(8)?,row.get::<_,Option<i64>>(9)?,row.get::<_,Option<i64>>(10)?))
    ).map_err(|error| sqlite_error("cannot decode management recovery state", error))?;
    if kind == "native"
        && phase == "ready"
        && id.is_none()
        && source.is_none()
        && version.is_none()
        && hash.is_none()
        && key.is_none()
        && users.is_none()
        && prefixes.is_none()
        && addresses.is_none()
        && pools.is_none()
    {
        return Ok(None);
    }
    let phase = match (kind.as_str(), phase.as_str()) {
        ("restored", "pending_review") => Phase::PendingReview,
        ("restored", "ready") => Phase::Ready,
        ("snapshot", "pending_takeover") => Phase::PendingTakeover,
        _ => return Err(corrupt()),
    };
    let id = id.filter(|id| super::valid_id(id)).ok_or_else(corrupt)?;
    let source_node_id = source
        .filter(|id| super::valid_id(id))
        .ok_or_else(corrupt)?;
    let node: String = connection
        .query_row(
            "SELECT node_id FROM node_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot inspect recovery node identity", error))?;
    if (node == source_node_id) != (phase == Phase::PendingTakeover)
        || id == node
        || id == source_node_id
    {
        return Err(corrupt());
    }
    let schema: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| sqlite_error("cannot inspect recovery provenance vocabulary", error))?;
    let source_schema_version = version
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| (13..=super::SCHEMA_VERSION).contains(n) && *n <= schema)
        .ok_or_else(corrupt)?;
    let source_database_sha256 = hash
        .filter(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(corrupt)?;
    let node_key_sha256: [u8; 32] = key.ok_or_else(corrupt)?.try_into().map_err(|_| corrupt())?;
    fn amount(value: Option<i64>, maximum: u32) -> io::Result<u32> {
        value
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n <= maximum)
            .ok_or_else(corrupt)
    }
    let record = Record {
        id,
        source_node_id,
        source_schema_version,
        source_database_sha256,
        phase,
        node_key_sha256,
        imported_users: amount(users, 1024)?,
        imported_prefixes: amount(prefixes, 256)?,
        imported_addresses: amount(addresses, 1024)?,
        imported_pools: amount(pools, 128)?,
    };
    if phase == Phase::PendingTakeover
        && (schema < 24
            || source_schema_version != schema
            || record.imported_users != 0
            || record.imported_prefixes != 0
            || record.imported_addresses != 0
            || record.imported_pools != 0)
    {
        return Err(corrupt());
    }
    Ok(Some(record))
}

/// Read-only offline status, including pending review; never repair a bad fence.
pub(in crate::manage) fn status(directory: &Path) -> io::Result<Status> {
    let mut connection = super::peers::open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot inspect recovery snapshot", error))?;
    status_in(&transaction)
}

fn status_in(connection: &Connection) -> io::Result<Status> {
    let overview = read_overview(connection)?;
    let recovery = if overview.schema_version >= 14 {
        record_in(connection)?
    } else {
        None
    };
    Ok(Status {
        node_id: overview.node_id,
        schema_version: overview.schema_version,
        recovery,
    })
}

/// Check once under the serve-lifetime author before egress preparation/binds.
/// Legacy/native nodes need no pin; recovered Ready nodes must keep their new
/// key pin. Pending state returns PermissionDenied and does not mutate anything.
pub(in crate::manage) fn startup(directory: &Path) -> io::Result<Option<[u8; 32]>> {
    super::reject_snapshot_directory(directory)?;
    super::source::reject_marker(directory)?;
    let connection = super::peers::open_existing(directory, false)?;
    super::source::require_unprotected(&connection)?;
    drop(connection);
    diagnostic_startup(directory)
}

/// Read readiness/key pin for offline witness diagnostics only. This does not
/// approve ordinary startup or writes on a source-required directory.
pub(in crate::manage) fn diagnostic_startup(directory: &Path) -> io::Result<Option<[u8; 32]>> {
    super::reject_snapshot_directory(directory)?;
    ready_key(status(directory)?.recovery)
}

/// Same readiness/key rule within an existing source transaction. This does
/// not check directory markers; the journal caller separately retains its
/// checked directory author and refuses snapshot directories before opening SQL.
#[cfg(feature = "witness-journal")]
pub(super) fn startup_in(connection: &Connection) -> io::Result<Option<[u8; 32]>> {
    ready_key(status_in(connection)?.recovery)
}

fn ready_key(recovery: Option<Record>) -> io::Result<Option<[u8; 32]>> {
    match recovery {
        Some(record) if record.phase != Phase::Ready => Err(pending()),
        Some(record) => Ok(Some(record.node_key_sha256)),
        None => Ok(None),
    }
}

/// Common write admission; recovery/finalize use explicit private connections.
pub(super) fn require_writable(connection: &Connection) -> io::Result<()> {
    let overview = read_overview(connection)?;
    if overview.schema_version >= 14
        && record_in(connection)?.is_some_and(|r| r.phase != Phase::Ready)
    {
        return Err(pending());
    }
    Ok(())
}

/// Import only validated configuration drafts into a new private directory.
/// Supported source packages are immutable and rechecked after typed reads.
/// No existing destination, key, database or directory is overwritten. Fresh
/// node/admin/meter IDs are checked against the bounded source identity set;
/// resource/recovery IDs additionally exclude all previously allocated IDs.
/// Users have no protocols, grants, presets or credentials and are disabled;
/// retained address/pool drafts drain. Prefixes are inventory only. Deleted and
/// retired history, PHCs, certificates, ownership, receipts, jobs, audit and byte
/// counters are not copied. One transaction publishes all drafts plus Pending.
/// The caller supplies validated names and a new Argon2 PHC, never plaintext.
/// Failure retains private output; there is no automatic retry, restore-over or
/// service start. Existing SQLite/OS I/O budgets are not a hard global deadline.
/// Failure before the database claim can leave an empty private directory, but
/// no key, CSR or recovery identity. After claim the database is always retained
/// and ordinary init cannot reuse it, even if the schema transaction rolled back.
pub(in crate::manage) fn restore(
    input: &Path,
    directory: &Path,
    name: &str,
    administrator: &str,
    phc: &str,
    identity: Identity,
) -> io::Result<Status> {
    super::super::validate_names(name, administrator)?;
    if identity.key_pem.is_empty()
        || identity.key_pem.len() > 64 * 1024
        || identity.request_pem.is_empty()
        || identity.request_pem.len() > 64 * 1024
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recovery key and CSR must be nonempty bounded PEM material",
        ));
    }
    let output = backup::output_path(input, directory)?;
    let (manifest, source, mut ids) = backup::read_verified(input, |connection, manifest| {
        Ok((
            manifest.clone(),
            super::users::read_policy(connection)?,
            source_ids(connection, manifest.schema_version)?,
        ))
    })?;
    let drafts = drafts(source, &mut ids)?;
    let recovery_id = fresh_id(&mut ids)?;
    backup::create_directory(&output)?;
    super::initialize_with(
        &output,
        name,
        administrator,
        phc,
        |connection, node, admin| {
            for id in [node, admin] {
                reserve_base_id(&mut ids, id.to_owned())?;
            }
            let meter: String = connection
                .query_row(
                    "SELECT meter_epoch FROM traffic_state WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    sqlite_error("cannot inspect new recovery meter identity", error)
                })?;
            reserve_base_id(&mut ids, meter)?;
            write_drafts(connection, &drafts)?;
            connection
                .execute(
                    "UPDATE traffic_state SET loss_possible=1,history_gap=1 WHERE singleton=1",
                    [],
                )
                .map_err(|error| {
                    sqlite_error("cannot mark recovery history discontinuity", error)
                })?;
            let record = Record {
                id: recovery_id.clone(),
                source_node_id: manifest.node_id.clone(),
                source_schema_version: manifest.schema_version,
                source_database_sha256: manifest.database_sha256.clone(),
                phase: Phase::PendingReview,
                node_key_sha256: identity.public_key_sha256,
                imported_users: count(drafts.users.len())?,
                imported_prefixes: count(drafts.routing.prefixes.len())?,
                imported_addresses: count(drafts.routing.addresses.len())?,
                imported_pools: count(drafts.routing.pools.len())?,
            };
            let changed = connection.execute("UPDATE recovery_state SET kind='restored',phase='pending_review',recovery_id=?1,source_node_id=?2,source_schema_version=?3,source_database_sha256=?4,node_key_sha256=?5,imported_users=?6,imported_prefixes=?7,imported_addresses=?8,imported_pools=?9 WHERE singleton=1 AND kind='native'",
            params![record.id,record.source_node_id,record.source_schema_version,record.source_database_sha256,&record.node_key_sha256[..],record.imported_users,record.imported_prefixes,record.imported_addresses,record.imported_pools])
            .map_err(|error|sqlite_error("cannot save pending recovery provenance",error))?;
            if changed != 1 {
                return Err(corrupt());
            }
            for (file, contents) in [
                ("node.key", identity.key_pem.as_bytes()),
                ("node.csr", identity.request_pem.as_bytes()),
            ] {
                let mut handle = backup::new_file(&output.join(file))?;
                handle.write_all(contents)?;
                handle.sync_all()?;
            }
            backup::sync_directory(&output)?;
            if super::super::tls::node_key_sha256(&output.join("node.key"))?
                != record.node_key_sha256
            {
                return Err(invalid_data(
                    "recovery node key does not match its public key pin",
                ));
            }
            baseline(connection, &record)?;
            Ok(())
        },
    )?;
    status(&output)
}

/// Offline acknowledgement of this exact pending recovery, never activation of
/// proxy users or node grants. Both locks outlive commit; full RW SQLite/FK and
/// typed safe-baseline checks run before changing phase. Actual private key SPKI
/// must match its persistent pin. Failures/unknown commit outcomes are not
/// retried; inspect status. Ready retains provenance and the pin on every start.
pub(in crate::manage) fn finalize(directory: &Path, id: &str) -> io::Result<Status> {
    super::reject_snapshot_directory(directory)?;
    if !super::valid_id(id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recovery ID is malformed",
        ));
    }
    validate_directory(directory)?;
    let _author = super::lock(directory)?;
    let _update = super::update_lock(directory)?;
    validate_database(&directory.join(DATABASE_NAME))?;
    let mut connection = open(
        &directory.join(DATABASE_NAME),
        OpenFlags::SQLITE_OPEN_READ_WRITE,
    )?;
    configure(&connection)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|error| sqlite_error("cannot configure recovery durability", error))?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin recovery finalization", error))?;
    let before = status_in(&transaction)?;
    let record = before.recovery.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "node has no pending recovery")
    })?;
    if record.id != id {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "recovery ID changed; inspect status",
        ));
    }
    if record.phase == Phase::PendingTakeover {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "retained-identity snapshots require witnessed takeover; offline finalize cannot activate them",
        ));
    }
    if record.phase != Phase::PendingReview {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "recovery was already finalized; inspect status",
        ));
    }
    if super::super::tls::node_key_sha256(&directory.join("node.key"))? != record.node_key_sha256 {
        return Err(invalid_data(
            "recovery node key does not match its public key pin",
        ));
    }
    baseline(&transaction, &record)?;
    let changed=transaction.execute("UPDATE recovery_state SET phase='ready' WHERE singleton=1 AND recovery_id=?1 AND phase='pending_review'",[id])
        .map_err(|error|sqlite_error("cannot acknowledge pending recovery",error))?;
    if changed != 1 {
        return Err(corrupt());
    }
    let result = status_in(&transaction)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit recovery finalization", error))?;
    Ok(result)
}

fn source_ids(connection: &Connection, version: u32) -> io::Result<HashSet<String>> {
    let mut ids = HashSet::new();
    for sql in [
        "SELECT node_id FROM node_identity",
        "SELECT id FROM administrators",
        "SELECT id FROM proxy_users",
        "SELECT id FROM proxy_credentials",
        "SELECT node_id FROM peers",
        "SELECT id FROM routing_prefixes",
        "SELECT id FROM routing_addresses",
        "SELECT id FROM routing_pools",
        "SELECT job_id FROM control_outbox",
        "SELECT meter_epoch FROM traffic_state",
        "SELECT run_id FROM traffic_state WHERE run_id IS NOT NULL",
        "SELECT meter_epoch FROM remote_traffic_sources WHERE meter_epoch IS NOT NULL",
        "SELECT source_administrator_id FROM proxy_policy_audit WHERE source_administrator_id IS NOT NULL",
        "SELECT source_administrator_id FROM control_audit WHERE source_administrator_id IS NOT NULL",
        "SELECT source_administrator_id FROM routing_audit WHERE source_administrator_id IS NOT NULL",
        "SELECT source_administrator_id FROM preset_audit WHERE source_administrator_id IS NOT NULL",
    ] {
        collect_ids(connection, sql, &mut ids)?;
    }
    if version >= 14 {
        for sql in [
            "SELECT recovery_id FROM recovery_state WHERE recovery_id IS NOT NULL",
            "SELECT source_node_id FROM recovery_state WHERE source_node_id IS NOT NULL",
        ] {
            collect_ids(connection, sql, &mut ids)?;
        }
    }
    if version >= 15 {
        for sql in [
            "SELECT listener_id FROM endpoint_overrides",
            "SELECT DISTINCT listener_id FROM endpoint_audit",
            "SELECT source_administrator_id FROM endpoint_audit WHERE source_administrator_id IS NOT NULL",
        ] {
            collect_ids(connection, sql, &mut ids)?;
        }
    }
    if version >= 16 {
        for sql in [
            "SELECT id FROM user_operations",
            "SELECT administrator_id FROM user_operations WHERE administrator_id IS NOT NULL",
        ] {
            collect_ids(connection, sql, &mut ids)?;
        }
    }
    if version >= 17 {
        collect_ids(connection, "SELECT id FROM automation_principals", &mut ids)?;
    }
    if version >= 18 {
        for sql in [
            "SELECT automation_principal_id FROM user_operations WHERE automation_principal_id IS NOT NULL",
            "SELECT automation_principal_id FROM proxy_policy_audit WHERE automation_principal_id IS NOT NULL",
        ] {
            collect_ids(connection, sql, &mut ids)?;
        }
    }
    if version >= 19 {
        collect_ids(
            connection,
            "SELECT source_administrator_id FROM proxy_admission_audit WHERE source_administrator_id IS NOT NULL",
            &mut ids,
        )?;
    }
    if version >= 20 {
        super::targets::history::collect_source_ids(connection, &mut ids)?;
        if ids.len() > MAX_SOURCE_IDS + MAX_HISTORY_SOURCE_IDS {
            return Err(invalid_data(
                "source recovery history identities exceed their capacity",
            ));
        }
    }
    if version >= 21 {
        super::alerts::history::collect_source_ids(connection, &mut ids)?;
        if ids.len() > MAX_SOURCE_IDS + MAX_HISTORY_SOURCE_IDS + MAX_ALERT_SOURCE_IDS {
            return Err(invalid_data(
                "source recovery event identities exceed their capacity",
            ));
        }
    }
    if version >= 23 {
        super::notifications::collect_source_ids(connection, &mut ids)?;
        if ids.len()
            > MAX_SOURCE_IDS
                + MAX_HISTORY_SOURCE_IDS
                + MAX_ALERT_SOURCE_IDS
                + 6
                + 2 * crate::manage::notifications::MAX_EVENTS
        {
            return Err(invalid_data(
                "source recovery notification identities exceed their capacity",
            ));
        }
    }
    if version >= 25 {
        let witness = read_overview(connection)?.node_id;
        super::witness::collect_source_ids(connection, &witness, &mut ids)?;
    }
    if let Some(source) = super::source::load(connection, version)? {
        ids.insert(source.enrollment.binding_id);
        ids.insert(source.enrollment.writer_id);
        ids.insert(source.enrollment.witness_node_id);
        if let Some(id) = source.floor.intent_id {
            ids.insert(id);
        }
    }
    Ok(ids)
}

fn collect_ids(connection: &Connection, sql: &str, ids: &mut HashSet<String>) -> io::Result<()> {
    let mut statement = connection
        .prepare(&format!("{sql} LIMIT {}", MAX_SOURCE_IDS + 1))
        .map_err(|error| sqlite_error("cannot inspect source recovery identities", error))?;
    let mut rows = statement
        .query([])
        .map_err(|error| sqlite_error("cannot read source recovery identities", error))?;
    let mut count = 0;
    while let Some(row) = rows
        .next()
        .map_err(|error| sqlite_error("cannot read source recovery identity", error))?
    {
        count += 1;
        let value = row
            .get_ref(0)
            .map_err(|error| sqlite_error("cannot decode source recovery identity", error))?;
        let id = match value {
            rusqlite::types::ValueRef::Text(bytes) if bytes.len() == 22 => {
                std::str::from_utf8(bytes)
                    .map_err(|_| invalid_data("source recovery identity is not UTF-8"))?
                    .to_owned()
            }
            _ => {
                return Err(invalid_data(
                    "source recovery identity has an invalid type or length",
                ));
            }
        };
        if !super::valid_id(&id) || count > MAX_SOURCE_IDS {
            return Err(invalid_data(
                "source recovery identity catalog is malformed or too large",
            ));
        }
        ids.insert(id);
        if ids.len() > MAX_SOURCE_IDS {
            return Err(invalid_data(
                "source recovery identity catalog exceeds its capacity",
            ));
        }
    }
    Ok(())
}

fn fresh_id(ids: &mut HashSet<String>) -> io::Result<String> {
    for _ in 0..ID_ATTEMPTS {
        let id = random_id()?;
        if ids.insert(id.clone()) {
            return Ok(id);
        }
    }
    Err(io::Error::other(
        "cannot allocate a distinct recovery identity",
    ))
}

/// Initializer-owned IDs cannot be redrawn after schema creation. A collision
/// aborts the still-uncommitted restore instead of accepting identity reuse.
fn reserve_base_id(ids: &mut HashSet<String>, id: String) -> io::Result<()> {
    if !ids.insert(id) {
        return Err(invalid_data(
            "new recovery identity collided with a source or allocated identity",
        ));
    }
    Ok(())
}

fn drafts(mut source: PolicyData, ids: &mut HashSet<String>) -> io::Result<PolicyData> {
    // A recovered node has new identities and its own operator review fence.
    // Do not import the source's operational maintenance setting or history.
    source.accepting = true;
    source.credentials.clear();
    source.revision = 1;
    source.users.retain(|user| !user.deleted);
    for user in &mut source.users {
        user.id = fresh_id(ids)?;
        user.active = false;
        user.protocols.clear();
        user.revision = 1;
    }
    let mut prefixes = HashMap::new();
    source.routing.prefixes.retain(|entry| !entry.retired);
    for entry in &mut source.routing.prefixes {
        let old = entry.id.clone();
        entry.id = fresh_id(ids)?;
        entry.revision = 1;
        prefixes.insert(old, entry.id.clone());
    }
    source.routing.addresses.retain(|entry| {
        entry.state != ResourceState::Retired
            && entry
                .prefix_id
                .as_ref()
                .is_none_or(|id| prefixes.contains_key(id))
    });
    let mut addresses = HashMap::new();
    for entry in &mut source.routing.addresses {
        let old = entry.id.clone();
        entry.id = fresh_id(ids)?;
        entry.prefix_id = entry
            .prefix_id
            .as_ref()
            .and_then(|id| prefixes.get(id).cloned());
        entry.state = ResourceState::Draining;
        entry.revision = 1;
        addresses.insert(old, entry.id.clone());
    }
    source
        .routing
        .pools
        .retain(|entry| entry.state != ResourceState::Retired);
    for entry in &mut source.routing.pools {
        entry.id = fresh_id(ids)?;
        entry.members = entry
            .members
            .iter()
            .filter_map(|id| addresses.get(id).cloned())
            .collect();
        entry.state = ResourceState::Draining;
        entry.revision = 1;
    }
    source.routing.permissions = source
        .users
        .iter()
        .map(|user| RoutePermission {
            user_id: user.id.clone(),
            legacy_allowed: false,
            exits: Vec::new(),
            pools: Vec::new(),
        })
        .collect();
    source.presets.users = source
        .users
        .iter()
        .map(|user| UserPreset::native(user.id.clone()))
        .collect();
    source.presets.pools = source
        .routing
        .pools
        .iter()
        .map(|pool| PoolPreset::native(pool.id.clone()))
        .collect();
    access::validate_policy(&source)?;
    Ok(source)
}

fn write_drafts(connection: &Connection, policy: &PolicyData) -> io::Result<()> {
    for user in &policy.users {
        connection
            .execute(
                "INSERT INTO proxy_users VALUES(?1,?2,0,0,0,?3,1)",
                params![user.id, user.name, user.concurrent_limit],
            )
            .map_err(|error| sqlite_error("cannot import disabled user draft", error))?;
    }
    for entry in &policy.routing.prefixes {
        super::routing::write_entity(
            connection,
            &access::routing::RoutingEntity::Prefix(entry.clone()),
        )?;
    }
    for entry in &policy.routing.addresses {
        super::routing::write_entity(
            connection,
            &access::routing::RoutingEntity::Address(entry.clone()),
        )?;
    }
    for entry in &policy.routing.pools {
        super::routing::write_entity(
            connection,
            &access::routing::RoutingEntity::Pool(entry.clone()),
        )?;
    }
    for entry in &policy.routing.permissions {
        super::routing::write_permission(connection, entry)?;
    }
    for entry in &policy.presets.users {
        super::presets::write_user(connection, entry)?;
    }
    for entry in &policy.presets.pools {
        super::presets::write_pool(connection, entry)?;
    }
    Ok(())
}

fn baseline(connection: &Connection, record: &Record) -> io::Result<()> {
    if record_in(connection)?.as_ref() != Some(record) {
        return Err(invalid_data(
            "recovery provenance does not match its safe baseline",
        ));
    }
    backup::sqlite_checks(connection)?;
    let extra: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type IN('trigger','view'))",
            [],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot inspect recovery schema objects", error))?;
    if extra {
        return Err(invalid_data(
            "recovery schema contains unexpected executable objects",
        ));
    }
    let overview = read_overview(connection)?;
    if overview.administrator_count != 1 {
        return Err(corrupt());
    }
    if overview.schema_version >= 15 {
        let endpoints = super::endpoints::read_in(connection)?;
        if endpoints.revision != 1
            || !endpoints.digest.is_empty()
            || !endpoints.overrides.is_empty()
        {
            return Err(invalid_data(
                "recovery must not import endpoint declarations or configuration",
            ));
        }
    }
    if overview.schema_version >= 16 {
        super::operations::validate_snapshot(connection)?;
        let empty: bool = connection
            .query_row(
                "SELECT (SELECT last_sequence=0 FROM operations_state WHERE singleton=1)
                  AND NOT EXISTS(SELECT 1 FROM user_operations)",
                [],
                |row| row.get(0),
            )
            .map_err(|error| sqlite_error("cannot inspect recovery operation baseline", error))?;
        if !empty {
            return Err(invalid_data(
                "recovery must not import operation identities or receipts",
            ));
        }
    }
    if overview.schema_version >= 17 {
        super::automation::validate_snapshot(connection, overview.schema_version)?;
        let empty: bool = connection
            .query_row(
                "SELECT (SELECT last_sequence=0 FROM automation_state WHERE singleton=1)
               AND NOT EXISTS(SELECT 1 FROM automation_principals)
               AND NOT EXISTS(SELECT 1 FROM automation_audit)",
                [],
                |row| row.get(0),
            )
            .map_err(|error| sqlite_error("cannot inspect recovery automation baseline", error))?;
        if !empty {
            return Err(invalid_data(
                "recovery must not import automation identities or authority",
            ));
        }
    }
    if overview.schema_version >= 19 {
        super::admission::validate_snapshot(connection)?;
        let empty: bool = connection.query_row("SELECT (SELECT accepting=1 FROM proxy_admission_state WHERE singleton=1) AND NOT EXISTS(SELECT 1 FROM proxy_admission_audit)",[],|row|row.get(0))
            .map_err(|error|sqlite_error("cannot inspect recovery admission baseline",error))?;
        if !empty {
            return Err(invalid_data(
                "recovery must not import proxy admission settings or actors",
            ));
        }
    }
    if overview.schema_version >= 20 {
        super::targets::history::validate_snapshot(connection)?;
        let empty: bool = connection
            .query_row(
                "SELECT (SELECT last_sequence=0 FROM controller_history_state WHERE singleton=1)
                  AND NOT EXISTS(SELECT 1 FROM controller_history)",
                [],
                |row| row.get(0),
            )
            .map_err(|error| {
                sqlite_error("cannot inspect recovery controller history baseline", error)
            })?;
        if !empty {
            return Err(invalid_data(
                "recovery must not import controller jobs or their history",
            ));
        }
    }
    if overview.schema_version >= 21 {
        super::alerts::history::validate_snapshot(connection)?;
        super::alerts::history::require_empty(connection)?;
    }
    let policy = super::users::read_policy(connection)?;
    if policy.revision != 1
        || !policy.credentials.is_empty()
        || count(policy.users.len())? != record.imported_users
        || count(policy.routing.prefixes.len())? != record.imported_prefixes
        || count(policy.routing.addresses.len())? != record.imported_addresses
        || count(policy.routing.pools.len())? != record.imported_pools
        || policy
            .users
            .iter()
            .any(|u| u.active || u.deleted || !u.protocols.is_empty() || u.revision != 1)
        || policy
            .routing
            .prefixes
            .iter()
            .any(|p| p.retired || p.revision != 1)
        || policy
            .routing
            .addresses
            .iter()
            .any(|a| a.state != ResourceState::Draining || a.revision != 1)
        || policy
            .routing
            .pools
            .iter()
            .any(|p| p.state != ResourceState::Draining || p.revision != 1)
        || policy
            .routing
            .permissions
            .iter()
            .any(|p| p.legacy_allowed || !p.exits.is_empty() || !p.pools.is_empty())
        || policy
            .presets
            .users
            .iter()
            .any(|p| p.default_preset.is_some() || !p.allowed_presets.is_empty())
        || policy
            .presets
            .pools
            .iter()
            .any(|p| p.default_preset.is_some())
    {
        return Err(invalid_data(
            "recovery drafts no longer satisfy the disabled baseline",
        ));
    }
    for table in [
        "peers",
        "peer_certificates",
        "peer_audit",
        "proxy_credentials",
        "proxy_policy_audit",
        "control_receipts",
        "control_audit",
        "managed_targets",
        "control_outbox",
        "controller_audit",
        "routing_audit",
        "routing_exit_grants",
        "routing_pool_grants",
        "preset_audit",
        "administrator_audit",
        "traffic_series",
        "traffic_windows",
        "remote_traffic_sources",
    ] {
        let present: bool = connection
            .query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table})"),
                [],
                |row| row.get(0),
            )
            .map_err(|error| sqlite_error("cannot inspect recovery security baseline", error))?;
        if present {
            return Err(invalid_data(
                "recovery contains unexpected authorization or history",
            ));
        }
    }
    let valid:bool=connection.query_row("SELECT (SELECT last_sequence=0 FROM administrator_audit_state WHERE singleton=1) AND (SELECT controller_node_id IS NULL AND epoch=1 AND last_terminal_command=0 FROM control_ownership WHERE singleton=1) AND (SELECT revision=1 AND applied_revision IS NULL FROM proxy_policy_state WHERE singleton=1) AND (SELECT cursor=0 AND run_id IS NULL AND clean=1 AND loss_possible=1 AND history_gap=1 AND series_count=0 AND window_count=0 FROM traffic_state WHERE singleton=1)",[],|row|row.get(0))
        .map_err(|error|sqlite_error("cannot inspect recovery namespaces",error))?;
    if !valid {
        return Err(corrupt());
    }
    Ok(())
}

fn count(value: usize) -> io::Result<u32> {
    u32::try_from(value).map_err(|_| corrupt())
}
fn corrupt() -> io::Error {
    invalid_data("management recovery state is malformed")
}
fn pending() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "management recovery is pending; inspect its phase before selecting a recovery workflow",
    )
}

/// Reconstruct schema sixteen without weakening provenance's old CHECK.
#[cfg(test)]
pub(in crate::manage) fn restore_schema_sixteen_for_test(
    connection: &Connection,
) -> io::Result<()> {
    require_source_version_for_test(connection, 16)?;
    super::automation::ensure_unused_for_test(connection)?;
    super::operations::require_legacy_for_test(connection)?;
    super::users::require_legacy_audit_for_test(connection)?;
    restore_schema_eighteen_for_test(connection)?;
    super::operations::restore_legacy_for_test(connection)?;
    super::users::restore_legacy_audit_for_test(connection)?;
    super::automation::remove_schema_for_test(connection)?;
    create_table(connection, "recovery_state_fixture16", "13,14,15,16")?;
    connection.execute_batch("INSERT INTO recovery_state_fixture16 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_fixture16 RENAME TO recovery_state; PRAGMA user_version=16;")
        .map_err(|error| sqlite_error("cannot reconstruct schema sixteen fixture", error))
}

/// Rebuild a genuine read-only-automation schema17 fixture. Lossy actors or
/// write scopes are refused before any DDL; parent FKs are removed first.
#[cfg(test)]
pub(in crate::manage) fn restore_schema_seventeen_for_test(
    connection: &Connection,
) -> io::Result<()> {
    require_source_version_for_test(connection, 17)?;
    super::operations::require_legacy_for_test(connection)?;
    super::users::require_legacy_audit_for_test(connection)?;
    super::automation::require_legacy_for_test(connection)?;
    restore_schema_eighteen_for_test(connection)?;
    let transaction = connection
        .unchecked_transaction()
        .map_err(|error| sqlite_error("cannot begin schema seventeen fixture", error))?;
    super::operations::restore_legacy_for_test(&transaction)?;
    super::users::restore_legacy_audit_for_test(&transaction)?;
    super::automation::restore_schema_seventeen_for_test(&transaction)?;
    create_table(&transaction, "recovery_state_fixture17", "13,14,15,16,17")?;
    transaction.execute_batch("INSERT INTO recovery_state_fixture17 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_fixture17 RENAME TO recovery_state; PRAGMA user_version=17;")
        .map_err(|error| sqlite_error("cannot reconstruct schema seventeen fixture", error))?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit schema seventeen fixture", error))
}

/// Reconstruct schema fifteen without weakening provenance's old CHECK.
/// A record sourced from schema sixteen cannot be relabelled as historical.
#[cfg(test)]
pub(in crate::manage) fn restore_schema_fifteen_for_test(
    connection: &Connection,
) -> io::Result<()> {
    require_source_version_for_test(connection, 15)?;
    super::remove_operations_schema_for_test(connection)?;
    create_table(connection, "recovery_state_fixture15", "13,14,15")?;
    connection.execute_batch("INSERT INTO recovery_state_fixture15 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_fixture15 RENAME TO recovery_state; PRAGMA user_version=15;")
        .map_err(|error|sqlite_error("cannot reconstruct schema fifteen fixture",error))
}

/// Historical fixtures remove newer namespaces before lowering user_version;
/// production migration never drops an existing recovery fence.
#[cfg(test)]
pub(in crate::manage::store) fn restore_schema_fourteen_for_test(
    connection: &Connection,
) -> io::Result<()> {
    require_source_version_for_test(connection, 14)?;
    super::remove_operations_schema_for_test(connection)?;
    super::control::remove_endpoints_schema_for_test(connection)?;
    super::endpoints::remove_schema_for_test(connection)?;
    create_table(connection, "recovery_state_fixture14", "13,14")?;
    connection.execute_batch("INSERT INTO recovery_state_fixture14 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_fixture14 RENAME TO recovery_state; PRAGMA user_version=14;")
        .map_err(|error|sqlite_error("cannot reconstruct schema fourteen fixture",error))
}

/// Remove the recovery namespace as well when reconstructing schema thirteen.
#[cfg(test)]
pub(in crate::manage) fn remove_schema_for_test(connection: &Connection) -> io::Result<()> {
    require_source_version_for_test(connection, 13)?;
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| sqlite_error("cannot inspect recovery fixture schema", error))?;
    super::remove_operations_schema_for_test(connection)?;
    if version >= 15 {
        super::control::remove_endpoints_schema_for_test(connection)?;
        super::endpoints::remove_schema_for_test(connection)?;
    }
    connection
        .execute_batch("DROP TABLE IF EXISTS recovery_state")
        .map_err(|error| sqlite_error("cannot reconstruct pre-recovery fixture", error))?;
    if version >= 14 {
        connection
            .pragma_update(None, "user_version", 13)
            .map_err(|error| sqlite_error("cannot reconstruct schema thirteen fixture", error))?;
    }
    Ok(())
}

#[cfg(test)]
fn require_source_version_for_test(connection: &Connection, target: u32) -> io::Result<()> {
    super::notifications::ensure_unused_for_test(connection)?;
    let present: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='recovery_state' AND type='table')", [], |row| row.get(0))
        .map_err(|error| sqlite_error("cannot inspect recovery fixture provenance", error))?;
    if !present {
        return Ok(());
    }
    if record_in(connection)?.is_some_and(|record| record.source_schema_version > target) {
        return Err(invalid_data(
            "recovery provenance cannot become a historical fixture",
        ));
    }
    Ok(())
}

/// Remove only unused v19 admission vocabulary before constructing older
/// fixtures. The original v18 recovery CHECK must also exclude source19.
#[cfg(test)]
pub(in crate::manage) fn restore_schema_eighteen_for_test(
    connection: &Connection,
) -> io::Result<()> {
    if !connection.is_autocommit() {
        return restore_schema_eighteen_in(connection);
    }
    let transaction = connection
        .unchecked_transaction()
        .map_err(|error| sqlite_error("cannot begin schema eighteen fixture", error))?;
    restore_schema_eighteen_in(&transaction)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit schema eighteen fixture", error))
}

#[cfg(test)]
fn restore_schema_eighteen_in(connection: &Connection) -> io::Result<()> {
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| sqlite_error("cannot inspect admission fixture version", error))?;
    if version < 19 {
        return Ok(());
    }
    require_source_version_for_test(connection, 18)?;
    super::alerts::history::ensure_unused_for_test(connection)?;
    super::targets::history::ensure_unused_for_test(connection)?;
    super::notifications::remove_schema_for_test(connection)?;
    super::admission::remove_schema_for_test(connection)?;
    super::alerts::history::remove_schema_for_test(connection)?;
    super::targets::history::remove_schema_for_test(connection)?;
    create_table(connection, "recovery_state_fixture18", "13,14,15,16,17,18")?;
    connection.execute_batch("INSERT INTO recovery_state_fixture18 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_fixture18 RENAME TO recovery_state; PRAGMA user_version=18;")
        .map_err(|error|sqlite_error("cannot reconstruct schema eighteen fixture",error))
}

/// Construct a real schema19 fixture, never relabel issued history as legacy.
/// The preflight precedes DDL so rejection leaves every current namespace intact.
#[cfg(test)]
pub(in crate::manage) fn restore_schema_nineteen_for_test(
    connection: &Connection,
) -> io::Result<()> {
    if !connection.is_autocommit() {
        return restore_schema_nineteen_in(connection);
    }
    let transaction = connection
        .unchecked_transaction()
        .map_err(|error| sqlite_error("cannot begin schema nineteen fixture", error))?;
    restore_schema_nineteen_in(&transaction)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit schema nineteen fixture", error))
}

#[cfg(test)]
fn restore_schema_nineteen_in(connection: &Connection) -> io::Result<()> {
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| {
            sqlite_error("cannot inspect controller history fixture version", error)
        })?;
    if version < 20 {
        return Ok(());
    }
    require_source_version_for_test(connection, 19)?;
    super::alerts::history::ensure_unused_for_test(connection)?;
    super::targets::history::ensure_unused_for_test(connection)?;
    super::notifications::remove_schema_for_test(connection)?;
    super::alerts::history::remove_schema_for_test(connection)?;
    super::targets::history::remove_schema_for_test(connection)?;
    create_table(
        connection,
        "recovery_state_fixture19",
        "13,14,15,16,17,18,19",
    )?;
    connection.execute_batch("INSERT INTO recovery_state_fixture19 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_fixture19 RENAME TO recovery_state; PRAGMA user_version=19;")
        .map_err(|error| sqlite_error("cannot reconstruct schema nineteen fixture", error))
}

/// Construct a real schema20 fixture only before the monitor has issued a boot,
/// event or acknowledgement. All DDL participates in one owned/caller tx.
#[cfg(test)]
pub(in crate::manage) fn restore_schema_twenty_for_test(connection: &Connection) -> io::Result<()> {
    if !connection.is_autocommit() {
        return restore_schema_twenty_in(connection);
    }
    let tx = connection
        .unchecked_transaction()
        .map_err(|e| sqlite_error("cannot begin schema twenty fixture", e))?;
    restore_schema_twenty_in(&tx)?;
    tx.commit()
        .map_err(|e| sqlite_error("cannot commit schema twenty fixture", e))
}
#[cfg(test)]
fn restore_schema_twenty_in(connection: &Connection) -> io::Result<()> {
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| sqlite_error("cannot inspect event fixture version", e))?;
    if version < 21 {
        return Ok(());
    }
    require_source_version_for_test(connection, 20)?;
    super::alerts::history::ensure_unused_for_test(connection)?;
    super::notifications::remove_schema_for_test(connection)?;
    super::alerts::history::remove_schema_for_test(connection)?;
    create_table(
        connection,
        "recovery_state_fixture20",
        "13,14,15,16,17,18,19,20",
    )?;
    connection.execute_batch("INSERT INTO recovery_state_fixture20 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_fixture20 RENAME TO recovery_state; PRAGMA user_version=20;").map_err(|e|sqlite_error("cannot reconstruct schema twenty fixture",e))
}

#[cfg(test)]
pub(in crate::manage) fn restore_schema_twenty_one_for_test(
    connection: &Connection,
) -> io::Result<()> {
    if !connection.is_autocommit() {
        return restore_schema_twenty_one_in(connection);
    }
    let tx = connection
        .unchecked_transaction()
        .map_err(|error| sqlite_error("cannot begin schema twenty one fixture", error))?;
    restore_schema_twenty_one_in(&tx)?;
    tx.commit()
        .map_err(|error| sqlite_error("cannot commit schema twenty one fixture", error))
}

#[cfg(test)]
fn restore_schema_twenty_one_in(connection: &Connection) -> io::Result<()> {
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| sqlite_error("cannot inspect schema twenty one fixture", error))?;
    if version < 22 {
        return Ok(());
    }
    require_source_version_for_test(connection, 21)?;
    super::alerts::history::require_legacy_for_test(connection)?;
    super::notifications::remove_schema_for_test(connection)?;
    create_table(
        connection,
        "recovery_state_fixture21",
        "13,14,15,16,17,18,19,20,21",
    )?;
    connection.execute_batch("INSERT INTO recovery_state_fixture21 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_fixture21 RENAME TO recovery_state; PRAGMA user_version=21;")
        .map_err(|error|sqlite_error("cannot reconstruct schema twenty one fixture",error))
}

/// Recreate schema22's real provenance fence before migration tests. Configured
/// notification authority is never discarded to manufacture an old fixture.
#[cfg(test)]
pub(in crate::manage) fn restore_schema_twenty_two_for_test(
    connection: &Connection,
) -> io::Result<()> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|e| sqlite_error("cannot begin schema twenty two fixture", e))?;
    require_source_version_for_test(&tx, 22)?;
    super::notifications::remove_schema_for_test(&tx)?;
    create_table(
        &tx,
        "recovery_state_fixture22",
        "13,14,15,16,17,18,19,20,21,22",
    )?;
    tx.execute_batch("INSERT INTO recovery_state_fixture22 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_fixture22 RENAME TO recovery_state; PRAGMA user_version=22;")
        .map_err(|e| sqlite_error("cannot reconstruct schema twenty two fixture", e))?;
    tx.commit()
        .map_err(|e| sqlite_error("cannot commit schema twenty two fixture", e))
}

/// Schema24 changes only recovery admission vocabulary. Preserve all v23 tables
/// and original provenance when producing a genuine pre-v24 test database;
/// future-source or retained-identity rows cannot be downgraded this way.
#[cfg(test)]
pub(in crate::manage) fn restore_schema_twenty_three_for_test(
    connection: &Connection,
) -> io::Result<()> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|error| sqlite_error("cannot begin schema twenty three fixture", error))?;
    if record_in(&tx)?.is_some_and(|record| {
        record.phase == Phase::PendingTakeover || record.source_schema_version > 23
    }) {
        return Err(invalid_data(
            "recovery provenance cannot become a schema twenty three fixture",
        ));
    }
    super::witness::remove_schema_for_test(&tx)?;
    create_table(
        &tx,
        "recovery_state_fixture23",
        "13,14,15,16,17,18,19,20,21,22,23",
    )?;
    tx.execute_batch("INSERT INTO recovery_state_fixture23 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_fixture23 RENAME TO recovery_state; PRAGMA user_version=23;")
        .map_err(|error| sqlite_error("cannot reconstruct schema twenty three fixture", error))?;
    tx.commit()
        .map_err(|error| sqlite_error("cannot commit schema twenty three fixture", error))
}

/// Preserve the real schema24 vocabulary in old-file migration fixtures.
/// Issued witness records cannot be erased to manufacture an old database.
#[cfg(test)]
pub(in crate::manage) fn restore_schema_twenty_four_for_test(
    connection: &Connection,
) -> io::Result<()> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|e| sqlite_error("cannot begin schema twenty four fixture", e))?;
    require_source_version_for_test(&tx, 24)?;
    super::witness::remove_schema_for_test(&tx)?;
    create_table(
        &tx,
        "recovery_state_fixture24",
        "13,14,15,16,17,18,19,20,21,22,23,24",
    )?;
    tx.execute_batch("INSERT INTO recovery_state_fixture24 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_fixture24 RENAME TO recovery_state; PRAGMA user_version=24;")
        .map_err(|e| sqlite_error("cannot reconstruct schema twenty four fixture",e))?;
    tx.commit()
        .map_err(|e| sqlite_error("cannot commit schema twenty four fixture", e))
}

/// Reconstruct genuine schema25 without erasing source authority. Unlike older
/// fixtures, original witness-side bindings are allowed and remain untouched.
#[cfg(test)]
pub(in crate::manage) fn restore_schema_twenty_five_for_test(
    connection: &Connection,
) -> io::Result<()> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|e| sqlite_error("cannot begin schema twenty five fixture", e))?;
    if record_in(&tx)?.is_some_and(|r| r.source_schema_version > 25) {
        return Err(corrupt());
    }
    super::source::remove_schema_for_test(&tx)?;
    create_table(
        &tx,
        "recovery_state_fixture25",
        "13,14,15,16,17,18,19,20,21,22,23,24,25",
    )?;
    tx.execute_batch("INSERT INTO recovery_state_fixture25 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_fixture25 RENAME TO recovery_state; PRAGMA user_version=25;")
        .map_err(|e|sqlite_error("cannot reconstruct schema twenty five fixture",e))?;
    tx.commit()
        .map_err(|e| sqlite_error("cannot commit schema twenty five fixture", e))
}

/// Genuine schema26 fixture, retaining all source/witness and policy state.
/// Only a never-used Web service namespace may be removed for this downgrade.
#[cfg(test)]
pub(in crate::manage) fn restore_schema_twenty_six_for_test(
    connection: &Connection,
) -> io::Result<()> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|e| sqlite_error("cannot begin schema twenty six fixture", e))?;
    if record_in(&tx)?.is_some_and(|r| r.source_schema_version > 26) {
        return Err(corrupt());
    }
    super::proxy_service::remove_schema_for_test(&tx)?;
    create_table(
        &tx,
        "recovery_state_fixture26",
        "13,14,15,16,17,18,19,20,21,22,23,24,25,26",
    )?;
    tx.execute_batch("INSERT INTO recovery_state_fixture26 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_fixture26 RENAME TO recovery_state; PRAGMA user_version=26;")
        .map_err(|e| sqlite_error("cannot reconstruct schema twenty six fixture",e))?;
    tx.commit()
        .map_err(|e| sqlite_error("cannot commit schema twenty six fixture", e))
}

/// Genuine schema27 fixture: no encrypted copies or future recovery provenance.
#[cfg(test)]
pub(in crate::manage) fn restore_schema_twenty_seven_for_test(
    connection: &Connection,
) -> io::Result<()> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|e| sqlite_error("cannot begin schema twenty seven fixture", e))?;
    if record_in(&tx)?.is_some_and(|r| r.source_schema_version > 27) {
        return Err(corrupt());
    }
    super::secrets::project_legacy_for_test(&tx)?;
    create_table(
        &tx,
        "recovery_state_fixture27",
        "13,14,15,16,17,18,19,20,21,22,23,24,25,26,27",
    )?;
    tx.execute_batch("INSERT INTO recovery_state_fixture27 SELECT * FROM recovery_state; DROP TABLE recovery_state; ALTER TABLE recovery_state_fixture27 RENAME TO recovery_state; PRAGMA user_version=27;")
        .map_err(|e| sqlite_error("cannot reconstruct schema twenty seven fixture", e))?;
    tx.commit()
        .map_err(|e| sqlite_error("cannot commit schema twenty seven fixture", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{
        Protocol,
        routing::{AddressFamily, RoutingEntity},
    };
    use crate::manage::store::{self, PolicyChange};
    use sha2::{Digest as _, Sha256};
    use std::{fs, path::PathBuf};

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$Zml4dHVyZQ";

    #[test]
    fn restore_as_new_does_not_copy_external_witness_authority() -> TestResult {
        let fixture = Fixture::new()?;
        let peer = store::random_id()?;
        // Enrollment metadata only; the real DER/SAN transport is covered by the
        // witness node tests, not by this offline safe-draft import fixture.
        store::register_peer(
            &fixture.source,
            &peer,
            "witness source",
            b"fixture certificate",
            "peer.test",
            None,
        )?;
        let enrollment = crate::manage::witness::Enrollment {
            witness_node_id: store::inspect(&fixture.source)?.node_id,
            binding_id: store::random_id()?,
            peer_node_id: peer,
            writer_id: store::random_id()?,
            baseline: "0".repeat(64),
        };
        store::witness::bind(&fixture.source, &enrollment)?;
        let source = raw(&fixture.source)?;
        let excluded = source_ids(&source, store::SCHEMA_VERSION)?;
        assert!(excluded.contains(&enrollment.binding_id));
        assert!(excluded.contains(&enrollment.writer_id));
        store::create_backup(&fixture.source, &fixture.package)?;
        fixture.recover()?;
        let output = raw(&fixture.output)?;
        assert_eq!(
            output.query_row("SELECT count(*) FROM recovery_witness", [], |r| r
                .get::<_, i64>(0))?,
            0
        );
        assert_eq!(
            store::witness::inspect(&fixture.source, &enrollment.binding_id)?.enrollment,
            enrollment
        );
        assert_eq!(
            startup(&fixture.output).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        Ok(())
    }

    #[test]
    fn restore_as_new_never_copies_webhook_secrets_or_delivery_authority() -> TestResult {
        use crate::manage::notifications::Change;
        let fixture = Fixture::new()?;
        let source = raw(&fixture.source)?;
        let actor: String = source.query_row("SELECT id FROM administrators", [], |r| r.get(0))?;
        let node = store::inspect(&fixture.source)?.node_id;
        let operation = super::super::random_id()?;
        store::notifications::change(
            &fixture.source,
            &store::update_lock(&fixture.source)?,
            &actor,
            &Change {
                expected_node_id: node,
                expected_revision: "0".into(),
                operation_id: operation.clone(),
                enabled: true,
                automatic_retry: false,
                url: Some("https://hooks.example/private?secret=test".into()),
                bearer: Some("fake-test-token".into()),
                clear_bearer: false,
                clear_destination: false,
                discard_pending: false,
            },
        )?;
        assert!(source_ids(&source, store::SCHEMA_VERSION)?.contains(&operation));
        store::create_backup(&fixture.source, &fixture.package)?;
        fixture.recover()?;
        let output = raw(&fixture.output)?;
        let actor: String = output.query_row("SELECT id FROM administrators", [], |r| r.get(0))?;
        let restored = store::notifications::status(&fixture.output, &actor)?;
        assert!(!restored.enabled && !restored.configured && !restored.has_bearer);
        assert!(restored.pending.is_none());
        assert_ne!(restored.operation_id.as_ref(), Some(&operation));
        assert!(
            store::notifications::status(
                &fixture.source,
                &source.query_row("SELECT id FROM administrators", [], |r| r
                    .get::<_, String>(0))?
            )?
            .enabled
        );
        Ok(())
    }

    #[test]
    fn recovery_uses_a_fresh_admission_baseline_not_the_sources_maintenance_setting() -> TestResult
    {
        let fixture = Fixture::new()?;
        let connection = raw(&fixture.source)?;
        let administrator: String =
            connection.query_row("SELECT id FROM administrators", [], |row| row.get(0))?;
        let source = store::inspect(&fixture.source)?.node_id;
        store::apply_policy_asserted(
            &fixture.source,
            &administrator,
            1,
            PolicyChange::SetAdmission { accepting: false },
            &store::update_lock(&fixture.source)?,
            &store::admission::Assertion {
                node_id: source,
                epoch: 1,
            },
        )?;
        store::create_backup(&fixture.source, &fixture.package)?;
        let restored = fixture.recover()?;
        assert_eq!(
            restored.recovery.as_ref().unwrap().source_schema_version,
            store::SCHEMA_VERSION
        );
        assert!(store::load_policy(&fixture.output)?.accepting);
        let output = raw(&fixture.output)?;
        let audits: i64 =
            output.query_row("SELECT count(*) FROM proxy_admission_audit", [], |row| {
                row.get(0)
            })?;
        assert_eq!(audits, 0);
        assert!(!store::load_policy(&fixture.source)?.accepting);
        Ok(())
    }

    #[test]
    fn new_identity_recovery_discards_controller_history_and_the_executable_slot() -> TestResult {
        let fixture = Fixture::populated()?;
        let source = raw(&fixture.source)?;
        let (peer, first, administrator): (String, String, String) = source.query_row(
            "SELECT peer_id,job_id,administrator_id FROM control_outbox",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        drop(source);
        // The first request is locally superseded only after the observed peer
        // high-water proves its sequence spent. A second explicit request replaces
        // the executable slot, while the first result remains historical.
        store::targets::observe(&fixture.source, &peer, 1, 2, 1, 1)?;
        store::targets::supersede(&fixture.source, &administrator, &peer, &first)?;
        let second = store::targets::enqueue(
            &fixture.source,
            &administrator,
            1,
            store::Command {
                target_node_id: peer.clone(),
                epoch: 2,
                command_id: 2,
                expected_policy_revision: 1,
                source_administrator_id: administrator.clone(),
                change: PolicyChange::CreateUser {
                    name: "later remote draft".into(),
                    protocols: vec![],
                    concurrent_limit: 1,
                },
            },
        )?;
        let package = fixture.root.join("history-package");
        store::create_backup(&fixture.source, &package)?;
        let source = raw(&fixture.source)?;
        let excluded = source_ids(&source, store::SCHEMA_VERSION)?;
        assert!(excluded.contains(&first) && excluded.contains(&second.job_id));
        for id in [&first, &second.job_id] {
            assert!(reserve_base_id(&mut excluded.clone(), id.clone()).is_err());
        }
        let source_history: i64 =
            source.query_row("SELECT count(*) FROM controller_history", [], |row| {
                row.get(0)
            })?;
        assert_eq!(source_history, 2);
        drop(source);
        let database = fs::read(package.join(DATABASE_NAME))?;
        let manifest = fs::read(package.join("manifest.json"))?;
        let restored = restore(
            &package,
            &fixture.output,
            "new node",
            "new-admin",
            "new fixture PHC",
            identity()?,
        )?;
        let record = restored.recovery.unwrap();
        assert_eq!(record.source_schema_version, store::SCHEMA_VERSION);
        let output = raw(&fixture.output)?;
        let empty: (i64,i64,i64,i64) = output.query_row(
        "SELECT (SELECT last_sequence FROM controller_history_state), (SELECT count(*) FROM controller_history), (SELECT count(*) FROM control_outbox), (SELECT count(*) FROM managed_targets)", [],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    )?;
        assert_eq!(empty, (0, 0, 0, 0));
        assert_ne!(restored.node_id, store::inspect(&fixture.source)?.node_id);
        baseline(&output, &record)?;
        for id in source_ids(&output, store::SCHEMA_VERSION)? {
            if id != record.source_node_id {
                assert!(!excluded.contains(&id));
            }
        }
        output.execute("UPDATE controller_history_state SET last_sequence=1", [])?;
        assert!(finalize(&fixture.output, &record.id).is_err());
        assert_eq!(
            status(&fixture.output)?.recovery.as_ref().unwrap().phase,
            Phase::PendingReview
        );
        output.execute("UPDATE controller_history_state SET last_sequence=0", [])?;
        let new_administrator: String =
            output.query_row("SELECT id FROM administrators", [], |row| row.get(0))?;
        drop(output);
        finalize(&fixture.output, &record.id)?;
        assert!(
            store::targets::history::list(&fixture.output, &new_administrator, &peer, None, 25)
                .is_err()
        );
        assert!(store::targets::job(&fixture.output, &peer)?.is_none());
        assert!(
            store::targets::retry(&fixture.output, &new_administrator, &peer, &second.job_id)
                .is_err()
        );
        assert_eq!(fs::read(package.join(DATABASE_NAME))?, database);
        assert_eq!(fs::read(package.join("manifest.json"))?, manifest);
        Ok(())
    }

    #[test]
    fn new_identity_recovery_discards_events_monitor_boot_and_acknowledgements() -> TestResult {
        use store::alerts::history::{self, Ack, Batch, Observation, Transition, TransitionKind};
        let fixture = Fixture::new()?;
        let source = raw(&fixture.source)?;
        let actor: String =
            source.query_row("SELECT id FROM administrators", [], |row| row.get(0))?;
        let node = store::read_overview(&source)?.node_id;
        drop(source);
        let boot = random_id()?;
        // This removed resource identity exists only in historical observations,
        // not in today's IPAM inventory. New allocations must exclude it as well.
        let historical_resource = random_id()?;
        let gate = store::update_lock(&fixture.source)?;
        history::start(&fixture.source, &gate, &boot)?;
        let commit = history::record(
            &fixture.source,
            &gate,
            &Batch {
                boot_id: boot.clone(),
                sequence: 1,
                transitions: vec![Transition {
                    kind: TransitionKind::Opened,
                    observation: Observation {
                        incident_id: 1,
                        kind: crate::manage::alerts::Kind::EgressCheck,
                        origin_node_id: node.clone(),
                        resource_id: Some(historical_resource.clone()),
                        slot: "bind".into(),
                        check: Some(crate::manage::health::CheckKind::Bind),
                        target: None,
                        code: "egress_failed".into(),
                        first_observed_at_unix_ms: Some(1),
                        last_observed_at_unix_ms: Some(1),
                        evidence_sequence: Some(1),
                    },
                    observed_at_unix_ms: Some(1),
                    ended_reason: None,
                }],
            },
        )?;
        let sequence = commit.first_event_sequence.expect("fixture transition");
        let old_episode = history::acknowledge(
            &fixture.source,
            &gate,
            &actor,
            &Ack {
                expected_node_id: node.clone(),
                episode_id: sequence,
                expected_transition_sequence: sequence,
            },
        )?;
        assert!(old_episode.is_acknowledged);
        drop(gate);
        let source = raw(&fixture.source)?;
        let excluded = source_ids(&source, store::SCHEMA_VERSION)?;
        for id in [&boot, &historical_resource] {
            assert!(excluded.contains(id));
            assert!(reserve_base_id(&mut excluded.clone(), id.clone()).is_err());
        }
        drop(source);
        store::create_backup(&fixture.source, &fixture.package)?;
        let database = fs::read(fixture.package.join(DATABASE_NAME))?;
        let manifest = fs::read(fixture.package.join("manifest.json"))?;
        let restored = fixture.recover()?;
        let record = restored.recovery.expect("new identity provenance");
        assert_eq!(record.source_schema_version, store::SCHEMA_VERSION);
        assert_ne!(restored.node_id, node);
        let output = raw(&fixture.output)?;
        let empty = output.query_row(
        "SELECT last_sequence,trimmed,batch_sequence,boot_id,batch_digest,batch_first,batch_last,last_incident_id,(SELECT count(*) FROM alert_episodes),(SELECT count(*) FROM alert_events) FROM alert_history_state WHERE singleton=1", [],
        |row| Ok((row.get::<_,i64>(0)?, row.get::<_,i64>(1)?, row.get::<_,i64>(2)?, row.get::<_,Option<String>>(3)?, row.get::<_,Option<Vec<u8>>>(4)?, row.get::<_,Option<i64>>(5)?, row.get::<_,Option<i64>>(6)?, row.get::<_,String>(7)?, row.get::<_,i64>(8)?, row.get::<_,i64>(9)?)),
    )?;
        assert_eq!(empty, (0, 0, 0, None, None, None, None, "0".into(), 0, 0));
        history::require_empty(&output)?;
        baseline(&output, &record)?;
        let new_administrator: String =
            output.query_row("SELECT id FROM administrators", [], |row| row.get(0))?;
        assert_ne!(new_administrator, actor);
        assert!(!source_ids(&output, store::SCHEMA_VERSION)?.contains(&historical_resource));
        // Even a boot marker without incidents invalidates the reviewed recovery
        // baseline. Finalization cannot turn it into a newly running monitor.
        output.execute("UPDATE alert_history_state SET boot_id=?1", [&boot])?;
        assert!(finalize(&fixture.output, &record.id).is_err());
        assert_eq!(
            status(&fixture.output)?
                .recovery
                .expect("still pending")
                .phase,
            Phase::PendingReview
        );
        output.execute("UPDATE alert_history_state SET boot_id=NULL", [])?;
        drop(output);
        finalize(&fixture.output, &record.id)?;
        let page = history::list(
            &fixture.output,
            &new_administrator,
            &history::Query {
                before: None,
                limit: 20,
                origin_node_id: None,
                episode_id: None,
            },
        )?;
        assert!(page.items.is_empty());
        assert!(history::get(&fixture.output, &new_administrator, 2)?.is_none());
        let gate = store::update_lock(&fixture.output)?;
        assert!(
            history::acknowledge(
                &fixture.output,
                &gate,
                &new_administrator,
                &Ack {
                    expected_node_id: restored.node_id,
                    episode_id: sequence,
                    expected_transition_sequence: sequence,
                }
            )
            .is_err()
        );
        drop(gate);
        assert_eq!(
            history::episode(&fixture.source, &actor, old_episode.id)?,
            Some(old_episode)
        );
        assert_eq!(fs::read(fixture.package.join(DATABASE_NAME))?, database);
        assert_eq!(fs::read(fixture.package.join("manifest.json"))?, manifest);
        Ok(())
    }

    /// Owns one exclusively created private temporary leaf and no caller paths.
    struct Fixture {
        root: PathBuf,
        source: PathBuf,
        package: PathBuf,
        output: PathBuf,
    }
    impl Fixture {
        fn new() -> io::Result<Self> {
            let root = std::env::temp_dir().join(format!("vproxy-safe-recovery-{}", random_id()?));
            backup::create_directory(&root)?;
            let source = root.join("source");
            store::initialize(&source, "source node", "old-admin", PHC)?;
            Ok(Self {
                source,
                package: root.join("package"),
                output: root.join("restored"),
                root,
            })
        }
        fn populated() -> TestResultFixture {
            Self::populated_with_jobs(true)
        }
        fn populated_with_jobs(include_jobs: bool) -> TestResultFixture {
            let fixture = Self::new()?;
            let connection = super::super::peers::open_existing(&fixture.source, true)?;
            let administrator: String =
                connection.query_row("SELECT id FROM administrators", [], |row| row.get(0))?;
            drop(connection);
            let mut revision = 1;
            let mut change = |change| {
                let result = store::apply_policy(
                    &fixture.source,
                    &administrator,
                    revision,
                    change,
                    &store::update_lock(&fixture.source)?,
                )?;
                revision = result.policy.revision;
                Ok::<_, io::Error>(result)
            };
            let user = change(PolicyChange::CreateUser {
                name: "draft user".into(),
                protocols: vec![Protocol::Http, Protocol::Socks5],
                concurrent_limit: 8,
            })?
            .user
            .unwrap()
            .id;
            change(PolicyChange::CreateCredential {
                user_id: user.clone(),
            })?;
            let prefix = match change(PolicyChange::CreatePrefix {
                name: "inventory".into(),
                cidr: "127.0.0.0/8".parse()?,
            })?
            .routing
            .unwrap()
            {
                RoutingEntity::Prefix(value) => value.id,
                _ => panic!("prefix fixture"),
            };
            let address = match change(PolicyChange::CreateAddress {
                name: "loopback".into(),
                ip: "127.0.0.1".parse()?,
                prefix_id: Some(prefix),
            })?
            .routing
            .unwrap()
            {
                RoutingEntity::Address(value) => value.id,
                _ => panic!("address fixture"),
            };
            let pool = match change(PolicyChange::CreatePool {
                name: "pool".into(),
                family: AddressFamily::V4,
            })?
            .routing
            .unwrap()
            {
                RoutingEntity::Pool(value) => value.id,
                _ => panic!("pool fixture"),
            };
            change(PolicyChange::AddPoolMember {
                pool_id: pool.clone(),
                address_id: address.clone(),
            })?;
            change(PolicyChange::SetRoutePermission {
                permission: RoutePermission {
                    user_id: user.clone(),
                    legacy_allowed: true,
                    exits: vec![address],
                    pools: vec![pool],
                },
            })?;
            change(PolicyChange::SetUserPresets {
                presets: UserPreset {
                    user_id: user,
                    default_preset: Some(crate::ebpf::Profile::Windows),
                    allowed_presets: vec![crate::ebpf::Profile::Windows],
                },
            })?;
            let deleted = change(PolicyChange::CreateUser {
                name: "deleted history".into(),
                protocols: vec![Protocol::Http],
                concurrent_limit: 2,
            })?
            .user
            .unwrap()
            .id;
            change(PolicyChange::DeleteUser { id: deleted })?;
            let retired = match change(PolicyChange::CreatePool {
                name: "retired history".into(),
                family: AddressFamily::V4,
            })?
            .routing
            .unwrap()
            {
                RoutingEntity::Pool(value) => value.id,
                _ => panic!("pool fixture"),
            };
            change(PolicyChange::SetPoolState {
                id: retired,
                state: ResourceState::Retired,
            })?;
            // Both an advertised address and an explicit suppression belong to the
            // old node, not to the new node's disabled recovery drafts.
            let node = store::inspect(&fixture.source)?.node_id;
            let listeners = [18080, 18081]
                .into_iter()
                .map(|port| {
                    let bind = std::net::SocketAddr::from(([127, 0, 0, 1], port));
                    Ok(store::endpoints::ListenerKey {
                        id: crate::manage::proxy::endpoint_id(
                            &node,
                            crate::manage::proxy::Protocol::Http,
                            bind,
                        ),
                        protocol: crate::manage::proxy::Protocol::Http,
                        bind,
                        configured_public_address: Some(format!("old.example:{port}")),
                    })
                })
                .collect::<io::Result<Vec<_>>>()?;
            let inventory = store::endpoints::Inventory::new(&node, listeners)?;
            let gate = store::update_lock(&fixture.source)?;
            let state = store::endpoints::configure(&fixture.source, &gate, &inventory)?;
            let state = store::endpoints::change_local(
                &fixture.source,
                &gate,
                &administrator,
                state.revision,
                &state.digest,
                &inventory,
                &store::endpoints::Change {
                    listener_id: inventory.listeners[0].id.clone(),
                    selection: store::endpoints::AddressSelection::Custom {
                        public_address: "old-public.example:443".into(),
                    },
                },
            )?;
            store::endpoints::change_local(
                &fixture.source,
                &gate,
                &administrator,
                state.revision,
                &state.digest,
                &inventory,
                &store::endpoints::Change {
                    listener_id: inventory.listeners[1].id.clone(),
                    selection: store::endpoints::AddressSelection::Hidden,
                },
            )?;
            drop(gate);
            let peer = random_id()?;
            store::register_peer(
                &fixture.source,
                &peer,
                "old peer",
                b"fixture certificate",
                "old.invalid",
                None,
            )?;
            store::set_owner(
                &fixture.source,
                &store::update_lock(&fixture.source)?,
                &administrator,
                1,
                Some(&peer),
            )?;
            let connection = super::super::peers::open_existing(&fixture.source, true)?;
            connection.execute(
                "UPDATE administrator_audit_state SET last_sequence=12345",
                [],
            )?;
            drop(connection);
            if include_jobs {
                store::targets::configure(
                    &fixture.source,
                    &administrator,
                    &peer,
                    None,
                    "https://old.invalid",
                    true,
                    None,
                )?;
                store::targets::observe(&fixture.source, &peer, 1, 2, 0, 1)?;
                store::targets::enqueue(
                    &fixture.source,
                    &administrator,
                    1,
                    store::Command {
                        target_node_id: peer,
                        epoch: 2,
                        command_id: 1,
                        expected_policy_revision: 1,
                        source_administrator_id: administrator.clone(),
                        change: PolicyChange::CreateUser {
                            name: "remote pending draft".into(),
                            protocols: vec![Protocol::Http],
                            concurrent_limit: 1,
                        },
                    },
                )?;
            }
            store::create_backup(&fixture.source, &fixture.package)?;
            Ok(fixture)
        }
        fn recover(&self) -> Result<Status, Box<dyn std::error::Error>> {
            Ok(restore(
                &self.package,
                &self.output,
                "new node",
                "new-admin",
                "new fixture PHC",
                identity()?,
            )?)
        }
    }
    type TestResultFixture = Result<Fixture, Box<dyn std::error::Error>>;
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn identity() -> Result<Identity, Box<dyn std::error::Error>> {
        use rcgen::PublicKeyData as _;
        let key = rcgen::KeyPair::generate()?;
        let request = rcgen::CertificateParams::new(vec!["new.invalid".into()])?
            .serialize_request(&key)?
            .pem()?;
        Ok(Identity {
            key_pem: Zeroizing::new(key.serialize_pem()),
            request_pem: request,
            public_key_sha256: Sha256::digest(key.subject_public_key_info()).into(),
        })
    }

    fn raw(directory: &Path) -> io::Result<Connection> {
        let connection = open(
            &directory.join(DATABASE_NAME),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        configure(&connection)?;
        Ok(connection)
    }

    #[test]
    fn restore_creates_new_disabled_drafts_and_persistent_gate_then_finalizes() -> TestResult {
        let fixture = Fixture::populated()?;
        let source_database = fs::read(fixture.package.join(DATABASE_NAME))?;
        let source_manifest = fs::read(fixture.package.join("manifest.json"))?;
        let source = raw(&fixture.source)?;
        let excluded = source_ids(&source, store::SCHEMA_VERSION)?;
        let old = store::inspect(&fixture.source)?;
        let restored = fixture.recover()?;
        assert_ne!(restored.node_id, old.node_id);
        let endpoint_state = store::endpoints::read(&fixture.output)?;
        assert!(endpoint_state.digest.is_empty());
        assert!(endpoint_state.overrides.is_empty());
        let record = restored.recovery.unwrap();
        assert_eq!(record.phase, Phase::PendingReview);
        assert_eq!(
            (
                record.imported_users,
                record.imported_prefixes,
                record.imported_addresses,
                record.imported_pools
            ),
            (1, 1, 1, 1)
        );
        assert_eq!(
            startup(&fixture.output).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            super::super::peers::open_existing(&fixture.output, true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let policy = store::load_policy(&fixture.output)?;
        assert!(
            policy
                .users
                .iter()
                .all(|user| !user.active && user.protocols.is_empty())
        );
        assert!(policy.credentials.is_empty());
        let destination = raw(&fixture.output)?;
        baseline(&destination, &record)?;
        for id in source_ids(&destination, store::SCHEMA_VERSION)? {
            if id != record.source_node_id {
                assert!(!excluded.contains(&id), "recovery reused a source identity");
            }
        }
        let phc: String =
            destination.query_row("SELECT password_hash FROM administrators", [], |row| {
                row.get(0)
            })?;
        assert_eq!(phc, "new fixture PHC");
        let key = fs::read(fixture.output.join("node.key"))?;
        assert!(!key.is_empty());
        assert!(fs::metadata(fixture.output.join("node.csr"))?.len() > 0);
        drop(destination);
        let author = store::lock(&fixture.output)?;
        assert_eq!(
            finalize(&fixture.output, &record.id).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(author);
        let update = store::update_lock(&fixture.output)?;
        assert_eq!(
            finalize(&fixture.output, &record.id).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(update);
        assert!(finalize(&fixture.output, &random_id()?).is_err());
        let ready = finalize(&fixture.output, &record.id)?;
        assert_eq!(ready.recovery.as_ref().unwrap().phase, Phase::Ready);
        assert_eq!(startup(&fixture.output)?, Some(record.node_key_sha256));
        assert!(super::super::peers::open_existing(&fixture.output, true).is_ok());
        assert!(finalize(&fixture.output, &record.id).is_err());
        assert_eq!(
            fs::read(fixture.package.join(DATABASE_NAME))?,
            source_database
        );
        assert_eq!(
            fs::read(fixture.package.join("manifest.json"))?,
            source_manifest
        );
        Ok(())
    }

    #[test]
    fn restored_key_and_safe_baseline_must_survive_until_finalize() -> TestResult {
        for sql in [
            "UPDATE proxy_users SET protocols=1",
            "UPDATE traffic_state SET history_gap=0",
            "UPDATE administrator_audit_state SET last_sequence=1",
            "UPDATE recovery_state SET imported_users=2",
        ] {
            let fixture = Fixture::populated()?;
            let pending = fixture.recover()?.recovery.unwrap();
            let connection = raw(&fixture.output)?;
            connection.execute(sql, [])?;
            drop(connection);
            assert!(finalize(&fixture.output, &pending.id).is_err(), "{sql}");
            assert_eq!(
                status(&fixture.output)?.recovery.unwrap().phase,
                Phase::PendingReview
            );
        }
        let fixture = Fixture::populated()?;
        let record = fixture.recover()?.recovery.unwrap();
        let replacement = identity()?;
        fs::write(
            fixture.output.join("node.key"),
            replacement.key_pem.as_bytes(),
        )?;
        assert!(finalize(&fixture.output, &record.id).is_err());
        assert_eq!(
            status(&fixture.output)?.recovery.unwrap().phase,
            Phase::PendingReview
        );
        Ok(())
    }

    #[test]
    fn failed_key_validation_retains_claimed_database_and_never_native_ready() -> TestResult {
        let fixture = Fixture::populated()?;
        let mut material = identity()?;
        material.public_key_sha256 = [0; 32];
        assert!(
            restore(
                &fixture.package,
                &fixture.output,
                "new node",
                "new-admin",
                "new PHC",
                material
            )
            .is_err()
        );
        assert!(fixture.output.join(DATABASE_NAME).is_file());
        assert!(status(&fixture.output).is_err());
        assert!(startup(&fixture.output).is_err());
        assert_eq!(
            store::initialize(&fixture.output, "must not reuse", "admin", PHC)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        Ok(())
    }

    #[test]
    fn restore_refuses_existing_directories_and_source_relatives() -> TestResult {
        let fixture = Fixture::populated()?;
        backup::create_directory(&fixture.output)?;
        assert!(fixture.recover().is_err());
        assert_eq!(fs::read_dir(&fixture.output)?.count(), 0);
        for output in [
            &fixture.package,
            &fixture.package.join("child"),
            &fixture.root,
        ] {
            assert!(
                restore(
                    &fixture.package,
                    output,
                    "new node",
                    "new-admin",
                    PHC,
                    identity()?
                )
                .is_err()
            );
        }
        assert!(!fixture.package.join("child").exists());
        Ok(())
    }

    #[test]
    fn legacy_fixture_ddl_conflicts_preserve_current_namespaces_and_operator_material() -> TestResult
    {
        fn catalog(connection: &Connection) -> rusqlite::Result<Vec<(String, String)>> {
            let mut statement = connection
                .prepare("SELECT name,sql FROM sqlite_schema WHERE type='table' ORDER BY name")?;
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect()
        }
        for version in [18, 19, 20] {
            let fixture = Fixture::new()?;
            let connection = raw(&fixture.source)?;
            let collision = if version == 18 {
                "recovery_state_fixture18"
            } else if version == 19 {
                "recovery_state_fixture19"
            } else {
                "recovery_state_fixture20"
            };
            connection.execute_batch(&format!("CREATE TABLE {collision}(sentinel TEXT); INSERT INTO {collision} VALUES('operator material');"))?;
            let before = catalog(&connection)?;
            let result = if version == 18 {
                restore_schema_eighteen_for_test(&connection)
            } else if version == 19 {
                restore_schema_nineteen_for_test(&connection)
            } else {
                restore_schema_twenty_for_test(&connection)
            };
            assert!(result.is_err());
            assert_eq!(catalog(&connection)?, before);
            assert_eq!(
                status(&fixture.source)?.schema_version,
                store::SCHEMA_VERSION
            );
            assert!(status(&fixture.source)?.recovery.is_none());
            store::targets::history::validate_snapshot(&connection)?;
            store::alerts::history::validate_snapshot(&connection)?;
            assert!(store::load_policy(&fixture.source)?.accepting);
            let retained: String =
                connection.query_row(&format!("SELECT sentinel FROM {collision}"), [], |row| {
                    row.get(0)
                })?;
            assert_eq!(retained, "operator material");
        }
        Ok(())
    }

    #[test]
    fn recovery_rows_fail_closed_and_cannot_be_downgraded() -> TestResult {
        for sql in [
            "DELETE FROM recovery_state",
            "PRAGMA ignore_check_constraints=ON; UPDATE recovery_state SET phase='pending_review'",
            "PRAGMA ignore_check_constraints=ON; INSERT INTO recovery_state(singleton,kind,phase) VALUES(2,'native','ready')",
            "PRAGMA user_version=13",
        ] {
            let fixture = Fixture::new()?;
            raw(&fixture.source)?.execute_batch(sql)?;
            assert!(status(&fixture.source).is_err(), "{sql}");
            assert!(startup(&fixture.source).is_err());
            assert!(super::super::peers::open_existing(&fixture.source, true).is_err());
        }
        Ok(())
    }

    #[test]
    fn schema_thirteen_migration_is_native_and_pending_cannot_migrate() -> TestResult {
        let fixture = Fixture::new()?;
        let connection = raw(&fixture.source)?;
        remove_schema_for_test(&connection)?;
        drop(connection);
        assert_eq!(status(&fixture.source)?.schema_version, 13);
        assert_eq!(startup(&fixture.source)?, None);
        let old = store::inspect(&fixture.source)?.node_id;
        store::migrate(
            &fixture.source,
            &fixture.root.join("before-migration.sqlite3"),
        )?;
        let migrated = status(&fixture.source)?;
        assert_eq!(migrated.schema_version, store::SCHEMA_VERSION);
        assert_eq!(migrated.node_id, old);
        assert!(migrated.recovery.is_none());
        store::create_backup(&fixture.source, &fixture.package)?;
        let record = fixture.recover()?.recovery.unwrap();
        assert!(
            store::migrate(
                &fixture.output,
                &fixture.root.join("must-not-migrate.sqlite3")
            )
            .is_err()
        );
        assert_eq!(status(&fixture.output)?.recovery.unwrap(), record);
        Ok(())
    }

    #[test]
    fn source_is_rechecked_after_typed_recovery_reads() -> TestResult {
        let fixture = Fixture::populated()?;
        let result = backup::read_verified(&fixture.package, |connection, _| {
            let policy = super::super::users::read_policy(connection)?;
            fs::write(fixture.package.join("manifest.json"), b"{}")?;
            Ok(policy)
        });
        assert!(result.is_err());
        assert!(!fixture.output.exists());
        Ok(())
    }

    #[test]
    fn historical_backups_remain_readonly_recovery_inputs() -> TestResult {
        for version in [13, 14, 15, 16, 17, 18, 19, 20] {
            // Historical configuration fixtures retain live drafts but issue no
            // current history identity that a downgrade would have to erase.
            let fixture = Fixture::populated_with_jobs(false)?;
            let database = fixture.package.join(DATABASE_NAME);
            let connection = raw(&fixture.package)?;
            match version {
                13 => remove_schema_for_test(&connection)?,
                14 => restore_schema_fourteen_for_test(&connection)?,
                15 => restore_schema_fifteen_for_test(&connection)?,
                16 => restore_schema_sixteen_for_test(&connection)?,
                17 => restore_schema_seventeen_for_test(&connection)?,
                18 => restore_schema_eighteen_for_test(&connection)?,
                19 => restore_schema_nineteen_for_test(&connection)?,
                20 => restore_schema_twenty_for_test(&connection)?,
                _ => unreachable!(),
            }
            drop(connection);
            let bytes = fs::read(&database)?;
            let hash = Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = fixture.package.join("manifest.json");
            let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
            manifest["schema_version"] = version.into();
            manifest["database_bytes"] = (bytes.len() as u64).into();
            manifest["database_sha256"] = hash.into();
            fs::write(&path, serde_json::to_vec(&manifest)?)?;
            let encoded = fs::read(&path)?;
            assert_eq!(
                store::verify_backup(&fixture.package)?.schema_version,
                version
            );
            let restored = fixture.recover()?;
            assert_eq!(restored.schema_version, store::SCHEMA_VERSION);
            assert_eq!(restored.recovery.unwrap().source_schema_version, version);
            assert_eq!(fs::read(database)?, bytes);
            assert_eq!(fs::read(path)?, encoded);
            assert_eq!(fs::read_dir(&fixture.package)?.count(), 2);
        }
        Ok(())
    }

    #[test]
    fn genuine_old_pending_finalizes_before_migration_and_retains_pin() -> TestResult {
        for version in [14, 15, 16, 19, 20] {
            let fixture = Fixture::new()?;
            store::create_backup(&fixture.source, &fixture.package)?;
            let connection = raw(&fixture.package)?;
            if version == 14 {
                restore_schema_fourteen_for_test(&connection)?;
            } else if version == 15 {
                restore_schema_fifteen_for_test(&connection)?;
            } else if version == 16 {
                restore_schema_sixteen_for_test(&connection)?;
            } else if version == 19 {
                restore_schema_nineteen_for_test(&connection)?;
            } else {
                restore_schema_twenty_for_test(&connection)?;
            }
            drop(connection);
            let database = fs::read(fixture.package.join(DATABASE_NAME))?;
            let path = fixture.package.join("manifest.json");
            let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
            manifest["schema_version"] = version.into();
            manifest["database_bytes"] = (database.len() as u64).into();
            manifest["database_sha256"] = Sha256::digest(&database)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                .into();
            fs::write(path, serde_json::to_vec(&manifest)?)?;
            let restored = fixture.recover()?;
            let record = restored.recovery.unwrap();
            if version == 14 {
                restore_schema_fourteen_for_test(&raw(&fixture.output)?)?;
            } else if version == 15 {
                restore_schema_fifteen_for_test(&raw(&fixture.output)?)?;
            } else if version == 16 {
                restore_schema_sixteen_for_test(&raw(&fixture.output)?)?;
            } else if version == 19 {
                restore_schema_nineteen_for_test(&raw(&fixture.output)?)?;
            } else {
                restore_schema_twenty_for_test(&raw(&fixture.output)?)?;
            }
            assert_eq!(status(&fixture.output)?.schema_version, version);
            let connection = raw(&fixture.output)?;
            connection.execute_batch("PRAGMA ignore_check_constraints=ON")?;
            connection.execute(
                "UPDATE recovery_state SET source_schema_version=?1",
                [version + 1],
            )?;
            assert!(status(&fixture.output).is_err());
            connection.execute(
                "UPDATE recovery_state SET source_schema_version=?1",
                [version],
            )?;
            drop(connection);
            let migration = fixture.root.join("pending-must-not-migrate.sqlite3");
            assert_eq!(
                store::migrate(&fixture.output, &migration)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(!migration.exists());
            assert_eq!(status(&fixture.output)?.recovery, Some(record.clone()));
            let ready = finalize(&fixture.output, &record.id)?;
            assert_eq!(ready.schema_version, version);
            let ready_record = ready.recovery.unwrap();
            assert_eq!(ready_record.phase, Phase::Ready);
            let backup = fixture.root.join("ready-old.sqlite3");
            assert_eq!(
                store::migrate(&fixture.output, &backup)?.schema_version,
                store::SCHEMA_VERSION
            );
            assert_eq!(status(&fixture.output)?.recovery, Some(ready_record));
            assert_eq!(startup(&fixture.output)?, Some(record.node_key_sha256));
            assert_eq!(
                store::read_overview(&Connection::open(backup)?)?.schema_version,
                version
            );
            let endpoints = store::endpoints::read(&fixture.output)?;
            assert_eq!(endpoints.revision, 1);
            assert!(endpoints.digest.is_empty());
            assert!(endpoints.overrides.is_empty());
            let operations: (i64, i64) = raw(&fixture.output)?.query_row(
                "SELECT (SELECT last_sequence FROM operations_state WHERE singleton=1),
                    (SELECT count(*) FROM user_operations)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert_eq!(operations, (0, 0));
        }
        Ok(())
    }

    #[test]
    fn historical_upgrade_is_atomic_and_preserves_operations_and_private_old_snapshot() -> TestResult
    {
        fn operation_rows(
            connection: &Connection,
        ) -> rusqlite::Result<Vec<Vec<rusqlite::types::Value>>> {
            // Compare every historical column; schema18's new actor column is
            // checked separately rather than weakening the old byte comparison.
            let mut statement = connection.prepare("SELECT id,node_id,administrator_id,sequence,expected_revision,expected_epoch,action,digest,user_id,state,saved_revision,rejection FROM user_operations ORDER BY sequence")?;
            let columns = statement.column_count();
            let rows = statement.query_map([], |row| {
                (0..columns).map(|column| row.get(column)).collect()
            })?;
            rows.collect()
        }

        for (version, fail) in [(15, false), (15, true), (16, false), (16, true)] {
            let fixture = Fixture::new()?;
            let connection = raw(&fixture.source)?;
            let old_operations = if version == 15 {
                restore_schema_fifteen_for_test(&connection)?;
                None
            } else {
                restore_schema_sixteen_for_test(&connection)?;
                let actor: String =
                    connection.query_row("SELECT id FROM administrators", [], |row| row.get(0))?;
                store::operations::reserve(
                    &fixture.source,
                    &store::update_lock(&fixture.source)?,
                    &actor,
                    &store::operations::Input {
                        expected_node_id: None,
                        expected_revision: 1,
                        expected_epoch: 1,
                        change: store::operations::UserChange::CreateUser {
                            name: "schema sixteen reservation".into(),
                            protocols: vec![Protocol::Http],
                            concurrent_limit: 1,
                        },
                    },
                )?;
                Some(operation_rows(&connection)?)
            };
            if fail {
                connection.execute_batch("CREATE TABLE recovery_state_v17(sentinel TEXT); INSERT INTO recovery_state_v17 VALUES('operator material');")?;
            }
            let node = status(&fixture.source)?.node_id;
            let old_fence: String = connection.query_row(
                "SELECT sql FROM sqlite_schema WHERE name='recovery_state'",
                [],
                |row| row.get(0),
            )?;
            drop(connection);
            let backup = fixture.root.join(format!("schema{version}.sqlite3"));
            let result = store::migrate(&fixture.source, &backup);
            let source = raw(&fixture.source)?;
            assert_eq!(status(&fixture.source)?.node_id, node);
            let old = Connection::open(&backup)?;
            assert_eq!(store::read_overview(&old)?.schema_version, version);
            assert_eq!(
                old.query_row(
                    "SELECT sql FROM sqlite_schema WHERE name='recovery_state'",
                    [],
                    |row| row.get::<_, String>(0)
                )?,
                old_fence
            );
            if let Some(rows) = &old_operations {
                assert_eq!(&operation_rows(&old)?, rows);
                assert_eq!(&operation_rows(&source)?, rows);
                assert_eq!(
                    source.query_row(
                        "SELECT last_sequence FROM operations_state WHERE singleton=1",
                        [],
                        |row| row.get::<_, i64>(0)
                    )?,
                    1
                );
                assert_eq!(
                    old.query_row(
                        "SELECT last_sequence FROM operations_state WHERE singleton=1",
                        [],
                        |row| row.get::<_, i64>(0)
                    )?,
                    1
                );
            }
            if fail {
                assert!(result.is_err());
                assert_eq!(status(&fixture.source)?.schema_version, version);
                assert_eq!(
                    source.query_row(
                        "SELECT sql FROM sqlite_schema WHERE name='recovery_state'",
                        [],
                        |row| row.get::<_, String>(0)
                    )?,
                    old_fence
                );
                let operations: i64 = source.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name IN('operations_state','user_operations')",
                [], |row| row.get(0),
            )?;
                assert_eq!(operations, if version == 15 { 0 } else { 2 });
                let automation: i64 = source.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name IN('automation_state','automation_principals','automation_audit')", [], |row| row.get(0),
            )?;
                assert_eq!(automation, 0);
                let sentinel: String =
                    source.query_row("SELECT sentinel FROM recovery_state_v17", [], |row| {
                        row.get(0)
                    })?;
                assert_eq!(sentinel, "operator material");
            } else {
                assert_eq!(result?.schema_version, store::SCHEMA_VERSION);
                let machine_actors: i64 = source.query_row(
                "SELECT count(*) FROM user_operations WHERE automation_principal_id IS NOT NULL",
                [],
                |row| row.get(0),
            )?;
                assert_eq!(machine_actors, 0);
                assert!(status(&fixture.source)?.recovery.is_none());
                let state: (i64, i64) = source.query_row(
                    "SELECT (SELECT last_sequence FROM operations_state WHERE singleton=1),
                        (SELECT count(*) FROM user_operations)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                assert_eq!(state, if version == 15 { (0, 0) } else { (1, 1) });
                assert!(store::automation::list(&fixture.source)?.is_empty());
                assert_eq!(
                    source.execute(
                        "UPDATE recovery_state SET kind='restored',phase='pending_review',
                   recovery_id=?1,source_node_id=?2,source_schema_version=17,
                   source_database_sha256=?3,node_key_sha256=?4,
                   imported_users=0,imported_prefixes=0,imported_addresses=0,imported_pools=0
                 WHERE singleton=1",
                        params![random_id()?, random_id()?, "0".repeat(64), &[7_u8; 32][..]],
                    )?,
                    1
                );
                assert_eq!(
                    status(&fixture.source)?
                        .recovery
                        .unwrap()
                        .source_schema_version,
                    17
                );
            }
        }
        Ok(())
    }

    #[test]
    fn new_identity_recovery_never_imports_reserved_or_saved_operation_authority() -> TestResult {
        use store::operations::{self, Input, Outcome, UserChange};

        let fixture = Fixture::new()?;
        let connection = raw(&fixture.source)?;
        let administrator: String =
            connection.query_row("SELECT id FROM administrators", [], |row| row.get(0))?;
        drop(connection);
        let input = Input {
            expected_node_id: None,
            expected_revision: 1,
            expected_epoch: 1,
            change: UserChange::CreateUser {
                name: "operation draft".into(),
                protocols: vec![Protocol::Http],
                concurrent_limit: 2,
            },
        };
        let gate = store::update_lock(&fixture.source)?;
        let reserved = operations::reserve(&fixture.source, &gate, &administrator, &input)?;
        let user = match operations::execute(
            &fixture.source,
            &gate,
            &administrator,
            &reserved.id,
            input.clone(),
        )? {
            Outcome::Accepted { change, .. } => change.user.unwrap().id,
            _ => panic!("new operation must be accepted"),
        };
        let pending = operations::reserve(
            &fixture.source,
            &gate,
            &administrator,
            &Input {
                expected_node_id: None,
                expected_revision: 2,
                expected_epoch: 1,
                change: UserChange::DeleteUser { id: user },
            },
        )?;
        assert!(store::remove_operations_schema_for_test(&raw(&fixture.source)?).is_err());
        drop(gate);
        store::create_backup(&fixture.source, &fixture.package)?;
        let package = fs::read(fixture.package.join(DATABASE_NAME))?;
        let manifest = fs::read(fixture.package.join("manifest.json"))?;
        let excluded = source_ids(&raw(&fixture.source)?, store::SCHEMA_VERSION)?;
        assert!(excluded.contains(&reserved.id) && excluded.contains(&pending.id));
        let restored = fixture.recover()?;
        let record = restored.recovery.unwrap();
        assert_eq!(record.source_schema_version, store::SCHEMA_VERSION);
        let destination = raw(&fixture.output)?;
        let actual: (i64, i64) = destination.query_row(
            "SELECT (SELECT last_sequence FROM operations_state WHERE singleton=1),
                (SELECT count(*) FROM user_operations)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(actual, (0, 0));
        destination.execute("UPDATE operations_state SET last_sequence=1", [])?;
        assert!(finalize(&fixture.output, &record.id).is_err());
        assert_eq!(
            status(&fixture.output)?.recovery.as_ref().unwrap().phase,
            Phase::PendingReview
        );
        destination.execute("UPDATE operations_state SET last_sequence=0", [])?;
        let new_administrator: String =
            destination.query_row("SELECT id FROM administrators", [], |row| row.get(0))?;
        assert_ne!(administrator, new_administrator);
        drop(destination);
        finalize(&fixture.output, &record.id)?;
        let gate = store::update_lock(&fixture.output)?;
        assert!(
            operations::execute(
                &fixture.output,
                &gate,
                &new_administrator,
                &reserved.id,
                input
            )
            .is_err()
        );
        assert_eq!(store::load_policy(&fixture.output)?.revision, 1);
        assert_eq!(fs::read(fixture.package.join(DATABASE_NAME))?, package);
        assert_eq!(fs::read(fixture.package.join("manifest.json"))?, manifest);
        Ok(())
    }

    #[test]
    fn new_identity_recovery_discards_automation_authority_and_excludes_its_ids() -> TestResult {
        use store::automation::{self, Credential, Error};

        let fixture = Fixture::new()?;
        let active = automation::create(
            &fixture.source,
            "old active principal",
            automation::Scope::UsersRead,
            3600,
            |_| Ok(()),
        )?;
        let mut token = Zeroizing::new(String::new());
        let active = automation::rotate(
            &fixture.source,
            &active.id,
            active.generation,
            3600,
            |value| {
                *token = value.to_owned();
                Ok(())
            },
        )?;
        let mut revoked_token = Zeroizing::new(String::new());
        let revoked = automation::create(
            &fixture.source,
            "old revoked principal",
            automation::Scope::UsersRead,
            3600,
            |value| {
                *revoked_token = value.to_owned();
                Ok(())
            },
        )?;
        automation::revoke(&fixture.source, &revoked.id, revoked.generation)?;
        let credential = Credential::parse(token.as_str())?;
        assert!(automation::list_users(&fixture.source, &credential, false, None, 1).is_ok());
        let rejected = automation::list_users(
            &fixture.source,
            &Credential::parse(revoked_token.as_str())?,
            false,
            None,
            1,
        )
        .err()
        .unwrap();
        assert!(matches!(
            rejected
                .get_ref()
                .and_then(|error| error.downcast_ref::<Error>()),
            Some(Error::Unauthorized)
        ));
        let source_principals = automation::list(&fixture.source)?;
        let source = raw(&fixture.source)?;
        let source_state: (i64, i64, i64) = source.query_row(
            "SELECT (SELECT last_sequence FROM automation_state WHERE singleton=1),
                (SELECT count(*) FROM automation_principals),
                (SELECT count(*) FROM automation_audit)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(source_state, (4, 2, 4));
        let excluded = source_ids(&source, store::SCHEMA_VERSION)?;
        for id in [&active.id, &revoked.id] {
            assert!(excluded.contains(id));
            // The exclusion is an enforced allocator precondition, not a claim
            // that an unforced random draw happened to avoid these two IDs.
            assert!(reserve_base_id(&mut excluded.clone(), id.to_owned()).is_err());
        }
        drop(source);
        store::create_backup(&fixture.source, &fixture.package)?;
        assert_eq!(
            store::verify_backup(&fixture.package)?.schema_version,
            store::SCHEMA_VERSION
        );
        assert_eq!(automation::list(&fixture.package)?, source_principals);
        let database = fs::read(fixture.package.join(DATABASE_NAME))?;
        let manifest = fs::read(fixture.package.join("manifest.json"))?;

        let restored = fixture.recover()?;
        assert_eq!(restored.schema_version, store::SCHEMA_VERSION);
        let record = restored.recovery.unwrap();
        assert_eq!(record.source_schema_version, store::SCHEMA_VERSION);
        let destination = raw(&fixture.output)?;
        let empty: (i64, i64, i64) = destination.query_row(
            "SELECT (SELECT last_sequence FROM automation_state WHERE singleton=1),
                (SELECT count(*) FROM automation_principals),
                (SELECT count(*) FROM automation_audit)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(empty, (0, 0, 0));
        baseline(&destination, &record)?;
        for id in source_ids(&destination, store::SCHEMA_VERSION)? {
            if id != record.source_node_id {
                assert!(!excluded.contains(&id));
            }
        }
        let mut delivered = false;
        assert!(
            automation::create(
                &fixture.output,
                "cannot bypass Pending",
                automation::Scope::UsersRead,
                3600,
                |_| {
                    delivered = true;
                    Ok(())
                }
            )
            .is_err()
        );
        assert!(!delivered);
        // A nonempty authority highwater cannot be finalized as an empty import;
        // ordinary typed namespace checks may reject it before the baseline does.
        destination.execute("UPDATE automation_state SET last_sequence=1", [])?;
        assert!(finalize(&fixture.output, &record.id).is_err());
        destination.execute("UPDATE automation_state SET last_sequence=0", [])?;
        assert_eq!(status(&fixture.output)?.recovery, Some(record.clone()));
        drop(destination);
        finalize(&fixture.output, &record.id)?;
        for old in [credential, Credential::parse(revoked_token.as_str())?] {
            let error = automation::list_users(&fixture.output, &old, false, None, 1)
                .err()
                .unwrap();
            assert!(matches!(
                error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<Error>()),
                Some(Error::Unauthorized)
            ));
        }
        assert!(automation::list(&fixture.output)?.is_empty());
        assert_eq!(store::load_policy(&fixture.output)?.revision, 1);
        assert_eq!(automation::list(&fixture.source)?, source_principals);
        assert_eq!(fs::read(fixture.package.join(DATABASE_NAME))?, database);
        assert_eq!(fs::read(fixture.package.join("manifest.json"))?, manifest);
        assert_eq!(fs::read_dir(&fixture.package)?.count(), 2);
        Ok(())
    }

    #[test]
    fn new_identity_recovery_discards_both_operation_actor_namespaces_and_machine_audit()
    -> TestResult {
        use std::sync::Arc;
        use store::{automation, operations};

        let fixture = Fixture::new()?;
        let mut token = Zeroizing::new(String::new());
        let principal = automation::create(
            &fixture.source,
            "source writer",
            automation::Scope::UsersWrite,
            3600,
            |value| {
                token.push_str(value);
                Ok(())
            },
        )?;
        let machine =
            operations::Caller::Automation(Arc::new(automation::Credential::parse(&token)?));
        let input = operations::Input {
            expected_node_id: None,
            expected_revision: 1,
            expected_epoch: 1,
            change: operations::UserChange::CreateUser {
                name: "recovered machine draft".into(),
                protocols: vec![Protocol::Http],
                concurrent_limit: 1,
            },
        };
        let gate = store::update_lock(&fixture.source)?;
        let machine_operation = operations::reserve_as(&fixture.source, &gate, &machine, &input)?;
        assert!(matches!(
            operations::execute_as(
                &fixture.source,
                &gate,
                &machine,
                &machine_operation.id,
                input
            )?,
            operations::Outcome::Accepted { .. }
        ));
        let source = raw(&fixture.source)?;
        let administrator: String =
            source.query_row("SELECT id FROM administrators", [], |row| row.get(0))?;
        let admin_operation = operations::reserve(
            &fixture.source,
            &gate,
            &administrator,
            &operations::Input {
                expected_node_id: None,
                expected_revision: 2,
                expected_epoch: 1,
                change: operations::UserChange::CreateUser {
                    name: "never executed draft".into(),
                    protocols: vec![Protocol::Http],
                    concurrent_limit: 1,
                },
            },
        )?;
        drop(gate);
        let excluded = source_ids(&source, 18)?;
        for id in [
            &principal.id,
            &administrator,
            &machine_operation.id,
            &admin_operation.id,
        ] {
            assert!(excluded.contains(id));
            assert!(reserve_base_id(&mut excluded.clone(), id.to_owned()).is_err());
        }
        drop(source);
        store::create_backup(&fixture.source, &fixture.package)?;
        let database = fs::read(fixture.package.join(DATABASE_NAME))?;
        let manifest = fs::read(fixture.package.join("manifest.json"))?;
        let restored = fixture.recover()?;
        let record = restored.recovery.unwrap();
        assert_eq!(record.imported_users, 1);
        let destination = raw(&fixture.output)?;
        let empty: (i64,i64,i64,i64) = destination.query_row(
        "SELECT (SELECT count(*) FROM user_operations),(SELECT last_sequence FROM operations_state),(SELECT count(*) FROM automation_principals),(SELECT count(*) FROM proxy_policy_audit)", [],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    )?;
        assert_eq!(empty, (0, 0, 0, 0));
        baseline(&destination, &record)?;
        for id in source_ids(&destination, 18)? {
            if id != record.source_node_id {
                assert!(!excluded.contains(&id));
            }
        }
        drop(destination);
        finalize(&fixture.output, &record.id)?;
        assert!(operations::get_as(&fixture.output, &machine, &machine_operation.id).is_err());
        assert!(operations::get(&fixture.output, &administrator, &admin_operation.id).is_err());
        assert!(fs::read(fixture.package.join(DATABASE_NAME))? == database);
        assert!(fs::read(fixture.package.join("manifest.json"))? == manifest);
        Ok(())
    }

    #[test]
    fn initializer_collisions_fail_and_resource_ids_exclude_prior_allocations() -> TestResult {
        let source = random_id()?;
        let mut ids = HashSet::from([source.clone()]);
        assert!(reserve_base_id(&mut ids, source.clone()).is_err());
        assert_eq!(ids.len(), 1);
        let allocated = fresh_id(&mut ids)?;
        assert_ne!(allocated, source);
        assert!(reserve_base_id(&mut ids, allocated).is_err());
        assert_eq!(ids.len(), 2);
        Ok(())
    }

    #[test]
    fn finalize_rejects_executable_schema_without_running_transition_faults() -> TestResult {
        for sql in [
            "CREATE TRIGGER fixture_ignore BEFORE UPDATE OF phase ON recovery_state BEGIN SELECT RAISE(IGNORE); END;",
            "CREATE TRIGGER fixture_abort AFTER UPDATE OF phase ON recovery_state BEGIN SELECT RAISE(ABORT,'fixture'); END;",
            "CREATE TABLE fixture_deferred(parent INTEGER REFERENCES recovery_state(singleton) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fixture_commit_failure AFTER UPDATE OF phase ON recovery_state BEGIN INSERT INTO fixture_deferred VALUES(2); END;",
            "CREATE VIEW fixture_view AS SELECT 1 AS value;",
        ] {
            let fixture = Fixture::new()?;
            store::create_backup(&fixture.source, &fixture.package)?;
            let record = fixture.recover()?.recovery.unwrap();
            let connection = raw(&fixture.output)?;
            connection.execute_batch(sql)?;
            // No orphan exists yet, and none of these triggers has fired. Public
            // finalize must reject the executable schema at its normal baseline,
            // not be described as exercising its UPDATE or COMMIT error paths.
            backup::sqlite_checks(&connection)?;
            drop(connection);
            let error = finalize(&fixture.output, &record.id).unwrap_err();
            assert!(error.to_string().contains("unexpected executable objects"));
            assert_eq!(status(&fixture.output)?.recovery, Some(record));
            assert_eq!(
                startup(&fixture.output).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        Ok(())
    }
}
