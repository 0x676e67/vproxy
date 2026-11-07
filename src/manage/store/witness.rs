//! Witness-side durable, bounded high-water records. Nothing in this module
//! activates a restored source or pretends that the source has journaled all
//! writes. SQLite FULL and the existing update gate protect each transition.

use super::{
    RemoteAuthorization, UpdateGuard, invalid_data, peers::open_existing, read_overview,
    sqlite_error,
};
use crate::manage::{
    tls,
    witness::{Enrollment, Error, Phase, Record, Transition, digest, sequence},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{io, path::Path};

const MAX_BINDINGS: i64 = 1024;
const MAX_RECORD_BYTES: usize = 2048;

pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection
        .execute_batch(
            "CREATE TABLE recovery_witness (
        binding_id TEXT PRIMARY KEY NOT NULL CHECK(length(binding_id)=22),
        peer_node_id TEXT NOT NULL UNIQUE REFERENCES peers(node_id) CHECK(length(peer_node_id)=22),
        payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 2048)
    ) STRICT;",
        )
        .map_err(|e| sqlite_error("cannot create recovery witness records", e))
}

/// Catalog/capacity validation also runs for read-only overview. A missing
/// schema is never interpreted as a missing binding to recreate automatically.
pub(super) fn validate_schema(connection: &Connection, version: u32) -> io::Result<()> {
    if version < 25 {
        return Ok(());
    }
    let count: i64 = connection
        .query_row("SELECT count(*) FROM recovery_witness", [], |r| r.get(0))
        .map_err(|e| sqlite_error("cannot inspect witness records", e))?;
    if !(0..=MAX_BINDINGS).contains(&count) {
        return Err(corrupt());
    }
    Ok(())
}

fn corrupt() -> io::Error {
    invalid_data("recovery witness record is malformed")
}

fn encode(record: &Record) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(record).map_err(|_| corrupt())?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(corrupt());
    }
    Ok(bytes)
}

/// Validate SQL indexes against the entire bounded record, including canonical
/// encoding and the baseline/transition shape. Corruption is not a CAS conflict.
fn decode(binding: &str, peer: &str, bytes: &[u8], witness: &str) -> io::Result<Record> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(corrupt());
    }
    let record: Record = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
    record.validate().map_err(|_| corrupt())?;
    if record.enrollment.binding_id != binding
        || record.enrollment.peer_node_id != peer
        || record.enrollment.witness_node_id != witness
        || encode(&record)? != bytes
    {
        return Err(corrupt());
    }
    Ok(record)
}

fn require(connection: &Connection) -> io::Result<String> {
    let overview = read_overview(connection)?;
    if overview.schema_version < 25 {
        return Err(Error::UpgradeRequired.error());
    }
    Ok(overview.node_id)
}

fn load(connection: &Connection, binding: &str, witness: &str) -> io::Result<Option<Record>> {
    if !super::valid_id(binding) {
        return Err(Error::Invalid.error());
    }
    connection
        .query_row(
            "SELECT peer_node_id,payload FROM recovery_witness WHERE binding_id=?1",
            [binding],
            |r| {
                let peer: String = r.get(0)?;
                let bytes = match r.get_ref(1)? {
                    rusqlite::types::ValueRef::Blob(v) if v.len() <= MAX_RECORD_BYTES => v.to_vec(),
                    _ => return Err(rusqlite::Error::InvalidQuery),
                };
                Ok((peer, bytes))
            },
        )
        .optional()
        .map_err(|e| sqlite_error("cannot read witness record", e))?
        .map(|(peer, bytes)| decode(binding, &peer, &bytes, witness))
        .transpose()
}

/// Explicit offline enrollment is idempotent only for an identical immutable
/// request. A retired peer/binding is not reusable and no request erases a floor.
pub(in crate::manage) fn bind(directory: &Path, enrollment: &Enrollment) -> io::Result<Record> {
    enrollment.validate()?;
    let _author = super::lock(directory)?;
    let _update = super::update_lock(directory)?;
    let mut connection = open_existing(directory, true)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin witness enrollment", e))?;
    let record = bind_in(&tx, enrollment)?;
    tx.commit()
        .map_err(|e| sqlite_error("cannot commit witness enrollment", e))?;
    Ok(record)
}

/// Stage an offline file-author enrollment in the caller's original transaction.
/// An identical active binding is read-only; no peer/binding can erase a floor.
/// The caller owns commit/confirmation and must not expose the result earlier.
pub(super) fn bind_in(
    tx: &rusqlite::Transaction<'_>,
    enrollment: &Enrollment,
) -> io::Result<Record> {
    held(tx)?;
    enrollment.validate()?;
    let witness = require(tx)?;
    if enrollment.witness_node_id != witness {
        return Err(Error::Conflict.error());
    }
    if let Some(record) = load(tx, &enrollment.binding_id, &witness)? {
        if record.enrollment != *enrollment || record.retired {
            return Err(Error::Conflict.error());
        }
        return Ok(record);
    }
    let authorized: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM peers p JOIN peer_certificates c ON p.node_id=c.node_id WHERE p.node_id=?1 AND p.active=1 AND c.revoked=0)", [&enrollment.peer_node_id], |r| r.get(0))
        .map_err(|e| sqlite_error("cannot check witness peer enrollment", e))?;
    if !authorized {
        return Err(Error::Denied.error());
    }
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM recovery_witness WHERE peer_node_id=?1)",
            [&enrollment.peer_node_id],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot check witness peer binding", e))?;
    if exists {
        return Err(Error::Conflict.error());
    }
    let count: i64 = tx
        .query_row("SELECT count(*) FROM recovery_witness", [], |r| r.get(0))
        .map_err(|e| sqlite_error("cannot count witness bindings", e))?;
    if count >= MAX_BINDINGS {
        return Err(Error::Capacity.error());
    }
    let record = Record {
        enrollment: enrollment.clone(),
        sequence: "0".into(),
        previous: None,
        commitment: enrollment.baseline.clone(),
        phase: Phase::Confirmed,
        retired: false,
    };
    let inserted = tx
        .execute(
            "INSERT INTO recovery_witness VALUES(?1,?2,?3)",
            params![
                enrollment.binding_id,
                enrollment.peer_node_id,
                encode(&record)?
            ],
        )
        .map_err(|e| sqlite_error("cannot enroll witness binding", e))?;
    if inserted != 1 || load(tx, &enrollment.binding_id, &witness)?.as_ref() != Some(&record) {
        return Err(corrupt());
    }
    Ok(record)
}

/// Offline read remains possible after retirement/revocation for diagnosis.
/// It does not recreate missing records or claim the source can be recovered.
pub(in crate::manage) fn inspect(directory: &Path, binding: &str) -> io::Result<Record> {
    super::control::read_snapshot(directory, |connection| {
        let witness = require(connection)?;
        load(connection, binding, &witness)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "witness binding not found"))
    })
}

/// Current handshake DER, SAN and authorization revision are checked inside the
/// *same* transaction as the witness read/write. Proxy ownership grants nothing.
fn authorize(
    connection: &Connection,
    authorization: &RemoteAuthorization,
    record: &Record,
) -> io::Result<()> {
    let peer = super::peers::authorize_in(connection, &authorization.leaf)?
        .ok_or_else(|| Error::Denied.error())?;
    if record.retired
        || peer.node_id != record.enrollment.peer_node_id
        || peer.node_id != authorization.node_id
        || peer.authorization_revision != authorization.authorization_revision
        || tls::verify_peer_name(&authorization.leaf, &peer.expected_san).is_err()
    {
        return Err(Error::Denied.error());
    }
    Ok(())
}

pub(in crate::manage) fn remote_inspect(
    directory: &Path,
    authorization: &RemoteAuthorization,
    binding: &str,
) -> io::Result<Record> {
    super::control::read_snapshot(directory, |connection| {
        let witness = require(connection)?;
        // Missing and other-peer bindings have the same response remotely.
        let record = load(connection, binding, &witness)?.ok_or_else(|| Error::Denied.error())?;
        authorize(connection, authorization, &record)?;
        Ok(record)
    })
}

/// Reserve advances one step from a confirmed floor. Confirm acknowledges only
/// that exact reservation; it cannot jump, cancel or change the payload. Reply
/// loss permits exact replay; later sequences make the original outcome expired,
/// never a new advance. The worker retains its update gate through commit even
/// if the network task is cancelled. I/O failure leaves the result unknown.
pub(in crate::manage) fn transition(
    directory: &Path,
    guard: &UpdateGuard,
    authorization: &RemoteAuthorization,
    request: &Transition,
    confirm: bool,
) -> io::Result<Record> {
    guard.ensure(directory)?;
    request.validate()?;
    let mut connection = open_existing(directory, true)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin witness transition", e))?;
    let record = transition_in(&tx, authorization, request, confirm)?;
    tx.commit()
        .map_err(|e| sqlite_error("cannot commit witness transition", e))?;
    Ok(record)
}

/// Recheck the exact handshake DER/SAN/revision with the bound writer and CAS
/// inside the held transaction. Exact repeats perform no DML, so a Source can
/// return a confirmed receipt without a net-zero intent or another reservation.
pub(in crate::manage) fn transition_in(
    tx: &rusqlite::Transaction<'_>,
    authorization: &RemoteAuthorization,
    request: &Transition,
    confirm: bool,
) -> io::Result<Record> {
    held(tx)?;
    request.validate()?;
    let witness = require(tx)?;
    let mut record =
        load(tx, &request.binding_id, &witness)?.ok_or_else(|| Error::Denied.error())?;
    authorize(tx, authorization, &record)?;
    if request.witness_node_id != witness || request.writer_id != record.enrollment.writer_id {
        return Err(Error::Conflict.error());
    }
    let current = sequence(&record.sequence)?;
    let next = sequence(&request.sequence)?;
    let changed = if next == current {
        if record.previous.as_ref() != Some(&request.previous)
            || record.commitment != request.commitment
        {
            return Err(Error::Conflict.error());
        }
        let changed = confirm && record.phase != Phase::Confirmed;
        if changed {
            record.phase = Phase::Confirmed;
        }
        // Reserve replay after confirmation must not reopen a pending state.
        changed
    } else if !confirm
        && record.phase == Phase::Confirmed
        && current.checked_add(1) == Some(next)
        && record.commitment == request.previous
    {
        record.sequence = request.sequence.clone();
        record.previous = Some(request.previous.clone());
        record.commitment = request.commitment.clone();
        record.phase = Phase::Pending;
        true
    } else {
        return Err(Error::Conflict.error());
    };
    if changed {
        save(tx, &record)?;
    }
    Ok(record)
}

fn save(connection: &Connection, record: &Record) -> io::Result<()> {
    let changed = connection
        .execute(
            "UPDATE recovery_witness SET payload=?1 WHERE binding_id=?2",
            params![encode(record)?, record.enrollment.binding_id],
        )
        .map_err(|e| sqlite_error("cannot update witness record", e))?;
    if changed != 1
        || load(
            connection,
            &record.enrollment.binding_id,
            &record.enrollment.witness_node_id,
        )?
        .as_ref()
            != Some(record)
    {
        return Err(corrupt());
    }
    Ok(())
}

/// Retirement is permanent and CAS-bound to an observed sequence/commitment.
/// Exact repeats are safe, but neither a new baseline nor a new binding for the
/// same peer can erase its tombstone. This is not an infrastructure fence.
pub(in crate::manage) fn retire(
    directory: &Path,
    binding: &str,
    expected_sequence: &str,
    expected_commitment: &str,
) -> io::Result<Record> {
    sequence(expected_sequence)?;
    if !digest(expected_commitment) {
        return Err(Error::Invalid.error());
    }
    let _author = super::lock(directory)?;
    let _update = super::update_lock(directory)?;
    let mut connection = open_existing(directory, true)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin witness retirement", e))?;
    let record = retire_in(&tx, binding, expected_sequence, expected_commitment)?;
    tx.commit()
        .map_err(|e| sqlite_error("cannot commit witness retirement", e))?;
    Ok(record)
}

/// File-author retirement is permanent and CAS-bound, not a takeover permit.
/// Exact repeats are read-only; stale input never changes the original record.
pub(super) fn retire_in(
    tx: &rusqlite::Transaction<'_>,
    binding: &str,
    expected_sequence: &str,
    expected_commitment: &str,
) -> io::Result<Record> {
    held(tx)?;
    sequence(expected_sequence)?;
    if !digest(expected_commitment) {
        return Err(Error::Invalid.error());
    }
    let witness = require(tx)?;
    let mut record = load(tx, binding, &witness)?.ok_or_else(|| Error::Conflict.error())?;
    if record.sequence != expected_sequence || record.commitment != expected_commitment {
        return Err(Error::Conflict.error());
    }
    if !record.retired {
        record.retired = true;
        save(tx, &record)?;
    }
    Ok(record)
}

fn held(connection: &Connection) -> io::Result<()> {
    if connection.is_autocommit() {
        // A lost transaction is an implementation/storage failure, not a bad
        // peer request. Preserve the unknown-result/fencing path for Source.
        return Err(io::Error::other("witness transaction is not held"));
    }
    Ok(())
}

/// Backup integrity validation, not a freshness proof. A restored witness must
/// never be auto-enrolled using an old package's contents.
pub(super) fn validate_snapshot(connection: &Connection, witness: &str) -> io::Result<()> {
    visit(connection, witness, |_| {})
}

/// Preserve old binding/incarnation IDs in restore-as-new's exclusion set, but
/// never copy witness authority into that new node's empty ledger.
pub(super) fn collect_source_ids(
    connection: &Connection,
    witness: &str,
    ids: &mut std::collections::HashSet<String>,
) -> io::Result<()> {
    visit(connection, witness, |record| {
        ids.insert(record.enrollment.binding_id);
        ids.insert(record.enrollment.writer_id);
        ids.insert(record.enrollment.peer_node_id);
    })
}

fn visit(connection: &Connection, witness: &str, mut accept: impl FnMut(Record)) -> io::Result<()> {
    let mut stmt = connection
        .prepare("SELECT binding_id,peer_node_id,payload FROM recovery_witness LIMIT 1025")
        .map_err(|e| sqlite_error("cannot inspect witness snapshot", e))?;
    let mut rows = stmt
        .query([])
        .map_err(|e| sqlite_error("cannot read witness snapshot", e))?;
    let mut count = 0;
    while let Some(row) = rows
        .next()
        .map_err(|e| sqlite_error("cannot scan witness snapshot", e))?
    {
        count += 1;
        if count > MAX_BINDINGS {
            return Err(corrupt());
        }
        let binding: String = row.get(0).map_err(|_| corrupt())?;
        let peer: String = row.get(1).map_err(|_| corrupt())?;
        let bytes = match row.get_ref(2).map_err(|_| corrupt())? {
            rusqlite::types::ValueRef::Blob(v) if v.len() <= MAX_RECORD_BYTES => v,
            _ => return Err(corrupt()),
        };
        accept(decode(&binding, &peer, bytes, witness)?);
    }
    Ok(())
}

/// Reconstruct historical fixtures only when no binding has ever been issued.
/// A tombstone is state too; test helpers must not silently discard one.
#[cfg(test)]
pub(in crate::manage) fn remove_schema_for_test(connection: &Connection) -> io::Result<()> {
    super::source::remove_schema_for_test(connection)?;
    connection
        .execute_batch("DROP TABLE IF EXISTS recovery_witness;")
        .map_err(|e| sqlite_error("cannot reconstruct pre-witness fixture", e))
}
