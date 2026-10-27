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
    ensure_unused_for_test(connection)?;
    super::source::remove_schema_for_test(connection)?;
    connection
        .execute_batch("DROP TABLE IF EXISTS recovery_witness;")
        .map_err(|e| sqlite_error("cannot reconstruct pre-witness fixture", e))
}

#[cfg(test)]
pub(in crate::manage) fn ensure_unused_for_test(connection: &Connection) -> io::Result<()> {
    super::source::ensure_unused_for_test(connection)?;
    let present: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='recovery_witness')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot inspect witness fixture", e))?;
    if present {
        let count: i64 = connection
            .query_row("SELECT count(*) FROM recovery_witness", [], |r| r.get(0))
            .map_err(|e| sqlite_error("cannot count witness fixture", e))?;
        if count != 0 {
            return Err(corrupt());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::{node::tests::Fixture, store, witness};

    #[test]
    fn exact_replays_do_no_dml_and_failed_retirement_leaves_the_original_record() -> io::Result<()>
    {
        let f = Fixture::new(true, false)?;
        let e = enrollment(&f)?;
        bind(&f.server_state, &e)?;
        let auth = authorization(&f)?;
        let input = request(&e, 1, &e.baseline, &"1".repeat(64));
        apply(&f, &auth, &input, false)?;
        let confirmed = apply(&f, &auth, &input, true)?;
        let mut c = open_existing(&f.server_state, true)?;
        c.execute_batch("CREATE TEMP TRIGGER forbid_witness_update BEFORE UPDATE ON recovery_witness BEGIN SELECT RAISE(ABORT,'unexpected witness update'); END;").map_err(io::Error::other)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io::Error::other)?;
        assert_eq!(bind_in(&tx, &e)?, confirmed);
        for confirm in [false, true] {
            assert_eq!(transition_in(&tx, &auth, &input, confirm)?, confirmed);
        }
        assert!(retire_in(&tx, &e.binding_id, "1", &input.commitment).is_err());
        assert_eq!(
            load(&tx, &e.binding_id, &e.witness_node_id)?,
            Some(confirmed)
        );
        tx.rollback().map_err(io::Error::other)?;
        let retired = retire(&f.server_state, &e.binding_id, "1", &input.commitment)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io::Error::other)?;
        assert_eq!(
            retire_in(&tx, &e.binding_id, "1", &input.commitment)?,
            retired
        );
        tx.rollback().map_err(io::Error::other)?;
        // SQL can end the transaction while its Rust owner is still alive. This
        // internal failure must not be classified as malformed peer input.
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io::Error::other)?;
        tx.execute_batch("ROLLBACK").map_err(io::Error::other)?;
        for error in [
            bind_in(&tx, &e).err(),
            transition_in(&tx, &auth, &input, false).err(),
            retire_in(&tx, &e.binding_id, "1", &input.commitment).err(),
        ] {
            let error = error.ok_or_else(|| io::Error::other("missing transaction accepted"))?;
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert!(
                error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<Error>())
                    .is_none()
            );
        }
        Ok(())
    }

    fn enrollment(f: &Fixture) -> io::Result<Enrollment> {
        Ok(Enrollment {
            witness_node_id: f.server_id.clone(),
            binding_id: store::random_id()?,
            peer_node_id: f.client_id.clone(),
            writer_id: store::random_id()?,
            baseline: "0".repeat(64),
        })
    }
    fn authorization(f: &Fixture) -> io::Result<RemoteAuthorization> {
        Ok(RemoteAuthorization {
            node_id: f.client_id.clone(),
            authorization_revision: 1,
            leaf: tls::read_certificate_leaf(&f.client_cert)?.into(),
        })
    }
    fn request(e: &Enrollment, n: u64, previous: &str, commitment: &str) -> Transition {
        Transition {
            witness_node_id: e.witness_node_id.clone(),
            binding_id: e.binding_id.clone(),
            writer_id: e.writer_id.clone(),
            sequence: n.to_string(),
            previous: previous.into(),
            commitment: commitment.into(),
        }
    }
    fn apply(
        f: &Fixture,
        a: &RemoteAuthorization,
        r: &Transition,
        confirm: bool,
    ) -> io::Result<Record> {
        transition(
            &f.server_state,
            &store::update_lock(&f.server_state)?,
            a,
            r,
            confirm,
        )
    }
    fn rejected<T>(value: io::Result<T>, expected: Error) {
        let error = value.err().expect("expected rejection");
        assert_eq!(
            error.get_ref().and_then(|e| e.downcast_ref::<Error>()),
            Some(&expected)
        );
    }

    #[test]
    fn reservation_survives_reopen_and_exact_replies_never_advance_twice() -> io::Result<()> {
        let f = Fixture::new(true, false)?;
        let e = enrollment(&f)?;
        let a = authorization(&f)?;
        let baseline = bind(&f.server_state, &e)?;
        assert_eq!(bind(&f.server_state, &e)?, baseline);
        let r = request(&e, 1, &e.baseline, &"1".repeat(64));
        rejected(apply(&f, &a, &r, true), Error::Conflict);
        let pending = apply(&f, &a, &r, false)?;
        assert_eq!(pending.phase, Phase::Pending);
        assert_eq!(inspect(&f.server_state, &e.binding_id)?, pending);
        assert_eq!(apply(&f, &a, &r, false)?, pending);
        let mut altered = r.clone();
        altered.commitment = "2".repeat(64);
        rejected(apply(&f, &a, &altered, false), Error::Conflict);
        rejected(apply(&f, &a, &altered, true), Error::Conflict);
        let r2 = request(&e, 2, &r.commitment, &"2".repeat(64));
        // Source rollback/crash does not permit an abort or a subsequent reserve.
        rejected(apply(&f, &a, &r2, false), Error::Conflict);
        let confirmed = apply(&f, &a, &r, true)?;
        assert_eq!(confirmed.phase, Phase::Confirmed);
        assert_eq!(apply(&f, &a, &r, true)?, confirmed);
        assert_eq!(apply(&f, &a, &r, false)?, confirmed);
        assert_eq!(bind(&f.server_state, &e)?, confirmed);
        let next = apply(&f, &a, &r2, false)?;
        rejected(apply(&f, &a, &r, false), Error::Conflict);
        rejected(apply(&f, &a, &r, true), Error::Conflict);
        assert_eq!(remote_inspect(&f.server_state, &a, &e.binding_id)?, next);
        Ok(())
    }

    #[test]
    fn witness_authority_is_bound_to_current_peer_not_proxy_owner() -> io::Result<()> {
        let f = Fixture::new(true, false)?;
        let e = enrollment(&f)?;
        bind(&f.server_state, &e)?;
        let mut a = authorization(&f)?;
        let r = request(&e, 1, &e.baseline, &"1".repeat(64));
        let record = apply(&f, &a, &r, false)?;
        a.authorization_revision = 2;
        rejected(
            remote_inspect(&f.server_state, &a, &e.binding_id),
            Error::Denied,
        );
        rejected(apply(&f, &a, &r, true), Error::Denied);
        a.authorization_revision = 1;
        a.node_id = store::random_id()?;
        rejected(apply(&f, &a, &r, true), Error::Denied);
        let a = authorization(&f)?;
        store::revoke_certificate(&f.server_state, &a.leaf, 1)?;
        rejected(
            remote_inspect(&f.server_state, &a, &e.binding_id),
            Error::Denied,
        );
        rejected(apply(&f, &a, &r, false), Error::Denied);
        assert_eq!(inspect(&f.server_state, &e.binding_id)?, record);
        Ok(())
    }

    #[test]
    fn retirement_and_missing_binding_cannot_reset_the_floor() -> io::Result<()> {
        let f = Fixture::new(true, false)?;
        let e = enrollment(&f)?;
        let a = authorization(&f)?;
        bind(&f.server_state, &e)?;
        let r = request(&e, 1, &e.baseline, &"1".repeat(64));
        apply(&f, &a, &r, false)?;
        rejected(
            retire(&f.server_state, &e.binding_id, "0", &e.baseline),
            Error::Conflict,
        );
        let retired = retire(&f.server_state, &e.binding_id, "1", &r.commitment)?;
        assert!(retired.retired);
        assert_eq!(
            retire(&f.server_state, &e.binding_id, "1", &r.commitment)?,
            retired
        );
        rejected(apply(&f, &a, &r, true), Error::Denied);
        rejected(bind(&f.server_state, &e), Error::Conflict);
        let mut new_binding = e.clone();
        new_binding.binding_id = store::random_id()?;
        rejected(bind(&f.server_state, &new_binding), Error::Conflict);
        rejected(
            remote_inspect(&f.server_state, &a, &new_binding.binding_id),
            Error::Denied,
        );
        assert_eq!(inspect(&f.server_state, &e.binding_id)?, retired);
        Ok(())
    }

    #[test]
    fn binding_and_writer_and_payload_are_not_substitutable() -> io::Result<()> {
        let f = Fixture::new(true, false)?;
        let e = enrollment(&f)?;
        let a = authorization(&f)?;
        let original = bind(&f.server_state, &e)?;
        let mut changed = e.clone();
        changed.baseline = "1".repeat(64);
        rejected(bind(&f.server_state, &changed), Error::Conflict);
        let r = request(&e, 1, &e.baseline, &"1".repeat(64));
        for field in 0..5 {
            let mut other = r.clone();
            match field {
                0 => other.witness_node_id = store::random_id()?,
                1 => other.writer_id = store::random_id()?,
                2 => other.previous = "2".repeat(64),
                3 => other.sequence = "2".into(),
                _ => other.binding_id = store::random_id()?,
            }
            rejected(
                apply(&f, &a, &other, false),
                if field == 4 {
                    Error::Denied
                } else {
                    Error::Conflict
                },
            );
        }
        assert_eq!(inspect(&f.server_state, &e.binding_id)?, original);
        Ok(())
    }

    #[test]
    fn competing_payloads_at_one_sequence_have_only_one_durable_winner() -> io::Result<()> {
        let f = Fixture::new(true, false)?;
        let e = enrollment(&f)?;
        bind(&f.server_state, &e)?;
        let a = authorization(&f)?;
        let one = request(&e, 1, &e.baseline, &"1".repeat(64));
        let two = request(&e, 1, &e.baseline, &"2".repeat(64));
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                barrier.wait();
                apply(&f, &a, &one, false)
            });
            let second = scope.spawn(|| {
                barrier.wait();
                apply(&f, &a, &two, false)
            });
            [first.join().unwrap(), second.join().unwrap()]
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        let loser = results.into_iter().find_map(Result::err).unwrap();
        assert!(matches!(
            loser.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::AlreadyExists
        ));
        let stored = inspect(&f.server_state, &e.binding_id)?;
        assert!(stored.commitment == one.commitment || stored.commitment == two.commitment);
        assert_eq!(stored.sequence, "1");
        Ok(())
    }

    #[test]
    fn malformed_counters_corruption_and_missing_schema_fail_without_repair() -> io::Result<()> {
        let f = Fixture::new(true, false)?;
        let e = enrollment(&f)?;
        let a = authorization(&f)?;
        let original = bind(&f.server_state, &e)?;
        let mut r = request(&e, 1, &e.baseline, &"1".repeat(64));
        for value in [
            "0",
            "+1",
            "01",
            " 1",
            "9223372036854775808",
            "18446744073709551616",
        ] {
            r.sequence = value.into();
            rejected(apply(&f, &a, &r, false), Error::Invalid);
        }
        assert_eq!(inspect(&f.server_state, &e.binding_id)?, original);
        let raw = open_existing(&f.server_state, true)?;
        assert!(remove_schema_for_test(&raw).is_err());
        raw.execute("UPDATE recovery_witness SET payload=?1", [b"{}".as_slice()])
            .map_err(io::Error::other)?;
        assert_eq!(
            inspect(&f.server_state, &e.binding_id)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
        raw.execute_batch("DROP TABLE recovery_witness;")
            .map_err(io::Error::other)?;
        assert!(store::inspect(&f.server_state).is_err());
        assert!(bind(&f.server_state, &e).is_err());
        assert!(
            !raw.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='recovery_witness')",
                [],
                |r| r.get::<_, bool>(0)
            )
            .map_err(io::Error::other)?
        );
        Ok(())
    }

    #[test]
    fn counter_ceiling_and_json_vocabulary_are_closed() -> io::Result<()> {
        assert_eq!(sequence("9223372036854775807")?, i64::MAX as u64);
        let f = Fixture::new(true, false)?;
        let e = enrollment(&f)?;
        let a = authorization(&f)?;
        let mut record = bind(&f.server_state, &e)?;
        record.sequence = i64::MAX.to_string();
        record.previous = Some(e.baseline.clone());
        record.commitment = "1".repeat(64);
        save(&open_existing(&f.server_state, true)?, &record)?;
        let r = request(&e, i64::MAX as u64 + 1, &record.commitment, &"2".repeat(64));
        rejected(apply(&f, &a, &r, false), Error::Invalid);
        let mut json = serde_json::to_value(request(&e, 1, &e.baseline, &"1".repeat(64)))
            .map_err(io::Error::other)?;
        json["secret"] = "not accepted".into();
        assert!(serde_json::from_value::<witness::Transition>(json).is_err());
        Ok(())
    }

    #[test]
    fn schema24_migration_is_backed_up_atomic_and_enables_no_bindings() -> io::Result<()> {
        for collide in [false, true] {
            let f = Fixture::new(true, false)?;
            let raw = open_existing(&f.server_state, true)?;
            store::recovery::restore_schema_twenty_four_for_test(&raw)?;
            let old_ddl: String = raw
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE name='recovery_state'",
                    [],
                    |r| r.get(0),
                )
                .map_err(io::Error::other)?;
            if collide {
                raw.execute_batch("CREATE TABLE recovery_witness(operator_note TEXT); INSERT INTO recovery_witness VALUES('preserve');").map_err(io::Error::other)?;
            }
            drop(raw);
            let backup = f.server_state.parent().unwrap().join("before25.sqlite3");
            let result = store::migrate(&f.server_state, &backup);
            let old = Connection::open(&backup).map_err(io::Error::other)?;
            assert_eq!(
                old.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                    .map_err(io::Error::other)?,
                24
            );
            assert_eq!(
                old.query_row(
                    "SELECT sql FROM sqlite_schema WHERE name='recovery_state'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .map_err(io::Error::other)?,
                old_ddl
            );
            let current = Connection::open(f.server_state.join(store::DATABASE_NAME))
                .map_err(io::Error::other)?;
            if collide {
                assert!(result.is_err());
                assert_eq!(store::inspect(&f.server_state)?.schema_version, 24);
                assert_eq!(
                    current
                        .query_row("SELECT operator_note FROM recovery_witness", [], |r| r
                            .get::<_, String>(
                            0
                        ))
                        .map_err(io::Error::other)?,
                    "preserve"
                );
                assert_eq!(
                    current
                        .query_row(
                            "SELECT sql FROM sqlite_schema WHERE name='recovery_state'",
                            [],
                            |r| r.get::<_, String>(0)
                        )
                        .map_err(io::Error::other)?,
                    old_ddl
                );
            } else {
                assert_eq!(result?.schema_version, store::SCHEMA_VERSION);
                assert_eq!(
                    current
                        .query_row("SELECT count(*) FROM recovery_witness", [], |r| r
                            .get::<_, i64>(0))
                        .map_err(io::Error::other)?,
                    0
                );
                assert_eq!(store::ownership(&f.server_state)?.controller_node_id, None);
                assert_eq!(store::inspect(&f.server_state)?.node_id, f.server_id);
            }
        }
        Ok(())
    }

    #[test]
    fn suppressed_or_rewritten_sql_never_returns_a_false_receipt() -> io::Result<()> {
        for rewrite in [false, true] {
            let f = Fixture::new(true, false)?;
            let e = enrollment(&f)?;
            let initial = bind(&f.server_state, &e)?;
            let raw = open_existing(&f.server_state, true)?;
            let sql = if rewrite {
                "CREATE TRIGGER bad_witness AFTER UPDATE ON recovery_witness BEGIN UPDATE recovery_witness SET payload=x'7b7d'; END;"
            } else {
                "CREATE TRIGGER bad_witness BEFORE UPDATE ON recovery_witness BEGIN SELECT RAISE(IGNORE); END;"
            };
            raw.execute_batch(sql).map_err(io::Error::other)?;
            let r = request(&e, 1, &e.baseline, &"1".repeat(64));
            assert_eq!(
                apply(&f, &authorization(&f)?, &r, false)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(inspect(&f.server_state, &e.binding_id)?, initial);
            // All historical fixture preflights reject before any DDL is changed.
            let catalog = |c: &Connection| -> rusqlite::Result<Vec<(String, String)>> {
                c.prepare("SELECT name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect()
            };
            let before = catalog(&raw).map_err(io::Error::other)?;
            assert!(store::recovery::restore_schema_fourteen_for_test(&raw).is_err());
            assert_eq!(catalog(&raw).map_err(io::Error::other)?, before);
        }
        Ok(())
    }
}
