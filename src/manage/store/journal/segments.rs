//! Ordered changeset segments inside one SQL transaction. This private kernel
//! is bound by Source format-3 metadata: its seal alone is not a witness,
//! snapshot, startup or COMMIT permit. Existing v2 intents are unchanged.
//!
//! Checkpoints drop each completed Session while SQL remains uncommitted. The
//! trusted caller must bound DML between checkpoints; the export limit is not
//! a general Session C-heap/time limit. Output stays private on every failure.

use super::*;
use rusqlite::session::ConflictAction;
use std::io::{Read, Seek, SeekFrom};

const MAGIC: &[u8; 8] = b"VPJSEG01";
const MAX_SEGMENTS: u32 = 1024;
pub(super) const MAX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ROWS: u64 = 131_072;
const MAX_STATE_ROWS: u64 = (crate::manage::store::alerts::history::MAX_ACTIVE
    + crate::manage::store::alerts::history::MAX_CLOSED
    + crate::manage::store::alerts::history::MAX_EVENTS
    + 1) as u64;
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;

/// Non-secret binding of ordered framing, exact bytes, row count and schema.
/// Only the Source commitment may authorize this evidence; constructing
/// one locally cannot authorize replay against a different source preimage.
/// The commitment binds every seal field, not only the file checksum.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Seal {
    pub(super) bytes: u64,
    pub(super) sha256: [u8; 32],
    segments: u32,
    rows: u64,
    pub(super) schema: String,
    before: [u8; 32],
    after: [u8; 32],
}

impl Seal {
    pub(super) fn validate(&self) -> io::Result<()> {
        if !(17..=MAX_BYTES).contains(&self.bytes)
            || !(1..=MAX_SEGMENTS).contains(&self.segments)
            || self.rows < u64::from(self.segments)
            || self.rows > MAX_ROWS
            || !crate::manage::witness::digest(&self.schema)
            || self.before == self.after
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Borrows the held SQL connection, never commits it, and claims new private
/// output only when the first nonempty valid checkpoint is ready. Session,
/// files and in-memory changes are not shared across tasks or network waits.
pub(super) struct Recorder<'a> {
    connection: &'a Connection,
    _veto: &'a Veto<'a>,
    session: Option<Session<'a>>,
    output: PathBuf,
    file: Option<File>,
    hash: Sha256,
    bytes: u64,
    segments: u32,
    rows: u64,
    schema: String,
    before: [u8; 32],
    failed: bool,
}

fn session(connection: &Connection) -> io::Result<Session<'_>> {
    let mut session = Session::new(connection)
        .map_err(|e| sqlite_error("cannot capture segmented source changes", e))?;
    // Attach all known tables, not only history: a callback must not be able to
    // smuggle an uncaptured policy/identity change through this narrow path.
    for table in super::super::backup::tables(SCHEMA_VERSION) {
        session
            .attach(Some(table))
            .map_err(|e| sqlite_error("cannot attach segmented source table", e))?;
    }
    Ok(session)
}

impl<'a> Recorder<'a> {
    pub(super) fn observed(&self) -> io::Result<bool> {
        if self.failed {
            return Err(invalid());
        }
        Ok(self.segments != 0 || !self.session.as_ref().ok_or_else(invalid)?.is_empty())
    }
    pub(super) fn needs_output(&self) -> io::Result<bool> {
        Ok(self.file.is_none() && self.observed()?)
    }
    /// Require an existing held transaction and a new output directory leaf.
    /// An unchanged observation allocates no files. No source state is changed
    /// or automatically initialized; original author/update gates remain with
    /// the trusted outer caller, not this filesystem/SQL component.
    pub(super) fn new(
        connection: &'a Connection,
        veto: &'a Veto<'a>,
        output: &Path,
    ) -> io::Result<Self> {
        if connection.is_autocommit()
            || !std::ptr::eq(connection, veto.connection)
            || veto.permit.load(Ordering::Acquire)
        {
            return Err(invalid());
        }
        let output = files::output_path(output)?;
        let schema = content::schema(connection)?;
        let before = history_content(connection)?;
        Ok(Self {
            connection,
            _veto: veto,
            session: Some(session(connection)?),
            output,
            file: None,
            hash: Sha256::new(),
            bytes: 0,
            segments: 0,
            rows: 0,
            schema,
            before,
            failed: false,
        })
    }

    /// End one bounded capture, without ending SQL. The same row may occur in
    /// later segments: its ordered intermediate pre/postimages remain bound.
    /// Only history/source-floor changes are accepted, never Reader policy.
    /// A failed checkpoint poisons this recorder even if the caller catches it.
    pub(super) fn checkpoint(&mut self) -> io::Result<bool> {
        if self.failed || self.connection.is_autocommit() {
            return Err(invalid());
        }
        let current = self.session.as_mut().ok_or_else(invalid)?;
        if current.is_empty() {
            return Ok(false);
        }
        self.failed = true;
        let payload = replay::session_payload(current)?;
        let delta = replay::delta(self.connection, &payload)?;
        if !delta.history_only() || delta.effect()? != Effect::Unchanged {
            return Err(denied());
        }
        let segments = self
            .segments
            .checked_add(1)
            .filter(|n| *n <= MAX_SEGMENTS)
            .ok_or_else(invalid)?;
        let rows = self
            .rows
            .checked_add(u64::try_from(delta.row_count()).map_err(|_| invalid())?)
            .filter(|n| *n <= MAX_ROWS)
            .ok_or_else(invalid)?;
        let length = u32::try_from(payload.len()).map_err(|_| invalid())?;
        let before = if self.file.is_none() {
            MAGIC.len() as u64
        } else {
            self.bytes
        };
        let bytes = before
            .checked_add(4)
            .and_then(|n| n.checked_add(u64::from(length)))
            .filter(|n| n.checked_add(4).is_some_and(|end| end <= MAX_BYTES))
            .ok_or_else(invalid)?;
        if self.file.is_none() {
            files::create_directory(&self.output)?;
            let mut file = super::super::backup::new_file(&self.output.join(PAYLOAD))?;
            file.write_all(MAGIC)?;
            self.hash.update(MAGIC);
            self.file = Some(file);
        }
        let prefix = length.to_be_bytes();
        let file = self.file.as_mut().ok_or_else(invalid)?;
        file.write_all(&prefix)?;
        file.write_all(&payload)?;
        self.hash.update(prefix);
        self.hash.update(payload.as_slice());
        self.bytes = bytes;
        self.segments = segments;
        self.rows = rows;
        // Delete the old Session before constructing another; neither captures
        // a second copy of later preimages. The same SQL transaction stays open.
        drop(self.session.take());
        self.session = Some(session(self.connection)?);
        self.failed = false;
        Ok(true)
    }

    /// Finish, flush and privately read back the framed stream. None means no observed DML,
    /// not a committed observation. Net-zero writes are rejected, not silently
    /// adopted as reads. I/O or changed schema retains incomplete output.
    pub(super) fn finish(mut self) -> io::Result<Option<Seal>> {
        self.checkpoint()?;
        if self.failed || content::schema(self.connection)? != self.schema {
            return Err(invalid());
        }
        drop(self.session.take());
        let after = history_content(self.connection)?;
        let Some(mut file) = self.file.take() else {
            if after != self.before {
                return Err(invalid());
            }
            return Ok(None);
        };
        if after == self.before {
            return Err(invalid());
        }
        let end = 0u32.to_be_bytes();
        file.write_all(&end)?;
        self.hash.update(end);
        self.bytes = self
            .bytes
            .checked_add(4)
            .filter(|n| *n <= MAX_BYTES)
            .ok_or_else(invalid)?;
        file.sync_all()?;
        drop(file);
        files::sync_directory(&self.output)?;
        let seal = Seal {
            bytes: self.bytes,
            sha256: self.hash.finalize().into(),
            segments: self.segments,
            rows: self.rows,
            schema: self.schema,
            before: self.before,
            after,
        };
        seal.validate()?;
        drop(Input::open(&self.output, &seal)?);
        Ok(Some(seal))
    }
}

/// An opened, handle-audited private stream. Initial checksum verification
/// precedes SQL; sequential reads hash again so completion also validates the
/// bytes actually applied, rather than relying solely on an earlier scan.
pub(super) struct Input {
    file: File,
    seal: Seal,
    hash: Sha256,
    bytes: u64,
    segments: u32,
    complete: bool,
    failed: bool,
}

impl Input {
    /// Validate ordered framing and every normalized table/effect without
    /// applying SQL. This is useful when binding an original operation; it is
    /// not evidence of either a committed postimage or a valid replay preimage.
    pub(super) fn effect(&mut self, connection: &Connection) -> io::Result<Effect> {
        let mut rows = 0u64;
        while let Some(payload) = self.next()? {
            let delta = replay::delta(connection, &payload)?;
            if !delta.history_only() || delta.effect()? != Effect::Unchanged {
                return Err(denied());
            }
            rows = rows
                .checked_add(u64::try_from(delta.row_count()).map_err(|_| invalid())?)
                .ok_or_else(invalid)?;
        }
        if rows != self.seal.rows {
            return Err(invalid());
        }
        Ok(Effect::Unchanged)
    }
    pub(super) fn open(directory: &Path, seal: &Seal) -> io::Result<Self> {
        seal.validate()?;
        files::check_directory(directory, true)?;
        let mut file = verified_file(&directory.join(PAYLOAD), seal.bytes, &hex(&seal.sha256))?;
        file.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; 8];
        file.read_exact(&mut header)?;
        if &header != MAGIC {
            return Err(invalid());
        }
        let mut hash = Sha256::new();
        hash.update(header);
        Ok(Self {
            file,
            seal: seal.clone(),
            hash,
            bytes: MAGIC.len() as u64,
            segments: 0,
            complete: false,
            failed: false,
        })
    }

    fn next(&mut self) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        if self.failed {
            return Err(invalid());
        }
        if self.complete {
            return Ok(None);
        }
        self.failed = true;
        let mut prefix = [0u8; 4];
        self.file.read_exact(&mut prefix)?;
        self.hash.update(prefix);
        self.bytes = self
            .bytes
            .checked_add(4)
            .filter(|n| *n <= self.seal.bytes)
            .ok_or_else(invalid)?;
        let length = u32::from_be_bytes(prefix);
        if length == 0 {
            let mut extra = [0u8; 1];
            if self.segments != self.seal.segments
                || self.bytes != self.seal.bytes
                || self.file.read(&mut extra)? != 0
                || <[u8; 32]>::from(self.hash.clone().finalize()) != self.seal.sha256
            {
                return Err(invalid());
            }
            self.complete = true;
            self.failed = false;
            return Ok(None);
        }
        let length = usize::try_from(length)
            .ok()
            .filter(|n| *n <= MAX_PAYLOAD)
            .ok_or_else(invalid)?;
        let bytes = self
            .bytes
            .checked_add(length as u64)
            .filter(|n| n.checked_add(4).is_some_and(|end| end <= self.seal.bytes))
            .ok_or_else(invalid)?;
        let segments = self
            .segments
            .checked_add(1)
            .filter(|n| *n <= self.seal.segments && *n <= MAX_SEGMENTS)
            .ok_or_else(invalid)?;
        let mut payload = Zeroizing::new(Vec::new());
        payload
            .try_reserve_exact(length)
            .map_err(|_| io::Error::other("cannot reserve bounded source segment"))?;
        payload.resize(length, 0);
        self.file.read_exact(payload.as_mut_slice())?;
        self.hash.update(payload.as_slice());
        self.bytes = bytes;
        self.segments = segments;
        self.failed = false;
        Ok(Some(payload))
    }
}

/// Check exact private bytes with fixed buffering, also for interrupted old
/// record retirement where no complete container need remain parseable.
pub(super) fn verified_file(path: &Path, bytes: u64, expected: &str) -> io::Result<File> {
    if bytes == 0 || bytes > MAX_BYTES {
        return Err(invalid());
    }
    let mut file = files::open_read(
        path,
        usize::try_from(MAX_BYTES).map_err(|_| invalid())?,
        true,
    )?;
    if file.metadata()?.len() != bytes {
        return Err(invalid());
    }
    let mut hash = Sha256::new();
    let mut buffer = Zeroizing::new([0u8; 8192]);
    let mut remaining = bytes;
    while remaining != 0 {
        let length = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| invalid())?;
        file.read_exact(&mut buffer[..length])?;
        hash.update(&buffer[..length]);
        remaining -= length as u64;
    }
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 || hex(&hash.finalize()) != expected {
        return Err(invalid());
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// Capacity is checked once, before the first claimed file, not before a
/// terminal read and not again while the reserved payload is being written.
pub(super) struct Admitted<'a, 's> {
    recorder: Recorder<'a>,
    scope: &'s Scope<'s>,
    execution: &'s execution::Execution<'a>,
}
impl<'a, 's> Admitted<'a, 's> {
    pub(super) fn new(
        connection: &'a Connection,
        veto: &'a Veto<'a>,
        output: &Path,
        scope: &'s Scope<'s>,
        execution: &'s execution::Execution<'a>,
    ) -> io::Result<Self> {
        Ok(Self {
            recorder: Recorder::new(connection, veto, output)?,
            scope,
            execution,
        })
    }
    fn reserve(&self) -> io::Result<()> {
        if self.recorder.needs_output()? {
            tracked::check_capacity_for(self.scope, MAX_BYTES)?;
        }
        Ok(())
    }
    pub(super) fn observed(&self) -> io::Result<bool> {
        self.recorder.observed()
    }
    pub(super) fn finish(self) -> io::Result<Option<Seal>> {
        self.execution.check()?;
        self.reserve()?;
        self.recorder.finish()
    }
}
impl Checkpoints for Admitted<'_, '_> {
    fn checkpoint(&mut self) -> io::Result<()> {
        self.execution.check()?;
        self.reserve()?;
        self.recorder.checkpoint()?;
        self.execution.check()
    }
}

/// Own the caller's complete transaction through verification. Success returns
/// it still uncommitted; failure explicitly rolls it back, including changes
/// before the first segment. No partial transaction or COMMIT permit escapes.
/// A rollback failure is returned as an error; that connection must be fenced,
/// not reused. Source identity/floor/witness admission is still an outer gate.
pub(super) fn replay<'a>(
    transaction: Transaction<'a>,
    veto: &Veto<'_>,
    input: &mut Input,
) -> io::Result<Transaction<'a>> {
    let execution = execution::Execution::new(&transaction, execution::Limits::HISTORY)?;
    let outcome =
        if std::ptr::eq(&*transaction, veto.connection) && !veto.permit.load(Ordering::Acquire) {
            apply(&transaction, input, &execution)
        } else {
            Err(denied())
        };
    // Clear before either transferring the live transaction or rolling it back.
    // Once replay has been dispatched, any budget failure retains its original
    // Pending operation rather than becoming a definite business rejection.
    let outcome = execution.finish().and(outcome);
    match outcome {
        Ok(()) => Ok(transaction),
        Err(original) => {
            if let Err(rollback) = transaction.rollback() {
                return Err(io::Error::other(Rollback { original, rollback }));
            }
            Err(original)
        }
    }
}

/// Keep the original failure and rollback diagnostics internal. Neither is a
/// remote protocol response or evidence that an operation can be replayed anew.
#[derive(Debug, thiserror::Error)]
#[error("segmented replay failed and rollback did not complete ({rollback})")]
struct Rollback {
    #[source]
    original: io::Error,
    rollback: rusqlite::Error,
}

fn apply(
    connection: &Connection,
    input: &mut Input,
    execution: &execution::Execution<'_>,
) -> io::Result<()> {
    if connection.is_autocommit()
        || input.failed
        || input.complete
        || input.segments != 0
        || content::schema(connection)? != input.seal.schema
        || history_content(connection)? != input.seal.before
    {
        return Err(invalid());
    }
    let mut rows = 0u64;
    while let Some(payload) = input.next()? {
        execution.check()?;
        let expected = replay::delta(connection, &payload)?;
        if !expected.history_only() || expected.effect()? != Effect::Unchanged {
            return Err(denied());
        }
        rows = rows
            .checked_add(u64::try_from(expected.row_count()).map_err(|_| invalid())?)
            .filter(|n| *n <= MAX_ROWS)
            .ok_or_else(invalid)?;
        let mut session = session(connection)?;
        connection
            .apply_strm(
                &mut io::Cursor::new(payload.as_slice()),
                None::<fn(&str) -> bool>,
                |_, _| ConflictAction::SQLITE_CHANGESET_ABORT,
            )
            .map_err(|e| sqlite_error("cannot apply original source segment", e))?;
        let actual = replay::session_payload(&mut session)?;
        drop(session);
        if expected != replay::delta(connection, &actual)? {
            return Err(invalid());
        }
        execution.check()?;
    }
    let fk: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot inspect segmented replay foreign keys", e))?;
    if !input.complete
        || rows != input.seal.rows
        || fk
        || content::schema(connection)? != input.seal.schema
        || history_content(connection)? != input.seal.after
    {
        return Err(invalid());
    }
    Ok(())
}

/// Only the fixed history tables, not the full traffic database. Two bounded
/// scans bind untouched rows as well as changed keys and reject cross-segment
/// net-zero writes without retaining an unbounded map of old row values. This
/// cost belongs only to the prospective segmented path, not ordinary writes.
fn history_content(connection: &Connection) -> io::Result<[u8; 32]> {
    use rusqlite::types::ValueRef;
    let mut hash = Sha256::new();
    hash.update(b"vproxy.history.segment-state.v1\0");
    let mut count = 0u64;
    let mut bytes = 0u64;
    for (table, key) in [
        ("alert_history_state", "singleton"),
        ("alert_episodes", "id"),
        ("alert_events", "sequence"),
    ] {
        hash.update(table.as_bytes());
        let columns = content::columns(connection, table, &mut hash)?.count;
        let mut statement = connection
            .prepare(&format!("SELECT * FROM {table} ORDER BY {key}"))
            .map_err(|e| sqlite_error("cannot prepare bounded history commitment", e))?;
        let mut rows = statement
            .query([])
            .map_err(|e| sqlite_error("cannot read bounded history commitment", e))?;
        while let Some(row) = rows
            .next()
            .map_err(|e| sqlite_error("cannot scan bounded history commitment", e))?
        {
            count = count
                .checked_add(1)
                .filter(|n| *n <= MAX_STATE_ROWS)
                .ok_or_else(invalid)?;
            hash.update([1]);
            for column in 0..columns {
                let value = row
                    .get_ref(column)
                    .map_err(|e| sqlite_error("cannot inspect history commitment value", e))?;
                let length = match value {
                    ValueRef::Text(value) | ValueRef::Blob(value) => value.len(),
                    ValueRef::Null => 1,
                    ValueRef::Integer(_) | ValueRef::Real(_) => 8,
                };
                if length > 8192 {
                    return Err(invalid());
                }
                bytes = bytes
                    .checked_add(u64::try_from(length).map_err(|_| invalid())?)
                    .filter(|n| *n <= MAX_STATE_BYTES)
                    .ok_or_else(invalid)?;
                content::cell(&mut hash, value)?;
            }
        }
        hash.update([0]);
        hash.update(count.to_be_bytes());
    }
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    //! SQL/container proofs only. Synthetic blob cells obey the physical schema,
    //! not the alert business decoder; no witness/identity or capacity claim follows.
    use super::*;
    use crate::manage::store;

    struct Fixture {
        directory: PathBuf,
        node: String,
        author: Option<Guard>,
    }
    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory =
                std::env::temp_dir().join(format!("vproxy-segments-{}", store::random_id()?));
            let overview = store::initialize(&directory, "segments", "admin", "fixture-phc")?;
            let author = Some(store::lock(&directory)?);
            Ok(Self {
                directory,
                node: overview.node_id,
                author,
            })
        }
        fn connection(&self) -> io::Result<Connection> {
            peers::open_existing(&self.directory, true)
        }
        fn insert(&self, connection: &Connection, id: u64, payload: &[u8]) -> io::Result<()> {
            connection
                .execute(
                    "INSERT INTO alert_events VALUES(?1,?1,?2,NULL,?3)",
                    rusqlite::params![
                        i64::try_from(id).map_err(|_| invalid())?,
                        self.node,
                        payload
                    ],
                )
                .map_err(io::Error::other)?;
            Ok(())
        }
        fn small(&self) -> io::Result<(PathBuf, Seal)> {
            let connection = self.connection()?;
            let veto = Veto::new(&connection)?;
            let tx = begin(&connection)?;
            let output = self.directory.join("small");
            let mut recorder = Recorder::new(&tx, &veto, &output)?;
            self.insert(&tx, 1, b"one")?;
            recorder.checkpoint()?;
            for bytes in [b"two".as_slice(), b"three"] {
                tx.execute(
                    "UPDATE alert_events SET payload=?1 WHERE sequence=1",
                    [bytes],
                )
                .map_err(io::Error::other)?;
                recorder.checkpoint()?;
            }
            let seal = recorder.finish()?.ok_or_else(invalid)?;
            tx.rollback().map_err(io::Error::other)?;
            Ok((output, seal))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            drop(self.author.take());
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
    fn begin(connection: &Connection) -> io::Result<Transaction<'_>> {
        Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
            .map_err(io::Error::other)
    }
    fn count(connection: &Connection) -> io::Result<i64> {
        connection
            .query_row("SELECT count(*) FROM alert_events", [], |r| r.get(0))
            .map_err(io::Error::other)
    }
    fn payload(connection: &Connection) -> io::Result<Vec<u8>> {
        connection
            .query_row(
                "SELECT payload FROM alert_events WHERE sequence=1",
                [],
                |r| r.get(0),
            )
            .map_err(io::Error::other)
    }
    fn replace(output: &Path, seal: &mut Seal, bytes: &[u8]) -> io::Result<()> {
        fs::write(output.join(PAYLOAD), bytes)?;
        seal.bytes = u64::try_from(bytes.len()).map_err(|_| invalid())?;
        seal.sha256 = Sha256::digest(bytes).into();
        Ok(())
    }

    #[test]
    fn ordered_segments_exceed_one_payload_limit_without_exposing_partial_sql_or_committing()
    -> io::Result<()> {
        let f = Fixture::new()?;
        let connection = f.connection()?;
        let observer = peers::open_existing(&f.directory, false)?;
        let veto = Veto::new(&connection)?;
        let tx = begin(&connection)?;
        let output = f.directory.join("large");
        let mut recorder = Recorder::new(&tx, &veto, &output)?;
        let bytes = [7u8; 1024];
        for n in 1..=16_384 {
            f.insert(&tx, n, &bytes)?;
            if n % 256 == 0 {
                assert!(recorder.checkpoint()?);
                assert_eq!(count(&observer)?, 0);
            }
        }
        let seal = recorder.finish()?.ok_or_else(invalid)?;
        assert_eq!((seal.segments, seal.rows), (64, 16_384));
        assert!(seal.bytes > MAX_PAYLOAD as u64);
        assert_eq!(fs::metadata(output.join(PAYLOAD))?.len(), seal.bytes);
        tx.rollback().map_err(io::Error::other)?;
        assert_eq!(count(&connection)?, 0);
        let mut input = Input::open(&output, &seal)?;
        let replayed = replay(begin(&connection)?, &veto, &mut input)?;
        assert_eq!(count(&replayed)?, 16_384);
        assert_eq!(count(&observer)?, 0);
        assert!(input.complete);
        assert!(replayed.commit().is_err()); // no witness/one-use permit was granted
        assert_eq!(count(&connection)?, 0);
        Ok(())
    }

    #[test]
    fn repeated_keys_keep_ordered_preimages_and_a_late_conflict_rolls_back_the_whole_transaction()
    -> io::Result<()> {
        let f = Fixture::new()?;
        let (output, mut seal) = f.small()?;
        let connection = f.connection()?;
        let veto = Veto::new(&connection)?;
        let tx = replay(
            begin(&connection)?,
            &veto,
            &mut Input::open(&output, &seal)?,
        )?;
        assert_eq!(payload(&tx)?, b"three");
        tx.rollback().map_err(io::Error::other)?;
        // Intentionally reseal an invalid third preimage to exercise SQL conflict,
        // not merely fail the initial file checksum. Such a local seal is not a
        // valid Source/witness commitment and is never exported by this kernel.
        let mut bytes = fs::read(output.join(PAYLOAD))?;
        let mut offset = MAGIC.len();
        for index in 0..seal.segments {
            let size = u32::from_be_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .map_err(|_| invalid())?,
            ) as usize;
            offset += 4;
            if index == 2 {
                let local = bytes[offset..offset + size]
                    .windows(3)
                    .position(|value| value == b"two")
                    .ok_or_else(invalid)?;
                bytes[offset + local..offset + local + 3].copy_from_slice(b"bad");
            }
            offset += size;
        }
        replace(&output, &mut seal, &bytes)?;
        let tx = begin(&connection)?;
        tx.execute(
            "UPDATE administrators SET password_hash='before-replay'",
            [],
        )
        .map_err(io::Error::other)?;
        assert!(replay(tx, &veto, &mut Input::open(&output, &seal)?).is_err());
        assert!(connection.is_autocommit());
        assert_eq!(count(&connection)?, 0);
        let verifier: String = connection
            .query_row("SELECT password_hash FROM administrators", [], |r| r.get(0))
            .map_err(io::Error::other)?;
        assert_eq!(verifier, "fixture-phc");
        Ok(())
    }

    #[test]
    fn unchanged_dropped_and_cross_segment_net_zero_output_never_becomes_a_committable_operation()
    -> io::Result<()> {
        let f = Fixture::new()?;
        let connection = f.connection()?;
        let veto = Veto::new(&connection)?;
        let tx = begin(&connection)?;
        let empty = f.directory.join("empty");
        assert!(Recorder::new(&tx, &veto, &empty)?.finish()?.is_none());
        assert!(!empty.try_exists()?);
        tx.rollback().map_err(io::Error::other)?;
        for dropped in [true, false] {
            let tx = begin(&connection)?;
            let output = f
                .directory
                .join(if dropped { "dropped" } else { "net-zero" });
            let mut recorder = Recorder::new(&tx, &veto, &output)?;
            f.insert(&tx, 1, b"kept privately")?;
            recorder.checkpoint()?;
            if dropped {
                drop(recorder);
            } else {
                tx.execute("DELETE FROM alert_events", [])
                    .map_err(io::Error::other)?;
                recorder.checkpoint()?;
                assert!(recorder.finish().is_err());
            }
            drop(tx);
            assert_eq!(count(&connection)?, 0);
            assert!(output.join(PAYLOAD).try_exists()?); // retained, never adopted/deleted
        }
        Ok(())
    }

    #[test]
    fn forbidden_changes_and_wrong_commit_guard_refuse_before_output_and_poison_the_recorder()
    -> io::Result<()> {
        let f = Fixture::new()?;
        let connection = f.connection()?;
        let veto = Veto::new(&connection)?;
        let other = f.connection()?;
        let wrong = Veto::new(&other)?;
        let tx = begin(&connection)?;
        let output = f.directory.join("forbidden");
        assert!(Recorder::new(&tx, &wrong, &output).is_err());
        let mut recorder = Recorder::new(&tx, &veto, &output)?;
        tx.execute("UPDATE administrators SET password_hash='forbidden'", [])
            .map_err(io::Error::other)?;
        assert_eq!(
            recorder.checkpoint().err().map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        assert!(recorder.finish().is_err());
        assert!(!output.try_exists()?);
        tx.rollback().map_err(io::Error::other)?;
        Ok(())
    }

    #[test]
    fn framing_checksum_schema_count_and_preimage_fail_closed_without_partial_sql() -> io::Result<()>
    {
        for mode in 0..6 {
            let f = Fixture::new()?;
            let (output, mut seal) = f.small()?;
            let connection = f.connection()?;
            let veto = Veto::new(&connection)?;
            let mut bytes = fs::read(output.join(PAYLOAD))?;
            match mode {
                0 => {
                    bytes.pop();
                    fs::write(output.join(PAYLOAD), &bytes)?;
                }
                1 => {
                    bytes.push(1);
                    replace(&output, &mut seal, &bytes)?;
                }
                2 => {
                    bytes[8..12].copy_from_slice(&(MAX_PAYLOAD as u32 + 1).to_be_bytes());
                    replace(&output, &mut seal, &bytes)?;
                }
                3 => {
                    seal.segments += 1;
                    seal.rows += 1;
                }
                4 => {
                    seal.schema = "f".repeat(64);
                }
                _ => {
                    seal.before[0] ^= 1;
                }
            }
            match Input::open(&output, &seal) {
                Err(_) => assert_eq!(mode, 0),
                Ok(mut input) => assert!(replay(begin(&connection)?, &veto, &mut input).is_err()),
            }
            assert_eq!(count(&connection)?, 0);
            assert!(connection.is_autocommit());
        }
        Ok(())
    }

    #[test]
    fn final_read_checksum_and_row_count_are_required_even_after_a_verified_open() -> io::Result<()>
    {
        let f = Fixture::new()?;
        let (output, seal) = f.small()?;
        let connection = f.connection()?;
        let veto = Veto::new(&connection)?;
        for checksum in [true, false] {
            let mut input = Input::open(&output, &seal)?;
            // Inject a post-open expectation mismatch; this is not a claim of a
            // hostile filesystem race against the existing private-file helpers.
            if checksum {
                input.seal.sha256[0] ^= 1;
            } else {
                input.seal.rows += 1;
            }
            assert!(replay(begin(&connection)?, &veto, &mut input).is_err());
            assert!(connection.is_autocommit());
            assert_eq!(count(&connection)?, 0);
            assert!(replay(begin(&connection)?, &veto, &mut input).is_err());
        }
        Ok(())
    }

    #[test]
    fn replay_independently_rejects_a_resealed_non_history_changeset() -> io::Result<()> {
        let f = Fixture::new()?;
        let connection = f.connection()?;
        let veto = Veto::new(&connection)?;
        let tx = begin(&connection)?;
        let mut session = Session::new(&connection).map_err(io::Error::other)?;
        session
            .attach(Some("administrators"))
            .map_err(io::Error::other)?;
        tx.execute("UPDATE administrators SET password_hash='not-history'", [])
            .map_err(io::Error::other)?;
        let payload = super::super::replay::session_payload(&mut session)?;
        drop(session);
        tx.rollback().map_err(io::Error::other)?;
        let output = f.directory.join("foreign-payload");
        files::create_directory(&output)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(
            &u32::try_from(payload.len())
                .map_err(|_| invalid())?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        files::write(&output, PAYLOAD, &bytes)?;
        let before = history_content(&connection)?;
        let mut after = before;
        after[0] ^= 1;
        let seal = Seal {
            bytes: bytes.len() as u64,
            sha256: Sha256::digest(&bytes).into(),
            segments: 1,
            rows: 1,
            schema: content::schema(&connection)?,
            before,
            after,
        };
        let mut input = Input::open(&output, &seal)?;
        assert_eq!(
            replay(begin(&connection)?, &veto, &mut input)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        let value: String = connection
            .query_row("SELECT password_hash FROM administrators", [], |r| r.get(0))
            .map_err(io::Error::other)?;
        assert_eq!(value, "fixture-phc");
        assert!(connection.is_autocommit());
        Ok(())
    }
}
