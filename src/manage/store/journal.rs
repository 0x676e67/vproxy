//! Private source transaction intents. This kernel is not enabled on ordinary
//! store writers: guarded runtime, snapshot binding and complete writer coverage
//! are required before exposing a source-protection mode. Bound sources remain fenced.
//!
//! A prepared transaction cannot commit before an exact Pending witness reply.
//! Its SQLite changeset is flushed privately first; only its digest goes to the
//! witness. Neither an intent file nor Confirmed JSON proves a local commit.

use super::{
    DATABASE_NAME, Guard, SCHEMA_VERSION, UpdateGuard, content, peers, read_overview, recovery,
    source, sqlite_error,
};
use crate::manage::{
    files,
    node::control::Fetched,
    tls,
    witness::{Enrollment, Phase, Record, Transition, digest, sequence},
};
use rusqlite::{Connection, Transaction, TransactionBehavior, session::Session};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;

const META: &str = "intent.json";
const PAYLOAD: &str = "changeset.bin";
const MAX_META: usize = 4096;
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

pub(in crate::manage) mod configuration;
mod driver;
pub(in crate::manage) use driver::is_uncertain;
mod execution;
mod impact;
pub(super) mod owner;
mod replay;
mod segments;
pub(in crate::manage) mod snapshot;
pub(in crate::manage) use crate::manage::store::alerts::history::Checkpoints;
pub(super) mod tracked;
pub(in crate::manage) mod worker;
pub(super) use impact::Effect;

/// The original source's two existing cooperative locks. This is not a lease,
/// proxy-owner grant or infrastructure-fencing proof. Both remain borrowed
/// through preparation, commit and explicit confirmation.
pub(super) struct Scope<'a> {
    pub(super) directory: &'a Path,
    pub(super) author: &'a Guard,
    pub(super) gate: &'a UpdateGuard,
    pub(super) enrollment: &'a Enrollment,
}

impl Scope<'_> {
    fn validate(&self, connection: &Connection) -> io::Result<()> {
        self.author.ensure(self.directory)?;
        self.gate.ensure(self.directory)?;
        self.enrollment.validate()?;
        let actual = connection.path().ok_or_else(invalid)?;
        if fs::canonicalize(actual)? != fs::canonicalize(self.directory.join(DATABASE_NAME))? {
            return Err(denied());
        }
        let mode: String = connection
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .map_err(|e| sqlite_error("cannot inspect source journal mode", e))?;
        for (name, expected) in [
            ("synchronous", 2_i64),
            ("foreign_keys", 1),
            ("trusted_schema", 0),
            ("ignore_check_constraints", 0),
        ] {
            let value: i64 = connection
                .pragma_query_value(None, name, |r| r.get(0))
                .map_err(|e| sqlite_error("cannot inspect source connection safety", e))?;
            if value != expected {
                return Err(invalid());
            }
        }
        let attached: i64 = connection
            .query_row(
                "SELECT count(*) FROM pragma_database_list WHERE name NOT IN('main','temp')",
                [],
                |r| r.get(0),
            )
            .map_err(|e| sqlite_error("cannot inspect source database attachments", e))?;
        if mode != "wal" || attached != 0 {
            return Err(invalid());
        }
        recovery::require_writable(connection)?;
        let overview = read_overview(connection)?;
        if overview.node_id != self.enrollment.peer_node_id
            || overview.schema_version != SCHEMA_VERSION
        {
            return Err(denied());
        }
        Ok(())
    }

    /// Repeat actual leaf/SAN/revision authorization in the caller's SQL view,
    /// without proxy ownership. Candidate writes may not remove or revise the
    /// witness channel needed to complete this exact source operation.
    fn authorize(&self, connection: &Connection, reply: &Fetched<Record>) -> io::Result<()> {
        self.validate(connection)?;
        reply.value.validate()?;
        let proof = &reply.authorization;
        let peer = peers::authorize_in(connection, &proof.leaf)?.ok_or_else(denied)?;
        if reply.value.retired
            || reply.value.enrollment != *self.enrollment
            || proof.node_id != self.enrollment.witness_node_id
            || peer.node_id != proof.node_id
            || peer.authorization_revision != proof.authorization_revision
            || tls::verify_peer_name(&proof.leaf, &peer.expected_san).is_err()
        {
            return Err(denied());
        }
        Ok(())
    }
}

/// Non-secret binding of the exact private payload. A hash proves neither
/// provenance nor freshness; callers still need current mTLS and source floors.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    format: u8,
    schema_version: u32,
    enrollment: Enrollment,
    transition: Transition,
    schema_sha256: String,
    payload_sha256: String,
    payload_bytes: u64,
    /// Random operation identity also written inside the captured SQL changes.
    intent_id: String,
    /// Exact committed preimage, for restart classification without guessing
    /// from file existence or trusting a witness confirmation alone.
    before: source::Floor,
    /// Native has no recovery pin; recovered Ready retains its permanent pin.
    /// Neither source state may be changed inside an ordinary witnessed write.
    recovery_key_sha256: Option<[u8; 32]>,
    /// Format 3 binds the complete ordered container descriptor. Omission is
    /// canonical for format 2, preserving existing private bytes/commitments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    segmented: Option<segments::Seal>,
    /// Format 4 seals a complete inert package, not a business mutation. Its
    /// only captured SQL change is the next original source-floor singleton.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot: Option<snapshot::Descriptor>,
    /// Exact accepted preimage, including for ordinary business/history/seal
    /// operations. Omission preserves all legacy metadata bytes/commitments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<source::Configuration>,
    /// Format 5 alone advances the accepted configuration. The kernel, never
    /// its business callback, appends this source-only CAS transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    configuration: Option<source::Configuration>,
}

impl Metadata {
    fn commitment(&self) -> io::Result<String> {
        let mut hash = Sha256::new();
        hash.update(match self.format {
            2 => b"vproxy.source.intent.v2\0",
            3 => b"vproxy.source.intent.v3\0",
            4 => b"vproxy.source.intent.v4\0",
            5 => b"vproxy.source.intent.v5\0",
            _ => return Err(invalid()),
        });
        hash.update([self.format]);
        hash.update(self.schema_version.to_be_bytes());
        match self.recovery_key_sha256 {
            None => hash.update([0]),
            Some(key) => {
                hash.update([1]);
                hash.update(key);
            }
        }
        let enrollment = serde_json::to_vec(&self.enrollment).map_err(|_| invalid())?;
        let before = serde_json::to_vec(&self.before).map_err(|_| invalid())?;
        for bytes in [
            enrollment.as_slice(),
            before.as_slice(),
            self.intent_id.as_bytes(),
            self.transition.sequence.as_bytes(),
            self.transition.previous.as_bytes(),
            self.schema_sha256.as_bytes(),
            self.payload_sha256.as_bytes(),
        ] {
            let length = u64::try_from(bytes.len()).map_err(|_| invalid())?;
            hash.update(length.to_be_bytes());
            hash.update(bytes);
        }
        hash.update(self.payload_bytes.to_be_bytes());
        if let Some(seal) = &self.segmented {
            let bytes = serde_json::to_vec(seal).map_err(|_| invalid())?;
            hash.update(
                u64::try_from(bytes.len())
                    .map_err(|_| invalid())?
                    .to_be_bytes(),
            );
            hash.update(bytes);
        }
        if let Some(snapshot) = &self.snapshot {
            let bytes = serde_json::to_vec(snapshot).map_err(|_| invalid())?;
            hash.update(
                u64::try_from(bytes.len())
                    .map_err(|_| invalid())?
                    .to_be_bytes(),
            );
            hash.update(bytes);
        }
        if self.binding.is_some() || self.configuration.is_some() {
            hash.update(b"vproxy.source.configuration.v1\0");
            let bytes =
                serde_json::to_vec(&(self.binding, self.configuration)).map_err(|_| invalid())?;
            hash.update(
                u64::try_from(bytes.len())
                    .map_err(|_| invalid())?
                    .to_be_bytes(),
            );
            hash.update(bytes);
        }
        Ok(hex(&hash.finalize()))
    }
    fn validate(&self, expected: &Enrollment) -> io::Result<()> {
        self.enrollment.validate()?;
        self.transition.validate()?;
        self.before.validate()?;
        if let Some(binding) = self.binding {
            binding.validate()?;
            if binding.revision > self.before.sequence {
                return Err(invalid());
            }
        }
        if self.format == 5 {
            let after = self.configuration.ok_or_else(invalid)?;
            after.validate()?;
            if self.binding.map_or(0, |c| c.revision).checked_add(1) != Some(after.revision)
                || self.binding.is_some_and(|c| c.sha256 == after.sha256)
            {
                return Err(invalid());
            }
        } else if self.configuration.is_some() {
            return Err(invalid());
        }
        let maximum = match (self.format, &self.segmented, &self.snapshot) {
            (2, None, None) => MAX_PAYLOAD as u64,
            (3, Some(seal), None) => {
                seal.validate()?;
                if seal.bytes != self.payload_bytes
                    || hex(&seal.sha256) != self.payload_sha256
                    || seal.schema != self.schema_sha256
                {
                    return Err(invalid());
                }
                segments::MAX_BYTES
            }
            (4, None, Some(snapshot)) => {
                snapshot.validate()?;
                snapshot::MAX_FLOOR_PAYLOAD as u64
            }
            (5, None, None) => snapshot::MAX_FLOOR_PAYLOAD as u64,
            _ => return Err(invalid()),
        };
        if self.schema_version != SCHEMA_VERSION
            || self.schema_version < 26
            || !super::valid_id(&self.intent_id)
            || self.before.sequence.checked_add(1) != Some(sequence(&self.transition.sequence)?)
            || (self.before.sequence == 0 && self.transition.previous != expected.baseline)
            || self.enrollment != *expected
            || self.transition.witness_node_id != expected.witness_node_id
            || self.transition.binding_id != expected.binding_id
            || self.transition.writer_id != expected.writer_id
            || !digest(&self.schema_sha256)
            || !digest(&self.payload_sha256)
            || self.payload_bytes == 0
            || self.payload_bytes > maximum
            || self.transition.commitment != self.commitment()?
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn matches(&self, record: &Record, phase: Phase) -> bool {
        record.phase == phase
            && !record.retired
            && record.enrollment == self.enrollment
            && record.sequence == self.transition.sequence
            && record.previous.as_ref() == Some(&self.transition.previous)
            && record.commitment == self.transition.commitment
    }
    fn after(&self) -> io::Result<source::Floor> {
        Ok(source::Floor {
            sequence: sequence(&self.transition.sequence)?,
            intent_id: Some(self.intent_id.clone()),
            previous: Some(self.transition.previous.clone()),
        })
    }
    fn before_state(&self) -> source::State {
        source::State {
            enrollment: self.enrollment.clone(),
            floor: self.before.clone(),
            configuration: self.binding,
        }
    }
    fn after_state(&self) -> io::Result<source::State> {
        Ok(source::State {
            enrollment: self.enrollment.clone(),
            floor: self.after()?,
            configuration: self.configuration.or(self.binding),
        })
    }
}

/// Open the retained source only under its existing cooperative locks. This
/// bypasses ordinary source refusal, not snapshot, identity or SQL validation.
pub(super) fn open(scope: &Scope<'_>) -> io::Result<Connection> {
    scope.author.ensure(scope.directory)?;
    scope.gate.ensure(scope.directory)?;
    super::reject_snapshot_directory(scope.directory)?;
    super::validate_directory(scope.directory)?;
    let path = scope.directory.join(DATABASE_NAME);
    super::validate_database(&path)?;
    let connection = super::connect(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    super::configure(&connection)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|e| sqlite_error("cannot configure source durability", e))?;
    scope.validate(&connection)?;
    Ok(connection)
}

impl Scope<'_> {
    fn state(&self, connection: &Connection) -> io::Result<source::State> {
        let state = source::load(connection, SCHEMA_VERSION)?.ok_or_else(denied)?;
        if state.enrollment != *self.enrollment {
            return Err(denied());
        }
        let marker = files::read(&self.directory.join(source::REQUIRED), MAX_META, true)?;
        if *marker != serde_json::to_vec(self.enrollment).map_err(|_| invalid())? {
            return Err(denied());
        }
        Ok(state)
    }
}

/// Stage a baseline under the offline author. The required-mode marker is
/// flushed first, so interruption before the SQL row cannot fall back to normal
/// startup, including in feature-off builds. This internal kernel has no CLI
/// activation; caller-supplied baseline is not snapshot/fencing approval.
/// A repeated call may only complete that exact still-unadvanced baseline.
pub(super) fn initialize(
    scope: &Scope<'_>,
    connection: &mut Connection,
    baseline: &Fetched<Record>,
) -> io::Result<()> {
    if !connection.is_autocommit() {
        return Err(invalid());
    }
    scope.authorize(connection, baseline)?;
    if baseline.value.phase != Phase::Confirmed || baseline.value.sequence != "0" {
        return Err(denied());
    }
    let expected = source::State {
        enrollment: scope.enrollment.clone(),
        floor: source::Floor {
            sequence: 0,
            intent_id: None,
            previous: None,
        },
        configuration: None,
    };
    let existing = source::load(connection, SCHEMA_VERSION)?;
    if existing.as_ref().is_some_and(|s| s != &expected) {
        return Err(denied());
    }
    let bytes = serde_json::to_vec(scope.enrollment).map_err(|_| invalid())?;
    match fs::symlink_metadata(scope.directory.join(source::REQUIRED)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            files::write(scope.directory, source::REQUIRED, &bytes)?
        }
        Err(e) => return Err(e),
        Ok(_) => {
            if *files::read(&scope.directory.join(source::REQUIRED), MAX_META, true)? != bytes {
                return Err(denied());
            }
        }
    }
    tracked::initialize_root(scope, existing.is_none())?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin source baseline", e))?;
    scope.authorize(&tx, baseline)?;
    if source::load(&tx, SCHEMA_VERSION)?.is_some_and(|s| s != expected) {
        return Err(denied());
    }
    source::save(&tx, &expected)?;
    tx.commit().map_err(|_| {
        io::Error::other("source baseline result is unknown; retain its required marker")
    })
}

/// Verified metadata and a private payload location, without Debug/Serialize.
/// The readback allocation is not retained across network waits. Neither load
/// nor a later payload read executes SQL or approves replay.
pub(super) struct Intent {
    directory: PathBuf,
    metadata: Metadata,
}

impl Intent {
    /// Read only the exact two private regular files, with bounded metadata and
    /// payload. Missing/partial/extra/corrupt files fail and remain untouched.
    /// Metadata must use the canonical encoding written by this kernel.
    pub(super) fn load(directory: &Path, enrollment: &Enrollment) -> io::Result<Self> {
        files::check_directory(directory, true)?;
        let mut count = 0_usize;
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            count += 1;
            if count > 2 || (entry.file_name() != META && entry.file_name() != PAYLOAD) {
                return Err(invalid());
            }
        }
        if count != 2 {
            return Err(invalid());
        }
        let bytes = files::read(&directory.join(META), MAX_META, true)?;
        let metadata: Metadata = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        metadata.validate(enrollment)?;
        if serde_json::to_vec(&metadata)
            .map_err(|_| invalid())?
            .as_slice()
            != bytes.as_slice()
        {
            return Err(invalid());
        }
        let intent = Self {
            directory: fs::canonicalize(directory)?,
            metadata,
        };
        intent.verify_payload()?;
        Ok(intent)
    }
    /// Obtain fresh bounded private bytes, repeating checksum and leaf/ACL
    /// checks on this actual read. A prior successful load is not authority to
    /// execute a subsequently replaced/corrupted file. No replay is performed.
    pub(super) fn payload(&self) -> io::Result<Zeroizing<Vec<u8>>> {
        if self.metadata.segmented.is_some() {
            return Err(invalid());
        }
        // The canonical, commitment-bound expected size is also the allocation
        // bound. A small intent need not reserve the global 16 MiB ceiling.
        let size = usize::try_from(self.metadata.payload_bytes)
            .ok()
            .filter(|n| *n > 0 && *n <= MAX_PAYLOAD)
            .ok_or_else(invalid)?;
        let payload = files::read(&self.directory.join(PAYLOAD), size, true)?;
        if u64::try_from(payload.len()).map_err(|_| invalid())? != self.metadata.payload_bytes
            || hex(&Sha256::digest(&*payload)) != self.metadata.payload_sha256
        {
            return Err(invalid());
        }
        Ok(payload)
    }
    pub(super) fn verify_payload(&self) -> io::Result<()> {
        if let Some(seal) = &self.metadata.segmented {
            drop(segments::Input::open(&self.directory, seal)?);
        } else {
            drop(self.payload()?);
        }
        Ok(())
    }
    pub(super) fn effect(&self, connection: &Connection) -> io::Result<Effect> {
        if self.metadata.snapshot.is_some() || self.metadata.format == 5 {
            snapshot::check_payload(connection, self)?;
            return Ok(Effect::Unchanged);
        }
        match &self.metadata.segmented {
            Some(seal) => segments::Input::open(&self.directory, seal)?.effect(connection),
            None => replay::delta(connection, &self.payload()?)?.effect(),
        }
    }
    /// Original operation only; no new sequence/payload is synthesized on load.
    pub(super) fn transition(&self) -> &Transition {
        &self.metadata.transition
    }
}

/// A one-use COMMIT permit. The safe SQLite hook does no SQL, I/O or async work.
/// This requires a dedicated connection without another commit/preupdate hook;
/// it is not installed on ordinary live store connections by this kernel.
struct Veto<'a> {
    connection: &'a Connection,
    permit: Arc<AtomicBool>,
}
impl<'a> Veto<'a> {
    fn new(connection: &'a Connection) -> io::Result<Self> {
        let permit = Arc::new(AtomicBool::new(false));
        let grant = permit.clone();
        connection
            .commit_hook(Some(move || !grant.swap(false, Ordering::AcqRel)))
            .map_err(|e| sqlite_error("cannot install source commit guard", e))?;
        Ok(Self { connection, permit })
    }
}
impl Drop for Veto<'_> {
    fn drop(&mut self) {
        self.permit.store(false, Ordering::Release);
        // A refused removal leaves the reset permit's veto installed. Drop
        // cannot report an error or turn cleanup into permission to commit.
        let _ = self.connection.commit_hook(None::<fn() -> bool>);
    }
}

/// Owns the uncommitted transaction and private intent. Declaration order drops
/// the transaction (ROLLBACK) before removing its commit veto. Exclusive borrow
/// prevents callers from changing the original connection after prepare returns.
pub(super) struct Prepared<'a, T> {
    transaction: Transaction<'a>,
    veto: Veto<'a>,
    scope: Scope<'a>,
    intent: Intent,
    value: T,
    /// New preparations always classify the original changeset. Legacy offline
    /// replay may have no policy-version contract and grants no live restore.
    effect: Option<Effect>,
}

/// A no-write observation has explicitly rolled back under the original fresh
/// confirmation. It owns no intent or sequence. Strict prepare never returns it.
#[allow(
    clippy::large_enum_variant,
    reason = "Short-lived source transactions stay inline instead of allocating once per write"
)]
pub(super) enum Captured<'a, T> {
    Read(T),
    Write(Prepared<'a, T>),
}

enum Mode<'a> {
    Write(Option<&'a str>),
    ReadOrWrite(&'a str),
    History(&'a str),
    Snapshot(&'a str, &'a snapshot::Descriptor),
    Configuration(&'a str, u64, [u8; 32]),
}

/// Capture strategy, before a fixed operation identity is allocated. Snapshot
/// is deliberately separate: ordinary writers cannot create floor-only intents.
pub(super) enum CaptureMode<'a> {
    Write,
    ReadOrWrite,
    History,
    Snapshot(&'a snapshot::Descriptor),
    Configuration {
        expected_revision: u64,
        sha256: [u8; 32],
    },
}

/// Local COMMIT succeeded, but the one-time result is withheld until an exact
/// Confirmed reply is checked. Dropping this owner cannot undo the local commit;
/// its intent remains for result-unknown reconciliation, never automatic replay.
pub(super) struct Committed<'a, T> {
    connection: &'a Connection,
    scope: Scope<'a>,
    intent: Intent,
    value: T,
}

/// Run trusted, bounded DML in a dedicated existing-store connection, using WAL,
/// FULL sync, FK checks and untrusted schema. Do not reuse a failed connection
/// after unknown callback side effects. The callback must not change connection
/// hooks/settings or execute transaction-control SQL. The commit
/// veto additionally refuses accidental early COMMIT; DDL or an empty net
/// changeset cannot become an intent. No request is sent by this function.
/// The callback remains responsible for actor/CAS and business-result checks;
/// this kernel captures actual SQL changes, not the meaning of its return value.
///
/// Session captures rows before rollback/commit; payload and metadata are
/// CreateNew, flushed, then read back. Any failure rolls back and preserves new
/// private output for inspection. Windows flush does not promise extra directory
/// entry durability. The payload cap bounds output, not Session/C heap or time.
#[cfg(test)]
fn prepare<'a, T>(
    scope: Scope<'a>,
    connection: &'a mut Connection,
    previous: &Fetched<Record>,
    previous_intent: Option<&Intent>,
    output: &Path,
    change: impl FnOnce(&Transaction<'_>) -> io::Result<T>,
) -> io::Result<Prepared<'a, T>> {
    prepare_inner(
        scope,
        connection,
        previous,
        previous_intent,
        output,
        None,
        change,
    )
}

fn prepare_inner<'a, T>(
    scope: Scope<'a>,
    connection: &'a mut Connection,
    previous: &Fetched<Record>,
    previous_intent: Option<&Intent>,
    output: &Path,
    identity: Option<&str>,
    change: impl FnOnce(&Transaction<'_>) -> io::Result<T>,
) -> io::Result<Prepared<'a, T>> {
    match capture(
        scope,
        connection,
        previous,
        previous_intent,
        output,
        Mode::Write(identity),
        |tx, _| change(tx),
    )? {
        Captured::Write(prepared) => Ok(prepared),
        Captured::Read(_) => Err(invalid()),
    }
}

fn capture<'a, T>(
    scope: Scope<'a>,
    connection: &'a mut Connection,
    previous: &Fetched<Record>,
    previous_intent: Option<&Intent>,
    output: &Path,
    mode: Mode<'_>,
    change: impl FnOnce(&mut Transaction<'_>, Option<&mut dyn Checkpoints>) -> io::Result<T>,
) -> io::Result<Captured<'a, T>> {
    if !connection.is_autocommit() {
        return Err(invalid());
    }
    scope.validate(connection)?;
    let veto = Veto::new(connection)?;
    let mut transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin source intent", e))?;
    let execution = execution::Execution::new(
        connection,
        match mode {
            Mode::History(_) => execution::Limits::HISTORY,
            Mode::Snapshot(_, _) => execution::Limits::SNAPSHOT,
            _ => execution::Limits::MUTATION,
        },
    )?;
    scope.authorize(&transaction, previous)?;
    if previous.value.phase != Phase::Confirmed || previous.value.retired {
        return Err(denied());
    }
    let before = scope.state(&transaction)?;
    if before.floor.sequence.to_string() != previous.value.sequence {
        return Err(denied());
    }
    if before.floor.sequence == 0 {
        if previous_intent.is_some() || previous.value.commitment != scope.enrollment.baseline {
            return Err(denied());
        }
    } else {
        let ancestor = previous_intent.ok_or_else(denied)?;
        ancestor.metadata.validate(scope.enrollment)?;
        if ancestor.metadata.after_state()? != before
            || !ancestor.metadata.matches(&previous.value, Phase::Confirmed)
        {
            return Err(denied());
        }
        ancestor.verify_payload()?;
    }
    let schema = content::schema(&transaction)?;
    let recovery_key = recovery::startup_in(&transaction)?;
    let output = files::output_path(output)?;
    let history = matches!(mode, Mode::History(_));
    let mut session = if history {
        None
    } else {
        let mut session = Session::new(connection)
            .map_err(|e| sqlite_error("cannot capture source intent", e))?;
        for table in super::backup::tables(SCHEMA_VERSION) {
            session
                .attach(Some(table))
                .map_err(|e| sqlite_error("cannot attach source intent table", e))?;
        }
        Some(session)
    };
    let mut recorder = if history {
        Some(segments::Admitted::new(
            connection, &veto, &output, &scope, &execution,
        )?)
    } else {
        None
    };
    let value = match recorder.as_mut() {
        Some(recorder) => change(&mut transaction, Some(recorder)),
        None => change(&mut transaction, None),
    };
    execution.check()?;
    let value = value?;
    let snapshot = match mode {
        Mode::Snapshot(_, descriptor) => {
            descriptor.validate()?;
            if !session.as_ref().ok_or_else(invalid)?.is_empty()
                || content::calculate(&transaction, None)? != descriptor.database_content_sha256
            {
                return Err(denied());
            }
            Some(descriptor.clone())
        }
        _ => None,
    };
    if scope.state(&transaction)? != before {
        return Err(denied());
    }
    let configuration = match mode {
        Mode::Configuration(_, expected, sha256) => {
            if !session.as_ref().ok_or_else(invalid)?.is_empty()
                || before.configuration.map_or(0, |c| c.revision) != expected
            {
                return Err(denied());
            }
            if before.configuration.is_some_and(|c| c.sha256 == sha256) {
                None
            } else {
                Some(source::Configuration {
                    revision: expected
                        .checked_add(1)
                        .filter(|r| *r <= i64::MAX as u64)
                        .ok_or_else(invalid)?,
                    sha256,
                })
            }
        }
        _ => None,
    };
    let observed = match &recorder {
        Some(recorder) => recorder.observed()?,
        None => !session.as_ref().ok_or_else(invalid)?.is_empty(),
    };
    if !observed && snapshot.is_none() && configuration.is_none() {
        if !matches!(
            mode,
            Mode::ReadOrWrite(_) | Mode::History(_) | Mode::Configuration(..)
        ) {
            return Err(invalid());
        }
        if connection.is_autocommit() || content::schema(&transaction)? != schema {
            return Err(invalid());
        }
        scope.authorize(&transaction, previous)?;
        if recovery::startup_in(&transaction)? != recovery_key {
            return Err(denied());
        }
        drop(session);
        drop(recorder);
        execution.finish()?;
        transaction
            .rollback()
            .map_err(|e| sqlite_error("cannot end source observation", e))?;
        return Ok(Captured::Read(value));
    }
    let next = sequence(&previous.value.sequence)?
        .checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or_else(invalid)?;
    let identity = match mode {
        Mode::Write(id) => id,
        Mode::ReadOrWrite(id) | Mode::History(id) => Some(id),
        Mode::Snapshot(id, _) => Some(id),
        Mode::Configuration(id, _, _) => Some(id),
    };
    let intent_id = if let Some(id) = identity {
        if !super::valid_id(id) {
            return Err(invalid());
        }
        id.to_owned()
    } else {
        super::random_id()?
    };
    let after = source::State {
        enrollment: scope.enrollment.clone(),
        floor: source::Floor {
            sequence: next,
            intent_id: Some(intent_id.clone()),
            previous: Some(previous.value.commitment.clone()),
        },
        configuration: configuration.or(before.configuration),
    };
    source::save(&transaction, &after)?;
    if connection.is_autocommit() || content::schema(&transaction)? != schema {
        return Err(invalid());
    }
    scope.authorize(&transaction, previous)?;
    if recovery::startup_in(&transaction)? != recovery_key {
        return Err(denied());
    }
    // Read-only observations above need no reservation. A changed candidate
    // may have staged SQL, but cannot claim intent files or Reserve without
    // space for the maximum bounded payload and its fixed protocol records.
    let (segmented, payload_sha256, payload_bytes) = if let Some(recorder) = recorder.take() {
        let seal = recorder.finish()?.ok_or_else(invalid)?;
        let hash = hex(&seal.sha256);
        let bytes = seal.bytes;
        (Some(seal), hash, bytes)
    } else {
        tracked::check_capacity(&scope)?;
        // Raw candidates still claim files only after callback validation.
        files::create_directory(&output)?;
        let mut writer = PayloadWriter {
            file: super::backup::new_file(&output.join(PAYLOAD))?,
            hash: Sha256::new(),
            bytes: 0,
        };
        session
            .as_mut()
            .ok_or_else(invalid)?
            .changeset_strm(&mut writer)
            .map_err(|e| sqlite_error("cannot write source intent payload", e))?;
        writer.file.sync_all()?;
        if writer.bytes == 0 {
            return Err(invalid());
        }
        let hash = hex(&writer.hash.finalize());
        let bytes = writer.bytes;
        drop(writer.file);
        (None, hash, bytes)
    };
    drop(session);
    drop(recorder);
    let mut metadata = Metadata {
        format: if configuration.is_some() {
            5
        } else if snapshot.is_some() {
            4
        } else if segmented.is_some() {
            3
        } else {
            2
        },
        schema_version: SCHEMA_VERSION,
        enrollment: scope.enrollment.clone(),
        transition: Transition {
            witness_node_id: scope.enrollment.witness_node_id.clone(),
            binding_id: scope.enrollment.binding_id.clone(),
            writer_id: scope.enrollment.writer_id.clone(),
            sequence: next.to_string(),
            previous: previous.value.commitment.clone(),
            commitment: String::new(),
        },
        schema_sha256: schema,
        payload_sha256,
        payload_bytes,
        intent_id,
        before: before.floor,
        recovery_key_sha256: recovery_key,
        segmented,
        snapshot,
        binding: before.configuration,
        configuration,
    };
    metadata.transition.commitment = metadata.commitment()?;
    metadata.validate(scope.enrollment)?;
    let bytes = serde_json::to_vec(&metadata).map_err(|_| invalid())?;
    if bytes.len() > MAX_META {
        return Err(invalid());
    }
    files::write(&output, META, &bytes)?;
    let intent = Intent::load(&output, scope.enrollment)?;
    let effect = if intent.metadata.segmented.is_some()
        || intent.metadata.snapshot.is_some()
        || intent.metadata.format == 5
    {
        intent.effect(&transaction)?
    } else {
        let delta = replay::delta(&transaction, &intent.payload()?)?;
        if !delta.has_business_change() {
            return Err(invalid());
        }
        delta.effect()?
    };
    execution.finish()?;
    Ok(Captured::Write(Prepared {
        transaction,
        veto,
        scope,
        intent,
        value,
        effect: Some(effect),
    }))
}

impl<'a, T> Prepared<'a, T> {
    pub(super) fn intent(&self) -> &Intent {
        &self.intent
    }

    /// Validate the original Pending reservation and the current source SQL
    /// authority before granting exactly one COMMIT. Every SQLite commit error
    /// is result-unknown, even if a later rollback is attempted by SQLite/Drop.
    // Raw completion belongs only to this kernel's offline/replay paths. Store
    // callers use the ordered driver and supply its explicit admission barrier.
    fn commit(self, pending: &Fetched<Record>) -> io::Result<Committed<'a, T>> {
        self.commit_after(pending, || Ok(()))
    }

    /// Invoke the source owner's admission barrier only after exact Pending,
    /// candidate authority/floor/pin checks, and before granting COMMIT. A failed
    /// barrier rolls back SQL but cannot cancel the durable witness reservation.
    fn commit_after(
        self,
        pending: &Fetched<Record>,
        before_commit: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<Committed<'a, T>> {
        self.scope.authorize(&self.transaction, pending)?;
        if self.scope.state(&self.transaction)? != self.intent.metadata.after_state()? {
            return Err(denied());
        }
        if recovery::startup_in(&self.transaction)? != self.intent.metadata.recovery_key_sha256 {
            return Err(denied());
        }
        if !self.intent.metadata.matches(&pending.value, Phase::Pending) {
            return Err(denied());
        }
        before_commit()?;
        let Self {
            transaction,
            veto,
            scope,
            intent,
            value,
            effect: _,
        } = self;
        veto.permit.store(true, Ordering::Release);
        let result = transaction.commit();
        if result.is_err() {
            return Err(io::Error::other(
                "source commit result is unknown; retain the original intent",
            ));
        }
        let connection = veto.connection;
        drop(veto);
        Ok(Committed {
            connection,
            scope,
            intent,
            value,
        })
    }
}

impl<T> Committed<'_, T> {
    pub(super) fn intent(&self) -> &Intent {
        &self.intent
    }

    /// Release the original in-memory result only after exact confirmation.
    /// Error or lost reply cannot roll back committed rows and must be reported
    /// as unknown; neither this method nor Drop retries or removes the intent.
    pub(super) fn confirm(self, confirmed: &Fetched<Record>) -> io::Result<T> {
        let check = || -> io::Result<()> {
            self.scope.authorize(self.connection, confirmed)?;
            if self.scope.state(self.connection)? != self.intent.metadata.after_state()? {
                return Err(denied());
            }
            if recovery::startup_in(self.connection)? != self.intent.metadata.recovery_key_sha256 {
                return Err(denied());
            }
            if !self
                .intent
                .metadata
                .matches(&confirmed.value, Phase::Confirmed)
            {
                return Err(denied());
            }
            Ok(())
        };
        check().map_err(|_| {
            io::Error::other("source confirmation is unknown; retain the original intent")
        })?;
        Ok(self.value)
    }
}

/// A read-only restart observation, never a permission to run a business
/// request or serve traffic. Reserved requires exact-byte replay admission;
/// Committed requires confirmation only. Confirmed cannot recreate secrets.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Restart {
    Unreserved,
    Reserved,
    Committed,
    Confirmed,
}

/// Resume only the confirmation of an already committed exact local intent.
/// No changeset is applied, callback run or one-time result reconstructed. The
/// returned owner retains both guards and requires an exact Confirmed proof;
/// SQL-old, already-confirmed or mismatched observations refuse this path.
pub(super) fn resume_committed<'a>(
    scope: Scope<'a>,
    connection: &'a mut Connection,
    intent: Intent,
    pending: &Fetched<Record>,
) -> io::Result<Committed<'a, ()>> {
    if inspect_restart(&scope, connection, &intent, pending)? != Restart::Committed {
        return Err(denied());
    }
    Ok(Committed {
        connection,
        scope,
        intent,
        value: (),
    })
}

/// Compare one retained intent, current SQL floor and actual fresh witness
/// proof in an IMMEDIATE snapshot under the original locks. Every mismatch,
/// missing/corrupt file, stale/future floor or retired/revised identity refuses
/// without writing SQL or changing the witness. A Confirmed record with the
/// old local floor is inconsistent and cannot authorize replay.
pub(super) fn inspect_restart(
    scope: &Scope<'_>,
    connection: &mut Connection,
    intent: &Intent,
    reply: &Fetched<Record>,
) -> io::Result<Restart> {
    intent.metadata.validate(scope.enrollment)?;
    intent.verify_payload()?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot inspect source restart", e))?;
    scope.authorize(&tx, reply)?;
    if content::schema(&tx)? != intent.metadata.schema_sha256
        || recovery::startup_in(&tx)? != intent.metadata.recovery_key_sha256
    {
        return Err(denied());
    }
    let state = scope.state(&tx)?;
    if state == intent.metadata.before_state() {
        if intent.metadata.matches(&reply.value, Phase::Pending) {
            return Ok(Restart::Reserved);
        }
        if reply.value.phase == Phase::Confirmed
            && reply.value.sequence == state.floor.sequence.to_string()
            && reply.value.commitment == intent.metadata.transition.previous
        {
            return Ok(Restart::Unreserved);
        }
    } else if state == intent.metadata.after_state()? {
        if intent.metadata.matches(&reply.value, Phase::Pending) {
            return Ok(Restart::Committed);
        }
        if intent.metadata.matches(&reply.value, Phase::Confirmed) {
            return Ok(Restart::Confirmed);
        }
    }
    Err(denied())
}

/// Streaming private output, with no second growable vector of row payloads.
struct PayloadWriter {
    file: File,
    hash: Sha256,
    bytes: u64,
}
impl Write for PayloadWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = u64::try_from(bytes.len()).map_err(|_| invalid())?;
        let total = self
            .bytes
            .checked_add(length)
            .filter(|n| *n <= MAX_PAYLOAD as u64)
            .ok_or_else(invalid)?;
        self.file.write_all(bytes)?;
        self.hash.update(bytes);
        self.bytes = total;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "source intent is invalid, incomplete or unsupported",
    )
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "source intent authorization or witness record differs",
    )
}
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 15)]));
    }
    out
}

#[cfg(test)]
pub(in crate::manage) use tests::worker::Live as SourceFixture;
#[cfg(test)]
pub(in crate::manage) use tests::worker::snapshots::Export as SourceExportFixture;

#[cfg(test)]
mod tests {
    //! Unit proofs use the fixture's registered DER. A separate test exercises the
    //! complete TLS witness client/server path. All stores/keys here are fresh.
    use super::tracked::Journal;
    use super::*;
    use crate::manage::{node, policy::Coordinator, witness};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    mod configuration {
        //! Exact configuration pre/postimages survive ordinary writes and replay.
        use super::*;

        #[test]
        fn confirmed_configuration_postread_failure_is_unknown_and_exact_resume_does_not_reapply()
        -> io::Result<()> {
            use crate::manage::node::control::witness::Action;
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let mut witness = super::driver::Witness::new(&f, &e)?;
            let a = crate::manage::store::lock(&f.client_state)?;
            let g = crate::manage::store::update_lock(&f.client_state)?;
            drop(source_connection(&f, &a, &g, &e)?);
            let desired = super::super::configuration::Desired {
                expected_revision: 0,
                sha256: [11; 32],
            };
            let mut confirmed = false;
            let error = super::super::configuration::accept(
                &f.client_state,
                &a,
                &g,
                &e,
                &desired,
                &mut |op| {
                    if confirmed && matches!(&op.action, Action::Inspect) {
                        return Err(io::ErrorKind::PermissionDenied.into());
                    }
                    let is_confirmation = matches!(&op.action, Action::Confirm(_));
                    let reply = witness.request(op)?;
                    confirmed |= is_confirmation;
                    Ok(reply)
                },
            )
            .err()
            .ok_or_else(invalid)?;
            assert!(is_uncertain(&error));
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert_eq!((witness.reserves, witness.confirms), (1, 1));
            let saved = super::super::configuration::reconcile(
                &f.client_state,
                &a,
                &g,
                &e,
                &desired,
                &mut |op| witness.request(op),
            )?;
            assert_eq!(saved.revision, 1);
            assert_eq!(saved.sha256, desired.sha256);
            assert_eq!((witness.reserves, witness.confirms), (1, 1));
            let c = open(&scope(&f, &a, &g, &e))?;
            assert_eq!(
                source::load(&c, SCHEMA_VERSION)?
                    .ok_or_else(invalid)?
                    .floor
                    .sequence,
                1
            );
            Ok(())
        }

        #[test]
        fn configuration_cas_is_source_only_and_survives_business_write_and_exact_replay()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = crate::manage::store::lock(&f.client_state)?;
            let g = crate::manage::store::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
            // A configuration transition cannot smuggle business SQL into a floor-only
            // operation, even when the callback's returned value looks successful.
            assert!(
                journal
                    .capture(
                        &mut c,
                        &baseline(&f, &e)?,
                        CaptureMode::Configuration {
                            expected_revision: 0,
                            sha256: [7; 32]
                        },
                        |tx, _| changed(tx)
                    )
                    .is_err()
            );
            assert_eq!(verifier(&c)?, "fixture-phc");
            let prepared = match journal.capture(
                &mut c,
                &baseline(&f, &e)?,
                CaptureMode::Configuration {
                    expected_revision: 0,
                    sha256: [7; 32],
                },
                |_, _| Ok(()),
            )? {
                Captured::Write(prepared) => prepared,
                Captured::Read(_) => return Err(invalid()),
            };
            let path = prepared.intent.directory.clone();
            let transition = prepared.intent.transition().clone();
            assert_eq!(prepared.intent.metadata.format, 5);
            snapshot::check_payload(&prepared.transaction, &prepared.intent)?;
            journal.dispatch(&prepared)?;
            drop(prepared);
            assert!(
                source::load(&c, SCHEMA_VERSION)?
                    .ok_or_else(invalid)?
                    .configuration
                    .is_none()
            );
            let committed =
                journal.replay_pending(&mut c, 1, &reply(&f, &e, &transition, Phase::Pending)?)?;
            committed.confirm(&reply(&f, &e, &transition, Phase::Confirmed)?)?;
            let accepted = source::Configuration {
                revision: 1,
                sha256: [7; 32],
            };
            assert_eq!(
                source::load(&c, SCHEMA_VERSION)?
                    .ok_or_else(invalid)?
                    .configuration,
                Some(accepted)
            );
            let previous = reply(&f, &e, &transition, Phase::Confirmed)?;
            assert!(matches!(
                journal.capture(
                    &mut c,
                    &previous,
                    CaptureMode::Configuration {
                        expected_revision: 1,
                        sha256: [7; 32]
                    },
                    |_, _| Ok(())
                )?,
                Captured::Read(())
            ));
            assert!(
                journal
                    .capture(
                        &mut c,
                        &previous,
                        CaptureMode::Configuration {
                            expected_revision: 0,
                            sha256: [7; 32]
                        },
                        |_, _| Ok(())
                    )
                    .is_err()
            );
            assert_eq!(
                source::load(&c, SCHEMA_VERSION)?
                    .ok_or_else(invalid)?
                    .floor
                    .sequence,
                1
            );
            let prepared = journal.prepare(&mut c, &previous, changed)?;
            assert_eq!(prepared.intent.metadata.binding, Some(accepted));
            let second = prepared.intent.transition().clone();
            journal.dispatch(&prepared)?;
            prepared
                .commit(&reply(&f, &e, &second, Phase::Pending)?)?
                .confirm(&reply(&f, &e, &second, Phase::Confirmed)?)?;
            assert_eq!(
                source::load(&c, SCHEMA_VERSION)?
                    .ok_or_else(invalid)?
                    .configuration,
                Some(accepted)
            );
            assert_eq!(verifier(&c)?, "journal-fixture-phc");
            let previous = reply(&f, &e, &second, Phase::Confirmed)?;
            let history = match journal.capture(
                &mut c,
                &previous,
                CaptureMode::History,
                |tx, checkpoints| {
                    crate::manage::store::alerts::history::Writer::Source {
                        tx,
                        checkpoints: checkpoints.ok_or_else(invalid)?,
                    }
                    .start("AAAAAAAAAAAAAAAAAAAAAA")
                },
            )? {
                Captured::Write(prepared) => prepared,
                Captured::Read(_) => return Err(invalid()),
            };
            assert_eq!(history.intent.metadata.binding, Some(accepted));
            let third = history.intent.transition().clone();
            journal.dispatch(&history)?;
            history
                .commit(&reply(&f, &e, &third, Phase::Pending)?)?
                .confirm(&reply(&f, &e, &third, Phase::Confirmed)?)?;
            let previous = reply(&f, &e, &third, Phase::Confirmed)?;
            let updated = match journal.capture(
                &mut c,
                &previous,
                CaptureMode::Configuration {
                    expected_revision: 1,
                    sha256: [9; 32],
                },
                |_, _| Ok(()),
            )? {
                Captured::Write(prepared) => prepared,
                Captured::Read(_) => return Err(invalid()),
            };
            let fourth = updated.intent.transition().clone();
            journal.dispatch(&updated)?;
            updated
                .commit(&reply(&f, &e, &fourth, Phase::Pending)?)?
                .confirm(&reply(&f, &e, &fourth, Phase::Confirmed)?)?;
            assert_eq!(
                source::load(&c, SCHEMA_VERSION)?
                    .ok_or_else(invalid)?
                    .configuration,
                Some(source::Configuration {
                    revision: 2,
                    sha256: [9; 32]
                })
            );
            // A rehashed local metadata file is not authority to change either image.
            let mut old = Intent::load(&path, &e)?;
            old.metadata
                .configuration
                .as_mut()
                .ok_or_else(invalid)?
                .sha256 = [8; 32];
            old.metadata.transition.commitment = old.metadata.commitment()?;
            old.metadata.validate(&e)?;
            assert!(snapshot::check_payload(&c, &old).is_err());
            Ok(())
        }

        #[test]
        fn configuration_mismatch_refuses_same_floor_restart_and_dispatch() -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = crate::manage::store::lock(&f.client_state)?;
            let g = crate::manage::store::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
            let prepared = match journal.capture(
                &mut c,
                &baseline(&f, &e)?,
                CaptureMode::Configuration {
                    expected_revision: 0,
                    sha256: [1; 32],
                },
                |_, _| Ok(()),
            )? {
                Captured::Write(prepared) => prepared,
                Captured::Read(_) => return Err(invalid()),
            };
            let original = prepared.intent.transition().clone();
            let mut bad =
                source::load(&prepared.transaction, SCHEMA_VERSION)?.ok_or_else(invalid)?;
            bad.configuration.as_mut().ok_or_else(invalid)?.sha256 = [2; 32];
            source::save(&prepared.transaction, &bad)?;
            assert!(journal.dispatch(&prepared).is_err());
            drop(prepared);
            let intent = journal.pending(&c)?.ok_or_else(invalid)?;
            // At the post-floor a wrong configuration must not count as committed.
            source::save(&c, &bad)?;
            assert!(
                inspect_restart(
                    &scope(&f, &a, &g, &e),
                    &mut c,
                    &intent,
                    &reply(&f, &e, &original, Phase::Pending)?
                )
                .is_err()
            );
            assert!(journal.current(&c).is_err());
            assert!(snapshot::check_configuration(&c, &e, [1; 32]).is_err());
            snapshot::check_configuration(&c, &e, [2; 32])?;
            // Ordinary feature-on/off store paths remain fenced after config binding.
            assert!(crate::manage::store::recovery::startup(&f.client_state).is_err());
            Ok(())
        }
    }
    mod delta {
        use super::*;

        fn output(session: &mut Session<'_>) -> io::Result<Vec<u8>> {
            let mut bytes = Vec::new();
            session
                .changeset_strm(&mut bytes)
                .map_err(io::Error::other)?;
            Ok(bytes)
        }

        #[test]
        fn normalization_accepts_table_reordering_but_distinguishes_null_from_undefined()
        -> io::Result<()> {
            let f = node::tests::Fixture::new(true, true)?;
            let target = peers::open_existing(&f.client_state, false)?;
            let mut captures = Vec::new();
            for reversed in [false, true] {
                let c = Connection::open_in_memory().map_err(io::Error::other)?;
                c.execute_batch("CREATE TABLE administrators(id TEXT PRIMARY KEY NOT NULL,username TEXT,password_hash TEXT) STRICT;
          CREATE TABLE peer_audit(sequence INTEGER PRIMARY KEY,entry TEXT,action TEXT,node_id TEXT,authorization_revision INTEGER) STRICT;
          CREATE TABLE routing_pool_members(pool_id TEXT NOT NULL,address_id TEXT NOT NULL,PRIMARY KEY(pool_id,address_id)) STRICT;").map_err(io::Error::other)?;
                let mut session = Session::new(&c).map_err(io::Error::other)?;
                let mut tables = ["administrators", "peer_audit", "routing_pool_members"];
                if reversed {
                    tables.reverse();
                }
                for table in tables {
                    session.attach(Some(table)).map_err(io::Error::other)?;
                }
                c.execute_batch("INSERT INTO administrators VALUES('row-one','name','hash'); INSERT INTO peer_audit VALUES(1,'offline','register','peer',1);
          INSERT INTO routing_pool_members VALUES('shared-pool','first-address'),('shared-pool','second-address'),('other-pool','first-address');").map_err(io::Error::other)?;
                captures.push(output(&mut session)?);
            }
            assert_ne!(captures[0], captures[1]);
            assert!(replay::delta(&target, &captures[0])? == replay::delta(&target, &captures[1])?);

            let mut changed = Vec::new();
            for null_username in [false, true] {
                let c = Connection::open_in_memory().map_err(io::Error::other)?;
                c.execute_batch("CREATE TABLE administrators(id TEXT PRIMARY KEY NOT NULL,username TEXT,password_hash TEXT) STRICT; INSERT INTO administrators VALUES('row-one','name','hash');").map_err(io::Error::other)?;
                let mut session = Session::new(&c).map_err(io::Error::other)?;
                session
                    .attach(Some("administrators"))
                    .map_err(io::Error::other)?;
                c.execute_batch(if null_username {
                    "UPDATE administrators SET username=NULL,password_hash=NULL;"
                } else {
                    "UPDATE administrators SET password_hash=NULL;"
                })
                .map_err(io::Error::other)?;
                changed.push(output(&mut session)?);
            }
            assert!(replay::delta(&target, &changed[0])? != replay::delta(&target, &changed[1])?);
            Ok(())
        }

        #[test]
        fn incompatible_tables_counts_keys_patchsets_and_partial_bytes_are_rejected()
        -> io::Result<()> {
            let f = node::tests::Fixture::new(true, true)?;
            let target = peers::open_existing(&f.client_state, false)?;
            for mode in 0..4 {
                let c = Connection::open_in_memory().map_err(io::Error::other)?;
                let (table, ddl, insert) = match mode {
                    0 => (
                        "foreign_table",
                        "CREATE TABLE foreign_table(id TEXT PRIMARY KEY,value TEXT) STRICT;",
                        "INSERT INTO foreign_table VALUES('a','b');",
                    ),
                    1 => (
                        "administrators",
                        "CREATE TABLE administrators(id TEXT PRIMARY KEY,username TEXT,password_hash TEXT,extra TEXT) STRICT;",
                        "INSERT INTO administrators VALUES('a','b','c','d');",
                    ),
                    2 => (
                        "administrators",
                        "CREATE TABLE administrators(id TEXT,username TEXT PRIMARY KEY,password_hash TEXT) STRICT;",
                        "INSERT INTO administrators VALUES('a','b','c');",
                    ),
                    _ => (
                        "administrators",
                        "CREATE TABLE administrators(id TEXT PRIMARY KEY,username TEXT,password_hash TEXT) STRICT;",
                        "INSERT INTO administrators VALUES('a','b','c');",
                    ),
                };
                c.execute_batch(ddl).map_err(io::Error::other)?;
                let mut session = Session::new(&c).map_err(io::Error::other)?;
                session.attach(Some(table)).map_err(io::Error::other)?;
                c.execute_batch(insert).map_err(io::Error::other)?;
                let bytes = if mode == 3 {
                    let mut bytes = Vec::new();
                    session
                        .patchset_strm(&mut bytes)
                        .map_err(io::Error::other)?;
                    bytes
                } else {
                    output(&mut session)?
                };
                assert!(replay::delta(&target, &bytes).is_err(), "mode {mode}");
            }
            for bytes in [b"".as_slice(), b"T", b"invalid"] {
                assert!(replay::delta(&target, bytes).is_err());
            }
            Ok(())
        }

        #[test]
        fn changeset_normalization_index_has_an_enforced_row_limit() -> io::Result<()> {
            let f = node::tests::Fixture::new(true, true)?;
            let target = peers::open_existing(&f.client_state, false)?;
            let c = Connection::open_in_memory().map_err(io::Error::other)?;
            c.execute_batch("CREATE TABLE administrators(id INTEGER PRIMARY KEY,username TEXT,password_hash TEXT) STRICT;").map_err(io::Error::other)?;
            let mut session = Session::new(&c).map_err(io::Error::other)?;
            session
                .attach(Some("administrators"))
                .map_err(io::Error::other)?;
            let tx = c.unchecked_transaction().map_err(io::Error::other)?;
            {
                let mut statement = tx
                    .prepare("INSERT INTO administrators VALUES(?1,'fixture','hash')")
                    .map_err(io::Error::other)?;
                for i in 1..=65_536 {
                    statement.execute([i]).map_err(io::Error::other)?;
                }
            }
            tx.commit().map_err(io::Error::other)?;
            let accepted = output(&mut session)?;
            assert!(accepted.len() < MAX_PAYLOAD);
            assert!(replay::delta(&target, &accepted).is_ok());
            c.execute(
                "INSERT INTO administrators VALUES(65537,'fixture','hash')",
                [],
            )
            .map_err(io::Error::other)?;
            let refused = output(&mut session)?;
            assert!(refused.len() < MAX_PAYLOAD);
            assert!(replay::delta(&target, &refused).is_err());
            Ok(())
        }

        #[test]
        fn aborted_or_filtered_apply_cannot_match_the_original_net_changes() -> io::Result<()> {
            use rusqlite::session::ConflictAction;
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = crate::manage::store::lock(&f.client_state)?;
            let g = crate::manage::store::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
            let prepared = journal.prepare(&mut c, &baseline(&f, &e)?, changed)?;
            let payload = prepared.intent().payload()?;
            drop(prepared);
            c.execute_batch("CREATE TRIGGER ignore_replay BEFORE UPDATE ON administrators BEGIN SELECT RAISE(IGNORE); END;").map_err(io::Error::other)?;
            let expected = replay::delta(&c, &payload)?;
            let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate)
                .map_err(io::Error::other)?;
            let mut session = Session::new(&c).map_err(io::Error::other)?;
            for table in crate::manage::store::backup::tables(SCHEMA_VERSION) {
                session.attach(Some(table)).map_err(io::Error::other)?;
            }
            assert!(
                tx.apply_strm(
                    &mut io::Cursor::new(&*payload),
                    None::<fn(&str) -> bool>,
                    |_, _| ConflictAction::SQLITE_CHANGESET_ABORT,
                )
                .is_err()
            );
            drop(session);
            drop(tx);
            c.execute_batch("DROP TRIGGER ignore_replay;")
                .map_err(io::Error::other)?;
            let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate)
                .map_err(io::Error::other)?;
            let mut session = Session::new(&c).map_err(io::Error::other)?;
            for table in crate::manage::store::backup::tables(SCHEMA_VERSION) {
                session.attach(Some(table)).map_err(io::Error::other)?;
            }
            // Deliberately omit one table using SQLite's documented filter, while the
            // production replay always passes None. Apply succeeds, but the independent
            // net-change comparison must detect the omission.
            tx.apply_strm(
                &mut io::Cursor::new(&*payload),
                Some(|table: &str| table != "administrators"),
                |_, _| ConflictAction::SQLITE_CHANGESET_ABORT,
            )
            .map_err(io::Error::other)?;
            let actual = output(&mut session)?;
            assert!(expected != replay::delta(&tx, &actual)?);
            assert_eq!(verifier(&tx)?, "fixture-phc");
            drop(session);
            drop(tx);
            assert_eq!(
                source::load(&c, SCHEMA_VERSION)?
                    .ok_or_else(invalid)?
                    .floor
                    .sequence,
                0
            );
            Ok(())
        }

        #[test]
        fn a_net_zero_business_callback_cannot_claim_a_sequence() -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = crate::manage::store::lock(&f.client_state)?;
            let g = crate::manage::store::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
            assert!(
                journal
                    .prepare(&mut c, &baseline(&f, &e)?, |tx| {
                        tx.execute(
                            "INSERT INTO peer_audit VALUES(99,'offline','register',?1,1)",
                            [&f.server_id],
                        )
                        .map_err(io::Error::other)?;
                        tx.execute("DELETE FROM peer_audit WHERE sequence=99", [])
                            .map_err(io::Error::other)
                    })
                    .is_err()
            );
            assert!(journal.pending(&c)?.is_none());
            let prepared = journal.prepare(&mut c, &baseline(&f, &e)?, changed)?;
            assert_eq!(prepared.intent().transition().sequence, "1");
            Ok(())
        }
    }
    mod driver {
        use super::*;

        #[test]
        fn unresolved_owner_state_has_the_same_uncertainty_marker_as_a_lost_source_reply() {
            let unresolved = super::super::driver::unresolved();
            assert_eq!(unresolved.kind(), io::ErrorKind::Other);
            assert!(super::super::is_uncertain(&unresolved));
            let dispatched = super::super::driver::uncertain(io::ErrorKind::WouldBlock.into());
            assert_eq!(dispatched.kind(), io::ErrorKind::Other);
            assert!(super::super::is_uncertain(&dispatched));
            assert!(!super::super::is_uncertain(&io::Error::other(
                "before dispatch"
            )));
            assert!(!super::super::is_uncertain(
                &io::ErrorKind::WouldBlock.into()
            ));
        }
        use crate::manage::{
            node::control::witness::{Action, Operation},
            store::users,
        };

        /// Actual witness-store transitions with the fixture's registered DER. The
        /// transport fault is injected only after the witness operation has returned,
        /// so a permission/busy error is deliberately not evidence of remote rollback.
        pub(super) struct Witness<'a> {
            fixture: &'a node::tests::Fixture,
            enrollment: Enrollment,
            authorization: super::super::super::RemoteAuthorization,
            _author: Guard,
            pub(super) fail: u8,
            pub(super) fail_before: bool,
            pub(super) kind: io::ErrorKind,
            pub(super) reserves: usize,
            pub(super) confirms: usize,
        }

        impl<'a> Witness<'a> {
            pub(super) fn new(f: &'a node::tests::Fixture, e: &Enrollment) -> io::Result<Self> {
                super::super::super::witness::bind(&f.server_state, e)?;
                let pem = files::read(&f.client_cert, 16 * 1024, false)?;
                let der = rustls_pemfile::certs(&mut pem.as_slice())
                    .next()
                    .transpose()?
                    .ok_or_else(invalid)?;
                Ok(Self {
                    fixture: f,
                    enrollment: e.clone(),
                    authorization: super::super::super::RemoteAuthorization {
                        node_id: f.client_id.clone(),
                        authorization_revision: 1,
                        leaf: Arc::from(der.as_ref()),
                    },
                    _author: super::super::super::lock(&f.server_state)?,
                    fail: 0,
                    fail_before: false,
                    kind: io::ErrorKind::PermissionDenied,
                    reserves: 0,
                    confirms: 0,
                })
            }
            pub(super) fn request(&mut self, operation: Operation) -> io::Result<Fetched<Record>> {
                assert_eq!(operation.enrollment, self.enrollment);
                let stage = match operation.action {
                    Action::Inspect => 1,
                    Action::Reserve(_) => 2,
                    Action::Confirm(_) => 3,
                };
                let fail = self.fail == stage;
                if fail {
                    self.fail = 0;
                    if self.fail_before {
                        return Err(io::Error::new(self.kind, "fixture refused witness request"));
                    }
                }
                let record = match operation.action {
                    Action::Inspect => super::super::super::witness::remote_inspect(
                        &self.fixture.server_state,
                        &self.authorization,
                        &self.enrollment.binding_id,
                    )?,
                    Action::Reserve(t) | Action::Confirm(t) => {
                        let confirm = stage == 3;
                        self.reserves += usize::from(!confirm);
                        self.confirms += usize::from(confirm);
                        let gate = super::super::super::update_lock(&self.fixture.server_state)?;
                        super::super::super::witness::transition(
                            &self.fixture.server_state,
                            &gate,
                            &self.authorization,
                            &t,
                            confirm,
                        )?
                    }
                };
                if fail {
                    return Err(io::Error::new(
                        self.kind,
                        "fixture discarded durable witness reply",
                    ));
                }
                proof(self.fixture, record)
            }
        }

        pub(super) fn administrator(connection: &Connection) -> io::Result<String> {
            connection
                .query_row("SELECT id FROM administrators", [], |r| r.get(0))
                .map_err(io::Error::other)
        }

        pub(super) fn create_user(
            connection: &Transaction<'_>,
            administrator: &str,
        ) -> io::Result<users::ChangeResult> {
            users::apply_local_in(
                connection,
                administrator,
                1,
                users::PolicyChange::CreateUser {
                    name: "driver user".into(),
                    protocols: vec![crate::access::Protocol::Http],
                    concurrent_limit: 4,
                },
                None,
            )
        }

        #[test]
        fn shared_policy_transaction_keeps_actor_cas_and_one_time_delivery() -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let mut witness = Witness::new(&f, &e)?;
            let author = super::super::super::lock(&f.client_state)?;
            let gate = super::super::super::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &author, &gate, &e)?;
            let journal = Journal::open(scope(&f, &author, &gate, &e), &c)?;
            let admin = administrator(&c)?;
            for mode in 0..3 {
                let error = journal
                    .run(
                        &mut c,
                        &mut |op| witness.request(op),
                        |tx| {
                            users::apply_local_in(
                                tx,
                                if mode == 0 { &f.server_id } else { &admin },
                                if mode == 1 { 2 } else { 1 },
                                if mode == 2 {
                                    users::PolicyChange::SetAdmission { accepting: false }
                                } else {
                                    users::PolicyChange::CreateUser {
                                        name: "rejected".into(),
                                        protocols: vec![],
                                        concurrent_limit: 1,
                                    }
                                },
                                None,
                            )
                        },
                        |_, _| Ok(()),
                        || Ok(()),
                    )
                    .err()
                    .ok_or_else(invalid)?;
                assert_eq!(
                    error.kind(),
                    match mode {
                        0 => io::ErrorKind::PermissionDenied,
                        1 => io::ErrorKind::AlreadyExists,
                        _ => io::ErrorKind::InvalidInput,
                    }
                );
                assert_eq!(witness.reserves, 0);
                assert!(journal.pending(&c)?.is_none());
            }
            let user = journal.run(
                &mut c,
                &mut |op| witness.request(op),
                |tx| create_user(tx, &admin),
                |_, _| Ok(()),
                || Ok(()),
            )?;
            let user_id = user.user.ok_or_else(invalid)?.id;
            assert_eq!(user.policy.revision, 2);
            let credential = journal.run(
                &mut c,
                &mut |op| witness.request(op),
                |tx| {
                    users::apply_local_in(
                        tx,
                        &admin,
                        2,
                        users::PolicyChange::CreateCredential { user_id },
                        None,
                    )
                },
                |_, _| Ok(()),
                || Ok(()),
            )?;
            assert!(credential.secret.is_some());
            assert!(credential.credential.is_some());
            assert_eq!(credential.policy.revision, 3);
            assert_eq!((witness.reserves, witness.confirms), (2, 2));
            journal.reconcile(&mut c, &mut |op| witness.request(op), || Ok(()))?;
            assert_eq!((witness.reserves, witness.confirms), (2, 2));
            Ok(())
        }

        #[test]
        fn lost_reserve_or_confirm_is_unknown_and_only_explicit_original_reconciliation_advances()
        -> io::Result<()> {
            for (stage, before) in [(2, false), (3, true), (3, false)] {
                for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::WouldBlock] {
                    let f = node::tests::Fixture::new_with_private_source(true, true)?;
                    let e = enrollment(&f);
                    let mut witness = Witness::new(&f, &e)?;
                    let author = super::super::super::lock(&f.client_state)?;
                    let gate = super::super::super::update_lock(&f.client_state)?;
                    let mut c = source_connection(&f, &author, &gate, &e)?;
                    let journal = Journal::open(scope(&f, &author, &gate, &e), &c)?;
                    let admin = administrator(&c)?;
                    let user_id = journal
                        .run(
                            &mut c,
                            &mut |op| witness.request(op),
                            |tx| create_user(tx, &admin),
                            |_, _| Ok(()),
                            || Ok(()),
                        )?
                        .user
                        .ok_or_else(invalid)?
                        .id;
                    witness.fail = stage;
                    witness.fail_before = before;
                    witness.kind = kind;
                    let error = journal
                        .run(
                            &mut c,
                            &mut |op| witness.request(op),
                            |tx| {
                                users::apply_local_in(
                                    tx,
                                    &admin,
                                    2,
                                    users::PolicyChange::CreateCredential { user_id },
                                    None,
                                )
                            },
                            |_, _| Ok(()),
                            || Ok(()),
                        )
                        .err()
                        .ok_or_else(invalid)?;
                    assert_eq!(error.kind(), io::ErrorKind::Other);
                    assert!(!error.to_string().contains("fixture"));
                    assert_eq!(
                        error
                            .get_ref()
                            .and_then(|e| e.source())
                            .and_then(|e| e.downcast_ref::<io::Error>())
                            .map(io::Error::kind),
                        Some(kind)
                    );
                    let count: i64 = c
                        .query_row("SELECT count(*) FROM proxy_credentials", [], |r| r.get(0))
                        .map_err(io::Error::other)?;
                    assert_eq!(count, i64::from(stage == 3));
                    let reserve_count = witness.reserves;
                    let mut called = false;
                    // A fresh exact Confirmed/postimage resolves the commit, although
                    // the lost secret remains unavailable. Pending on either side must
                    // still refuse a new callback and require explicit reconciliation.
                    let settled = stage == 3 && !before;
                    let rejected = journal.run(
                        &mut c,
                        &mut |op| witness.request(op),
                        |_| {
                            called = true;
                            Err::<(), _>(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "new request rejected",
                            ))
                        },
                        |_, _| Ok(()),
                        || Ok(()),
                    );
                    assert_eq!(
                        rejected.err().map(|e| e.kind()),
                        Some(if settled {
                            io::ErrorKind::InvalidInput
                        } else {
                            io::ErrorKind::Other
                        })
                    );
                    assert_eq!(called, settled);
                    assert_eq!(witness.reserves, reserve_count);
                    drop(c);
                    let mut c = open(&scope(&f, &author, &gate, &e))?;
                    journal.reconcile(&mut c, &mut |op| witness.request(op), || Ok(()))?;
                    let count: i64 = c
                        .query_row("SELECT count(*) FROM proxy_credentials", [], |r| r.get(0))
                        .map_err(io::Error::other)?;
                    assert_eq!(count, 1);
                    let record =
                        super::super::super::witness::inspect(&f.server_state, &e.binding_id)?;
                    assert_eq!(
                        (record.sequence.as_str(), record.phase),
                        ("2", Phase::Confirmed)
                    );
                    let confirms = witness.confirms;
                    journal.reconcile(&mut c, &mut |op| witness.request(op), || Ok(()))?;
                    assert_eq!(
                        (witness.reserves, witness.confirms),
                        (reserve_count, confirms)
                    );
                }
            }
            Ok(())
        }

        #[test]
        fn retained_unsent_requires_explicit_reconcile_and_confirmed_old_sql_is_refused()
        -> io::Result<()> {
            for confirmed_old in [false, true] {
                let f = node::tests::Fixture::new_with_private_source(true, true)?;
                let e = enrollment(&f);
                let mut witness = Witness::new(&f, &e)?;
                let author = super::super::super::lock(&f.client_state)?;
                let gate = super::super::super::update_lock(&f.client_state)?;
                let mut c = source_connection(&f, &author, &gate, &e)?;
                let journal = Journal::open(scope(&f, &author, &gate, &e), &c)?;
                let candidate = journal.prepare(&mut c, &baseline(&f, &e)?, changed)?;
                if confirmed_old {
                    witness.request(journal.dispatch(&candidate)?)?;
                    witness.request(Operation {
                        enrollment: e.clone(),
                        action: Action::Confirm(candidate.intent().transition().clone()),
                    })?;
                }
                drop(candidate);
                let mut called = false;
                assert!(
                    journal
                        .run(
                            &mut c,
                            &mut |op| witness.request(op),
                            |tx| {
                                called = true;
                                changed(tx)
                            },
                            |_, _| Ok(()),
                            || Ok(())
                        )
                        .is_err()
                );
                assert!(!called);
                let result = journal.reconcile(&mut c, &mut |op| witness.request(op), || Ok(()));
                if confirmed_old {
                    assert_eq!(result.err().map(|e| e.kind()), Some(io::ErrorKind::Other));
                    assert_eq!(verifier(&c)?, "fixture-phc");
                    assert!(journal.pending(&c)?.is_some());
                } else {
                    result?;
                    assert_eq!(verifier(&c)?, "journal-fixture-phc");
                    assert!(journal.pending(&c)?.is_none());
                }
                assert_eq!((witness.reserves, witness.confirms), (1, 1));
            }
            Ok(())
        }

        #[tokio::test]
        async fn actual_tls_driver_retains_both_guards_when_the_request_wait_is_dropped()
        -> io::Result<()> {
            use crate::manage::node::control::Offline;
            use tokio::{
                net::TcpListener,
                sync::oneshot,
                time::{Duration, timeout},
            };
            use tokio_util::sync::CancellationToken;
            let f = Arc::new(node::tests::Fixture::new_with_private_source(true, true)?);
            let reader = crate::access::Reader::new(crate::access::tests::policy(1, 1))?;
            let flow = reader
                .authenticate(
                    crate::access::tests::LOGIN,
                    &crate::access::tests::secret(),
                    crate::access::Protocol::Http,
                )
                .map_err(|_| invalid())?;
            let worker_reader = reader.clone();
            let e = enrollment(&f);
            super::super::super::witness::bind(&f.server_state, &e)?;
            let policy = Coordinator::new(
                f.server_state.clone(),
                super::super::super::load_policy(&f.server_state)?,
                Arc::new(super::super::super::lock(&f.server_state)?),
            )?;
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let stop = CancellationToken::new();
            let server = tokio::spawn(node::serve(
                listener,
                f.config(address)?,
                f.server_state.clone(),
                stop.clone(),
                Some(policy),
                None,
                None,
            ));
            let (entered, waiting) = oneshot::channel();
            let (release, hold) = std::sync::mpsc::sync_channel(1);
            let (finished, completion) = oneshot::channel();
            let worker_fixture = f.clone();
            let handle = tokio::runtime::Handle::current();
            let worker = tokio::task::spawn_blocking(move || {
                let result = (|| -> io::Result<()> {
                    let f = worker_fixture;
                    let author = Arc::new(super::super::super::lock(&f.client_state)?);
                    let gate = super::super::super::update_lock(&f.client_state)?;
                    let offline = Offline::new(
                        &f.client_state,
                        author.clone(),
                        &f.client_id,
                        tls::node_identity(&f.ca, &f.client_cert, &f.client_key)?,
                    )?;
                    let s = scope(&f, &author, &gate, &e);
                    let mut c = open(&s)?;
                    let endpoint = format!("https://localhost:{}", address.port());
                    let baseline = handle.block_on(offline.request(
                        &endpoint,
                        &e.witness_node_id,
                        Operation {
                            enrollment: e.clone(),
                            action: Action::Inspect,
                        },
                    ))?;
                    initialize(&s, &mut c, &baseline)?;
                    let journal = Journal::open(scope(&f, &author, &gate, &e), &c)?;
                    let mut entered = Some(entered);
                    let mut suspension = None;
                    journal.run(
                        &mut c,
                        &mut |op| {
                            if matches!(op.action, Action::Confirm(_)) {
                                if let Some(signal) = entered.take() {
                                    let _ = signal.send(());
                                }
                                hold.recv_timeout(Duration::from_secs(10))
                                    .map_err(io::Error::other)?;
                            }
                            handle.block_on(offline.request(&endpoint, &e.witness_node_id, op))
                        },
                        |tx| changed(tx),
                        |_, _| Ok(()),
                        || {
                            suspension = Some(worker_reader.suspend()?);
                            Ok(())
                        },
                    )?;
                    suspension.as_mut().ok_or_else(invalid)?.restore()?;
                    assert_eq!(verifier(&c)?, "journal-fixture-phc");
                    Ok(())
                })();
                // All source guards/connection have dropped before this completion.
                let _ = finished.send(result);
            });
            let result = async {
                timeout(Duration::from_secs(10), waiting)
                    .await
                    .map_err(io::Error::other)?
                    .map_err(io::Error::other)?;
                drop(worker); // The requesting wait disappears; the accepted worker does not.
                assert!(reader.revision().is_err());
                assert!(matches!(
                    reader.authenticate(
                        crate::access::tests::LOGIN,
                        &crate::access::tests::secret(),
                        crate::access::Protocol::Http
                    ),
                    Err(crate::access::Error::Unavailable)
                ));
                assert_eq!(
                    super::super::super::lock(&f.client_state)
                        .err()
                        .map(|e| e.kind()),
                    Some(io::ErrorKind::WouldBlock)
                );
                assert_eq!(
                    super::super::super::update_lock(&f.client_state)
                        .err()
                        .map(|e| e.kind()),
                    Some(io::ErrorKind::WouldBlock)
                );
                release.send(()).map_err(io::Error::other)?;
                timeout(Duration::from_secs(10), completion)
                    .await
                    .map_err(io::Error::other)?
                    .map_err(io::Error::other)??;
                let record = super::super::super::witness::inspect(
                    &f.server_state,
                    &enrollment(&f).binding_id,
                )?;
                assert_eq!(
                    (record.sequence.as_str(), record.phase),
                    ("1", Phase::Confirmed)
                );
                super::super::super::lock(&f.client_state)?;
                super::super::super::update_lock(&f.client_state)?;
                assert_eq!(reader.revision()?, 1);
                assert_eq!(reader.admission()?.active_operations, 1);
                drop(flow);
                assert!(
                    reader
                        .authenticate(
                            crate::access::tests::LOGIN,
                            &crate::access::tests::secret(),
                            crate::access::Protocol::Http
                        )
                        .is_ok()
                );
                Ok(())
            }
            .await;
            stop.cancel();
            server.await.map_err(io::Error::other)??;
            result
        }

        #[test]
        fn commit_barrier_follows_exact_pending_and_refusal_leaves_sql_old() -> io::Result<()> {
            use std::cell::Cell;
            for mode in 0..3 {
                let f = node::tests::Fixture::new_with_private_source(true, true)?;
                let e = enrollment(&f);
                let mut witness = Witness::new(&f, &e)?;
                let author = super::super::super::lock(&f.client_state)?;
                let gate = super::super::super::update_lock(&f.client_state)?;
                let mut c = source_connection(&f, &author, &gate, &e)?;
                let observer = super::super::super::peers::open_existing(&f.client_state, false)?;
                let journal = Journal::open(scope(&f, &author, &gate, &e), &c)?;
                let reader = crate::access::Reader::new(users::read_policy(&c)?)?;
                let admin = administrator(&c)?;
                let stage = Cell::new(0);
                let barriers = Cell::new(0);
                let mut held = None;
                let result = journal.run(
                    &mut c,
                    &mut |op| {
                        let action = match op.action {
                            Action::Inspect => 1,
                            Action::Reserve(_) => 2,
                            Action::Confirm(_) => 3,
                        };
                        if action == 3 {
                            assert!(reader.revision().is_err());
                            assert_eq!(
                                source::load(&observer, SCHEMA_VERSION)?
                                    .ok_or_else(invalid)?
                                    .floor
                                    .sequence,
                                1
                            );
                        }
                        let mut reply = witness.request(op)?;
                        stage.set(action);
                        if mode == 1 && action == 2 {
                            reply.value.phase = Phase::Confirmed;
                        }
                        Ok(reply)
                    },
                    |tx| create_user(tx, &admin),
                    |_, _| Ok(()),
                    || {
                        barriers.set(barriers.get() + 1);
                        assert_eq!(stage.get(), 2);
                        assert_eq!(
                            source::load(&observer, SCHEMA_VERSION)?
                                .ok_or_else(invalid)?
                                .floor
                                .sequence,
                            0
                        );
                        if mode == 0 {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "fixture barrier refused",
                            ));
                        }
                        held = Some(reader.suspend()?);
                        Ok(())
                    },
                );
                if mode < 2 {
                    assert_eq!(result.err().map(|e| e.kind()), Some(io::ErrorKind::Other));
                    assert_eq!(barriers.get(), usize::from(mode == 0));
                    assert_eq!(
                        source::load(&c, SCHEMA_VERSION)?
                            .ok_or_else(invalid)?
                            .floor
                            .sequence,
                        0
                    );
                    assert_eq!(witness.confirms, 0);
                    journal.reconcile(&mut c, &mut |op| witness.request(op), || {
                        held = Some(reader.suspend()?);
                        Ok(())
                    })?;
                    held.as_mut()
                        .ok_or_else(invalid)?
                        .publish(users::read_policy(&c)?)?;
                } else {
                    let candidate = result?;
                    assert_eq!(barriers.get(), 1);
                    assert!(reader.revision().is_err());
                    held.as_mut()
                        .ok_or_else(invalid)?
                        .publish(candidate.policy)?;
                }
                assert_eq!(reader.revision()?, 2);
                assert_eq!((witness.reserves, witness.confirms), (1, 1));
            }
            Ok(())
        }

        #[test]
        fn unknown_confirmation_keeps_suspension_until_original_policy_or_same_revision_recovery()
        -> io::Result<()> {
            for changes_policy in [false, true] {
                let f = node::tests::Fixture::new_with_private_source(true, true)?;
                let e = enrollment(&f);
                let mut witness = Witness::new(&f, &e)?;
                let author = super::super::super::lock(&f.client_state)?;
                let gate = super::super::super::update_lock(&f.client_state)?;
                let mut c = source_connection(&f, &author, &gate, &e)?;
                let journal = Journal::open(scope(&f, &author, &gate, &e), &c)?;
                let reader = crate::access::Reader::new(users::read_policy(&c)?)?;
                let admin = administrator(&c)?;
                let mut held = None;
                witness.fail = 3;
                witness.fail_before = true;
                let result = journal.run(
                    &mut c,
                    &mut |op| witness.request(op),
                    |tx| {
                        if changes_policy {
                            create_user(tx, &admin).map(|_| ())
                        } else {
                            changed(tx).map(|_| ())
                        }
                    },
                    |_, _| Ok(()),
                    || {
                        held = Some(reader.suspend()?);
                        Ok(())
                    },
                );
                assert_eq!(result.err().map(|e| e.kind()), Some(io::ErrorKind::Other));
                assert!(reader.revision().is_err());
                assert!(reader.publish(users::read_policy(&c)?).is_err());
                journal.reconcile(
                    &mut c,
                    &mut |op| {
                        assert!(reader.revision().is_err());
                        witness.request(op)
                    },
                    || {
                        assert!(held.is_some());
                        Ok(())
                    },
                )?;
                assert!(reader.revision().is_err());
                if changes_policy {
                    held.as_mut()
                        .ok_or_else(invalid)?
                        .publish(users::read_policy(&c)?)?;
                    assert_eq!(reader.revision()?, 2);
                } else {
                    held.as_mut().ok_or_else(invalid)?.restore()?;
                    assert_eq!(reader.revision()?, 1);
                    assert_eq!(users::read_policy(&c)?.revision, 1);
                }
                assert_eq!((witness.reserves, witness.confirms), (1, 1));
            }
            Ok(())
        }
    }
    mod history {
        //! Format compatibility and admission on fresh private source fixtures.
        use super::*;
        use crate::manage::store::alerts::history::Writer;

        #[test]
        fn mixed_formats_preserve_legacy_commitment_and_bind_every_segment_seal_field()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = crate::manage::store::lock(&f.client_state)?;
            let g = crate::manage::store::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
            let prepared = journal.prepare(&mut c, &baseline(&f, &e)?, changed)?;
            let metadata = &prepared.intent.metadata;
            assert_eq!(metadata.format, 2);
            assert!(
                serde_json::to_value(metadata)
                    .map_err(io::Error::other)?
                    .get("segmented")
                    .is_none()
            );
            // Independent pre-format-3 domain/field algorithm, including original
            // length framing and omitted optional seal in canonical v2 metadata.
            let mut hash = Sha256::new();
            hash.update(b"vproxy.source.intent.v2\0");
            hash.update([2]);
            hash.update(SCHEMA_VERSION.to_be_bytes());
            hash.update([0]);
            for value in [
                serde_json::to_vec(&metadata.enrollment).map_err(io::Error::other)?,
                serde_json::to_vec(&metadata.before).map_err(io::Error::other)?,
                metadata.intent_id.as_bytes().to_vec(),
                metadata.transition.sequence.as_bytes().to_vec(),
                metadata.transition.previous.as_bytes().to_vec(),
                metadata.schema_sha256.as_bytes().to_vec(),
                metadata.payload_sha256.as_bytes().to_vec(),
            ] {
                hash.update((value.len() as u64).to_be_bytes());
                hash.update(value);
            }
            hash.update(metadata.payload_bytes.to_be_bytes());
            assert_eq!(hex(&hash.finalize()), metadata.transition.commitment);
            journal.dispatch(&prepared)?;
            let transition = prepared.intent.transition().clone();
            prepared
                .commit(&reply(&f, &e, &transition, Phase::Pending)?)?
                .confirm(&reply(&f, &e, &transition, Phase::Confirmed)?)?;
            let previous = reply(&f, &e, &transition, Phase::Confirmed)?;
            let prepared = match journal.capture(
                &mut c,
                &previous,
                CaptureMode::History,
                |tx, checkpoints| {
                    Writer::Source {
                        tx,
                        checkpoints: checkpoints.ok_or_else(invalid)?,
                    }
                    .start("AAAAAAAAAAAAAAAAAAAAAA")
                },
            )? {
                Captured::Write(value) => value,
                Captured::Read(_) => return Err(invalid()),
            };
            let metadata = &prepared.intent.metadata;
            let original = serde_json::to_value(metadata).map_err(io::Error::other)?;
            assert_eq!(metadata.format, 3);
            assert!(
                serde_json::to_vec(metadata)
                    .map_err(io::Error::other)?
                    .len()
                    <= MAX_META
            );
            for name in [
                "bytes", "sha256", "segments", "rows", "schema", "before", "after",
            ] {
                let mut value = original.clone();
                let slot = &mut value["segmented"][name];
                match slot {
                    serde_json::Value::Number(n) => {
                        *slot = serde_json::json!(n.as_u64().ok_or_else(invalid)? + 1)
                    }
                    serde_json::Value::Array(a) => {
                        a[0] = serde_json::json!((a[0].as_u64().ok_or_else(invalid)? + 1) % 256)
                    }
                    serde_json::Value::String(s) => {
                        let digit = if s.starts_with('a') { "b" } else { "a" };
                        s.replace_range(..1, digit);
                    }
                    _ => return Err(invalid()),
                }
                let altered: Metadata = serde_json::from_value(value).map_err(io::Error::other)?;
                assert_ne!(
                    altered.commitment()?,
                    metadata.transition.commitment,
                    "{name}"
                );
                assert!(altered.validate(&e).is_err(), "{name}");
            }
            for (format, segmented) in [
                (2, original["segmented"].clone()),
                (3, serde_json::Value::Null),
            ] {
                let mut value = original.clone();
                value["format"] = serde_json::json!(format);
                value["segmented"] = segmented;
                let mut altered: Metadata =
                    serde_json::from_value(value).map_err(io::Error::other)?;
                altered.transition.commitment = altered.commitment()?;
                assert!(altered.validate(&e).is_err());
            }
            journal.dispatch(&prepared)?;
            let transition = prepared.intent.transition().clone();
            drop(prepared); // The source must replay the exact format-3 bytes, not rerun start.
            let pending = reply(&f, &e, &transition, Phase::Pending)?;
            let confirmed = reply(&f, &e, &transition, Phase::Confirmed)?;
            journal
                .replay_pending(&mut c, 2, &pending)?
                .confirm(&confirmed)?;
            let prepared = journal.prepare(&mut c, &confirmed, |tx| {
                tx.execute("UPDATE administrators SET password_hash='continued-v2'", [])
                    .map_err(io::Error::other)
            })?;
            assert_eq!(prepared.intent.metadata.format, 2);
            let transition = prepared.intent.transition().clone();
            journal.dispatch(&prepared)?;
            let confirmed = reply(&f, &e, &transition, Phase::Confirmed)?;
            prepared
                .commit(&reply(&f, &e, &transition, Phase::Pending)?)?
                .confirm(&confirmed)?;
            assert_eq!(verifier(&c)?, "continued-v2");
            Ok(())
        }

        #[test]
        fn history_capacity_refuses_before_claiming_output_but_allows_terminal_read()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = crate::manage::store::lock(&f.client_state)?;
            let g = crate::manage::store::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
            let root = f.client_state.join("witness-intents");
            for n in 0..251 {
                File::create_new(root.join(format!("unknown-{n}")))?;
            }
            let count = fs::read_dir(&root)?.count();
            let error = journal
                .capture(
                    &mut c,
                    &baseline(&f, &e)?,
                    CaptureMode::History,
                    |tx, checkpoints| {
                        Writer::Source {
                            tx,
                            checkpoints: checkpoints.ok_or_else(invalid)?,
                        }
                        .start("AAAAAAAAAAAAAAAAAAAAAA")
                    },
                )
                .err()
                .ok_or_else(invalid)?;
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert_eq!(scope(&f, &a, &g, &e).state(&c)?.floor.sequence, 0);
            assert_eq!(fs::read_dir(&root)?.count(), count);
            match journal.capture(&mut c, &baseline(&f, &e)?, CaptureMode::History, |_, _| {
                Ok(7)
            })? {
                Captured::Read(n) => assert_eq!(n, 7),
                Captured::Write(_) => return Err(invalid()),
            }
            assert_eq!(fs::read_dir(&root)?.count(), count);
            Ok(())
        }

        #[test]
        fn a_rejected_callback_after_checkpoint_rolls_back_all_sql_and_keeps_only_private_evidence()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = crate::manage::store::lock(&f.client_state)?;
            let g = crate::manage::store::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
            let before = content::calculate(&c, None)?;
            let error = journal
                .capture(
                    &mut c,
                    &baseline(&f, &e)?,
                    CaptureMode::History,
                    |tx, checkpoints| {
                        let checkpoints = checkpoints.ok_or_else(invalid)?;
                        Writer::Source { tx, checkpoints }.start("AAAAAAAAAAAAAAAAAAAAAA")?;
                        checkpoints.checkpoint()?;
                        Err::<(), _>(denied())
                    },
                )
                .err()
                .ok_or_else(invalid)?;
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(content::calculate(&c, None)?, before);
            assert!(journal.pending(&c)?.is_none());
            let root = f.client_state.join("witness-intents");
            let outputs = fs::read_dir(&root)?.collect::<Result<Vec<_>, _>>()?;
            assert_eq!(outputs.len(), 1);
            assert!(outputs[0].path().join(PAYLOAD).try_exists()?);
            assert!(!outputs[0].path().join(META).try_exists()?);
            // Incomplete output is not adopted, dispatched or removed on a later read.
            match journal.capture(&mut c, &baseline(&f, &e)?, CaptureMode::History, |_, _| {
                Ok(())
            })? {
                Captured::Read(()) => {}
                Captured::Write(_) => return Err(invalid()),
            }
            assert!(outputs[0].path().join(PAYLOAD).try_exists()?);
            Ok(())
        }
    }
    mod owner {
        use super::super::{impact, owner::Owner};
        use super::driver::{Witness, administrator, create_user};
        use super::*;
        use crate::manage::store::users;

        #[test]
        fn owner_publishes_actual_saved_policy_and_metadata_keeps_original_revision_and_leases()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let mut witness = Witness::new(&f, &e)?;
            let a = super::super::super::lock(&f.client_state)?;
            let g = super::super::super::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let admin = administrator(&c)?;
            let mut owner =
                Owner::open(scope(&f, &a, &g, &e), &mut c, &mut |op| witness.request(op))?;
            let reader = owner.reader();
            assert_eq!(owner.restoration().node_id, f.client_id);
            let id = owner
                .run(&mut c, &mut |op| witness.request(op), |tx| {
                    create_user(tx, &admin)
                })?
                .user
                .ok_or_else(invalid)?
                .id;
            let result = owner.run(&mut c, &mut |op| witness.request(op), |tx| {
                users::apply_local_in(
                    tx,
                    &admin,
                    2,
                    users::PolicyChange::CreateCredential {
                        user_id: id.clone(),
                    },
                    None,
                )
            })?;
            let credential = result.credential.ok_or_else(invalid)?;
            let secret = result.secret.ok_or_else(invalid)?;
            let old = reader
                .authenticate(
                    &credential.login,
                    secret.as_bytes(),
                    crate::access::Protocol::Http,
                )
                .map_err(|_| invalid())?;
            assert_eq!(reader.revision()?, 3);
            owner.run(&mut c, &mut |op| witness.request(op), |tx| {
                tx.execute(
                    "UPDATE proxy_policy_state SET applied_revision=revision",
                    [],
                )
                .map_err(io::Error::other)
            })?;
            assert_eq!(reader.revision()?, 3);
            assert_eq!(reader.admission()?.active_operations, 1);
            owner.run(&mut c, &mut |op| witness.request(op), |tx| {
                users::apply_local_in(
                    tx,
                    &admin,
                    3,
                    users::PolicyChange::SetUserActive { id, active: false },
                    None,
                )
            })?;
            assert_eq!(reader.revision()?, 4);
            assert!(matches!(
                reader.authenticate(
                    &credential.login,
                    secret.as_bytes(),
                    crate::access::Protocol::Http
                ),
                Err(crate::access::Error::Denied)
            ));
            assert_eq!(reader.admission()?.active_operations, 1);
            drop(old);
            assert_eq!(reader.admission()?.active_operations, 0);
            assert_eq!((witness.reserves, witness.confirms), (4, 4));
            drop(owner);
            assert!(reader.revision().is_err());
            Ok(())
        }

        #[test]
        fn owner_retains_original_binding_and_suspension_for_every_lost_reply_window()
        -> io::Result<()> {
            for (stage, before) in [(2, false), (3, true), (3, false)] {
                for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::WouldBlock] {
                    let f = node::tests::Fixture::new_with_private_source(true, true)?;
                    let e = enrollment(&f);
                    let mut witness = Witness::new(&f, &e)?;
                    let a = super::super::super::lock(&f.client_state)?;
                    let g = super::super::super::update_lock(&f.client_state)?;
                    let mut c = source_connection(&f, &a, &g, &e)?;
                    let admin = administrator(&c)?;
                    let mut owner =
                        Owner::open(scope(&f, &a, &g, &e), &mut c, &mut |op| witness.request(op))?;
                    let reader = owner.reader();
                    let user_id = owner
                        .run(&mut c, &mut |op| witness.request(op), |tx| {
                            create_user(tx, &admin)
                        })?
                        .user
                        .ok_or_else(invalid)?
                        .id;
                    witness.fail = stage;
                    witness.fail_before = before;
                    witness.kind = kind;
                    let error = owner
                        .run(&mut c, &mut |op| witness.request(op), |tx| {
                            users::apply_local_in(
                                tx,
                                &admin,
                                2,
                                users::PolicyChange::CreateCredential { user_id },
                                None,
                            )
                        })
                        .err()
                        .ok_or_else(invalid)?;
                    assert_eq!(error.kind(), io::ErrorKind::Other);
                    assert!(reader.revision().is_err());
                    let mut called = false;
                    assert!(
                        owner
                            .run(&mut c, &mut |op| witness.request(op), |tx| {
                                called = true;
                                changed(tx)
                            })
                            .is_err()
                    );
                    assert!(!called);
                    drop(c);
                    let mut c = open(&scope(&f, &a, &g, &e))?;
                    owner.reconcile(&mut c, &mut |op| witness.request(op))?;
                    assert_eq!(reader.revision()?, 3);
                    let count: i64 = c
                        .query_row("SELECT count(*) FROM proxy_credentials", [], |r| r.get(0))
                        .map_err(io::Error::other)?;
                    assert_eq!(count, 1);
                    let confirms = witness.confirms;
                    owner.reconcile(&mut c, &mut |op| witness.request(op))?;
                    assert_eq!((witness.reserves, witness.confirms), (2, confirms));
                }
            }
            Ok(())
        }

        #[test]
        fn lost_locator_cannot_turn_a_dispatched_original_into_a_clean_predecessor()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let mut witness = Witness::new(&f, &e)?;
            let a = super::super::super::lock(&f.client_state)?;
            let g = super::super::super::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let admin = administrator(&c)?;
            let mut owner =
                Owner::open(scope(&f, &a, &g, &e), &mut c, &mut |op| witness.request(op))?;
            let reader = owner.reader();
            witness.fail = 2;
            assert!(
                owner
                    .run(&mut c, &mut |op| witness.request(op), |tx| create_user(
                        tx, &admin
                    ))
                    .is_err()
            );
            let root = f.client_state.join("witness-intents");
            let locator = root.join("1.json");
            let original = fs::read(&locator)?;
            fs::remove_file(&locator)?; // Exact leaf in this fresh private fixture only.
            let mut requested = false;
            assert!(
                owner
                    .reconcile(&mut c, &mut |_| {
                        requested = true;
                        baseline(&f, &e)
                    })
                    .is_err()
            );
            assert!(!requested);
            assert!(reader.revision().is_err());
            // Simulate explicit restoration of the *exact* original file, not an owner
            // repair operation or permission to regenerate it after an unknown result.
            files::write(&root, "1.json", &original)?;
            owner.reconcile(&mut c, &mut |op| witness.request(op))?;
            assert_eq!(reader.revision()?, 2);
            assert_eq!((witness.reserves, witness.confirms), (1, 1));
            Ok(())
        }

        #[test]
        fn unversioned_policy_writes_are_refused_but_definite_business_rejection_keeps_reader()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let mut witness = Witness::new(&f, &e)?;
            let a = super::super::super::lock(&f.client_state)?;
            let g = super::super::super::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let admin = administrator(&c)?;
            let mut owner =
                Owner::open(scope(&f, &a, &g, &e), &mut c, &mut |op| witness.request(op))?;
            let reader = owner.reader();
            owner.run(&mut c, &mut |op| witness.request(op), |tx| {
                create_user(tx, &admin)
            })?;
            let error = owner
                .run(&mut c, &mut |op| witness.request(op), |_| {
                    Err::<(), _>(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "fixture rejection",
                    ))
                })
                .err()
                .ok_or_else(invalid)?;
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(reader.revision()?, 2);
            for sql in [
                "UPDATE proxy_users SET concurrent_limit=5",
                "UPDATE proxy_admission_state SET accepting=0",
                "UPDATE routing_permissions SET legacy_allowed=0",
                "UPDATE user_presets SET allowed_mask=2",
            ] {
                assert!(
                    owner
                        .run(&mut c, &mut |op| witness.request(op), |tx| tx
                            .execute(sql, [])
                            .map_err(io::Error::other))
                        .is_err()
                );
                assert_eq!(witness.reserves, 1);
                assert!(reader.revision().is_err());
                owner.reconcile(&mut c, &mut |op| witness.request(op))?;
                assert_eq!(reader.revision()?, 2);
            }
            reader.fail_closed();
            let mut called = false;
            assert!(
                owner
                    .run(&mut c, &mut |op| witness.request(op), |tx| {
                        called = true;
                        changed(tx)
                    })
                    .is_err()
            );
            assert!(!called);
            assert!(
                owner
                    .reconcile(&mut c, &mut |_| {
                        called = true;
                        baseline(&f, &e)
                    })
                    .is_err()
            );
            assert!(!called);
            Ok(())
        }

        #[test]
        fn policy_dependency_inventory_refuses_unversioned_changes_for_every_reader_table()
        -> io::Result<()> {
            let f = node::tests::Fixture::new(true, true)?;
            let target = super::super::super::peers::open_existing(&f.client_state, false)?;
            for table in super::super::super::backup::tables(SCHEMA_VERSION) {
                impact::table(&target, table)?;
            }
            assert!(impact::table(&target, "future_reader_dependency").is_err());
            // Actual Reader dependencies require a versioned policy. The two new
            // native-only service tables are stricter: no Source mutation is supported.
            // Never infer either classification from a table-name prefix.
            for table in [
                "proxy_users",
                "proxy_credentials",
                "routing_prefixes",
                "routing_addresses",
                "routing_pools",
                "routing_pool_members",
                "routing_permissions",
                "routing_exit_grants",
                "routing_pool_grants",
                "user_presets",
                "pool_presets",
                "proxy_admission_state",
                "proxy_service_state",
                "proxy_service_operations",
            ] {
                let shape = content::columns(&target, table, &mut Sha256::new())?;
                let c = Connection::open_in_memory().map_err(io::Error::other)?;
                let cols = (0..shape.count)
                    .map(|i| format!("c{i} ANY NOT NULL"))
                    .collect::<Vec<_>>()
                    .join(",");
                let key = shape
                    .primary_key
                    .iter()
                    .map(|(i, _)| format!("c{i}"))
                    .collect::<Vec<_>>()
                    .join(",");
                c.execute_batch(&format!(
                    "CREATE TABLE {table}({cols},PRIMARY KEY({key})) STRICT;"
                ))
                .map_err(io::Error::other)?;
                let mut session = Session::new(&c).map_err(io::Error::other)?;
                session.attach(Some(table)).map_err(io::Error::other)?;
                let values = (0..shape.count)
                    .map(|_| "'fixture'")
                    .collect::<Vec<_>>()
                    .join(",");
                c.execute_batch(&format!("INSERT INTO {table} VALUES({values});"))
                    .map_err(io::Error::other)?;
                let mut bytes = Vec::new();
                session
                    .changeset_strm(&mut bytes)
                    .map_err(io::Error::other)?;
                assert!(replay::delta(&target, &bytes)?.effect().is_err(), "{table}");
            }
            Ok(())
        }

        #[test]
        fn native_listener_settings_are_refused_even_with_a_valid_policy_revision() -> io::Result<()>
        {
            for table in ["proxy_service_state", "proxy_service_operations"] {
                let c = Connection::open_in_memory().map_err(io::Error::other)?;
                c.execute_batch(&format!(
            "CREATE TABLE proxy_policy_state(singleton INTEGER PRIMARY KEY,revision INTEGER NOT NULL,applied_revision INTEGER) STRICT;
             INSERT INTO proxy_policy_state VALUES(1,1,NULL);
             CREATE TABLE {table}(singleton INTEGER PRIMARY KEY,value TEXT NOT NULL) STRICT;
             INSERT INTO {table} VALUES(1,'old');"
        )).map_err(io::Error::other)?;
                let mut session = Session::new(&c).map_err(io::Error::other)?;
                session.attach::<&str>(None).map_err(io::Error::other)?;
                c.execute_batch(&format!(
                    "UPDATE {table} SET value='new'; UPDATE proxy_policy_state SET revision=2;"
                ))
                .map_err(io::Error::other)?;
                let mut bytes = Vec::new();
                session
                    .changeset_strm(&mut bytes)
                    .map_err(io::Error::other)?;
                assert!(replay::delta(&c, &bytes)?.effect().is_err(), "{table}");
            }
            Ok(())
        }

        #[test]
        fn a_different_publisher_during_reserve_cannot_be_adopted_as_the_original_policy()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let mut witness = Witness::new(&f, &e)?;
            let a = super::super::super::lock(&f.client_state)?;
            let g = super::super::super::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let mut owner =
                Owner::open(scope(&f, &a, &g, &e), &mut c, &mut |op| witness.request(op))?;
            let reader = owner.reader();
            let mut different = users::read_policy(&c)?;
            different.revision = 2;
            let mut different = Some(different);
            let result = owner.run(
                &mut c,
                &mut |op| {
                    if matches!(
                        op.action,
                        crate::manage::node::control::witness::Action::Reserve(_)
                    ) {
                        // Simulate an accidental second publisher between preflight
                        // and COMMIT. It must not become the saved original policy.
                        reader.publish(different.take().ok_or_else(invalid)?)?;
                    }
                    witness.request(op)
                },
                |tx| changed(tx),
            );
            assert_eq!(result.err().map(|e| e.kind()), Some(io::ErrorKind::Other));
            assert!(different.is_none());
            assert!(reader.revision().is_err());
            assert_eq!(verifier(&c)?, "fixture-phc");
            assert_eq!((witness.reserves, witness.confirms), (1, 0));
            assert!(
                owner
                    .reconcile(&mut c, &mut |op| witness.request(op))
                    .is_err()
            );
            assert!(reader.revision().is_err());
            Ok(())
        }

        #[test]
        fn policy_revision_uses_named_column_and_refuses_nonadvancing_or_replaced_state()
        -> io::Result<()> {
            for reordered in [false, true] {
                let c = Connection::open_in_memory().map_err(io::Error::other)?;
                let columns = if reordered {
                    "applied_revision ANY NOT NULL,singleton INTEGER PRIMARY KEY,revision ANY NOT NULL"
                } else {
                    "singleton INTEGER PRIMARY KEY,revision ANY NOT NULL,applied_revision ANY NOT NULL"
                };
                c.execute_batch(&format!(
                    "CREATE TABLE proxy_policy_state({columns}) STRICT;
             INSERT INTO proxy_policy_state(singleton,revision,applied_revision) VALUES(1,4,0);"
                ))
                .map_err(io::Error::other)?;
                for (sql, expected) in [
                    (
                        "UPDATE proxy_policy_state SET applied_revision=4",
                        Some(impact::Effect::Unchanged),
                    ),
                    (
                        "UPDATE proxy_policy_state SET revision=5",
                        Some(impact::Effect::Changed {
                            before: 4,
                            after: 5,
                        }),
                    ),
                    ("UPDATE proxy_policy_state SET revision=3", None),
                    ("UPDATE proxy_policy_state SET revision=0", None),
                    ("UPDATE proxy_policy_state SET revision='5'", None),
                    ("DELETE FROM proxy_policy_state", None),
                    (
                        "INSERT INTO proxy_policy_state(singleton,revision,applied_revision) VALUES(2,5,0)",
                        None,
                    ),
                ] {
                    let tx = c.unchecked_transaction().map_err(io::Error::other)?;
                    let mut session = Session::new(&tx).map_err(io::Error::other)?;
                    session
                        .attach(Some("proxy_policy_state"))
                        .map_err(io::Error::other)?;
                    tx.execute_batch(sql).map_err(io::Error::other)?;
                    let mut bytes = Vec::new();
                    session
                        .changeset_strm(&mut bytes)
                        .map_err(io::Error::other)?;
                    let actual = replay::delta(&tx, &bytes)?.effect();
                    match expected {
                        Some(effect) => assert_eq!(actual?, effect, "{sql}"),
                        None => assert!(actual.is_err(), "{sql}"),
                    }
                    drop(session);
                    tx.rollback().map_err(io::Error::other)?;
                }
            }
            Ok(())
        }

        #[test]
        fn dedicated_owner_with_one_tokio_blocking_thread_recovers_actual_tls_lost_confirmation()
        -> io::Result<()> {
            use crate::manage::node::control::Offline;
            use tokio::{
                sync::oneshot,
                time::{Duration, timeout},
            };
            use tokio_util::sync::CancellationToken;

            // Offline authorization and the witness server both need spawn_blocking.
            // The accepted source operation must not occupy their only worker while it
            // waits on TLS. A dedicated owner thread leaves that budget available.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .max_blocking_threads(1)
                .build()?;
            runtime.block_on(async {
                let f = Arc::new(node::tests::Fixture::new_with_private_source(true, true)?);
                let e = enrollment(&f);
                super::super::super::witness::bind(&f.server_state, &e)?;
                let coordinator = Coordinator::new(
                    f.server_state.clone(),
                    super::super::super::load_policy(&f.server_state)?,
                    Arc::new(super::super::super::lock(&f.server_state)?),
                )?;
                let fault = Arc::new(node::tests::CutResponse {
                    witness_confirm: true,
                    ..Default::default()
                });
                fault
                    .armed
                    .store(true, std::sync::atomic::Ordering::Release);
                let stop = CancellationToken::new();
                let (address, server) = node::tests::start_cut_response_node(
                    &f,
                    coordinator,
                    fault.clone(),
                    stop.clone(),
                )
                .await?;
                let (finished, completion) = oneshot::channel();
                let worker_fixture = f.clone();
                let handle = tokio::runtime::Handle::current();
                let worker = std::thread::Builder::new()
                    .name("test-source-owner".into())
                    .spawn(move || {
                        let result = (|| -> io::Result<()> {
                            let f = worker_fixture;
                            let author = Arc::new(super::super::super::lock(&f.client_state)?);
                            let gate = super::super::super::update_lock(&f.client_state)?;
                            let offline = Offline::new(
                                &f.client_state,
                                author.clone(),
                                &f.client_id,
                                tls::node_identity(&f.ca, &f.client_cert, &f.client_key)?,
                            )?;
                            let endpoint = format!("https://localhost:{}", address.port());
                            let mut request = |op| {
                                handle.block_on(offline.request(&endpoint, &e.witness_node_id, op))
                            };
                            let s = scope(&f, &author, &gate, &e);
                            let mut c = open(&s)?;
                            let baseline =
                                request(crate::manage::node::control::witness::Operation {
                                    enrollment: e.clone(),
                                    action: crate::manage::node::control::witness::Action::Inspect,
                                })?;
                            initialize(&s, &mut c, &baseline)?;
                            let admin = administrator(&c)?;
                            let mut owner = Owner::open(s, &mut c, &mut request)?;
                            let reader = owner.reader();
                            let error = owner
                                .run(&mut c, &mut request, |tx| create_user(tx, &admin))
                                .err()
                                .ok_or_else(invalid)?;
                            assert_eq!(error.kind(), io::ErrorKind::Other);
                            assert!(reader.revision().is_err());
                            owner.reconcile(&mut c, &mut request)?;
                            assert_eq!(reader.revision()?, 2);
                            let count: i64 = c
                                .query_row("SELECT count(*) FROM proxy_users", [], |row| row.get(0))
                                .map_err(io::Error::other)?;
                            assert_eq!(count, 1);
                            drop(owner);
                            assert!(reader.revision().is_err());
                            Ok(())
                        })();
                        // Completion is sent only after Source SQL, guards and Offline drop.
                        let _ = finished.send(result);
                    })?;
                let result = timeout(Duration::from_secs(30), completion).await;
                stop.cancel();
                let server_result = server.await.map_err(io::Error::other)?;
                // Never join an in-flight source thread on the sole runtime I/O thread.
                // Success/caught I/O error has sent completion after dropping its state.
                let result = result
                    .map_err(io::Error::other)?
                    .map_err(io::Error::other)?;
                worker
                    .join()
                    .map_err(|_| io::Error::other("source owner test panicked"))?;
                result?;
                server_result?;
                assert_eq!(fault.cuts.load(std::sync::atomic::Ordering::Acquire), 1);
                let record = super::super::super::witness::inspect(
                    &f.server_state,
                    &enrollment(&f).binding_id,
                )?;
                assert_eq!(
                    (record.sequence.as_str(), record.phase),
                    ("1", Phase::Confirmed)
                );
                super::super::super::lock(&f.client_state)?;
                super::super::super::update_lock(&f.client_state)?;
                Ok(())
            })
        }
    }
    mod restart {
        use super::*;

        #[cfg(windows)]
        #[test]
        fn baseline_does_not_repair_an_existing_nonprivate_parent() -> io::Result<()> {
            let f = node::tests::Fixture::new(true, true)?;
            let e = enrollment(&f);
            let a = crate::manage::store::lock(&f.client_state)?;
            let g = crate::manage::store::update_lock(&f.client_state)?;
            let s = scope(&f, &a, &g, &e);
            let mut c = open(&s)?;
            assert_eq!(
                initialize(&s, &mut c, &baseline(&f, &e)?)
                    .err()
                    .map(|e| e.kind()),
                Some(io::ErrorKind::PermissionDenied)
            );
            assert!(!f.client_state.join(source::REQUIRED).exists());
            assert_eq!(source::load(&c, SCHEMA_VERSION)?, None);
            assert!(crate::manage::files::check_directory(&f.client_state, true).is_err());
            Ok(())
        }

        #[test]
        fn source_floor_trigger_cannot_publish_a_different_or_ignored_candidate() -> io::Result<()>
        {
            for after in [false, true] {
                let f = node::tests::Fixture::new_with_private_source(true, true)?;
                let e = enrollment(&f);
                let a = crate::manage::store::lock(&f.client_state)?;
                let g = crate::manage::store::update_lock(&f.client_state)?;
                let mut c = source_connection(&f, &a, &g, &e)?;
                let before = source::load(&c, SCHEMA_VERSION)?;
                let ddl = if after {
                    "CREATE TRIGGER bad_source AFTER UPDATE ON recovery_source BEGIN UPDATE recovery_source SET payload=x'7b7d'; END;"
                } else {
                    "CREATE TRIGGER bad_source BEFORE UPDATE ON recovery_source BEGIN SELECT RAISE(IGNORE); END;"
                };
                c.execute_batch(ddl).map_err(io::Error::other)?;
                let path = f.client_state.join("bad-floor");
                assert!(
                    prepare(
                        scope(&f, &a, &g, &e),
                        &mut c,
                        &baseline(&f, &e)?,
                        None,
                        &path,
                        changed
                    )
                    .is_err()
                );
                assert_eq!(source::load(&c, SCHEMA_VERSION)?, before);
                assert_eq!(verifier(&c)?, "fixture-phc");
                assert!(!path.join(META).exists());
            }
            Ok(())
        }

        #[test]
        fn restart_distinguishes_original_uncommitted_and_committed_operation_without_replaying()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = super::super::super::lock(&f.client_state)?;
            let g = super::super::super::update_lock(&f.client_state)?;
            let s = scope(&f, &a, &g, &e);
            let mut c = source_connection(&f, &a, &g, &e)?;
            let first = f.client_state.join("restart-before");
            let prepared = prepare(
                scope(&f, &a, &g, &e),
                &mut c,
                &baseline(&f, &e)?,
                None,
                &first,
                changed,
            )?;
            let transition = prepared.intent().transition().clone();
            drop(prepared);
            drop(c);
            let mut c = open(&s)?;
            let original = Intent::load(&first, &e)?;
            let pending = reply(&f, &e, &transition, Phase::Pending)?;
            let confirmed = reply(&f, &e, &transition, Phase::Confirmed)?;
            let before = source::load(&c, SCHEMA_VERSION)?.ok_or_else(invalid)?;
            assert_eq!(
                inspect_restart(&s, &mut c, &original, &baseline(&f, &e)?)?,
                Restart::Unreserved
            );
            assert_eq!(
                inspect_restart(&s, &mut c, &original, &pending)?,
                Restart::Reserved
            );
            assert!(inspect_restart(&s, &mut c, &original, &confirmed).is_err());
            assert_eq!(verifier(&c)?, "fixture-phc");
            assert_eq!(source::load(&c, SCHEMA_VERSION)?, Some(before));

            let second = f.client_state.join("restart-after");
            let prepared = prepare(
                scope(&f, &a, &g, &e),
                &mut c,
                &baseline(&f, &e)?,
                None,
                &second,
                changed,
            )?;
            let transition = prepared.intent().transition().clone();
            let pending = reply(&f, &e, &transition, Phase::Pending)?;
            drop(prepared.commit(&pending)?);
            drop(c);
            let mut c = open(&s)?;
            let committed = Intent::load(&second, &e)?;
            assert_eq!(
                inspect_restart(&s, &mut c, &committed, &pending)?,
                Restart::Committed
            );
            let confirmed = reply(&f, &e, &transition, Phase::Confirmed)?;
            assert_eq!(
                inspect_restart(&s, &mut c, &committed, &confirmed)?,
                Restart::Confirmed
            );
            let resumed = resume_committed(
                scope(&f, &a, &g, &e),
                &mut c,
                Intent::load(&second, &e)?,
                &pending,
            )?;
            resumed.confirm(&confirmed)?;
            assert_eq!(verifier(&c)?, "journal-fixture-phc");
            assert!(inspect_restart(&s, &mut c, &committed, &baseline(&f, &e)?).is_err());
            assert!(inspect_restart(&s, &mut c, &original, &pending).is_err());
            let retained = source::load(&c, SCHEMA_VERSION)?.ok_or_else(invalid)?;
            assert_eq!(retained.floor, committed.metadata.after()?);
            let mut substitute = retained.clone();
            substitute.floor.intent_id = Some(crate::manage::store::random_id()?);
            source::save(&c, &substitute)?;
            assert!(inspect_restart(&s, &mut c, &committed, &pending).is_err());
            source::save(&c, &retained)?;
            assert_eq!(verifier(&c)?, "journal-fixture-phc");
            assert!(peers::open_existing(&f.client_state, true).is_err());
            assert!(recovery::startup(&f.client_state).is_err());
            Ok(())
        }

        #[test]
        fn next_operation_requires_the_exact_committed_predecessor_and_refuses_floor_rewrites()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = crate::manage::store::lock(&f.client_state)?;
            let g = crate::manage::store::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let path = f.client_state.join("predecessor");
            let prepared = prepare(
                scope(&f, &a, &g, &e),
                &mut c,
                &baseline(&f, &e)?,
                None,
                &path,
                changed,
            )?;
            let transition = prepared.intent().transition().clone();
            let pending = reply(&f, &e, &transition, Phase::Pending)?;
            let committed = prepared.commit(&pending)?;
            let confirmed = reply(&f, &e, &transition, Phase::Confirmed)?;
            assert_eq!(committed.confirm(&confirmed)?, 1);
            let original = Intent::load(&path, &e)?;
            let next = f.client_state.join("next");
            assert!(
                prepare(
                    scope(&f, &a, &g, &e),
                    &mut c,
                    &confirmed,
                    None,
                    &next,
                    changed
                )
                .is_err()
            );
            assert!(!next.exists());
            let prepared = prepare(
                scope(&f, &a, &g, &e),
                &mut c,
                &confirmed,
                Some(&original),
                &next,
                |tx| {
                    tx.execute(
                        "UPDATE administrators SET password_hash='second-fixture-phc'",
                        [],
                    )
                    .map_err(io::Error::other)
                },
            )?;
            assert_eq!(prepared.intent().transition().sequence, "2");
            assert_eq!(
                prepared.intent().metadata.before,
                original.metadata.after()?
            );
            assert_ne!(
                prepared.intent().metadata.intent_id,
                original.metadata.intent_id
            );
            drop(prepared);
            assert_eq!(
                source::load(&c, SCHEMA_VERSION)?.ok_or_else(invalid)?.floor,
                original.metadata.after()?
            );
            assert_eq!(verifier(&c)?, "journal-fixture-phc");
            let rewrite = f.client_state.join("rewrite");
            assert!(
                prepare(
                    scope(&f, &a, &g, &e),
                    &mut c,
                    &confirmed,
                    Some(&original),
                    &rewrite,
                    |tx| {
                        tx.execute("DELETE FROM recovery_source", [])
                            .map_err(io::Error::other)?;
                        changed(tx)
                    }
                )
                .is_err()
            );
            assert_eq!(
                source::load(&c, SCHEMA_VERSION)?.ok_or_else(invalid)?.floor,
                original.metadata.after()?
            );
            Ok(())
        }

        #[test]
        fn interrupted_baseline_keeps_the_original_marker_and_can_only_finish_that_binding()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = crate::manage::store::lock(&f.client_state)?;
            let g = crate::manage::store::update_lock(&f.client_state)?;
            let s = scope(&f, &a, &g, &e);
            let mut c = open(&s)?;
            c.execute_batch("CREATE TRIGGER refuse_source BEFORE INSERT ON recovery_source BEGIN SELECT RAISE(IGNORE); END;").map_err(io::Error::other)?;
            assert!(initialize(&s, &mut c, &baseline(&f, &e)?).is_err());
            assert_eq!(source::load(&c, SCHEMA_VERSION)?, None);
            let marker = fs::read(f.client_state.join(source::REQUIRED))?;
            assert_eq!(marker, serde_json::to_vec(&e).map_err(io::Error::other)?);
            drop(c);
            assert!(peers::open_existing(&f.client_state, true).is_err());
            assert!(recovery::startup(&f.client_state).is_err());
            let mut c = open(&s)?;
            c.execute_batch("DROP TRIGGER refuse_source;")
                .map_err(io::Error::other)?;
            let mut other = e.clone();
            other.writer_id = crate::manage::store::random_id()?;
            assert!(
                initialize(&scope(&f, &a, &g, &other), &mut c, &baseline(&f, &other)?).is_err()
            );
            assert_eq!(fs::read(f.client_state.join(source::REQUIRED))?, marker);
            assert_eq!(source::load(&c, SCHEMA_VERSION)?, None);
            initialize(&s, &mut c, &baseline(&f, &e)?)?;
            initialize(&s, &mut c, &baseline(&f, &e)?)?;
            assert_eq!(
                source::load(&c, SCHEMA_VERSION)?
                    .ok_or_else(invalid)?
                    .enrollment,
                e
            );
            assert!(recovery::startup(&f.client_state).is_err());
            Ok(())
        }
    }
    mod retention {
        //! Filesystem interruption/capacity proofs on newly owned private fixtures.
        //! Replies here use registered DER but not a network witness; worker tests
        //! separately exercise lost confirmation over actual loopback mTLS.
        use super::*;

        /// Commit through the capture/dispatch/confirm kernel without automatic driver
        /// maintenance, modelling a retained backlog from before bounded collection.
        fn backlog(
            journal: &Journal<'_>,
            connection: &mut Connection,
            f: &node::tests::Fixture,
            e: &Enrollment,
            count: u64,
        ) -> io::Result<Fetched<Record>> {
            let mut confirmed = baseline(f, e)?;
            for n in 1..=count {
                let prepared = journal.prepare(connection, &confirmed, |tx| {
                    tx.execute(
                        "UPDATE administrators SET password_hash=?1",
                        [format!("retention-fixture-{n}")],
                    )
                    .map_err(io::Error::other)
                })?;
                journal.dispatch(&prepared)?;
                let transition = prepared.intent().transition().clone();
                let pending = reply(f, e, &transition, Phase::Pending)?;
                let committed = prepared.commit(&pending)?;
                confirmed = reply(f, e, &transition, Phase::Confirmed)?;
                committed.confirm(&confirmed)?;
            }
            Ok(confirmed)
        }

        #[test]
        fn retention_collects_four_old_records_per_sweep_and_keeps_unknown_and_two_latest()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = super::super::super::lock(&f.client_state)?;
            let g = super::super::super::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
            let confirmed = backlog(&journal, &mut c, &f, &e, 7)?;
            let root = f.client_state.join("witness-intents");
            files::write(&root, "unindexed.bin", b"not an operation")?;
            files::create_directory(&root.join("unindexed-directory"))?;
            files::write(&root.join("unindexed-directory"), "unknown.bin", b"keep")?;
            journal.maintain_confirmed(&c, &confirmed);
            for n in 1..=4 {
                assert!(!root.join(format!("{n}.json")).try_exists()?);
            }
            for n in 5..=7 {
                journal.load(n)?;
            }
            journal.maintain_confirmed(&c, &confirmed);
            assert!(!root.join("5.json").try_exists()?);
            journal.load(6)?;
            journal.load(7)?;
            assert_eq!(fs::read(root.join("unindexed.bin"))?, b"not an operation");
            assert_eq!(
                fs::read(root.join("unindexed-directory/unknown.bin"))?,
                b"keep"
            );
            assert_eq!(scope(&f, &a, &g, &e).state(&c)?.floor.sequence, 7);
            assert_eq!(verifier(&c)?, "retention-fixture-7");
            Ok(())
        }

        #[test]
        fn retention_resumes_each_ordered_unlink_boundary_from_its_private_marker() -> io::Result<()>
        {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = super::super::super::lock(&f.client_state)?;
            let g = super::super::super::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
            let confirmed = backlog(&journal, &mut c, &f, &e, 8)?;
            let root = f.client_state.join("witness-intents");
            let mut directories = Vec::new();
            for n in 1..=6 {
                let directory = journal.load(n)?.directory;
                journal.stage_retirement(&c, n)?;
                // Simulate only states reachable in the production deletion order;
                // this is not a claim about filesystem behaviour under power loss.
                if n >= 2 {
                    fs::remove_file(directory.join(PAYLOAD))?;
                }
                if n >= 3 {
                    fs::remove_file(directory.join(META))?;
                }
                if n >= 4 {
                    fs::remove_dir(&directory)?;
                }
                if n >= 5 {
                    fs::remove_file(root.join(format!("sent-{n}.json")))?;
                }
                if n >= 6 {
                    fs::remove_file(root.join(format!("{n}.json")))?;
                }
                directories.push(directory);
            }
            journal.maintain_confirmed(&c, &confirmed);
            assert!(root.join("retired-5.json").try_exists()?);
            journal.maintain_confirmed(&c, &confirmed);
            for (index, directory) in directories.iter().enumerate() {
                assert!(!directory.try_exists()?);
                let n = index + 1;
                for name in [
                    format!("{n}.json"),
                    format!("sent-{n}.json"),
                    format!("retired-{n}.json"),
                ] {
                    assert!(!root.join(name).try_exists()?);
                }
            }
            journal.load(7)?;
            journal.load(8)?;
            Ok(())
        }

        #[test]
        fn retention_refuses_marker_aliases_to_current_or_predecessor_and_unexpected_content()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = super::super::super::lock(&f.client_state)?;
            let g = super::super::super::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
            let confirmed = backlog(&journal, &mut c, &f, &e, 4)?;
            let root = f.client_state.join("witness-intents");
            let old = journal.load(1)?;
            journal.stage_retirement(&c, 1)?;
            let marker = root.join("retired-1.json");
            let original = fs::read_to_string(&marker)?;
            for n in [3, 4] {
                let protected = journal.load(n)?;
                let altered =
                    original.replace(&old.metadata.intent_id, &protected.metadata.intent_id);
                fs::write(&marker, altered)?;
                journal.maintain_confirmed(&c, &confirmed);
                journal.load(1)?;
                journal.load(n)?;
            }
            fs::write(&marker, original)?;
            files::write(&old.directory, "unknown.bin", b"must remain")?;
            let payload = fs::read(old.directory.join(PAYLOAD))?;
            journal.maintain_confirmed(&c, &confirmed);
            assert_eq!(fs::read(old.directory.join(PAYLOAD))?, payload);
            assert_eq!(fs::read(old.directory.join("unknown.bin"))?, b"must remain");
            journal.load(3)?;
            journal.load(4)?;
            Ok(())
        }

        #[test]
        fn retention_preserves_empty_predecessor_even_if_old_marker_and_locators_alias_it()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = super::super::super::lock(&f.client_state)?;
            let g = super::super::super::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
            let confirmed = backlog(&journal, &mut c, &f, &e, 4)?;
            let root = f.client_state.join("witness-intents");
            let old = journal.load(1)?;
            let predecessor = journal.load(3)?;
            journal.stage_retirement(&c, 1)?;
            for name in ["retired-1.json", "1.json", "sent-1.json"] {
                let path = root.join(name);
                let text = fs::read_to_string(&path)?;
                fs::write(
                    path,
                    text.replace(&old.metadata.intent_id, &predecessor.metadata.intent_id),
                )?;
            }
            // Damage only this owned test preimage. An empty directory would otherwise
            // pass the resumable deletion checks; its witness-bound identity protects it.
            fs::remove_file(predecessor.directory.join(PAYLOAD))?;
            fs::remove_file(predecessor.directory.join(META))?;
            journal.maintain_confirmed(&c, &confirmed);
            assert!(predecessor.directory.try_exists()?);
            assert!(old.directory.join(PAYLOAD).try_exists()?);
            assert!(root.join("retired-1.json").try_exists()?);
            journal.load(4)?;
            Ok(())
        }

        #[test]
        fn retention_resume_rejects_changed_payload_and_wrong_enrollment_without_unlink()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = super::super::super::lock(&f.client_state)?;
            let g = super::super::super::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
            let confirmed = backlog(&journal, &mut c, &f, &e, 3)?;
            let old = journal.load(1)?;
            journal.stage_retirement(&c, 1)?;
            let root = f.client_state.join("witness-intents");
            let marker = root.join("retired-1.json");
            let original = fs::read_to_string(&marker)?;
            fs::write(
                &marker,
                original.replace(&e.writer_id, &URL_SAFE_NO_PAD.encode([77_u8; 16])),
            )?;
            journal.maintain_confirmed(&c, &confirmed);
            assert!(old.directory.join(META).try_exists()?);
            journal.load(1)?;
            fs::write(marker, original)?;
            fs::write(old.directory.join(PAYLOAD), b"changed payload")?;
            journal.maintain_confirmed(&c, &confirmed);
            assert!(old.directory.join(META).try_exists()?);
            assert!(root.join("1.json").try_exists()?);
            assert_eq!(fs::read(old.directory.join(PAYLOAD))?, b"changed payload");
            journal.load(2)?;
            journal.load(3)?;
            Ok(())
        }

        #[test]
        fn capacity_rolls_back_changed_candidate_before_files_but_keeps_terminal_reads()
        -> io::Result<()> {
            for bytes_limit in [true, false] {
                let f = node::tests::Fixture::new_with_private_source(true, true)?;
                let e = enrollment(&f);
                let a = super::super::super::lock(&f.client_state)?;
                let g = super::super::super::update_lock(&f.client_state)?;
                let mut c = source_connection(&f, &a, &g, &e)?;
                let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
                let root = f.client_state.join("witness-intents");
                if bytes_limit {
                    files::write(&root, "unindexed.bin", b"")?;
                    // Logical length only: no 512MiB buffer/read or disk-block claim.
                    File::options()
                        .write(true)
                        .open(root.join("unindexed.bin"))?
                        .set_len(512 * 1024 * 1024)?;
                } else {
                    for n in 0..251 {
                        File::create_new(root.join(format!("unknown-{n}")))?;
                    }
                }
                let before = fs::read_dir(&root)?.count();
                let error = journal
                    .prepare(&mut c, &baseline(&f, &e)?, changed)
                    .err()
                    .ok_or_else(invalid)?;
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                assert_eq!(verifier(&c)?, "fixture-phc");
                assert_eq!(scope(&f, &a, &g, &e).state(&c)?.floor.sequence, 0);
                assert_eq!(fs::read_dir(&root)?.count(), before);
                assert!(journal.pending(&c)?.is_none());
                match journal.prepare_or_read(&mut c, &baseline(&f, &e)?, |_| Ok(7))? {
                    Captured::Read(n) => assert_eq!(n, 7),
                    Captured::Write(_) => return Err(invalid()),
                }
                assert_eq!(fs::read_dir(&root)?.count(), before);
            }
            Ok(())
        }
    }
    mod snapshots {
        //! Floor-only seals cannot relabel business DML or replay onto changed content.
        //! Native v2/v3 canonical-byte compatibility is covered by the history test.
        use super::*;

        #[test]
        fn snapshot_capture_rejects_business_dml_and_binds_each_descriptor_field() -> io::Result<()>
        {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = super::super::super::lock(&f.client_state)?;
            let g = super::super::super::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
            let descriptor = snapshot::Descriptor {
                snapshot_id: super::super::super::random_id()?,
                package_sha256: "1".repeat(64),
                database_content_sha256: content::calculate(&c, None)?,
            };
            assert!(
                journal
                    .capture(
                        &mut c,
                        &baseline(&f, &e)?,
                        CaptureMode::Snapshot(&descriptor),
                        |tx, _| changed(tx)
                    )
                    .is_err()
            );
            assert_eq!(verifier(&c)?, "fixture-phc");
            let prepared = match journal.capture(
                &mut c,
                &baseline(&f, &e)?,
                CaptureMode::Snapshot(&descriptor),
                |_, _| Ok(()),
            )? {
                Captured::Write(prepared) => prepared,
                Captured::Read(_) => return Err(invalid()),
            };
            let metadata = &prepared.intent.metadata;
            assert_eq!(metadata.format, 4);
            assert!(metadata.segmented.is_none());
            snapshot::check_payload(&prepared.transaction, &prepared.intent)?;
            let original = serde_json::to_value(metadata).map_err(io::Error::other)?;
            for field in ["snapshot_id", "package_sha256", "database_content_sha256"] {
                let mut value = original.clone();
                value["snapshot"][field] = serde_json::json!(if field == "snapshot_id" {
                    super::super::super::random_id()?
                } else {
                    "2".repeat(64)
                });
                let altered: Metadata = serde_json::from_value(value).map_err(io::Error::other)?;
                assert_ne!(altered.commitment()?, metadata.transition.commitment);
                assert!(altered.validate(&e).is_err());
            }
            drop(prepared);
            let retained = journal.pending(&c)?.ok_or_else(invalid)?;
            let transition = retained.transition().clone();
            c.execute(
                "UPDATE administrators SET password_hash='changed-after-capture'",
                [],
            )
            .map_err(io::Error::other)?;
            assert!(
                journal
                    .replay_pending(&mut c, 1, &reply(&f, &e, &transition, Phase::Pending)?)
                    .is_err()
            );
            assert_eq!(
                source::load(&c, SCHEMA_VERSION)?
                    .ok_or_else(invalid)?
                    .floor
                    .sequence,
                0
            );
            assert_eq!(verifier(&c)?, "changed-after-capture");
            Ok(())
        }

        #[test]
        fn a_rehashed_business_intent_cannot_be_adopted_as_a_snapshot_floor() -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = super::super::super::lock(&f.client_state)?;
            let g = super::super::super::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let hash = content::calculate(&c, None)?;
            let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
            let prepared = journal.prepare(&mut c, &baseline(&f, &e)?, changed)?;
            let path = prepared.intent.directory.clone();
            drop(prepared);
            let mut intent = Intent::load(&path, &e)?;
            intent.metadata.format = 4;
            intent.metadata.snapshot = Some(snapshot::Descriptor {
                snapshot_id: super::super::super::random_id()?,
                package_sha256: "1".repeat(64),
                database_content_sha256: hash,
            });
            intent.metadata.transition.commitment = intent.metadata.commitment()?;
            intent.metadata.validate(&e)?;
            assert!(snapshot::check_payload(&c, &intent).is_err());
            assert_eq!(verifier(&c)?, "fixture-phc");
            Ok(())
        }
    }
    mod tracked {
        use super::*;
        use crate::manage::node::control::witness::Action;

        #[test]
        fn fixed_locator_dispatch_and_exact_replay_retain_original_sequence_and_final_sql()
        -> io::Result<()> {
            let f = node::tests::Fixture::new_with_private_source(true, true)?;
            let e = enrollment(&f);
            let a = crate::manage::store::lock(&f.client_state)?;
            let g = crate::manage::store::update_lock(&f.client_state)?;
            let mut c = source_connection(&f, &a, &g, &e)?;
            let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
            assert!(journal.current(&c)?.is_none());
            assert!(journal.pending(&c)?.is_none());
            let prepared = journal.prepare(&mut c, &baseline(&f, &e)?, changed)?;
            let payload = prepared.intent().payload()?;
            assert!(payload.len() < 64 * 1024);
            assert!(payload.capacity() < 64 * 1024); // Previously every read reserved >16 MiB.
            drop(payload);
            let expected = content::calculate(&prepared.transaction, None)?;
            let transition = prepared.intent().transition().clone();
            assert!(!journal.was_dispatched(prepared.intent())?);
            let operation = journal.dispatch(&prepared)?;
            assert!(matches!(operation.action,Action::Reserve(ref t) if t==&transition));
            assert!(journal.was_dispatched(prepared.intent())?);
            let sent = f.client_state.join("witness-intents/sent-1.json");
            let original_sent = fs::read(&sent)?;
            journal.dispatch(&prepared)?;
            assert_eq!(fs::read(&sent)?, original_sent);
            drop(prepared);
            drop(c);

            let mut c = open(&scope(&f, &a, &g, &e))?;
            let intent = journal.pending(&c)?.ok_or_else(invalid)?;
            assert_eq!(intent.transition(), &transition);
            assert_eq!(verifier(&c)?, "fixture-phc");
            let mut called = false;
            assert_eq!(
                journal
                    .prepare(&mut c, &baseline(&f, &e)?, |tx| {
                        called = true;
                        changed(tx)
                    })
                    .err()
                    .map(|e| e.kind()),
                Some(io::ErrorKind::AlreadyExists)
            );
            assert!(!called);
            let pending = reply(&f, &e, &transition, Phase::Pending)?;
            let committed = journal.replay_pending(&mut c, 1, &pending)?;
            let confirmed = reply(&f, &e, &transition, Phase::Confirmed)?;
            committed.confirm(&confirmed)?;
            assert_eq!(content::calculate(&c, None)?, expected);
            assert_eq!(verifier(&c)?, "journal-fixture-phc");
            assert!(journal.pending(&c)?.is_none());
            let current = journal.current(&c)?.ok_or_else(invalid)?;
            assert_eq!(current.transition(), &transition);
            assert!(
                journal
                    .dispatch_retained(&mut c, &current, &confirmed)
                    .is_err()
            );
            journal
                .resume_committed(&mut c, 1, &pending)?
                .confirm(&confirmed)?;

            let next = journal.prepare(&mut c, &confirmed, |tx| {
                tx.execute(
                    "UPDATE administrators SET password_hash='next-fixture-phc'",
                    [],
                )
                .map_err(io::Error::other)
            })?;
            let next_transition = next.intent().transition().clone();
            drop(next);
            let retained = journal.pending(&c)?.ok_or_else(invalid)?;
            assert!(!journal.was_dispatched(&retained)?);
            let operation = journal.dispatch_retained(&mut c, &retained, &confirmed)?;
            assert!(matches!(operation.action,Action::Reserve(ref t) if t==&next_transition));
            assert!(journal.was_dispatched(&retained)?);
            assert_eq!(verifier(&c)?, "journal-fixture-phc");
            Ok(())
        }

        #[test]
        fn partial_index_bad_dispatch_and_missing_established_root_are_not_repaired()
        -> io::Result<()> {
            for mode in 0..5 {
                let f = node::tests::Fixture::new_with_private_source(true, true)?;
                let e = enrollment(&f);
                let a = crate::manage::store::lock(&f.client_state)?;
                let g = crate::manage::store::update_lock(&f.client_state)?;
                let s = scope(&f, &a, &g, &e);
                let root = f.client_state.join("witness-intents");
                if mode == 3 {
                    let mut c = open(&s)?;
                    files::create_directory(&root)?;
                    files::write(&root, "operator-note", b"preserve")?;
                    assert!(initialize(&s, &mut c, &baseline(&f, &e)?).is_err());
                    assert_eq!(source::load(&c, SCHEMA_VERSION)?, None);
                    assert_eq!(fs::read(root.join("operator-note"))?, b"preserve");
                    assert!(f.client_state.join(source::REQUIRED).exists());
                    continue;
                }
                let mut c = source_connection(&f, &a, &g, &e)?;
                if mode == 2 {
                    fs::remove_dir(&root)?; // Exact empty directory owned by this fixture.
                    assert!(Journal::open(scope(&f, &a, &g, &e), &c).is_err());
                    assert!(initialize(&s, &mut c, &baseline(&f, &e)?).is_err());
                    assert!(!root.exists());
                    continue;
                }
                let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
                let leaf = if mode == 0 {
                    files::write(&root, "1.json", b"{")?;
                    root.join("1.json")
                } else {
                    let prepared = journal.prepare(&mut c, &baseline(&f, &e)?, changed)?;
                    if mode == 4 {
                        let leaf = prepared.intent().directory.join(PAYLOAD);
                        fs::write(&leaf, b"{")?;
                        assert!(journal.dispatch(&prepared).is_err());
                        assert!(!root.join("sent-1.json").exists());
                        drop(prepared);
                        leaf
                    } else {
                        journal.dispatch(&prepared)?;
                        drop(prepared);
                        let leaf = root.join("sent-1.json");
                        fs::write(&leaf, b"{")?; // Preserve the original private file ACL.
                        leaf
                    }
                };
                assert!(journal.pending(&c).is_err());
                assert!(journal.load(1).is_err());
                let mut called = false;
                assert!(
                    journal
                        .prepare(&mut c, &baseline(&f, &e)?, |tx| {
                            called = true;
                            changed(tx)
                        })
                        .is_err()
                );
                assert!(!called);
                assert_eq!(fs::read(leaf)?, b"{");
                assert_eq!(verifier(&c)?, "fixture-phc");
                assert_eq!(
                    source::load(&c, SCHEMA_VERSION)?
                        .ok_or_else(invalid)?
                        .floor
                        .sequence,
                    0
                );
            }
            Ok(())
        }

        #[test]
        fn replay_conflict_wrong_phase_and_corrupt_bytes_preserve_the_local_preimage()
        -> io::Result<()> {
            for mode in 0..4 {
                let f = node::tests::Fixture::new_with_private_source(true, true)?;
                let e = enrollment(&f);
                let a = crate::manage::store::lock(&f.client_state)?;
                let g = crate::manage::store::update_lock(&f.client_state)?;
                let mut c = source_connection(&f, &a, &g, &e)?;
                let journal = Journal::open(scope(&f, &a, &g, &e), &c)?;
                let prepared = journal.prepare(&mut c, &baseline(&f, &e)?, changed)?;
                let transition = prepared.intent().transition().clone();
                journal.dispatch(&prepared)?;
                drop(prepared);
                let mut proof = reply(&f, &e, &transition, Phase::Pending)?;
                let original = journal.load(1)?;
                let before = source::load(&c, SCHEMA_VERSION)?;
                let hash = if mode == 0 {
                    "conflicting-fixture-phc"
                } else {
                    "fixture-phc"
                };
                match mode {
                    0 => {
                        c.execute("UPDATE administrators SET password_hash=?1", [hash])
                            .map_err(io::Error::other)?;
                    }
                    1 => proof.value.phase = Phase::Confirmed,
                    2 => {
                        c.execute_batch("ALTER TABLE administrators ADD COLUMN extra TEXT;")
                            .map_err(io::Error::other)?;
                    }
                    _ => {
                        let mut bytes = fs::read(original.directory.join(PAYLOAD))?;
                        bytes[0] ^= 1;
                        fs::write(original.directory.join(PAYLOAD), bytes)?;
                    }
                }
                assert!(journal.replay_pending(&mut c, 1, &proof).is_err());
                assert_eq!(verifier(&c)?, hash);
                assert_eq!(source::load(&c, SCHEMA_VERSION)?, before);
            }
            Ok(())
        }

        #[tokio::test]
        async fn tracked_pending_replay_uses_the_actual_witness_after_reopening_source()
        -> io::Result<()> {
            use crate::manage::node::control::{Offline, witness::Operation};
            use tokio::net::TcpListener;
            use tokio_util::sync::CancellationToken;
            let f = Arc::new(node::tests::Fixture::new_with_private_source(true, true)?);
            let e = enrollment(&f);
            crate::manage::store::witness::bind(&f.server_state, &e)?;
            let policy = Coordinator::new(
                f.server_state.clone(),
                crate::manage::store::load_policy(&f.server_state)?,
                Arc::new(crate::manage::store::lock(&f.server_state)?),
            )?;
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let stop = CancellationToken::new();
            let task = tokio::spawn(node::serve(
                listener,
                f.config(address)?,
                f.server_state.clone(),
                stop.clone(),
                Some(policy),
                None,
                None,
            ));
            let worker = f.clone();
            let expected = e.clone();
            let endpoint = format!("https://localhost:{}", address.port());
            let handle = tokio::runtime::Handle::current();
            let result = tokio::task::spawn_blocking(move || -> io::Result<()> {
                let author = Arc::new(crate::manage::store::lock(&worker.client_state)?);
                let gate = crate::manage::store::update_lock(&worker.client_state)?;
                let source = Offline::new(
                    &worker.client_state,
                    author.clone(),
                    &worker.client_id,
                    tls::node_identity(&worker.ca, &worker.client_cert, &worker.client_key)?,
                )?;
                let inspect = || Operation {
                    enrollment: expected.clone(),
                    action: Action::Inspect,
                };
                let previous = handle.block_on(source.request(
                    &endpoint,
                    &expected.witness_node_id,
                    inspect(),
                ))?;
                let s = scope(&worker, &author, &gate, &expected);
                let mut c = open(&s)?;
                initialize(&s, &mut c, &previous)?;
                let journal = Journal::open(scope(&worker, &author, &gate, &expected), &c)?;
                let prepared = journal.prepare(&mut c, &previous, changed)?;
                let original = prepared.intent().transition().clone();
                let operation = journal.dispatch(&prepared)?;
                let pending = handle.block_on(source.request(
                    &endpoint,
                    &expected.witness_node_id,
                    operation,
                ))?;
                assert_eq!(pending.value.phase, Phase::Pending);
                drop(prepared);
                drop(c);
                let mut c = open(&s)?;
                assert_eq!(verifier(&c)?, "fixture-phc");
                let fresh = handle.block_on(source.request(
                    &endpoint,
                    &expected.witness_node_id,
                    inspect(),
                ))?;
                assert_eq!(fresh.value.commitment, original.commitment);
                let committed = journal.replay_pending(&mut c, 1, &fresh)?;
                let confirmed = handle.block_on(source.request(
                    &endpoint,
                    &expected.witness_node_id,
                    Operation {
                        enrollment: expected.clone(),
                        action: Action::Confirm(committed.intent().transition().clone()),
                    },
                ))?;
                committed.confirm(&confirmed)?;
                assert_eq!(verifier(&c)?, "journal-fixture-phc");
                assert_eq!(
                    journal.current(&c)?.ok_or_else(invalid)?.transition(),
                    &original
                );
                Ok(())
            })
            .await
            .map_err(io::Error::other)?;
            stop.cancel();
            task.await.map_err(io::Error::other)??;
            result?;
            let record = crate::manage::store::witness::inspect(&f.server_state, &e.binding_id)?;
            assert_eq!(record.phase, Phase::Confirmed);
            assert_eq!(record.sequence, "1");
            Ok(())
        }
    }
    pub(super) mod worker {
        use super::*;
        use crate::manage::store::users;
        use crate::manage::{policy::Coordinator, store};
        use tokio::time::{Duration, timeout};
        use tokio_util::sync::CancellationToken;

        mod commands {
            use super::*;
            use crate::manage::store::{
                automation,
                operations::{Caller, Input, State, UserChange},
            };
            use zeroize::Zeroizing;

            pub(super) fn entries(live: &Live) -> io::Result<usize> {
                fs::read_dir(live.fixture.client_state.join("witness-intents"))?.try_fold(
                    0_usize,
                    |n, row| {
                        row?;
                        n.checked_add(1).ok_or_else(invalid)
                    },
                )
            }
            pub(super) fn command(
                live: &Live,
                id: u64,
                revision: u64,
                change: users::PolicyChange,
            ) -> store::Command {
                store::Command {
                    target_node_id: live.fixture.client_id.clone(),
                    epoch: 2,
                    command_id: id,
                    expected_policy_revision: revision,
                    source_administrator_id: live.administrator.clone(),
                    change,
                }
            }
            pub(super) fn authorization(live: &Live) -> io::Result<store::RemoteAuthorization> {
                Ok(super::super::baseline(&live.fixture, &live.enrollment)?.authorization)
            }
            fn input(live: &Live, revision: u64) -> Input {
                Input {
                    expected_node_id: Some(live.fixture.client_id.clone()),
                    expected_revision: revision,
                    expected_epoch: 1,
                    change: UserChange::CreateUser {
                        name: "durable source task".into(),
                        protocols: vec![crate::access::Protocol::Http],
                        concurrent_limit: 2,
                    },
                }
            }

            #[tokio::test]
            async fn source_remote_commands_keep_current_authority_metadata_replay_and_applied_receipts()
            -> io::Result<()> {
                let live = Live::new(Default::default()).await?;
                let result = async {
                    assert!(
                        live.source
                            .set_owner(live.fixture.server_id.clone(), 1, None)
                            .await
                            .is_err()
                    );
                    assert_eq!(entries(&live)?, 0);
                    live.source
                        .set_owner(
                            live.administrator.clone(),
                            1,
                            Some(live.fixture.server_id.clone()),
                        )
                        .await?;
                    let auth = authorization(&live)?;
                    let created = live
                        .source
                        .command(authorization(&live)?, command(&live, 1, 1, live.user()))
                        .await?;
                    assert_eq!(created.receipt.status, store::ReceiptStatus::Saved);
                    let user = created.user.ok_or_else(invalid)?.id;
                    let credential_change = || users::PolicyChange::CreateCredential {
                        user_id: user.clone(),
                    };
                    let created = live
                        .source
                        .command(
                            authorization(&live)?,
                            command(&live, 2, 2, credential_change()),
                        )
                        .await?;
                    let credential = created.credential.ok_or_else(invalid)?;
                    let secret = created.secret.ok_or_else(invalid)?;
                    let reader = live.source.reader();
                    let old = reader
                        .authenticate(
                            &credential.login,
                            secret.as_bytes(),
                            crate::access::Protocol::Http,
                        )
                        .map_err(|_| invalid())?;
                    let before = entries(&live)?;
                    let replay = live
                        .source
                        .command(
                            authorization(&live)?,
                            command(&live, 2, 2, credential_change()),
                        )
                        .await?;
                    assert!(
                        replay.replayed
                            && replay.secret.is_none()
                            && replay.user.is_none()
                            && replay.credential.is_none()
                    );
                    assert_eq!(
                        (live.floor()?.sequence, entries(&live)?),
                        ("3".into(), before)
                    );
                    let mut stale = authorization(&live)?;
                    stale.authorization_revision += 1;
                    assert!(
                        live.source
                            .command(stale, command(&live, 2, 2, credential_change()))
                            .await
                            .is_err()
                    );
                    assert!(
                        live.source
                            .command(authorization(&live)?, command(&live, 2, 2, live.user()))
                            .await
                            .is_err()
                    );
                    assert!(
                        live.source
                            .command(authorization(&live)?, command(&live, 4, 3, live.user()))
                            .await
                            .is_err()
                    );
                    assert_eq!(entries(&live)?, before);
                    let rejected = live
                        .source
                        .command(authorization(&live)?, command(&live, 3, 1, live.user()))
                        .await?;
                    assert_eq!(rejected.receipt.status, store::ReceiptStatus::Rejected);
                    assert_eq!(reader.revision()?, 3);
                    let rejected_entries = entries(&live)?;
                    assert!(
                        live.source
                            .command(authorization(&live)?, command(&live, 3, 1, live.user()))
                            .await?
                            .replayed
                    );
                    assert_eq!(
                        (live.floor()?.sequence, entries(&live)?),
                        ("4".into(), rejected_entries)
                    );
                    live.source.activate().await?;
                    let replay = live
                        .source
                        .command(
                            authorization(&live)?,
                            command(&live, 2, 2, credential_change()),
                        )
                        .await?;
                    assert_eq!(replay.receipt.status, store::ReceiptStatus::Applied);
                    assert!(replay.secret.is_none());
                    assert_eq!(live.floor()?.sequence, "5");
                    live.source
                        .set_owner(live.administrator.clone(), 2, None)
                        .await?;
                    assert!(
                        live.source
                            .command(auth, command(&live, 2, 2, credential_change()))
                            .await
                            .is_err()
                    );
                    assert_eq!(live.floor()?.sequence, "6");
                    live.source
                        .change(
                            live.administrator.clone(),
                            3,
                            users::PolicyChange::SetUserActive {
                                id: user,
                                active: false,
                            },
                        )
                        .await?;
                    assert_eq!(
                        (reader.revision()?, live.floor()?.sequence),
                        (4, "8".into())
                    );
                    assert!(matches!(
                        reader.authenticate(
                            &credential.login,
                            secret.as_bytes(),
                            crate::access::Protocol::Http
                        ),
                        Err(crate::access::Error::Denied)
                    ));
                    assert_eq!(reader.admission()?.active_operations, 1);
                    drop(old);
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)
            }

            #[tokio::test]
            async fn source_remote_lost_reserve_or_confirm_requires_original_reconcile_before_readonly_replay()
            -> io::Result<()> {
                for reserve in [true, false] {
                    let live = Live::new(node::tests::CutResponse {
                        witness_reserve: reserve,
                        witness_confirm: !reserve,
                        ..Default::default()
                    })
                    .await?;
                    let result = async {
                        live.source
                            .set_owner(
                                live.administrator.clone(),
                                1,
                                Some(live.fixture.server_id.clone()),
                            )
                            .await?;
                        let auth = authorization(&live)?;
                        let user = live
                            .source
                            .command(authorization(&live)?, command(&live, 1, 1, live.user()))
                            .await?
                            .user
                            .ok_or_else(invalid)?
                            .id;
                        let change = || users::PolicyChange::CreateCredential {
                            user_id: user.clone(),
                        };
                        live.arm();
                        let error = live
                            .source
                            .command(authorization(&live)?, command(&live, 2, 2, change()))
                            .await
                            .err()
                            .ok_or_else(invalid)?;
                        assert_eq!(error.kind(), io::ErrorKind::Other);
                        assert!(live.source.reader().revision().is_err());
                        assert!(
                            live.source
                                .command(authorization(&live)?, command(&live, 2, 2, change()))
                                .await
                                .is_err()
                        );
                        live.source.reconcile_source().await?;
                        let count = entries(&live)?;
                        let replay = live
                            .source
                            .command(auth, command(&live, 2, 2, change()))
                            .await?;
                        assert!(
                            replay.replayed
                                && replay.secret.is_none()
                                && replay.credential.is_none()
                        );
                        assert_eq!(
                            (live.floor()?.sequence, entries(&live)?),
                            ("3".into(), count)
                        );
                        let c = store::peers::open_existing(&live.fixture.client_state, false)?;
                        let credentials: i64 = c
                            .query_row("SELECT count(*) FROM proxy_credentials", [], |r| r.get(0))
                            .map_err(io::Error::other)?;
                        assert_eq!(credentials, 1);
                        Ok(())
                    }
                    .await;
                    let closed = live.close().await;
                    result.and(closed)?;
                }
                Ok(())
            }

            #[tokio::test]
            async fn source_tasks_keep_terminal_results_after_policy_and_owner_changes_without_new_sequence()
            -> io::Result<()> {
                let live = Live::new(Default::default()).await?;
                let result = async {
                    let caller = Caller::Administrator(live.administrator.clone());
                    let first = input(&live, 1);
                    let reserved = live
                        .source
                        .reserve_user_operation(caller.clone(), first.clone())
                        .await?;
                    assert_eq!(reserved.state, State::Reserved);
                    let saved = live
                        .source
                        .execute_user_operation(caller.clone(), reserved.id.clone(), first.clone())
                        .await?;
                    assert_eq!(
                        (saved.state, live.source.reader().revision()?),
                        (State::Saved, 2)
                    );
                    let before = entries(&live)?;
                    let replay = live
                        .source
                        .execute_user_operation(caller.clone(), reserved.id.clone(), first.clone())
                        .await?;
                    assert_eq!(replay, saved);
                    assert_eq!(
                        (live.floor()?.sequence, entries(&live)?),
                        ("2".into(), before)
                    );
                    let mut changed = first.clone();
                    changed.expected_revision = 2;
                    assert!(
                        live.source
                            .execute_user_operation(caller.clone(), reserved.id.clone(), changed)
                            .await
                            .is_err()
                    );
                    assert_eq!(entries(&live)?, before);
                    let second = input(&live, 2);
                    let reserved2 = live
                        .source
                        .reserve_user_operation(caller.clone(), second.clone())
                        .await?;
                    live.source
                        .change(live.administrator.clone(), 2, live.user())
                        .await?;
                    let rejected = live
                        .source
                        .execute_user_operation(
                            caller.clone(),
                            reserved2.id.clone(),
                            second.clone(),
                        )
                        .await?;
                    assert_eq!(rejected.state, State::Rejected);
                    assert_eq!(live.source.reader().revision()?, 3);
                    assert_eq!(live.floor()?.sequence, "5");
                    assert_eq!(
                        live.source
                            .execute_user_operation(caller.clone(), reserved2.id, second)
                            .await?,
                        rejected
                    );
                    let third = input(&live, 3);
                    let reserved3 = live
                        .source
                        .reserve_user_operation(caller.clone(), third.clone())
                        .await?;
                    live.source
                        .set_owner(
                            live.administrator.clone(),
                            1,
                            Some(live.fixture.server_id.clone()),
                        )
                        .await?;
                    let refused = live
                        .source
                        .execute_user_operation(caller.clone(), reserved3.id, third)
                        .await?;
                    assert_eq!(
                        (refused.state, refused.rejection),
                        (State::Rejected, Some("resource_managed"))
                    );
                    assert_eq!(live.floor()?.sequence, "8");
                    assert_eq!(
                        live.source
                            .execute_user_operation(caller, reserved.id, first)
                            .await?,
                        saved
                    );
                    assert_eq!(live.floor()?.sequence, "8");
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)
            }

            #[tokio::test]
            async fn source_machine_and_same_text_administrator_have_separate_task_namespaces()
            -> io::Result<()> {
                let mut machine = None;
                let live = Live::new_with(Default::default(), |f| {
        let mut token = Zeroizing::new(String::new());
        let view = automation::create(&f.client_state, "source machine", automation::Scope::UsersWrite, 3600, |value| { token.push_str(value); Ok(()) })?;
        let credential = Caller::Automation(Arc::new(automation::Credential::parse(&token)?));
        let mut wrong = Zeroizing::new(token.to_string());
        let at = wrong.rfind('.').and_then(|n| n.checked_add(1)).ok_or_else(invalid)?;
        let replacement = if wrong.as_bytes().get(at) == Some(&b'A') { "B" } else { "A" };
        wrong.replace_range(at..at+1, replacement);
        let wrong = Caller::Automation(Arc::new(automation::Credential::parse(&wrong)?));
        let c = store::peers::open_existing(&f.client_state, true)?;
        c.execute("INSERT INTO administrators SELECT ?1,'same-principal-text',password_hash FROM administrators LIMIT 1", [&view.id]).map_err(io::Error::other)?;
        machine = Some((view, credential, wrong));
        Ok(())
    }).await?;
                let (principal, machine, wrong) = machine.ok_or_else(invalid)?;
                let result = async {
                    let administrator = Caller::Administrator(principal.id);
                    let input = input(&live, 1);
                    assert!(
                        live.source
                            .reserve_user_operation(wrong.clone(), input.clone())
                            .await
                            .is_err()
                    );
                    assert_eq!(entries(&live)?, 0);
                    let own = live
                        .source
                        .reserve_user_operation(machine.clone(), input.clone())
                        .await?;
                    let other = live
                        .source
                        .reserve_user_operation(administrator.clone(), input.clone())
                        .await?;
                    assert!(
                        live.source
                            .execute_user_operation(
                                administrator.clone(),
                                own.id.clone(),
                                input.clone()
                            )
                            .await
                            .is_err()
                    );
                    assert!(
                        live.source
                            .execute_user_operation(
                                machine.clone(),
                                other.id.clone(),
                                input.clone()
                            )
                            .await
                            .is_err()
                    );
                    let saved = live
                        .source
                        .execute_user_operation(machine.clone(), own.id.clone(), input.clone())
                        .await?;
                    assert_eq!(saved.state, State::Saved);
                    assert!(
                        live.source
                            .execute_user_operation(wrong, own.id.clone(), input.clone())
                            .await
                            .is_err()
                    );
                    assert_eq!(
                        live.source
                            .execute_user_operation(machine, own.id, input.clone())
                            .await?,
                        saved
                    );
                    assert_eq!(live.floor()?.sequence, "3");
                    assert_eq!(
                        live.source
                            .execute_user_operation(administrator, other.id, input)
                            .await?
                            .state,
                        State::Rejected
                    );
                    assert_eq!(live.floor()?.sequence, "4");
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)
            }

            #[tokio::test]
            async fn silently_ignored_application_receipt_never_reports_running_or_consumes_source_sequence()
            -> io::Result<()> {
                let live = Live::new_with(Default::default(), |f| {
        store::peers::open_existing(&f.client_state, true)?.execute_batch(
            "CREATE TRIGGER fixture_ignore_application BEFORE UPDATE OF status ON control_receipts WHEN NEW.status='applied' BEGIN SELECT RAISE(IGNORE); END;"
        ).map_err(io::Error::other)
    }).await?;
                let result = async {
                    live.source
                        .set_owner(
                            live.administrator.clone(),
                            1,
                            Some(live.fixture.server_id.clone()),
                        )
                        .await?;
                    live.source
                        .command(authorization(&live)?, command(&live, 1, 1, live.user()))
                        .await?;
                    let before = entries(&live)?;
                    assert!(live.source.activate().await.is_err());
                    assert!(!live.source.is_running());
                    assert!(live.source.reader().revision().is_err());
                    let c = store::peers::open_existing(&live.fixture.client_state, false)?;
                    assert_eq!(users::read_state(&c)?, (2, None));
                    assert_eq!(
                        (live.floor()?.sequence, entries(&live)?),
                        ("2".into(), before)
                    );
                    live.source.reconcile_source().await?;
                    assert_eq!(live.source.reader().revision()?, 2);
                    assert!(!live.source.is_running());
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)
            }

            #[test]
            fn source_observation_has_no_intent_but_net_zero_dml_and_ddl_still_refuse()
            -> io::Result<()> {
                use super::super::super::owner::Owner;
                use super::super::driver::Witness;
                let f = node::tests::Fixture::new_with_private_source(true, true)?;
                let e = super::super::enrollment(&f);
                let mut witness = Witness::new(&f, &e)?;
                let a = store::lock(&f.client_state)?;
                let g = store::update_lock(&f.client_state)?;
                let mut c = super::super::source_connection(&f, &a, &g, &e)?;
                let mut owner =
                    Owner::open(super::super::scope(&f, &a, &g, &e), &mut c, &mut |op| {
                        witness.request(op)
                    })?;
                for _ in 0..2 {
                    assert_eq!(
                        owner.run(&mut c, &mut |op| witness.request(op), |tx| {
                            users::read_state(tx)
                        })?,
                        (1, None)
                    );
                }
                let root = f.client_state.join("witness-intents");
                assert_eq!(fs::read_dir(&root)?.count(), 0);
                assert!(
                    owner
                        .run(&mut c, &mut |op| witness.request(op), |_| Err::<(), _>(
                            io::Error::new(io::ErrorKind::InvalidInput, "fixture refusal")
                        ))
                        .is_err()
                );
                assert_eq!(fs::read_dir(&root)?.count(), 0);
                assert!(
                    owner
                        .run(&mut c, &mut |op| witness.request(op), |tx| tx
                            .execute_batch(
                                "CREATE TABLE fixture_untracked(id INTEGER PRIMARY KEY) STRICT;"
                            )
                            .map_err(io::Error::other))
                        .is_err()
                );
                assert_eq!(fs::read_dir(&root)?.count(), 0);
                owner.reconcile(&mut c, &mut |op| witness.request(op))?;
                let mut ran = false;
                assert!(owner.run(&mut c, &mut |op| witness.request(op), |tx| {
        ran = true;
        tx.execute_batch("UPDATE administrators SET password_hash='temporary'; UPDATE administrators SET password_hash='fixture-phc';").map_err(io::Error::other)
    }).is_err());
                assert!(ran);
                owner.reconcile(&mut c, &mut |op| witness.request(op))?;
                assert_eq!((witness.reserves, witness.confirms), (0, 0));
                assert_eq!(owner.reader().revision()?, 1);
                assert_eq!(super::super::verifier(&c)?, "fixture-phc");
                Ok(())
            }
        }
        mod endpoints {
            use super::*;
            use crate::manage::{
                proxy::{ListenerView, Protocol},
                store::{
                    endpoint_control,
                    endpoints::{AddressSelection, Change, Inventory, State},
                },
            };

            fn listener() -> ListenerView {
                ListenerView {
                    protocol: Protocol::Http,
                    bind: ([127, 0, 0, 1], 18080).into(),
                    public_address: Some("default.example:18080".into()),
                }
            }

            async fn configure(live: &Live) -> io::Result<State> {
                live.source.configure_endpoints(vec![listener()])?;
                live.source
                    .configure_endpoint_settings(&live.fixture.client_id)
                    .await?;
                store::endpoints::read(&live.fixture.client_state)
            }

            fn declaration(live: &Live, selection: AddressSelection) -> io::Result<Change> {
                let inventory = live.source.endpoint_inventory()?;
                Ok(Change {
                    listener_id: inventory.listeners[0].id.clone(),
                    selection,
                })
            }

            fn command(
                live: &Live,
                id: u64,
                state: &State,
            ) -> io::Result<endpoint_control::Command> {
                Ok(endpoint_control::Command {
                    target_node_id: live.fixture.client_id.clone(),
                    epoch: 2,
                    command_id: id,
                    expected_metadata_revision: state.revision,
                    source_administrator_id: live.administrator.clone(),
                    generation: state.digest.clone(),
                    change: declaration(live, AddressSelection::Hidden)?,
                })
            }

            fn conflict(error: io::Error) {
                assert!(matches!(
                    error
                        .get_ref()
                        .and_then(|e| e.downcast_ref::<store::ControlError>()),
                    Some(store::ControlError::CommandConflict)
                ));
            }

            #[tokio::test]
            async fn source_local_endpoint_declarations_keep_policy_receipts_and_old_leases_unchanged()
            -> io::Result<()> {
                let live = Live::new(Default::default()).await?;
                let result = async {
                    let state = configure(&live).await?;
                    assert_eq!((state.revision, live.floor()?.sequence), (2, "1".into()));
                    let user = live
                        .source
                        .change(live.administrator.clone(), 1, live.user())
                        .await?
                        .user
                        .ok_or_else(invalid)?
                        .id;
                    let created = live
                        .source
                        .change(
                            live.administrator.clone(),
                            2,
                            users::PolicyChange::CreateCredential { user_id: user },
                        )
                        .await?;
                    let credential = created.credential.ok_or_else(invalid)?;
                    let secret = created.secret.ok_or_else(invalid)?;
                    live.source.activate().await?;
                    let reader = live.source.reader();
                    let lease = reader
                        .authenticate(
                            &credential.login,
                            secret.as_bytes(),
                            crate::access::Protocol::Http,
                        )
                        .map_err(|_| invalid())?;
                    let before = live.floor()?.sequence;
                    let files = commands::entries(&live)?;
                    for (administrator, revision, generation) in [
                        (
                            live.fixture.server_id.clone(),
                            state.revision,
                            state.digest.clone(),
                        ),
                        (live.administrator.clone(), 1, state.digest.clone()),
                        (live.administrator.clone(), state.revision, "a".repeat(64)),
                    ] {
                        assert!(
                            live.source
                                .endpoint_change(
                                    administrator,
                                    revision,
                                    generation,
                                    declaration(&live, AddressSelection::Hidden)?
                                )
                                .await
                                .is_err()
                        );
                    }
                    assert_eq!(
                        (live.floor()?.sequence, commands::entries(&live)?),
                        (before, files)
                    );
                    let state = live
                        .source
                        .endpoint_change(
                            live.administrator.clone(),
                            state.revision,
                            state.digest,
                            declaration(
                                &live,
                                AddressSelection::Custom {
                                    public_address: "PROXY.Example:443".into(),
                                },
                            )?,
                        )
                        .await?;
                    assert_eq!(
                        state.overrides[0].selection,
                        AddressSelection::Custom {
                            public_address: "proxy.example:443".into(),
                        }
                    );
                    let state = live
                        .source
                        .endpoint_change(
                            live.administrator.clone(),
                            state.revision,
                            state.digest,
                            declaration(&live, AddressSelection::Hidden)?,
                        )
                        .await?;
                    // A successful same-value declaration still has its own metadata audit.
                    let repeated = live
                        .source
                        .endpoint_change(
                            live.administrator.clone(),
                            state.revision,
                            state.digest.clone(),
                            declaration(&live, AddressSelection::Hidden)?,
                        )
                        .await?;
                    assert_eq!(repeated.revision, state.revision + 1);
                    let catalog = live
                        .source
                        .effective_endpoints(&live.fixture.client_id)
                        .await?;
                    assert!(catalog.proxy_running && catalog.listeners[0].public_address.is_none());
                    let status = live.source.status().await?;
                    assert_eq!(
                        (status.saved_revision, status.durable_applied_revision),
                        (3, Some(3))
                    );
                    assert_eq!(
                        (reader.revision()?, reader.admission()?.active_operations),
                        (3, 1)
                    );
                    let c = store::peers::open_existing(&live.fixture.client_state, false)?;
                    let audit: i64 = c
                        .query_row("SELECT count(*) FROM endpoint_audit", [], |r| r.get(0))
                        .map_err(io::Error::other)?;
                    assert_eq!(audit, 3);
                    drop(lease);
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)
            }

            #[tokio::test]
            async fn source_restart_syncs_only_startup_metadata_and_retains_detached_overrides()
            -> io::Result<()> {
                let live = Live::new(Default::default()).await?;
                let result = async {
                    let state = configure(&live).await?;
                    let id = declaration(&live, AddressSelection::Hidden)?.listener_id;
                    live.source
                        .endpoint_change(
                            live.administrator.clone(),
                            state.revision,
                            state.digest,
                            declaration(&live, AddressSelection::Hidden)?,
                        )
                        .await?;
                    live.source.shutdown_writer().await?;
                    // Restart the same private source, identity, enrollment and mTLS peer.
                    let resumed = Coordinator::new_source(
                        live.fixture.client_state.clone(),
                        live.author.clone(),
                        live.enrollment.clone(),
                        live.endpoint.clone(),
                        tls::node_identity(
                            &live.fixture.ca,
                            &live.fixture.client_cert,
                            &live.fixture.client_key,
                        )?,
                    )
                    .await?;
                    let result = async {
                        let mut changed = listener();
                        changed.bind.set_port(18081);
                        resumed.configure_endpoints(vec![changed])?;
                        resumed
                            .configure_endpoint_settings(&live.fixture.client_id)
                            .await?;
                        let settings = resumed.endpoint_settings(&live.fixture.client_id).await?;
                        settings.validate(&live.fixture.client_id)?;
                        assert_eq!(settings.revision, "4");
                        assert_eq!(settings.detached[0].id, id);
                        assert!(!settings.proxy_running);
                        assert_eq!(
                            (resumed.reader().revision()?, live.floor()?.sequence),
                            (1, "3".into())
                        );
                        // The second setup attempt observes the same digest without writing,
                        // then refuses replacing the process-local OnceLock.
                        let files = commands::entries(&live)?;
                        assert_eq!(
                            resumed
                                .configure_endpoint_settings(&live.fixture.client_id)
                                .await
                                .err()
                                .map(|e| e.kind()),
                            Some(io::ErrorKind::AlreadyExists)
                        );
                        assert_eq!(
                            (live.floor()?.sequence, commands::entries(&live)?),
                            ("3".into(), files)
                        );
                        let next = resumed
                            .endpoint_change(
                                live.administrator.clone(),
                                4,
                                settings.generation,
                                Change {
                                    listener_id: id,
                                    selection: AddressSelection::Inherit,
                                },
                            )
                            .await?;
                        assert!(next.overrides.is_empty());
                        assert_eq!((next.revision, resumed.reader().revision()?), (5, 1));
                        Ok(())
                    }
                    .await;
                    let stopped = resumed.shutdown_writer().await;
                    result.and(stopped)
                }
                .await;
                let closed = live.close().await;
                result.and(closed)
            }

            #[tokio::test]
            async fn source_endpoint_and_policy_commands_share_order_without_mixing_receipt_domains()
            -> io::Result<()> {
                let live = Live::new(Default::default()).await?;
                let result = async {
                    let state = configure(&live).await?;
                    live.source
                        .set_owner(
                            live.administrator.clone(),
                            1,
                            Some(live.fixture.server_id.clone()),
                        )
                        .await?;
                    let first = command(&live, 1, &state)?;
                    let result = live
                        .source
                        .endpoint_command(commands::authorization(&live)?, first.clone())
                        .await?;
                    assert!(!result.replayed);
                    assert_eq!(result.receipt.metadata_revision, Some(3));
                    assert_eq!(live.source.reader().revision()?, 1);
                    conflict(
                        live.source
                            .command(
                                commands::authorization(&live)?,
                                commands::command(&live, 1, 1, live.user()),
                            )
                            .await
                            .err()
                            .ok_or_else(invalid)?,
                    );
                    live.source
                        .command(
                            commands::authorization(&live)?,
                            commands::command(&live, 2, 1, live.user()),
                        )
                        .await?;
                    conflict(
                        live.source
                            .endpoint_command(
                                commands::authorization(&live)?,
                                command(&live, 2, &state)?,
                            )
                            .await
                            .err()
                            .ok_or_else(invalid)?,
                    );
                    let before = commands::entries(&live)?;
                    assert!(
                        live.source
                            .endpoint_command(
                                commands::authorization(&live)?,
                                command(&live, 4, &state)?
                            )
                            .await
                            .is_err()
                    );
                    let mut stale = commands::authorization(&live)?;
                    stale.authorization_revision += 1;
                    assert!(
                        live.source
                            .endpoint_command(stale, first.clone())
                            .await
                            .is_err()
                    );
                    let mut changed = first.clone();
                    changed.change.selection = AddressSelection::Inherit;
                    conflict(
                        live.source
                            .endpoint_command(commands::authorization(&live)?, changed)
                            .await
                            .err()
                            .ok_or_else(invalid)?,
                    );
                    assert_eq!(commands::entries(&live)?, before);
                    let rejection = command(&live, 3, &state)?;
                    let rejected = live
                        .source
                        .endpoint_command(commands::authorization(&live)?, rejection.clone())
                        .await?;
                    assert_eq!(
                        rejected.receipt.rejection,
                        Some("endpoint_revision_changed")
                    );
                    let before = commands::entries(&live)?;
                    assert!(
                        live.source
                            .endpoint_command(commands::authorization(&live)?, rejection)
                            .await?
                            .replayed
                    );
                    let replay = live
                        .source
                        .endpoint_command(commands::authorization(&live)?, first.clone())
                        .await?;
                    assert!(replay.replayed);
                    assert_eq!(replay.receipt, result.receipt);
                    assert_eq!(
                        (commands::entries(&live)?, live.floor()?.sequence),
                        (before, "5".into())
                    );
                    live.source.activate().await?;
                    let receipt = endpoint_control::receipt(
                        &live.fixture.client_state,
                        &commands::authorization(&live)?,
                        2,
                        1,
                    )?;
                    assert_eq!(receipt, result.receipt);
                    assert_eq!(
                        live.source.status().await?.durable_applied_revision,
                        Some(2)
                    );
                    live.source
                        .set_owner(live.administrator.clone(), 2, None)
                        .await?;
                    let before = commands::entries(&live)?;
                    assert!(
                        live.source
                            .endpoint_command(commands::authorization(&live)?, first)
                            .await
                            .is_err()
                    );
                    assert_eq!(commands::entries(&live)?, before);
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)
            }

            #[tokio::test]
            async fn lost_source_startup_and_endpoint_responses_require_exact_reconcile_not_reexecution()
            -> io::Result<()> {
                for reserve in [true, false] {
                    let live = Live::new(node::tests::CutResponse {
                        witness_reserve: reserve,
                        witness_confirm: !reserve,
                        ..Default::default()
                    })
                    .await?;
                    let result = async {
                        live.source.configure_endpoints(vec![listener()])?;
                        live.arm();
                        assert_eq!(
                            live.source
                                .configure_endpoint_settings(&live.fixture.client_id)
                                .await
                                .err()
                                .map(|e| e.kind()),
                            Some(io::ErrorKind::Other)
                        );
                        assert!(live.source.endpoint_inventory().is_err());
                        assert!(live.source.reader().revision().is_err());
                        assert!(
                            live.source
                                .configure_endpoint_settings(&live.fixture.client_id)
                                .await
                                .is_err()
                        );
                        live.source.reconcile_source().await?;
                        let before = commands::entries(&live)?;
                        live.source
                            .configure_endpoint_settings(&live.fixture.client_id)
                            .await?;
                        assert_eq!(
                            (commands::entries(&live)?, live.floor()?.sequence),
                            (before, "1".into())
                        );
                        let state = store::endpoints::read(&live.fixture.client_state)?;
                        live.source
                            .set_owner(
                                live.administrator.clone(),
                                1,
                                Some(live.fixture.server_id.clone()),
                            )
                            .await?;
                        let original = command(&live, 1, &state)?;
                        live.arm();
                        assert_eq!(
                            live.source
                                .endpoint_command(commands::authorization(&live)?, original.clone())
                                .await
                                .err()
                                .map(|e| e.kind()),
                            Some(io::ErrorKind::Other)
                        );
                        assert!(live.source.reader().revision().is_err());
                        assert!(
                            live.source
                                .endpoint_command(commands::authorization(&live)?, original.clone())
                                .await
                                .is_err()
                        );
                        live.source.reconcile_source().await?;
                        let before = commands::entries(&live)?;
                        let result = live
                            .source
                            .endpoint_command(commands::authorization(&live)?, original)
                            .await?;
                        assert!(result.replayed);
                        assert_eq!(result.receipt.metadata_revision, Some(3));
                        assert_eq!(
                            (commands::entries(&live)?, live.floor()?.sequence),
                            (before, "3".into())
                        );
                        let c = store::peers::open_existing(&live.fixture.client_state, false)?;
                        let audit: i64 = c
                            .query_row("SELECT count(*) FROM endpoint_audit", [], |r| r.get(0))
                            .map_err(io::Error::other)?;
                        assert_eq!(audit, 1);
                        assert_eq!(users::read_state(&c)?, (1, None));
                        assert_eq!(live.source.reader().revision()?, 1);
                        assert_eq!(live.fault.cuts.load(Ordering::Acquire), 2);
                        // The inventory's identity is still startup-owned, not read back
                        // from the remote command or persisted override as a new listener.
                        let inventory =
                            Inventory::from_views(&live.fixture.client_id, &[listener()])?;
                        assert_eq!(live.source.endpoint_inventory()?, inventory);
                        Ok(())
                    }
                    .await;
                    let closed = live.close().await;
                    result.and(closed)?;
                }
                Ok(())
            }
        }
        mod identities {
            //! File-author Source execution with real loopback mTLS. This does not wire a
            //! public offline CLI, create an administrator permission or start Source serve.

            use super::*;
            use crate::manage::{files, store::automation};
            use std::{path::PathBuf, sync::atomic::AtomicUsize};
            use zeroize::Zeroizing;

            async fn write<T: Send + 'static, R: Send + 'static>(
                live: &Live,
                operation: impl FnOnce(&mut store::identities::Writer<'_>) -> io::Result<T>
                + Send
                + 'static,
                finish: impl FnOnce(T) -> io::Result<R> + Send + 'static,
            ) -> io::Result<R> {
                live.source
                    .source_identity_write_then(live.author.clone(), operation, finish)
                    .await
            }

            fn scalar(live: &Live, sql: &str) -> io::Result<i64> {
                Connection::open(live.fixture.client_state.join("management.sqlite3"))
                    .map_err(io::Error::other)?
                    .query_row(sql, [], |r| r.get(0))
                    .map_err(io::Error::other)
            }

            fn output(live: &Live) -> io::Result<PathBuf> {
                let dir = live.fixture.client_state.join("identity-output");
                files::create_directory(&dir)?;
                Ok(dir)
            }

            fn key(path: &std::path::Path) -> io::Result<automation::Credential> {
                let bytes = files::read(path, 128, true)?;
                automation::Credential::parse(
                    std::str::from_utf8(&bytes).map_err(io::Error::other)?,
                )
            }

            async fn idle(live: &Live) -> io::Result<()> {
                timeout(Duration::from_secs(15), async {
                    while live.source.write_work().available_permits() != 1 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .map_err(io::Error::other)
            }

            #[tokio::test]
            async fn source_file_peer_cas_tombstones_and_bound_witness_channel_remain_authorized()
            -> io::Result<()> {
                let live = Live::new(Default::default()).await?;
                let result = async {
                    let audit_before = scalar(&live, "SELECT count(*) FROM peer_audit")?;
                    let id = store::random_id()?;
                    let cert = rcgen::generate_simple_self_signed(vec!["peer.example".into()])
                        .map_err(io::Error::other)?;
                    let der = cert.cert.der().to_vec();
                    let (peer, leaf) = (id.clone(), der.clone());
                    let first = write(
                        &live,
                        move |w| w.register_peer(&peer, "source peer", &leaf, "peer.example", None),
                        Ok,
                    )
                    .await?;
                    assert_eq!(first.authorization_revision, 1);
                    for (expected, active) in [(1, false), (2, true)] {
                        let peer = id.clone();
                        write(
                            &live,
                            move |w| w.set_peer_active(&peer, expected, active),
                            Ok,
                        )
                        .await?;
                    }
                    let (peer, leaf) = (id.clone(), der.clone());
                    let changed = write(
                        &live,
                        move |w| w.register_peer(&peer, "renamed", &leaf, "peer.example", Some(3)),
                        Ok,
                    )
                    .await?;
                    assert_eq!(changed.authorization_revision, 4);
                    let leaf = der.clone();
                    assert_eq!(
                        write(&live, move |w| w.revoke_certificate(&leaf, 4), Ok)
                            .await?
                            .authorization_revision,
                        5
                    );
                    let (peer, leaf) = (id, der);
                    assert_eq!(
                        write(
                            &live,
                            move |w| w.register_peer(
                                &peer,
                                "revive",
                                &leaf,
                                "peer.example",
                                Some(5)
                            ),
                            Ok
                        )
                        .await
                        .err()
                        .map(|e| e.kind()),
                        Some(io::ErrorKind::AlreadyExists)
                    );
                    assert_eq!(live.floor()?.sequence, "5");
                    let witness = live.fixture.server_id.clone();
                    assert_eq!(
                        write(&live, move |w| w.set_peer_active(&witness, 1, false), Ok)
                            .await
                            .err()
                            .map(|e| e.kind()),
                        Some(io::ErrorKind::PermissionDenied)
                    );
                    let leaf: Vec<u8> =
                        Connection::open(live.fixture.client_state.join("management.sqlite3"))
                            .map_err(io::Error::other)?
                            .query_row(
                                "SELECT der FROM peer_certificates WHERE node_id=?1 AND revoked=0",
                                [&live.fixture.server_id],
                                |r| r.get(0),
                            )
                            .map_err(io::Error::other)?;
                    assert_eq!(
                        write(&live, move |w| w.revoke_certificate(&leaf, 1), Ok)
                            .await
                            .err()
                            .map(|e| e.kind()),
                        Some(io::ErrorKind::PermissionDenied)
                    );
                    assert_eq!(live.floor()?.sequence, "5");
                    assert_eq!(live.source.reader().revision()?, 1);
                    assert_eq!(
                        scalar(&live, "SELECT count(*) FROM peer_audit")?,
                        audit_before.checked_add(5).ok_or_else(invalid)?
                    );
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)
            }

            #[tokio::test]
            async fn source_file_identity_rejects_foreign_author_and_running_service_before_business()
            -> io::Result<()> {
                let live = Live::new(Default::default()).await?;
                let result = async {
                    let dir = live.fixture.client_state.join("unrelated-author");
                    store::initialize(&dir, "other author", "admin", "synthetic PHC")?;
                    let wrong = Arc::new(store::lock(&dir)?);
                    let called = Arc::new(AtomicUsize::new(0));
                    let count = called.clone();
                    assert_eq!(
                        live.source
                            .source_identity_write_then(
                                wrong,
                                move |_w| {
                                    count.fetch_add(1, Ordering::AcqRel);
                                    Ok(())
                                },
                                Ok
                            )
                            .await
                            .err()
                            .map(|e| e.kind()),
                        Some(io::ErrorKind::PermissionDenied)
                    );
                    live.source.activate().await?;
                    let before = live.floor()?.sequence;
                    let count = called.clone();
                    assert_eq!(
                        write(
                            &live,
                            move |_w| {
                                count.fetch_add(1, Ordering::AcqRel);
                                Ok(())
                            },
                            Ok
                        )
                        .await
                        .err()
                        .map(|e| e.kind()),
                        Some(io::ErrorKind::PermissionDenied)
                    );
                    assert_eq!(called.load(Ordering::Acquire), 0);
                    assert_eq!(live.floor()?.sequence, before);
                    live.source.deactivate();
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)
            }

            #[tokio::test]
            async fn source_automation_cancelled_wait_delivers_only_confirmed_private_key_and_rotates_exactly()
            -> io::Result<()> {
                let pause = Arc::new(node::tests::ResponsePause::default());
                let live = Live::new(node::tests::CutResponse {
                    witness_only: true,
                    witness_confirm: true,
                    witness_sequence: Some(1),
                    pause: Some(pause.clone()),
                    ..Default::default()
                })
                .await?;
                let result = async {
                    let dir = output(&live)?;
                    let path = dir.join("first");
                    live.arm();
                    let saved = dir.clone();
                    let mut request = Box::pin(write(
                        &live,
                        |w| {
                            w.create_automation(
                                "source automation",
                                automation::Scope::UsersWrite,
                                3600,
                            )
                        },
                        move |issued| {
                            issued.deliver(|token| files::write(&saved, "first", token.as_bytes()))
                        },
                    ));
                    assert!(futures_util::poll!(&mut request).is_pending());
                    timeout(Duration::from_secs(15), pause.entered.notified())
                        .await
                        .map_err(io::Error::other)?;
                    assert!(!path.exists());
                    assert_eq!(live.source.write_work().available_permits(), 0);
                    drop(request);
                    pause.release.notify_one();
                    idle(&live).await?;
                    let old = key(&path)?;
                    assert!(
                        automation::list_users(&live.fixture.client_state, &old, false, None, 1)
                            .is_ok()
                    );
                    let first = automation::list(&live.fixture.client_state)?
                        .pop()
                        .ok_or_else(invalid)?;
                    let id = first.id.clone();
                    let saved = dir.clone();
                    let second = write(
                        &live,
                        move |w| w.rotate_automation(&id, 1, 3600),
                        move |issued| {
                            issued.deliver(|token| files::write(&saved, "second", token.as_bytes()))
                        },
                    )
                    .await?;
                    assert_eq!((second.generation, second.scope), (2, "users:write"));
                    assert!(
                        automation::list_users(&live.fixture.client_state, &old, false, None, 1)
                            .is_err()
                    );
                    let current = key(&dir.join("second"))?;
                    assert!(
                        automation::list_users(
                            &live.fixture.client_state,
                            &current,
                            false,
                            None,
                            1
                        )
                        .is_ok()
                    );
                    for _ in 0..2 {
                        let id = second.id.clone();
                        assert!(
                            write(&live, move |w| w.revoke_automation(&id, 2), Ok)
                                .await?
                                .revoked
                        );
                    }
                    assert!(
                        automation::list_users(
                            &live.fixture.client_state,
                            &current,
                            false,
                            None,
                            1
                        )
                        .is_err()
                    );
                    assert_eq!(live.floor()?.sequence, "3");
                    assert_eq!(scalar(&live, "SELECT count(*) FROM automation_audit")?, 3);
                    let failure = write(
                        &live,
                        |w| {
                            w.create_automation("failed output", automation::Scope::UsersRead, 3600)
                        },
                        |issued| {
                            issued.deliver(|_| {
                                Err(io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    "synthetic output failure",
                                ))
                            })
                        },
                    )
                    .await
                    .err()
                    .ok_or_else(invalid)?;
                    assert_eq!(failure.kind(), io::ErrorKind::Other);
                    assert!(
                        failure
                            .get_ref()
                            .is_some_and(|cause| cause.is::<automation::OutputError>())
                    );
                    assert!(!store::journal::is_uncertain(&failure));
                    assert_eq!(live.floor()?.sequence, "4");
                    assert_eq!(live.source.reader().revision()?, 1);
                    assert_eq!(scalar(&live, "SELECT count(*) FROM automation_audit")?, 4);
                    Ok(())
                }
                .await;
                pause.release.notify_one();
                let closed = live.close().await;
                result.and(closed)
            }

            #[tokio::test]
            async fn source_automation_unknown_issue_or_rotation_never_recreates_or_delivers_lost_secret()
            -> io::Result<()> {
                for reserve in [true, false] {
                    for rotation in [false, true] {
                        let sequence = if rotation { 2 } else { 1 };
                        let live = Live::new(node::tests::CutResponse {
                            witness_only: true,
                            witness_reserve: reserve,
                            witness_confirm: !reserve,
                            witness_sequence: Some(sequence),
                            ..Default::default()
                        })
                        .await?;
                        let result = async {
                            let dir = output(&live)?;
                            let existing = if rotation {
                                let saved = dir.clone();
                                Some(
                                    write(
                                        &live,
                                        |w| {
                                            w.create_automation(
                                                "source automation",
                                                automation::Scope::UsersRead,
                                                3600,
                                            )
                                        },
                                        move |issued| {
                                            issued.deliver(|token| {
                                                files::write(&saved, "old", token.as_bytes())
                                            })
                                        },
                                    )
                                    .await?,
                                )
                            } else {
                                None
                            };
                            let called = Arc::new(AtomicUsize::new(0));
                            let count = called.clone();
                            let saved = dir.clone();
                            live.arm();
                            assert!(
                                write(
                                    &live,
                                    move |w| match existing {
                                        Some(view) => w.rotate_automation(&view.id, 1, 3600),
                                        None => w.create_automation(
                                            "source automation",
                                            automation::Scope::UsersRead,
                                            3600
                                        ),
                                    },
                                    move |issued| issued.deliver(|token| {
                                        count.fetch_add(1, Ordering::AcqRel);
                                        files::write(&saved, "lost", token.as_bytes())
                                    })
                                )
                                .await
                                .is_err()
                            );
                            assert!(!dir.join("lost").exists());
                            assert_eq!(called.load(Ordering::Acquire), 0);
                            live.source.reconcile_source().await?;
                            assert_eq!(called.load(Ordering::Acquire), 0);
                            assert!(!dir.join("lost").exists());
                            let view = automation::list(&live.fixture.client_state)?
                                .pop()
                                .ok_or_else(invalid)?;
                            assert_eq!(view.generation, sequence);
                            if rotation {
                                assert!(
                                    automation::list_users(
                                        &live.fixture.client_state,
                                        &key(&dir.join("old"))?,
                                        false,
                                        None,
                                        1
                                    )
                                    .is_err()
                                );
                            }
                            assert_eq!(
                                scalar(&live, "SELECT count(*) FROM automation_audit")?,
                                i64::try_from(sequence).map_err(io::Error::other)?
                            );
                            assert_eq!(live.floor()?.sequence, sequence.to_string());
                            Ok(())
                        }
                        .await;
                        let closed = live.close().await;
                        result.and(closed)?;
                    }
                }
                Ok(())
            }

            #[tokio::test]
            async fn source_offline_password_recovery_keeps_prechange_backup_and_original_unknown_audit()
            -> io::Result<()> {
                for reserve in [true, false] {
                    let live = Live::new(node::tests::CutResponse {
                        witness_only: true,
                        witness_reserve: reserve,
                        witness_confirm: !reserve,
                        witness_sequence: Some(1),
                        ..Default::default()
                    })
                    .await?;
                    let result=async {
            let c=Connection::open(live.fixture.client_state.join("management.sqlite3")).map_err(io::Error::other)?;
            let (name,old):(String,String)=c.query_row("SELECT username,password_hash FROM administrators",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(io::Error::other)?;
            let old=Zeroizing::new(old);
            drop(c);
            let dir=output(&live)?;
            let rejected=live.fixture.client_state.join("blocked-backup.sqlite3");
            let (saved,actor)=(rejected.clone(),name.clone());
            assert_eq!(write(&live,move |w|w.reset_password(&actor,"synthetic new PHC",&saved),Ok).await.err().map(|e|e.kind()),Some(io::ErrorKind::PermissionDenied));
            assert!(!rejected.exists());
            let backup=dir.join("prechange.sqlite3");
            let (saved,actor)=(backup.clone(),name.clone());
            live.arm();
            let failure=write(&live,move |w|w.reset_password(&actor,"synthetic new PHC",&saved),Ok).await.err().ok_or_else(invalid)?;
            if !store::journal::is_uncertain(&failure) {return Err(failure);}
            assert!(backup.is_file());
            let prior=Connection::open(&backup).map_err(io::Error::other)?;
            let copied=Zeroizing::new(prior.query_row("SELECT password_hash FROM administrators",[],|r|r.get::<_,String>(0)).map_err(io::Error::other)?);
            assert_eq!(*copied,*old);
            drop(prior);
            live.source.reconcile_source().await?;
            assert_eq!(scalar(&live,"SELECT count(*) FROM administrator_audit WHERE entry='offline' AND action='reset_password'")?,1);
            let current=Connection::open(live.fixture.client_state.join("management.sqlite3")).map_err(io::Error::other)?;
            assert_eq!(current.query_row("SELECT password_hash FROM administrators",[],|r|r.get::<_,String>(0)).map_err(io::Error::other)?,"synthetic new PHC");
            drop(current);
            let (saved,actor)=(backup.clone(),name);
            assert_eq!(write(&live,move |w|w.reset_password(&actor,"another PHC",&saved),Ok).await.err().map(|e|e.kind()),Some(io::ErrorKind::AlreadyExists));
            assert_eq!(live.floor()?.sequence,"1");
            assert_eq!(live.source.reader().revision()?,1);
            Ok(())
        }.await;
                    let closed = live.close().await;
                    result.and(closed)?;
                }
                Ok(())
            }
        }
        mod owners {
            //! File-author ownership shares its original CAS/audit kernel. Real upstream
            //! mTLS confirms before output; no new HTTP capability or CLI route is created.
            use super::*;
            use std::sync::atomic::AtomicUsize;

            async fn change(
                live: &Live,
                expected: u64,
                controller: Option<String>,
            ) -> io::Result<store::Ownership> {
                live.source
                    .source_identity_write_then(
                        live.author.clone(),
                        move |w| w.set_owner(expected, controller.as_deref()),
                        Ok,
                    )
                    .await
            }
            fn audit(live: &Live) -> io::Result<i64> {
                Connection::open(live.fixture.client_state.join("management.sqlite3")).map_err(io::Error::other)?
        .query_row("SELECT count(*) FROM control_audit WHERE action='set_owner_offline' AND administrator_id IS NULL AND source_administrator_id IS NULL AND command_id IS NULL AND rejection IS NULL", [], |r|r.get(0)).map_err(io::Error::other)
            }

            #[tokio::test]
            async fn source_file_owner_keeps_distinct_authority_cas_epoch_and_restart()
            -> io::Result<()> {
                let mut live = Live::new(Default::default()).await?;
                let result = async {
                    for expected in [1, 2] {
                        let saved =
                            change(&live, expected, Some(live.fixture.server_id.clone())).await?;
                        assert_eq!(saved.epoch, expected + 1);
                        assert_eq!(
                            saved.controller_node_id.as_deref(),
                            Some(live.fixture.server_id.as_str())
                        );
                        assert_eq!(saved.last_terminal_command, 0);
                        assert_eq!(live.floor()?.sequence, expected.to_string());
                    }
                    let prior = live.floor()?;
                    for (expected, peer) in [
                        (1, Some(live.fixture.server_id.clone())),
                        (3, Some("invalid".into())),
                        (3, Some(live.fixture.client_id.clone())),
                    ] {
                        assert!(change(&live, expected, peer).await.is_err());
                        assert_eq!(live.floor()?, prior);
                        assert_eq!(audit(&live)?, 2);
                    }
                    let saved = change(&live, 3, None).await?;
                    assert_eq!((saved.epoch, saved.last_terminal_command), (4, 0));
                    assert!(saved.controller_node_id.is_none());
                    assert_eq!(live.floor()?.sequence, "3");
                    assert_eq!(audit(&live)?, 3);
                    live.restart_source().await?;
                    assert_eq!(live.source.ownership().await?, saved);
                    assert_eq!(live.source.reader().revision()?, 1);
                    assert_eq!(audit(&live)?, 3);
                    Ok(())
                }
                .await;
                result.and(live.close().await)
            }

            #[tokio::test]
            async fn source_file_owner_lost_reply_reconciles_original_without_double_epoch_or_audit()
            -> io::Result<()> {
                for reserve in [true, false] {
                    let live = Live::new(node::tests::CutResponse {
                        witness_only: true,
                        witness_reserve: reserve,
                        witness_confirm: !reserve,
                        witness_sequence: Some(1),
                        ..Default::default()
                    })
                    .await?;
                    let result = async {
                        live.arm();
                        let error = change(&live, 1, Some(live.fixture.server_id.clone()))
                            .await
                            .err()
                            .ok_or_else(invalid)?;
                        assert!(store::journal::is_uncertain(&error));
                        let original = live.floor()?;
                        assert!(
                            change(&live, 1, Some(live.fixture.server_id.clone()))
                                .await
                                .is_err()
                        );
                        assert_eq!(live.floor()?, original);
                        live.source.reconcile_source().await?;
                        let saved = live.source.ownership().await?;
                        assert_eq!(saved.epoch, 2);
                        assert_eq!(
                            saved.controller_node_id.as_deref(),
                            Some(live.fixture.server_id.as_str())
                        );
                        assert_eq!(audit(&live)?, 1);
                        assert_eq!(live.floor()?.sequence, "1");
                        assert!(
                            change(&live, 1, Some(live.fixture.server_id.clone()))
                                .await
                                .is_err()
                        );
                        assert_eq!(live.floor()?.sequence, "1");
                        assert_eq!(audit(&live)?, 1);
                        assert_eq!(live.source.reader().revision()?, 1);
                        Ok(())
                    }
                    .await;
                    result.and(live.close().await)?;
                }
                Ok(())
            }

            #[tokio::test]
            async fn source_file_owner_cancelled_wait_retains_permit_and_publishes_only_after_confirmation()
            -> io::Result<()> {
                let pause = Arc::new(node::tests::ResponsePause::default());
                let live = Live::new(node::tests::CutResponse {
                    witness_only: true,
                    witness_confirm: true,
                    witness_sequence: Some(1),
                    pause: Some(pause.clone()),
                    ..Default::default()
                })
                .await?;
                let result = async {
                    let delivered = Arc::new(AtomicUsize::new(0));
                    let finish = delivered.clone();
                    let peer = live.fixture.server_id.clone();
                    live.arm();
                    let mut waiting = Box::pin(live.source.source_identity_write_then(
                        live.author.clone(),
                        move |w| w.set_owner(1, Some(&peer)),
                        move |owner| {
                            finish.fetch_add(1, Ordering::AcqRel);
                            Ok(owner)
                        },
                    ));
                    assert!(futures_util::poll!(&mut waiting).is_pending());
                    timeout(Duration::from_secs(15), pause.entered.notified())
                        .await
                        .map_err(io::Error::other)?;
                    assert_eq!(delivered.load(Ordering::Acquire), 0);
                    assert_eq!(live.source.write_work().available_permits(), 0);
                    assert!(store::update_lock(&live.fixture.client_state).is_err());
                    drop(waiting);
                    pause.release.notify_one();
                    timeout(Duration::from_secs(15), async {
                        while live.source.write_work().available_permits() != 1 {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .map_err(io::Error::other)?;
                    assert_eq!(delivered.load(Ordering::Acquire), 1);
                    assert_eq!(live.source.ownership().await?.epoch, 2);
                    assert_eq!(live.floor()?.sequence, "1");
                    assert_eq!(audit(&live)?, 1);
                    assert_eq!(live.source.reader().revision()?, 1);
                    Ok(())
                }
                .await;
                // Do not leave a paused source worker on a returned operation error.
                pause.release.notify_one();
                result.and(live.close().await)
            }
        }
        mod retention {
            use super::*;

            #[tokio::test]
            async fn confirmed_retention_survives_lost_tls_reply_restart_and_cleanup_refusal()
            -> io::Result<()> {
                let mut live = Live::new(node::tests::CutResponse {
                    witness_confirm: true,
                    witness_sequence: Some(3),
                    ..Default::default()
                })
                .await?;
                let result = async {
                    let root = live.fixture.client_state.join("witness-intents");
                    for revision in 1..=2 {
                        live.source
                            .change(live.administrator.clone(), revision, live.user())
                            .await?;
                    }
                    live.arm();
                    let error = live
                        .source
                        .change(live.administrator.clone(), 3, live.user())
                        .await
                        .err()
                        .ok_or_else(invalid)?;
                    assert!(super::super::super::is_uncertain(&error));
                    assert!(live.source.reader().revision().is_err());
                    // No collection on lost Confirm, even though the witness committed it.
                    for n in 1..=3 {
                        assert!(root.join(format!("{n}.json")).try_exists()?);
                    }
                    live.source.reconcile_source().await?;
                    assert!(!root.join("1.json").try_exists()?);
                    assert_eq!(live.source.reader().revision()?, 4);
                    live.restart_source().await?;
                    assert_eq!(live.source.reader().revision()?, 4);
                    live.source
                        .change(live.administrator.clone(), 4, live.user())
                        .await?;
                    assert!(!root.join("2.json").try_exists()?);
                    // Unknown content in an obsolete operation is retained. It must not
                    // turn the next exact confirmed business result into a failed request.
                    let locator: serde_json::Value =
                        serde_json::from_slice(&fs::read(root.join("3.json"))?)
                            .map_err(io::Error::other)?;
                    let id = locator["intent_id"].as_str().ok_or_else(invalid)?;
                    files::write(&root.join(id), "unknown.bin", b"retained evidence")?;
                    let saved = live
                        .source
                        .change(live.administrator.clone(), 5, live.user())
                        .await?;
                    assert_eq!(saved.revision, 6);
                    assert_eq!(
                        (live.floor()?.sequence.as_str(), live.floor()?.phase),
                        ("5", Phase::Confirmed)
                    );
                    assert!(root.join("3.json").try_exists()?);
                    assert_eq!(
                        fs::read(root.join(id).join("unknown.bin"))?,
                        b"retained evidence"
                    );
                    for n in [4, 5] {
                        assert!(root.join(format!("{n}.json")).try_exists()?);
                    }
                    live.restart_source().await?;
                    assert_eq!(live.source.reader().revision()?, 6);
                    assert_eq!(live.fault.cuts.load(Ordering::Acquire), 1);
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)
            }
        }
        pub(in crate::manage::store::journal) mod snapshots {
            //! Offline capture/seal and internal registered-input handoff use real mTLS.
            //! The original worker is stopped/dropped before its directory is relocked;
            //! no lock bypass, trust change or public Source service startup is involved.
            use super::*;
            use crate::manage::{files, snapshot};
            use std::path::PathBuf;

            pub(in crate::manage) struct Export {
                pub(in crate::manage) fixture: Arc<node::tests::Fixture>,
                enrollment: Enrollment,
                pub(in crate::manage) configuration: PathBuf,
                output: PathBuf,
                fault: Arc<node::tests::CutResponse>,
                stop: CancellationToken,
                server: tokio::task::JoinHandle<io::Result<()>>,
                _remote: Arc<Coordinator>,
            }

            impl Export {
                async fn new(fault: node::tests::CutResponse) -> io::Result<Self> {
                    let live = Live::new(fault).await?;
                    Self::from_live(live).await
                }
                pub(in crate::manage) async fn from_live(live: Live) -> io::Result<Self> {
                    live.source.shutdown_writer().await?;
                    let Live {
                        fixture,
                        enrollment,
                        author,
                        endpoint,
                        remote,
                        source,
                        fault,
                        stop,
                        server,
                        ..
                    } = live;
                    drop(source);
                    drop(author);
                    let result = (|| {
                        let directory = fixture.ca.parent().ok_or_else(invalid)?.join("export");
                        files::create_directory(&directory)?;
                        let admin =
                            rcgen::generate_simple_self_signed(vec!["admin.example".into()])
                                .map_err(io::Error::other)?;
                        files::write(&directory, "admin.pem", admin.cert.pem().as_bytes())?;
                        files::write(
                            &directory,
                            "admin.key",
                            admin.signing_key.serialize_pem().as_bytes(),
                        )?;
                        // The transport fixture's key was not originally a private archive
                        // input on Windows. Copy this fresh key into the private inventory;
                        // never repair or reuse a real node's permissions.
                        files::write(&directory, "node.key", &fs::read(&fixture.client_key)?)?;
                        let configuration = directory.join("configuration.json");
                        files::write(&directory, "configuration.json", &serde_json::to_vec(&serde_json::json!({
                "format_version":2, "expected_node_id":fixture.client_id,
                "management":{"bind":"127.0.0.1:24443", "origin":"https://admin.example:24443", "surface":"api_only", "tls":{"mode":"manual", "certificate":directory.join("admin.pem"), "private_key":directory.join("admin.key")}},
                "node":{"bind":"127.0.0.1:24444", "origin":"https://client.test:24444", "ca":fixture.ca, "certificate":fixture.client_cert, "private_key":directory.join("node.key")},
                "proxy_config":null, "health_config":null, "observe_target_alerts":false, "egress":null,
                "source":{"endpoint":endpoint,"enrollment":enrollment}
            })).map_err(io::Error::other)?)?;
                        Ok((configuration, directory.join("package")))
                    })();
                    match result {
                        Ok((configuration, output)) => Ok(Self {
                            fixture,
                            enrollment,
                            configuration,
                            output,
                            fault,
                            stop,
                            server,
                            _remote: remote,
                        }),
                        Err(error) => {
                            stop.cancel();
                            server.await.map_err(io::Error::other)??;
                            Err(error)
                        }
                    }
                }
                async fn create(&self) -> io::Result<snapshot::Report> {
                    let (directory, configuration, output) = (
                        self.fixture.client_state.clone(),
                        self.configuration.clone(),
                        self.output.clone(),
                    );
                    tokio::task::spawn_blocking(move || {
                        snapshot::create(&directory, &configuration, &output)
                    })
                    .await
                    .map_err(io::Error::other)?
                }
                async fn seal(&self) -> io::Result<snapshot::Report> {
                    let (directory, output) =
                        (self.fixture.client_state.clone(), self.output.clone());
                    tokio::task::spawn_blocking(move || snapshot::seal(&directory, &output))
                        .await
                        .map_err(io::Error::other)?
                }
                pub(in crate::manage) async fn register(
                    &self,
                    expected_revision: u64,
                    resume: bool,
                ) -> io::Result<snapshot::Registered> {
                    let directory = self.fixture.client_state.clone();
                    let configuration = self.configuration.clone();
                    tokio::task::spawn_blocking(move || {
                        snapshot::register_configuration(
                            &directory,
                            &configuration,
                            expected_revision,
                            resume,
                        )
                    })
                    .await
                    .map_err(io::Error::other)?
                }
                async fn configure(
                    &self,
                    expected: u64,
                    sha256: [u8; 32],
                    reconcile: bool,
                ) -> io::Result<()> {
                    let f = self.fixture.clone();
                    let e = self.enrollment.clone();
                    let handle = tokio::runtime::Handle::current();
                    // The exact endpoint is in the already checked fresh fixture's input.
                    let input = fs::read(&self.configuration)?;
                    let input: snapshot::config::Configuration =
                        serde_json::from_slice(&input).map_err(io::Error::other)?;
                    let endpoint = input.source.ok_or_else(invalid)?.endpoint;
                    let key = self
                        .configuration
                        .parent()
                        .ok_or_else(invalid)?
                        .join("node.key");
                    tokio::task::spawn_blocking(move || {
                        let a = Arc::new(store::lock(&f.client_state)?);
                        let g = store::update_lock(&f.client_state)?;
                        let scope = scope(&f, &a, &g, &e);
                        let mut connection = open(&scope)?;
                        let journal = Journal::open(scope, &connection)?;
                        let identity = tls::node_identity(&f.ca, &f.client_cert, &key)?;
                        let offline = crate::manage::node::control::Offline::new(
                            &f.client_state,
                            a.clone(),
                            &f.client_id,
                            identity,
                        )?;
                        let mut request = |op| {
                            handle.block_on(offline.request(&endpoint, &e.witness_node_id, op))
                        };
                        if reconcile {
                            journal.reconcile(&mut connection, &mut request, || Ok(()))
                        } else {
                            journal.configure(&mut connection, expected, sha256, &mut request)
                        }
                    })
                    .await
                    .map_err(io::Error::other)?
                }
                async fn start_registered(
                    &self,
                    registered: snapshot::Registered,
                ) -> io::Result<(Arc<Coordinator>, snapshot::inputs::Prepared)> {
                    Coordinator::new_registered_source(
                        self.fixture.client_state.clone(),
                        Arc::new(store::lock(&self.fixture.client_state)?),
                        registered,
                    )
                    .await
                }
                /// Reserve the exact ephemeral node bind before capturing it. This is a
                /// private fixture input, not a port probe or a changed production origin.
                async fn node_listener(&self) -> io::Result<tokio::net::TcpListener> {
                    let listener =
                        tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
                    let address = listener.local_addr()?;
                    let mut description: serde_json::Value =
                        serde_json::from_slice(&fs::read(&self.configuration)?)
                            .map_err(io::Error::other)?;
                    description["node"]["bind"] = address.to_string().into();
                    description["node"]["origin"] =
                        format!("https://client.test:{}", address.port()).into();
                    fs::write(
                        &self.configuration,
                        serde_json::to_vec(&description).map_err(io::Error::other)?,
                    )?;
                    Ok(listener)
                }
                fn administrator(&self) -> io::Result<String> {
                    let connection =
                        Connection::open(self.fixture.client_state.join("management.sqlite3"))
                            .map_err(io::Error::other)?;
                    super::super::driver::administrator(&connection)
                }
                pub(in crate::manage) fn floor(&self) -> io::Result<Record> {
                    store::witness::inspect(&self.fixture.server_state, &self.enrollment.binding_id)
                }
                pub(in crate::manage) fn arm(&self) {
                    self.fault.armed.store(true, Ordering::Release);
                }
                pub(in crate::manage) async fn close(self) -> io::Result<()> {
                    self.stop.cancel();
                    self.server.await.map_err(io::Error::other)?
                }
            }

            #[tokio::test]
            async fn registered_node_serves_captured_mtls_and_withholds_keepalive_identity_until_original_confirmation()
            -> io::Result<()> {
                use bytes::Bytes;
                use http_body_util::{BodyExt as _, Empty};
                use hyper_util::rt::TokioIo;
                use tokio_rustls::TlsConnector;
                for reserve in [true, false] {
                    let export = Export::new(node::tests::CutResponse {
                        witness_only: true,
                        witness_reserve: reserve,
                        witness_confirm: !reserve,
                        witness_sequence: Some(2),
                        ..Default::default()
                    })
                    .await?;
                    let result = async {
                        let listener = export.node_listener().await?;
                        let address = listener.local_addr()?;
                        let client = export.fixture.server_identity()?.client_config()?;
                        let registered = export.register(0, false).await?;
                        let (coordinator, mut inputs) = export.start_registered(registered).await?;
                        let node = inputs.node_listener.take().ok_or_else(invalid)?;
                        for path in [
                            &export.configuration,
                            &export.fixture.ca,
                            &export.fixture.client_cert,
                        ] {
                            fs::remove_file(path)?;
                        }
                        fs::remove_file(
                            export
                                .configuration
                                .parent()
                                .ok_or_else(invalid)?
                                .join("node.key"),
                        )?;
                        let stop = CancellationToken::new();
                        let server = tokio::spawn(node::serve(
                            listener,
                            node,
                            export.fixture.client_state.clone(),
                            stop.clone(),
                            Some(coordinator.clone()),
                            None,
                            None,
                        ));
                        let mut drivers = tokio::task::JoinSet::new();
                        let result = timeout(Duration::from_secs(20), async {
                            let stream = tokio::net::TcpStream::connect(address).await?;
                            let stream = TlsConnector::from(client)
                                .connect(
                                    rustls_pki_types::ServerName::try_from("client.test")
                                        .map_err(io::Error::other)?,
                                    stream,
                                )
                                .await?;
                            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
                            let (mut client, connection) =
                                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                                    .await
                                    .map_err(io::Error::other)?;
                            drivers.spawn(connection);
                            // One TLS connection observes ready, uncertain and reconciled
                            // state. No reconnect or cached header can grant authority.
                            for stage in 0..3 {
                                if stage == 1 {
                                    export.fault.armed.store(true, Ordering::Release);
                                    let changed = coordinator
                                        .change(
                                            export.administrator()?,
                                            1,
                                            users::PolicyChange::CreateUser {
                                                name: "registered node user".into(),
                                                protocols: vec![crate::access::Protocol::Http],
                                                concurrent_limit: 1,
                                            },
                                        )
                                        .await;
                                    assert!(is_uncertain(&changed.err().ok_or_else(invalid)?));
                                    assert_eq!(export.fault.cuts.load(Ordering::Acquire), 1);
                                } else if stage == 2 {
                                    coordinator.reconcile_source().await?;
                                }
                                let request = http::Request::builder()
                                    .uri("/node/v1/identity")
                                    .header(
                                        http::header::HOST,
                                        format!("client.test:{}", address.port()),
                                    )
                                    .header("x-node-id", "not-authority")
                                    .body(Empty::<Bytes>::new())
                                    .map_err(io::Error::other)?;
                                let response = client
                                    .send_request(request)
                                    .await
                                    .map_err(io::Error::other)?;
                                assert_eq!(
                                    response.headers()[http::header::CACHE_CONTROL],
                                    "no-store"
                                );
                                assert!(!response.headers().contains_key(http::header::SET_COOKIE));
                                let status = response.status();
                                let bytes = response
                                    .into_body()
                                    .collect()
                                    .await
                                    .map_err(io::Error::other)?
                                    .to_bytes();
                                let body: serde_json::Value =
                                    serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                                if stage == 1 {
                                    assert_eq!(status, http::StatusCode::SERVICE_UNAVAILABLE);
                                    assert_eq!(body["error"]["code"], "authorization_unavailable");
                                    assert!(body.get("node_id").is_none());
                                } else {
                                    assert_eq!(status, http::StatusCode::OK);
                                    assert_eq!(body["node_id"], export.fixture.client_id);
                                    assert_eq!(
                                        body["verified_peer"]["node_id"],
                                        export.fixture.server_id
                                    );
                                    assert_eq!(body["verified_peer"]["authorization_revision"], 1);
                                    assert_eq!(
                                        export.floor()?.sequence,
                                        if stage == 0 { "1" } else { "2" }
                                    );
                                }
                            }
                            Ok::<_, io::Error>(())
                        })
                        .await
                        .map_err(io::Error::other)
                        .and_then(|r| r);
                        stop.cancel();
                        let served = server.await.map_err(io::Error::other);
                        drivers.abort_all();
                        while drivers.join_next().await.is_some() {}
                        let stopped = coordinator.shutdown_writer().await;
                        result?;
                        served??;
                        stopped?;
                        Ok(())
                    }
                    .await;
                    result.and(export.close().await)?;
                }
                Ok(())
            }

            #[tokio::test]
            async fn registered_node_requires_its_listener_directory_reference_signer_and_source_coordinator()
            -> io::Result<()> {
                for case in [
                    "missing",
                    "native",
                    "directory",
                    "reference",
                    "signer",
                    "listener",
                    "native_configuration",
                ] {
                    let export = Export::new(Default::default()).await?;
                    let result = async {
                        let listener = export.node_listener().await?;
                        let address = listener.local_addr()?;
                        let registered = export.register(0, false).await?;
                        let mut reference = registered.reference;
                        let (coordinator, mut inputs) = export.start_registered(registered).await?;
                        let configuration = match case {
                            "reference" => {
                                reference.revision += 1;
                                node::configure_registered(&inputs, reference)?
                            }
                            "signer" => {
                                // Preserve the static inventory but substitute another real
                                // loaded signer. The worker's independent actual-key pin,
                                // not the JSON digest alone, must reject this transport.
                                let other = node::tests::Fixture::new(true, true)?;
                                inputs.node = tls::node_identity(
                                    &other.ca,
                                    &other.client_cert,
                                    &other.client_key,
                                )?;
                                inputs.node_key_sha256 = inputs.node.key_sha256()?;
                                node::configure_registered(&inputs, reference)?
                            }
                            "native_configuration" => export.fixture.config(address)?,
                            _ => inputs.node_listener.take().ok_or_else(invalid)?,
                        };
                        let policy = match case {
                            "missing" => None,
                            "native" => Some(export._remote.clone()),
                            _ => Some(coordinator.clone()),
                        };
                        let directory = if case == "directory" {
                            export.fixture.server_state.clone()
                        } else {
                            export.fixture.client_state.clone()
                        };
                        let listener = if case == "listener" {
                            // Keep the first port reserved until the different bind exists.
                            let other =
                                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                                    .await?;
                            drop(listener);
                            other
                        } else {
                            listener
                        };
                        let before = export.floor()?;
                        let served = timeout(
                            Duration::from_secs(10),
                            node::serve(
                                listener,
                                configuration,
                                directory,
                                CancellationToken::new(),
                                policy,
                                None,
                                None,
                            ),
                        )
                        .await
                        .map_err(io::Error::other);
                        let reader = coordinator.reader().revision();
                        let stopped = coordinator.shutdown_writer().await;
                        assert_eq!(
                            served?.err().ok_or_else(invalid)?.kind(),
                            io::ErrorKind::PermissionDenied,
                            "case {case}"
                        );
                        stopped?;
                        assert_eq!(export.floor()?, before);
                        assert_eq!(reader?, 1);
                        Ok(())
                    }
                    .await;
                    result.and(export.close().await)?;
                }
                Ok(())
            }

            #[tokio::test]
            async fn registered_worker_uses_owned_inputs_after_paths_disappear_and_accepts_later_business_floor()
            -> io::Result<()> {
                let export = Export::new(Default::default()).await?;
                let result = async {
                    let parent = export.configuration.parent().ok_or_else(invalid)?;
                    files::write(parent, "health.json", br#"{"timeout_secs":5}"#)?;
                    let mut description: serde_json::Value =
                        serde_json::from_slice(&fs::read(&export.configuration)?)
                            .map_err(io::Error::other)?;
                    description["health_config"] = serde_json::to_value(parent.join("health.json"))
                        .map_err(io::Error::other)?;
                    fs::write(
                        &export.configuration,
                        serde_json::to_vec(&description).map_err(io::Error::other)?,
                    )?;
                    let first = export.register(0, false).await?;
                    let second = export.register(1, false).await?;
                    let reference = first.reference;
                    assert_eq!(second.reference, reference);
                    // Each signer/roots/config owner is already captured. Neither startup
                    // nor the later real witness operations may consult these old paths.
                    for path in [
                        export.configuration.clone(),
                        parent.join("health.json"),
                        parent.join("admin.pem"),
                        parent.join("admin.key"),
                        parent.join("node.key"),
                        export.fixture.ca.clone(),
                        export.fixture.client_cert.clone(),
                    ] {
                        fs::remove_file(path)?;
                    }
                    let (coordinator, inputs) = export.start_registered(first).await?;
                    let changed = coordinator
                        .change(
                            export.administrator()?,
                            1,
                            users::PolicyChange::CreateUser {
                                name: "captured startup".into(),
                                protocols: vec![crate::access::Protocol::Http],
                                concurrent_limit: 1,
                            },
                        )
                        .await;
                    let stopped = coordinator.shutdown_writer().await;
                    drop(coordinator);
                    assert_eq!(changed?.revision, 2);
                    stopped?;
                    assert_eq!(inputs.health.timeout_secs, 5);
                    assert!(inputs.management.is_some());
                    assert_eq!(inputs.sha256()?, reference.sha256);
                    assert_eq!(export.floor()?.sequence, "2"); // registration and policy; not running
                    let (restarted, retained) = export.start_registered(second).await?;
                    let observed = restarted.status().await;
                    let stopped = restarted.shutdown_writer().await;
                    drop(restarted);
                    assert_eq!(observed?.saved_revision, 2);
                    stopped?;
                    assert_eq!(retained.sha256()?, reference.sha256);
                    assert_eq!(export.floor()?.sequence, "2");
                    Ok(())
                }
                .await;
                result.and(export.close().await)
            }

            #[tokio::test]
            async fn registered_worker_refuses_changed_owned_configuration_and_another_directory()
            -> io::Result<()> {
                let export = Export::new(Default::default()).await?;
                let result = async {
                    let mut registered = export.register(0, false).await?;
                    let before = export.floor()?;
                    registered.inputs.configuration.observe_target_alerts = true;
                    assert_eq!(
                        export
                            .start_registered(registered)
                            .await
                            .err()
                            .ok_or_else(invalid)?
                            .kind(),
                        io::ErrorKind::PermissionDenied
                    );
                    assert_eq!(export.floor()?, before);
                    let registered = export.register(1, false).await?;
                    let other = export
                        .configuration
                        .parent()
                        .ok_or_else(invalid)?
                        .join("other-directory");
                    files::create_directory(&other)?;
                    let author = Arc::new(store::lock(&other)?);
                    assert_eq!(
                        Coordinator::new_registered_source(
                            other.clone(),
                            author.clone(),
                            registered
                        )
                        .await
                        .err()
                        .ok_or_else(invalid)?
                        .kind(),
                        io::ErrorKind::PermissionDenied
                    );
                    drop(author);
                    assert_eq!(export.floor()?, before);
                    assert!(!other.join("management.sqlite3").exists());
                    Ok(())
                }
                .await;
                result.and(export.close().await)
            }

            #[tokio::test]
            async fn registered_worker_requires_both_current_revision_and_digest_without_advancing_witness()
            -> io::Result<()> {
                let export = Export::new(Default::default()).await?;
                let result = async {
                    let mut wrong_revision = export.register(0, false).await?;
                    let stale = export.register(1, false).await?;
                    wrong_revision.reference.revision += 1;
                    let before = export.floor()?;
                    assert_eq!(
                        export
                            .start_registered(wrong_revision)
                            .await
                            .err()
                            .ok_or_else(invalid)?
                            .kind(),
                        io::ErrorKind::PermissionDenied
                    );
                    assert_eq!(export.floor()?, before);
                    let mut description: serde_json::Value =
                        serde_json::from_slice(&fs::read(&export.configuration)?)
                            .map_err(io::Error::other)?;
                    description["observe_target_alerts"] = true.into();
                    fs::write(
                        &export.configuration,
                        serde_json::to_vec(&description).map_err(io::Error::other)?,
                    )?;
                    let current = export.register(1, false).await?;
                    assert_eq!(current.reference.revision, 2);
                    let before = export.floor()?;
                    // Use the current revision with the old, internally consistent bytes:
                    // checking revision alone must not admit a different configuration.
                    let mut wrong_digest = stale;
                    wrong_digest.reference.revision = current.reference.revision;
                    assert_eq!(
                        export
                            .start_registered(wrong_digest)
                            .await
                            .err()
                            .ok_or_else(invalid)?
                            .kind(),
                        io::ErrorKind::PermissionDenied
                    );
                    assert_eq!(export.floor()?, before);
                    let (coordinator, _) = export.start_registered(current).await?;
                    coordinator.shutdown_writer().await?;
                    assert_eq!(export.floor()?, before);
                    Ok(())
                }
                .await;
                result.and(export.close().await)
            }

            #[tokio::test]
            async fn registered_worker_refuses_pending_and_only_reads_freshly_confirmed_original_sql()
            -> io::Result<()> {
                for reserve in [true, false] {
                    let export = Export::new(node::tests::CutResponse {
                        witness_only: true,
                        witness_reserve: reserve,
                        witness_confirm: !reserve,
                        witness_sequence: Some(2),
                        ..Default::default()
                    })
                    .await?;
                    let result = async {
                        let first = export.register(0, false).await?;
                        let second = export.register(1, false).await?;
                        let reference = first.reference;
                        let (coordinator, _) = export.start_registered(first).await?;
                        export.fault.armed.store(true, Ordering::Release);
                        let changed = coordinator
                            .change(
                                export.administrator()?,
                                1,
                                users::PolicyChange::CreateUser {
                                    name: "unknown startup".into(),
                                    protocols: vec![crate::access::Protocol::Http],
                                    concurrent_limit: 1,
                                },
                            )
                            .await;
                        let stopped = coordinator.shutdown_writer().await;
                        drop(coordinator);
                        assert!(is_uncertain(&changed.err().ok_or_else(invalid)?));
                        stopped?;
                        let before = export.floor()?;
                        let reopened = export.start_registered(second).await;
                        if reserve {
                            assert!(reopened.is_err());
                            assert_eq!(export.floor()?, before);
                            // Explicit offline reconciliation uses the retained original
                            // SQL, not a new callback or secret generation.
                            export.configure(1, reference.sha256, true).await?;
                        } else {
                            // Lost Confirm response is not proof that confirmation failed.
                            // A fresh exact Confirmed observation may admit the original
                            // committed SQL, without replay or another witness mutation.
                            let (coordinator, _) = reopened?;
                            let status = coordinator.status().await;
                            let stopped = coordinator.shutdown_writer().await;
                            drop(coordinator);
                            assert_eq!(status?.user_count, 1);
                            stopped?;
                            assert_eq!(export.floor()?, before);
                        }
                        assert!(store::recovery::startup(&export.fixture.client_state).is_err());
                        let recovered = export.register(1, false).await?;
                        let (coordinator, _) = export.start_registered(recovered).await?;
                        let status = coordinator.status().await;
                        let stopped = coordinator.shutdown_writer().await;
                        drop(coordinator);
                        assert_eq!(status?.user_count, 1);
                        stopped?;
                        assert_eq!(export.floor()?.sequence, "2");
                        Ok(())
                    }
                    .await;
                    result.and(export.close().await)?;
                }
                Ok(())
            }

            #[tokio::test]
            async fn fixed_input_registration_lost_reply_only_resumes_original_capture_and_matches_archive()
            -> io::Result<()> {
                for reserve in [true, false] {
                    let export = Export::new(node::tests::CutResponse {
                        witness_only: true,
                        witness_reserve: reserve,
                        witness_confirm: !reserve,
                        witness_sequence: Some(1),
                        ..Default::default()
                    })
                    .await?;
                    let result = async {
                        let original = fs::read(&export.configuration)?;
                        export.fault.armed.store(true, Ordering::Release);
                        assert!(export.register(0, false).await.is_err());
                        assert_eq!(export.fault.cuts.load(Ordering::Acquire), 1);
                        let pending = export.floor()?;
                        assert!(export.register(0, false).await.is_err());
                        assert_eq!(export.floor()?, pending);
                        let mut changed: serde_json::Value =
                            serde_json::from_slice(&original).map_err(io::Error::other)?;
                        changed["observe_target_alerts"] = true.into();
                        fs::write(
                            &export.configuration,
                            serde_json::to_vec(&changed).map_err(io::Error::other)?,
                        )?;
                        assert!(export.register(0, true).await.is_err());
                        assert_eq!(export.floor()?, pending);
                        fs::write(&export.configuration, &original)?;
                        let saved = export.register(0, true).await?;
                        assert_eq!(saved.reference.revision, 1);
                        assert_eq!(saved.inputs.sha256()?, saved.reference.sha256);
                        assert!(saved.inputs.management.is_some());
                        assert!(saved.inputs.proxy.is_none());
                        assert_eq!(saved.inputs.health.timeout_secs, 3);
                        assert_eq!(
                            saved.inputs.node.key_sha256()?,
                            saved.inputs.node_key_sha256
                        );
                        let reference = saved.reference;
                        drop(saved);
                        assert!(!export.output.exists());
                        assert_eq!(export.floor()?.phase, Phase::Confirmed);
                        assert_eq!(export.floor()?.sequence, "1");
                        assert_eq!(export.register(1, false).await?.reference, reference);
                        assert_eq!(export.floor()?.sequence, "1");
                        assert!(export.register(0, false).await.is_err());
                        export.create().await?;
                        assert_eq!(export.floor()?.sequence, "2");
                        assert_eq!(
                            snapshot::archived_configuration_sha256(&export.output)?,
                            reference.sha256
                        );
                        let before = export.floor()?;
                        assert!(export.register(0, true).await.is_err());
                        assert_eq!(export.floor()?, before);
                        Ok(())
                    }
                    .await;
                    result.and(export.close().await)?;
                }
                Ok(())
            }

            #[tokio::test]
            async fn fixed_input_rejects_invalid_health_or_foreign_binding_and_acme_never_opens_cache()
            -> io::Result<()> {
                let export = Export::new(Default::default()).await?;
                let result = async {
                    let original = fs::read(&export.configuration)?;
                    let parent = export.configuration.parent().ok_or_else(invalid)?;
                    files::write(parent, "invalid-health.json", br#"{"timeout_secs":0}"#)?;
                    let mut input: serde_json::Value =
                        serde_json::from_slice(&original).map_err(io::Error::other)?;
                    input["health_config"] =
                        serde_json::to_value(parent.join("invalid-health.json"))
                            .map_err(io::Error::other)?;
                    fs::write(
                        &export.configuration,
                        serde_json::to_vec(&input).map_err(io::Error::other)?,
                    )?;
                    let before = export.floor()?;
                    assert!(export.register(0, false).await.is_err());
                    assert_eq!(export.floor()?, before);
                    input = serde_json::from_slice(&original).map_err(io::Error::other)?;
                    input["source"]["enrollment"]["binding_id"] = store::random_id()?.into();
                    fs::write(
                        &export.configuration,
                        serde_json::to_vec(&input).map_err(io::Error::other)?,
                    )?;
                    assert!(export.register(0, false).await.is_err());
                    assert_eq!(export.floor()?, before);
                    input = serde_json::from_slice(&original).map_err(io::Error::other)?;
                    input["management"]["tls"] = serde_json::json!({"mode":"acme","options":{
                        "enabled":true,"accept_terms":true,"production":false,"contacts":[],
                        "challenge":"http-01","http_bind":"127.0.0.1:24445"
                    }});
                    fs::write(
                        &export.configuration,
                        serde_json::to_vec(&input).map_err(io::Error::other)?,
                    )?;
                    assert!(!export.fixture.client_state.join("acme").exists());
                    let saved = export.register(0, false).await?;
                    assert_eq!(saved.reference.revision, 1);
                    assert!(saved.inputs.management.is_none());
                    assert!(saved.inputs.acme_cache.is_none());
                    assert!(!export.fixture.client_state.join("acme").exists());
                    export.create().await?;
                    assert_eq!(
                        snapshot::archived_configuration_sha256(&export.output)?,
                        saved.reference.sha256
                    );
                    assert!(!export.fixture.client_state.join("acme").exists());
                    assert_eq!(export.floor()?.sequence, "2");
                    Ok(())
                }
                .await;
                result.and(export.close().await)
            }

            #[tokio::test]
            async fn source_configuration_real_tls_reconciles_original_and_checks_exported_static_assets()
            -> io::Result<()> {
                for reserve in [true, false] {
                    let mut export = Export::new(node::tests::CutResponse {
                        witness_only: true,
                        witness_reserve: reserve,
                        witness_confirm: !reserve,
                        witness_sequence: Some(2),
                        ..Default::default()
                    })
                    .await?;
                    let result = async {
                        export.create().await?;
                        let digest = snapshot::archived_configuration_sha256(&export.output)?;
                        export.fault.armed.store(true, Ordering::Release);
                        let error = export
                            .configure(0, digest, false)
                            .await
                            .err()
                            .ok_or_else(invalid)?;
                        assert!(is_uncertain(&error));
                        assert_eq!(export.fault.cuts.load(Ordering::Acquire), 1);
                        let prior = export.floor()?;
                        assert!(export.configure(0, digest, false).await.is_err());
                        assert_eq!(export.floor()?, prior);
                        export.configure(0, digest, true).await?;
                        assert_eq!(export.floor()?.sequence, "2");
                        assert_eq!(export.floor()?.phase, Phase::Confirmed);
                        export.configure(1, digest, false).await?;
                        assert_eq!(export.floor()?.sequence, "2");
                        assert!(export.configure(0, digest, false).await.is_err());
                        let first_package = export.output.clone();
                        export.output = first_package.with_file_name("accepted-package");
                        export.create().await?;
                        assert_eq!(export.floor()?.sequence, "3");
                        assert_eq!(
                            snapshot::archived_configuration_sha256(&export.output)?,
                            digest
                        );
                        // Change a real captured static file, keeping the same declared path.
                        let parent = export.configuration.parent().ok_or_else(invalid)?;
                        let cert = fs::read(parent.join("admin.pem"))?;
                        let mut changed = cert;
                        changed.push(b'\n');
                        fs::write(parent.join("admin.pem"), changed)?;
                        export.output = first_package.with_file_name("changed-package");
                        let prior = export.floor()?;
                        assert!(export.create().await.is_err());
                        assert_eq!(export.floor()?, prior);
                        assert!(!export.output.join("source").exists());
                        // Config binding does not retroactively turn an inert archive into
                        // fresh authority. Old package integrity remains independently valid.
                        snapshot::verify(&first_package)?;
                        Ok(())
                    }
                    .await;
                    result.and(export.close().await)?;
                }
                Ok(())
            }

            #[tokio::test]
            async fn source_snapshot_public_export_seals_the_complete_inert_package_once()
            -> io::Result<()> {
                let export = Export::new(Default::default()).await?;
                let result = async {
                    let report =
                        serde_json::to_value(export.create().await?).map_err(io::Error::other)?;
                    assert_eq!(report["source_sequence"], "1");
                    assert_eq!(
                        report["validation"],
                        "integrity_and_sealed_binding_not_current_witness_or_activation"
                    );
                    assert_eq!(export.floor()?.phase, Phase::Confirmed);
                    let saved = Intent::load(&export.output.join("source"), &export.enrollment)?;
                    assert_eq!(saved.metadata.format, 4);
                    assert!(saved.metadata.matches(&export.floor()?, Phase::Confirmed));
                    let bytes = fs::read(export.output.join("manifest.json"))?;
                    assert_eq!(
                        saved
                            .metadata
                            .snapshot
                            .as_ref()
                            .ok_or_else(invalid)?
                            .package_sha256,
                        hex(&Sha256::digest(&bytes))
                    );
                    store::read_backup_verified(&export.output.join("database"), |c, _| {
                        assert_eq!(
                            source::load(c, store::SCHEMA_VERSION)?
                                .ok_or_else(invalid)?
                                .floor
                                .sequence,
                            0
                        );
                        super::super::super::snapshot::check_payload(c, &saved)?;
                        Ok(())
                    })?;
                    assert!(store::recovery::startup(&export.output.join("database")).is_err());
                    assert!(snapshot::seal(&export.output, &export.output).is_err());
                    let original = export.floor()?;
                    assert!(export.create().await.is_err());
                    for _ in 0..2 {
                        assert_eq!(
                            serde_json::to_value(export.seal().await?).map_err(io::Error::other)?,
                            report
                        );
                        assert_eq!(export.floor()?, original);
                    }
                    // An exact partial publication can be completed, never a new intent.
                    fs::remove_file(export.output.join("source").join(PAYLOAD))?;
                    assert!(snapshot::verify(&export.output).is_err());
                    export.seal().await?;
                    assert_eq!(
                        Intent::load(&export.output.join("source"), &export.enrollment)?
                            .transition(),
                        saved.transition()
                    );
                    assert_eq!(export.floor()?, original);
                    Ok(())
                }
                .await;
                result.and(export.close().await)
            }

            #[tokio::test]
            async fn source_snapshot_lost_reserve_and_confirm_resume_only_the_original_seal()
            -> io::Result<()> {
                for reserve in [true, false] {
                    let export = Export::new(node::tests::CutResponse {
                        witness_only: true,
                        witness_reserve: reserve,
                        witness_confirm: !reserve,
                        witness_sequence: Some(1),
                        ..Default::default()
                    })
                    .await?;
                    let result = async {
                        export.fault.armed.store(true, Ordering::Release);
                        let error = export.create().await.err().ok_or_else(invalid)?;
                        assert!(super::super::super::driver::is_uncertain(&error));
                        assert_eq!(export.fault.cuts.load(Ordering::Acquire), 1);
                        assert!(export.output.join("manifest.json").exists());
                        assert!(!export.output.join("source").exists());
                        assert!(snapshot::verify(&export.output).is_err());
                        let pending = export.floor()?;
                        assert_eq!(
                            pending.phase,
                            if reserve {
                                Phase::Pending
                            } else {
                                Phase::Confirmed
                            }
                        );
                        let before = fs::read(export.output.join("manifest.json"))?;
                        export.seal().await?;
                        assert_eq!(export.floor()?.sequence, "1");
                        assert_eq!(export.floor()?.phase, Phase::Confirmed);
                        assert_eq!(fs::read(export.output.join("manifest.json"))?, before);
                        export.seal().await?;
                        assert_eq!(export.floor()?.sequence, "1");
                        Ok(())
                    }
                    .await;
                    result.and(export.close().await)?;
                }
                Ok(())
            }

            #[tokio::test]
            async fn source_snapshot_tamper_or_a_later_write_cannot_reseal_an_old_package()
            -> io::Result<()> {
                let export = Export::new(Default::default()).await?;
                let result = async {
                    export.create().await?;
                    let original = export.floor()?;
                    let path = export.output.join("source").join(PAYLOAD);
                    let payload = fs::read(&path)?;
                    fs::write(&path, b"corrupt evidence")?;
                    assert!(export.seal().await.is_err());
                    assert!(snapshot::verify(&export.output).is_err());
                    assert_eq!(fs::read(&path)?, b"corrupt evidence");
                    assert_eq!(export.floor()?, original);
                    fs::write(&path, payload)?;
                    let manifest_path = export.output.join("manifest.json");
                    let manifest_bytes = fs::read(&manifest_path)?;
                    let mut manifest: serde_json::Value =
                        serde_json::from_slice(&manifest_bytes).map_err(io::Error::other)?;
                    manifest["configuration"]["observe_target_alerts"] = serde_json::json!(true);
                    fs::write(
                        &manifest_path,
                        serde_json::to_vec(&manifest).map_err(io::Error::other)?,
                    )?;
                    assert!(export.seal().await.is_err());
                    assert!(snapshot::verify(&export.output).is_err());
                    assert_eq!(export.floor()?, original);
                    fs::write(manifest_path, manifest_bytes)?;
                    snapshot::verify(&export.output)?;
                    // A later ordinary Source writer is still ordered by the original
                    // journal. Local archive integrity remains valid but is not freshness.
                    let author = Arc::new(store::lock(&export.fixture.client_state)?);
                    let description: serde_json::Value =
                        serde_json::from_slice(&fs::read(&export.configuration)?)
                            .map_err(io::Error::other)?;
                    let endpoint = description["source"]["endpoint"]
                        .as_str()
                        .ok_or_else(invalid)?
                        .to_owned();
                    let coordinator = Coordinator::new_source(
                        export.fixture.client_state.clone(),
                        author.clone(),
                        export.enrollment.clone(),
                        endpoint,
                        tls::node_identity(
                            &export.fixture.ca,
                            &export.fixture.client_cert,
                            &export.fixture.client_key,
                        )?,
                    )
                    .await?;
                    let actor = {
                        let c = Connection::open(
                            export.fixture.client_state.join("management.sqlite3"),
                        )
                        .map_err(io::Error::other)?;
                        super::super::driver::administrator(&c)?
                    };
                    let changed = coordinator
                        .change(
                            actor,
                            1,
                            users::PolicyChange::CreateUser {
                                name: "after archive".into(),
                                protocols: vec![crate::access::Protocol::Http],
                                concurrent_limit: 1,
                            },
                        )
                        .await;
                    let stopped = coordinator.shutdown_writer().await;
                    drop(coordinator);
                    drop(author);
                    changed?;
                    stopped?;
                    assert_eq!(export.floor()?.sequence, "2");
                    let intent = Intent::load(&export.output.join("source"), &export.enrollment)?;
                    assert!(!intent.metadata.matches(&export.floor()?, Phase::Confirmed));
                    assert!(export.seal().await.is_err());
                    assert_eq!(export.floor()?.sequence, "2");
                    snapshot::verify(&export.output)?;
                    Ok(())
                }
                .await;
                result.and(export.close().await)
            }
        }
        mod witness {
            //! The Source may host another writer's witness records. The upstream service
            //! is real mTLS; the authenticated downstream author here is a synthetic caller,
            //! not a mutually dependent Source deployment or an independent failure domain.
            use super::*;

            fn enrollment(live: &Live) -> io::Result<Enrollment> {
                Ok(Enrollment {
                    witness_node_id: live.fixture.client_id.clone(),
                    binding_id: store::random_id()?,
                    peer_node_id: live.fixture.server_id.clone(),
                    writer_id: store::random_id()?,
                    baseline: "0".repeat(64),
                })
            }

            fn request(e: &Enrollment) -> Transition {
                Transition {
                    witness_node_id: e.witness_node_id.clone(),
                    binding_id: e.binding_id.clone(),
                    writer_id: e.writer_id.clone(),
                    sequence: "1".into(),
                    previous: e.baseline.clone(),
                    commitment: "1".repeat(64),
                }
            }

            async fn bind(live: &Live, e: &Enrollment) -> io::Result<Record> {
                let e = e.clone();
                live.source
                    .source_identity_write_then(
                        live.author.clone(),
                        move |w| w.bind_witness(&e),
                        Ok,
                    )
                    .await
            }

            fn authorization(live: &Live) -> io::Result<store::RemoteAuthorization> {
                super::commands::authorization(live)
            }

            #[tokio::test]
            async fn source_witness_file_author_binding_cas_and_permanent_retirement_are_idempotent()
            -> io::Result<()> {
                let mut live = Live::new(Default::default()).await?;
                let result = async {
                    let e = enrollment(&live)?;
                    let baseline = bind(&live, &e).await?;
                    assert_eq!(bind(&live, &e).await?, baseline);
                    assert_eq!(live.floor()?.sequence, "1");
                    let mut wrong = e.clone();
                    wrong.baseline = "a".repeat(64);
                    assert!(bind(&live, &wrong).await.is_err());
                    let input = request(&e);
                    let mut wrong = authorization(&live)?;
                    wrong.authorization_revision += 1;
                    assert_eq!(
                        live.source
                            .witness_transition(wrong, input.clone(), false)
                            .await
                            .err()
                            .map(|e| e.kind()),
                        Some(io::ErrorKind::PermissionDenied)
                    );
                    let pending = live
                        .source
                        .witness_transition(authorization(&live)?, input.clone(), false)
                        .await?;
                    assert_eq!(pending.phase, Phase::Pending);
                    assert_eq!(
                        live.source
                            .witness_transition(authorization(&live)?, input.clone(), false)
                            .await?,
                        pending
                    );
                    assert_eq!(live.floor()?.sequence, "2");
                    let confirmed = live
                        .source
                        .witness_transition(authorization(&live)?, input.clone(), true)
                        .await?;
                    for confirm in [false, true] {
                        assert_eq!(
                            live.source
                                .witness_transition(authorization(&live)?, input.clone(), confirm)
                                .await?,
                            confirmed
                        );
                    }
                    assert_eq!(live.floor()?.sequence, "3");
                    let mut wrong = input.clone();
                    wrong.commitment = "f".repeat(64);
                    assert!(
                        live.source
                            .witness_transition(authorization(&live)?, wrong, false)
                            .await
                            .is_err()
                    );
                    let binding = e.binding_id.clone();
                    assert!(
                        live.source
                            .source_identity_write_then(
                                live.author.clone(),
                                move |w| w.retire_witness(&binding, "0", &"1".repeat(64)),
                                Ok
                            )
                            .await
                            .is_err()
                    );
                    for _ in 0..2 {
                        let binding = e.binding_id.clone();
                        let retired = live
                            .source
                            .source_identity_write_then(
                                live.author.clone(),
                                move |w| w.retire_witness(&binding, "1", &"1".repeat(64)),
                                Ok,
                            )
                            .await?;
                        assert!(retired.retired);
                    }
                    assert_eq!(live.floor()?.sequence, "4");
                    assert!(bind(&live, &e).await.is_err());
                    let mut replacement = e.clone();
                    replacement.binding_id = store::random_id()?;
                    assert!(bind(&live, &replacement).await.is_err());
                    assert!(
                        live.source
                            .witness_inspect(authorization(&live)?, e.binding_id.clone())
                            .await
                            .is_err()
                    );
                    live.restart_source().await?;
                    assert!(
                        store::witness::inspect(&live.fixture.client_state, &e.binding_id)?.retired
                    );
                    assert_eq!(live.floor()?.sequence, "4");
                    assert_eq!(live.source.reader().revision()?, 1);
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)
            }

            #[tokio::test]
            async fn source_witness_lost_upstream_reply_blocks_inspection_until_exact_reconciliation()
            -> io::Result<()> {
                for reserve in [true, false] {
                    let live = Live::new(node::tests::CutResponse {
                        witness_only: true,
                        witness_reserve: reserve,
                        witness_confirm: !reserve,
                        witness_sequence: Some(2),
                        ..Default::default()
                    })
                    .await?;
                    let result = async {
                        let e = enrollment(&live)?;
                        bind(&live, &e).await?;
                        let input = request(&e);
                        live.arm();
                        let error = live
                            .source
                            .witness_transition(authorization(&live)?, input.clone(), false)
                            .await
                            .err()
                            .ok_or_else(invalid)?;
                        assert!(super::super::super::is_uncertain(&error));
                        assert_eq!(
                            store::witness::inspect(&live.fixture.client_state, &e.binding_id)?
                                .sequence,
                            if reserve { "0" } else { "1" }
                        );
                        assert_eq!(
                            live.source
                                .witness_inspect(authorization(&live)?, e.binding_id.clone())
                                .await
                                .err()
                                .map(|e| e.kind()),
                            Some(io::ErrorKind::WouldBlock)
                        );
                        live.source.reconcile_source().await?;
                        let current = live
                            .source
                            .witness_inspect(authorization(&live)?, e.binding_id.clone())
                            .await?;
                        assert_eq!(
                            (current.sequence.as_str(), current.phase),
                            ("1", Phase::Pending)
                        );
                        assert_eq!(
                            live.source
                                .witness_transition(authorization(&live)?, input.clone(), false)
                                .await?,
                            current
                        );
                        assert_eq!(live.floor()?.sequence, "2");
                        live.source
                            .witness_transition(authorization(&live)?, input, true)
                            .await?;
                        assert_eq!(live.floor()?.sequence, "3");
                        assert_eq!(live.source.reader().revision()?, 1);
                        Ok(())
                    }
                    .await;
                    let closed = live.close().await;
                    result.and(closed)?;
                }
                Ok(())
            }

            #[tokio::test]
            async fn cancelled_witness_transition_keeps_original_permit_and_refuses_unconfirmed_reads()
            -> io::Result<()> {
                let pause = Arc::new(node::tests::ResponsePause::default());
                let live = Live::new(node::tests::CutResponse {
                    witness_only: true,
                    witness_confirm: true,
                    witness_sequence: Some(2),
                    pause: Some(pause.clone()),
                    ..Default::default()
                })
                .await?;
                let result = async {
                    let e = enrollment(&live)?;
                    bind(&live, &e).await?;
                    live.arm();
                    let mut accepted = Box::pin(live.source.witness_transition(
                        authorization(&live)?,
                        request(&e),
                        false,
                    ));
                    assert!(futures_util::poll!(&mut accepted).is_pending());
                    timeout(Duration::from_secs(15), pause.entered.notified())
                        .await
                        .map_err(io::Error::other)?;
                    drop(accepted);
                    assert_eq!(live.source.write_work().available_permits(), 0);
                    assert!(store::update_lock(&live.fixture.client_state).is_err());
                    assert_eq!(
                        store::witness::inspect(&live.fixture.client_state, &e.binding_id)?.phase,
                        Phase::Pending
                    );
                    assert!(
                        live.source
                            .witness_inspect(authorization(&live)?, e.binding_id.clone())
                            .await
                            .is_err()
                    );
                    pause.release.notify_one();
                    timeout(Duration::from_secs(15), async {
                        while live.source.write_work().available_permits() != 1 {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .map_err(io::Error::other)?;
                    assert_eq!(
                        live.source
                            .witness_inspect(authorization(&live)?, e.binding_id)
                            .await?
                            .phase,
                        Phase::Pending
                    );
                    assert_eq!(live.floor()?.sequence, "2");
                    Ok(())
                }
                .await;
                pause.release.notify_one();
                let closed = live.close().await;
                result.and(closed)
            }
        }

        pub(in crate::manage) struct Live {
            pub(in crate::manage) fixture: Arc<node::tests::Fixture>,
            enrollment: Enrollment,
            pub(in crate::manage) administrator: String,
            pub(in crate::manage) author: Arc<Guard>,
            pub(in crate::manage) endpoint: String,
            pub(in crate::manage) remote: Arc<Coordinator>,
            pub(in crate::manage) source: Arc<Coordinator>,
            fault: Arc<node::tests::CutResponse>,
            stop: CancellationToken,
            server: tokio::task::JoinHandle<io::Result<()>>,
        }

        impl Live {
            async fn new(fault: node::tests::CutResponse) -> io::Result<Self> {
                Self::new_with(fault, |_| Ok(())).await
            }

            pub(in crate::manage) async fn new_with(
                fault: node::tests::CutResponse,
                configure: impl FnOnce(&node::tests::Fixture) -> io::Result<()>,
            ) -> io::Result<Self> {
                let f = Arc::new(node::tests::Fixture::new_with_private_source(true, true)?);
                configure(&f)?;
                let enrollment = enrollment(&f);
                store::witness::bind(&f.server_state, &enrollment)?;
                let author = Arc::new(store::lock(&f.client_state)?);
                let gate = store::update_lock(&f.client_state)?;
                let c = source_connection(&f, &author, &gate, &enrollment)?;
                let administrator = super::driver::administrator(&c)?;
                drop(c);
                drop(gate);
                let coordinator = Coordinator::new(
                    f.server_state.clone(),
                    store::load_policy(&f.server_state)?,
                    Arc::new(store::lock(&f.server_state)?),
                )?;
                let stop = CancellationToken::new();
                let fault = Arc::new(fault);
                let (address, server) = node::tests::start_cut_response_node(
                    &f,
                    coordinator.clone(),
                    fault.clone(),
                    stop.clone(),
                )
                .await?;
                let endpoint = format!("https://localhost:{}", address.port());
                let source = Coordinator::new_source(
                    f.client_state.clone(),
                    author.clone(),
                    enrollment.clone(),
                    endpoint.clone(),
                    tls::node_identity(&f.ca, &f.client_cert, &f.client_key)?,
                )
                .await?;
                Ok(Self {
                    fixture: f,
                    enrollment,
                    administrator,
                    author,
                    endpoint,
                    remote: coordinator,
                    source,
                    fault,
                    stop,
                    server,
                })
            }

            pub(in crate::manage) fn floor(&self) -> io::Result<Record> {
                store::witness::inspect(&self.fixture.server_state, &self.enrollment.binding_id)
            }
            pub(in crate::manage) fn arm(&self) {
                self.fault.armed.store(true, Ordering::Release);
            }
            /// Reopen the same confirmed source, author and witness after normal stop.
            /// Test callers must drop old collector/counter owners before using it.
            pub(in crate::manage) async fn restart_source(&mut self) -> io::Result<()> {
                self.source.shutdown_writer().await?;
                self.source = Coordinator::new_source(
                    self.fixture.client_state.clone(),
                    self.author.clone(),
                    self.enrollment.clone(),
                    self.endpoint.clone(),
                    tls::node_identity(
                        &self.fixture.ca,
                        &self.fixture.client_cert,
                        &self.fixture.client_key,
                    )?,
                )
                .await?;
                Ok(())
            }
            fn user(&self) -> users::PolicyChange {
                users::PolicyChange::CreateUser {
                    name: "source worker user".into(),
                    protocols: vec![crate::access::Protocol::Http],
                    concurrent_limit: 4,
                }
            }
            pub(in crate::manage) async fn close(self) -> io::Result<()> {
                let source = self.source.shutdown_writer().await;
                self.stop.cancel();
                let server = self.server.await.map_err(io::Error::other)?;
                source?;
                server
            }
        }

        #[tokio::test]
        async fn a_panicking_accepted_source_job_fences_reader_and_releases_its_writer_after_unwind()
        -> io::Result<()> {
            let live = Live::new(Default::default()).await?;
            let result = async {
                // Reuse this same private baseline and identity after a completed normal
                // stop; no database, certificates or authority are regenerated.
                live.source.shutdown_writer().await?;
                let (worker, ready) = super::super::worker::Worker::start(
                    live.fixture.client_state.clone(),
                    live.author.clone(),
                    live.enrollment.clone(),
                    live.endpoint.clone(),
                    tls::node_identity(
                        &live.fixture.ca,
                        &live.fixture.client_cert,
                        &live.fixture.client_key,
                    )?,
                )
                .await?;
                let admission = Arc::new(tokio::sync::Semaphore::new(1));
                let permit = admission
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(io::Error::other)?;
                let result = worker
                    .write(
                        permit,
                        |_| -> io::Result<()> {
                            panic!("fixture accepted source callback unwound");
                        },
                        || false,
                    )
                    .await;
                assert_eq!(result.err().map(|e| e.kind()), Some(io::ErrorKind::Other));
                assert!(ready.reader.revision().is_err());
                assert!(worker.shutdown().await.is_err());
                assert_eq!(admission.available_permits(), 1);
                store::update_lock(&live.fixture.client_state)?;
                assert_eq!(
                    (live.floor()?.sequence.as_str(), live.floor()?.phase),
                    ("0", Phase::Confirmed)
                );
                Ok(())
            }
            .await;
            let closed = live.close().await;
            result.and(closed)
        }

        #[test]
        fn coordinator_source_progresses_with_one_blocking_thread_and_confirms_application_receipts()
        -> io::Result<()> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .max_blocking_threads(1)
                .build()?;
            runtime.block_on(async {
                let live = Live::new(Default::default()).await?;
                let result = async {
                    let reader = live.source.reader();
                    assert_eq!(reader.revision()?, 1);
                    live.source.activate().await?;
                    live.source.activate().await?; // No net-zero source transaction.
                    assert_eq!(live.floor()?.sequence, "1");
                    let user = live
                        .source
                        .change(live.administrator.clone(), 1, live.user())
                        .await?;
                    assert!(user.running);
                    let id = user.user.ok_or_else(invalid)?.id;
                    let credential = live
                        .source
                        .change(
                            live.administrator.clone(),
                            2,
                            users::PolicyChange::CreateCredential {
                                user_id: id.clone(),
                            },
                        )
                        .await?;
                    assert!(credential.running);
                    let saved = credential.credential.ok_or_else(invalid)?;
                    let secret = credential.secret.ok_or_else(invalid)?;
                    let lease = reader
                        .authenticate(
                            &saved.login,
                            secret.as_bytes(),
                            crate::access::Protocol::Http,
                        )
                        .map_err(|_| invalid())?;
                    live.source
                        .change(
                            live.administrator.clone(),
                            3,
                            users::PolicyChange::SetUserActive { id, active: false },
                        )
                        .await?;
                    assert_eq!(reader.revision()?, 4);
                    assert_eq!(reader.admission()?.active_operations, 1);
                    assert!(matches!(
                        reader.authenticate(
                            &saved.login,
                            secret.as_bytes(),
                            crate::access::Protocol::Http
                        ),
                        Err(crate::access::Error::Denied)
                    ));
                    drop(lease);
                    assert_eq!(reader.admission()?.active_operations, 0);
                    let status = live.source.status().await?;
                    assert_eq!(
                        (status.saved_revision, status.durable_applied_revision),
                        (4, Some(4))
                    );
                    let before = live.floor()?;
                    assert_eq!(
                        (before.sequence.as_str(), before.phase),
                        ("7", Phase::Confirmed)
                    );
                    for (administrator, revision) in [
                        (live.fixture.server_id.clone(), 4),
                        (live.administrator.clone(), 2),
                    ] {
                        assert!(
                            live.source
                                .change(administrator, revision, live.user())
                                .await
                                .is_err()
                        );
                        assert_eq!(reader.revision()?, 4);
                    }
                    assert_eq!(live.floor()?.sequence, before.sequence);
                    assert!(store::peers::open_existing(&live.fixture.client_state, true).is_err());
                    // Remaining native-only writers stay blocked; this constructor is
                    // internal and cannot turn partial coverage into a runtime mode.
                    let peer = live.fixture.server_id.clone();
                    assert!(
                        live.source
                            .metadata_write(move |directory| store::set_peer_active(
                                directory, &peer, 1, false
                            ))
                            .await
                            .is_err()
                    );
                    assert_eq!(live.floor()?.sequence, before.sequence);
                    assert_eq!(reader.revision()?, 4);
                    live.source.shutdown_writer().await?;
                    assert!(reader.revision().is_err());
                    store::update_lock(&live.fixture.client_state)?;
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)
            })
        }

        #[tokio::test]
        async fn coordinator_source_lost_policy_or_applied_receipt_retains_original_without_secret_replay()
        -> io::Result<()> {
            for (reserve, active, sequence) in [
                (true, false, None),
                (false, false, None),
                (false, true, Some(5)),
            ] {
                let live = Live::new(node::tests::CutResponse {
                    witness_reserve: reserve,
                    witness_confirm: !reserve,
                    witness_sequence: sequence,
                    ..Default::default()
                })
                .await?;
                let result = async {
                    if active {
                        live.source.activate().await?;
                    }
                    let user = live
                        .source
                        .change(live.administrator.clone(), 1, live.user())
                        .await?
                        .user
                        .ok_or_else(invalid)?
                        .id;
                    live.arm();
                    let error = live
                        .source
                        .change(
                            live.administrator.clone(),
                            2,
                            users::PolicyChange::CreateCredential { user_id: user },
                        )
                        .await
                        .err()
                        .ok_or_else(invalid)?;
                    assert_eq!(error.kind(), io::ErrorKind::Other);
                    assert!(live.source.reader().revision().is_err());
                    let before = live.floor()?;
                    assert!(live.source.activate().await.is_err());
                    assert!(
                        live.source
                            .change(live.administrator.clone(), 2, live.user())
                            .await
                            .is_err()
                    );
                    assert_eq!(live.floor()?.sequence, before.sequence);
                    live.source.reconcile_source().await?;
                    assert_eq!(live.source.reader().revision()?, 3);
                    let c = store::peers::open_existing(&live.fixture.client_state, false)?;
                    let count: i64 = c
                        .query_row("SELECT count(*) FROM proxy_credentials", [], |row| {
                            row.get(0)
                        })
                        .map_err(io::Error::other)?;
                    assert_eq!(count, 1);
                    if active {
                        assert_eq!(users::read_state(&c)?.1, Some(3));
                    }
                    assert_eq!(
                        (live.floor()?.sequence.as_str(), live.floor()?.phase),
                        (if active { "5" } else { "2" }, Phase::Confirmed)
                    );
                    live.source.reconcile_source().await?;
                    assert_eq!(live.floor()?.sequence, if active { "5" } else { "2" });
                    assert_eq!(live.fault.cuts.load(Ordering::Acquire), 1);
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)?;
            }
            Ok(())
        }

        #[tokio::test]
        async fn cancelled_source_wait_and_shutdown_keep_the_accepted_job_and_both_guards_until_confirmed()
        -> io::Result<()> {
            let pause = Arc::new(node::tests::ResponsePause::default());
            let live = Live::new(node::tests::CutResponse {
                witness_confirm: true,
                pause: Some(pause.clone()),
                ..Default::default()
            })
            .await?;
            let result = async {
                live.arm();
                let mut change = Box::pin(live.source.change(
                    live.administrator.clone(),
                    1,
                    live.user(),
                ));
                assert!(futures_util::poll!(&mut change).is_pending());
                timeout(Duration::from_secs(10), pause.entered.notified())
                    .await
                    .map_err(io::Error::other)?;
                drop(change);
                assert_eq!(live.source.write_work().available_permits(), 0);
                assert!(live.source.reader().revision().is_err());
                assert!(store::update_lock(&live.fixture.client_state).is_err());
                assert!(store::lock(&live.fixture.client_state).is_err());
                let mut shutdown = Box::pin(live.source.shutdown_writer());
                assert!(futures_util::poll!(&mut shutdown).is_pending());
                drop(shutdown);
                assert!(
                    live.source
                        .change(live.administrator.clone(), 1, live.user())
                        .await
                        .is_err()
                );
                assert!(store::update_lock(&live.fixture.client_state).is_err());
                pause.release.notify_one();
                timeout(Duration::from_secs(10), live.source.shutdown_writer())
                    .await
                    .map_err(io::Error::other)??;
                assert!(live.source.reader().revision().is_err());
                store::update_lock(&live.fixture.client_state)?;
                let c = store::peers::open_existing(&live.fixture.client_state, false)?;
                let count: i64 = c
                    .query_row("SELECT count(*) FROM proxy_users", [], |row| row.get(0))
                    .map_err(io::Error::other)?;
                assert_eq!(count, 1);
                assert_eq!(
                    (live.floor()?.sequence.as_str(), live.floor()?.phase),
                    ("1", Phase::Confirmed)
                );
                Ok(())
            }
            .await;
            // Also release on a returned I/O failure so teardown never depends on the
            // requesting future retaining its wait. Notification retains one permit.
            pause.release.notify_one();
            let closed = live.close().await;
            result.and(closed)
        }
    }

    fn enrollment(f: &node::tests::Fixture) -> Enrollment {
        Enrollment {
            witness_node_id: f.server_id.clone(),
            peer_node_id: f.client_id.clone(),
            binding_id: URL_SAFE_NO_PAD.encode([31_u8; 16]),
            writer_id: URL_SAFE_NO_PAD.encode([32_u8; 16]),
            baseline: "0".repeat(64),
        }
    }
    fn proof(f: &node::tests::Fixture, record: Record) -> io::Result<Fetched<Record>> {
        let parent = f.ca.parent().ok_or_else(invalid)?;
        let pem = files::read(&parent.join("server.pem"), 16 * 1024, false)?;
        let der = rustls_pemfile::certs(&mut pem.as_slice())
            .next()
            .transpose()?
            .ok_or_else(invalid)?;
        Ok(Fetched {
            authorization: super::super::RemoteAuthorization {
                node_id: f.server_id.clone(),
                authorization_revision: 1,
                leaf: Arc::from(der.as_ref()),
            },
            value: record,
        })
    }
    fn baseline(f: &node::tests::Fixture, e: &Enrollment) -> io::Result<Fetched<Record>> {
        proof(
            f,
            Record {
                enrollment: e.clone(),
                sequence: "0".into(),
                previous: None,
                commitment: e.baseline.clone(),
                phase: Phase::Confirmed,
                retired: false,
            },
        )
    }
    fn reply(
        f: &node::tests::Fixture,
        e: &Enrollment,
        t: &Transition,
        phase: Phase,
    ) -> io::Result<Fetched<Record>> {
        proof(
            f,
            Record {
                enrollment: e.clone(),
                sequence: t.sequence.clone(),
                previous: Some(t.previous.clone()),
                commitment: t.commitment.clone(),
                phase,
                retired: false,
            },
        )
    }
    fn scope<'a>(
        f: &'a node::tests::Fixture,
        a: &'a Guard,
        g: &'a UpdateGuard,
        e: &'a Enrollment,
    ) -> Scope<'a> {
        Scope {
            directory: &f.client_state,
            author: a,
            gate: g,
            enrollment: e,
        }
    }
    fn changed(tx: &Transaction<'_>) -> io::Result<usize> {
        tx.execute(
            "UPDATE administrators SET password_hash='journal-fixture-phc'",
            [],
        )
        .map_err(|e| sqlite_error("fixture verifier change failed", e))
    }
    fn source_connection(
        f: &node::tests::Fixture,
        a: &Guard,
        g: &UpdateGuard,
        e: &Enrollment,
    ) -> io::Result<Connection> {
        let mut connection = open(&scope(f, a, g, e))?;
        initialize(&scope(f, a, g, e), &mut connection, &baseline(f, e)?)?;
        Ok(connection)
    }
    fn verifier(c: &Connection) -> io::Result<String> {
        c.query_row("SELECT password_hash FROM administrators", [], |r| r.get(0))
            .map_err(io::Error::other)
    }

    #[test]
    fn private_intent_survives_rollback_without_exposing_verifier_in_metadata() -> io::Result<()> {
        let f = node::tests::Fixture::new_with_private_source(true, true)?;
        let e = enrollment(&f);
        let a = super::super::lock(&f.client_state)?;
        let g = super::super::update_lock(&f.client_state)?;
        let mut c = source_connection(&f, &a, &g, &e)?;
        let output = f.client_state.join("intent-drop");
        let prepared = prepare(
            scope(&f, &a, &g, &e),
            &mut c,
            &baseline(&f, &e)?,
            None,
            &output,
            changed,
        )?;
        assert_eq!(prepared.intent().transition().sequence, "1");
        assert!(
            prepared
                .intent()
                .payload()?
                .windows(b"journal-fixture-phc".len())
                .any(|s| s == b"journal-fixture-phc")
        );
        assert!(!fs::read_to_string(output.join(META))?.contains("journal-fixture-phc"));
        let before = prepared.intent().transition().clone();
        drop(prepared);
        assert_eq!(verifier(&c)?, "fixture-phc");
        let loaded = Intent::load(&output, &e)?;
        assert_eq!(loaded.transition(), &before);
        assert_eq!(loaded.directory, fs::canonicalize(&output)?);
        let bytes = fs::read(output.join(PAYLOAD))?;
        assert_eq!(loaded.payload()?.as_slice(), bytes);
        assert!(
            prepare(
                scope(&f, &a, &g, &e),
                &mut c,
                &baseline(&f, &e)?,
                None,
                &output,
                changed
            )
            .is_err()
        );
        assert_eq!(verifier(&c)?, "fixture-phc");
        assert_eq!(fs::read(output.join(PAYLOAD))?, bytes);
        Ok(())
    }

    #[test]
    fn exact_pending_commit_and_confirm_are_separate_from_rejected_or_unknown_results()
    -> io::Result<()> {
        let f = node::tests::Fixture::new_with_private_source(true, true)?;
        let e = enrollment(&f);
        let a = super::super::lock(&f.client_state)?;
        let g = super::super::update_lock(&f.client_state)?;
        let mut c = source_connection(&f, &a, &g, &e)?;
        for i in 0..7 {
            let prepared = prepare(
                scope(&f, &a, &g, &e),
                &mut c,
                &baseline(&f, &e)?,
                None,
                &f.client_state.join(format!("rejected-{i}")),
                changed,
            )?;
            let mut pending = reply(&f, &e, prepared.intent().transition(), Phase::Pending)?;
            match i {
                0 => pending.value.phase = Phase::Confirmed,
                1 => pending.value.commitment = "5".repeat(64),
                2 => pending.value.sequence = "2".into(),
                3 => pending.authorization.authorization_revision = 2,
                4 => pending.value.enrollment.writer_id = URL_SAFE_NO_PAD.encode([33_u8; 16]),
                5 => pending.value.previous = Some("8".repeat(64)),
                _ => pending.value.retired = true,
            }
            assert_eq!(
                prepared.commit(&pending).err().map(|e| e.kind()),
                Some(io::ErrorKind::PermissionDenied)
            );
            assert_eq!(verifier(&c)?, "fixture-phc");
        }
        let output = f.client_state.join("committed");
        let prepared = prepare(
            scope(&f, &a, &g, &e),
            &mut c,
            &baseline(&f, &e)?,
            None,
            &output,
            changed,
        )?;
        let pending = reply(&f, &e, prepared.intent().transition(), Phase::Pending)?;
        let committed = prepared.commit(&pending)?;
        let mut confirmed = reply(&f, &e, committed.intent().transition(), Phase::Confirmed)?;
        confirmed.value.commitment = "6".repeat(64);
        assert_eq!(
            committed.confirm(&confirmed).err().map(|e| e.kind()),
            Some(io::ErrorKind::Other)
        );
        // Confirmation failure did not undo committed facts or replace the intent.
        assert_eq!(verifier(&c)?, "journal-fixture-phc");
        assert!(Intent::load(&output, &e).is_ok());
        Ok(())
    }

    #[test]
    fn early_commit_ddl_empty_delta_and_witness_revocation_cannot_escape_preparation()
    -> io::Result<()> {
        let f = node::tests::Fixture::new_with_private_source(true, true)?;
        let e = enrollment(&f);
        let a = super::super::lock(&f.client_state)?;
        let g = super::super::update_lock(&f.client_state)?;
        let mut c = source_connection(&f, &a, &g, &e)?;
        for mode in 0..5 {
            let output = f.client_state.join(format!("invalid-{mode}"));
            let result = prepare(
                scope(&f, &a, &g, &e),
                &mut c,
                &baseline(&f, &e)?,
                None,
                &output,
                |tx| {
                    match mode {
                        0 => tx
                            .execute_batch(
                                "UPDATE administrators SET password_hash='too-early'; COMMIT;",
                            )
                            .map_err(io::Error::other)?,
                        1 => tx
                            .execute_batch(
                                "CREATE TABLE journal_extra(id INTEGER PRIMARY KEY) STRICT;",
                            )
                            .map_err(io::Error::other)?,
                        2 => {}
                        3 => {
                            tx.execute(
                                "UPDATE peers SET active=0 WHERE node_id=?1",
                                [&f.server_id],
                            )
                            .map_err(io::Error::other)?;
                        }
                        _ => {
                            let key = tls::node_key_sha256(&f.client_key)?;
                            tx.execute("UPDATE recovery_state SET kind='restored',phase='ready',recovery_id=?1,source_node_id=?2,source_schema_version=13,source_database_sha256=?3,node_key_sha256=?4,imported_users=0,imported_prefixes=0,imported_addresses=0,imported_pools=0 WHERE singleton=1",
                        rusqlite::params![URL_SAFE_NO_PAD.encode([36_u8;16]),f.server_id,"7".repeat(64),&key[..]]).map_err(io::Error::other)?;
                        }
                    }
                    Ok(())
                },
            );
            assert!(result.is_err(), "mode {mode}");
            drop(result);
            assert_eq!(verifier(&c)?, "fixture-phc");
            assert!(!output.join(META).exists());
            assert!(
                super::super::authorize_peer(
                    &f.client_state,
                    &baseline(&f, &e)?.authorization.leaf
                )?
                .is_some()
            );
        }
        let extra: bool = c
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='journal_extra')",
                [],
                |r| r.get(0),
            )
            .map_err(io::Error::other)?;
        assert!(!extra);
        Ok(())
    }

    #[test]
    fn sqlite_commit_errors_never_masquerade_as_precommit_rejections() -> io::Result<()> {
        let f = node::tests::Fixture::new_with_private_source(true, true)?;
        let e = enrollment(&f);
        let a = super::super::lock(&f.client_state)?;
        let g = super::super::update_lock(&f.client_state)?;
        let mut c = source_connection(&f, &a, &g, &e)?;
        let output = f.client_state.join("deferred-fk");
        let prepared = prepare(
            scope(&f, &a, &g, &e),
            &mut c,
            &baseline(&f, &e)?,
            None,
            &output,
            |tx| {
                tx.execute_batch("PRAGMA defer_foreign_keys=ON;")
                    .map_err(io::Error::other)?;
                tx.execute("INSERT INTO peer_audit(sequence,entry,action,node_id,authorization_revision) VALUES(999,'offline','register',?1,1)",[URL_SAFE_NO_PAD.encode([34_u8;16])]).map_err(io::Error::other)?;
                changed(tx)
            },
        )?;
        let pending = reply(&f, &e, prepared.intent().transition(), Phase::Pending)?;
        let error = prepared.commit(&pending).err().ok_or_else(invalid)?;
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("unknown"));
        assert_eq!(verifier(&c)?, "fixture-phc");
        assert!(Intent::load(&output, &e).is_ok());
        Ok(())
    }

    #[test]
    fn nondurable_connection_is_refused_without_changing_its_mode() -> io::Result<()> {
        let f = node::tests::Fixture::new_with_private_source(true, true)?;
        let e = enrollment(&f);
        let a = super::super::lock(&f.client_state)?;
        let g = super::super::update_lock(&f.client_state)?;
        let mut c = source_connection(&f, &a, &g, &e)?;
        c.pragma_update(None, "synchronous", "OFF")
            .map_err(io::Error::other)?;
        let output = f.client_state.join("not-durable");
        assert!(
            prepare(
                scope(&f, &a, &g, &e),
                &mut c,
                &baseline(&f, &e)?,
                None,
                &output,
                changed
            )
            .is_err()
        );
        let setting: i64 = c
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .map_err(io::Error::other)?;
        assert_eq!(setting, 0);
        assert!(!output.exists());
        assert_eq!(verifier(&c)?, "fixture-phc");
        Ok(())
    }

    #[test]
    fn payload_output_limit_rejects_without_appending_or_truncating_prefix() -> io::Result<()> {
        let f = node::tests::Fixture::new_with_private_source(true, true)?;
        let path = f.client_state.join("limit-output");
        files::create_directory(&path)?;
        let mut writer = PayloadWriter {
            file: super::super::backup::new_file(&path.join(PAYLOAD))?,
            hash: Sha256::new(),
            bytes: 0,
        };
        let chunk = [42_u8; 64 * 1024];
        for _ in 0..MAX_PAYLOAD / chunk.len() {
            assert_eq!(writer.write(&chunk)?, chunk.len());
        }
        assert_eq!(writer.bytes, MAX_PAYLOAD as u64);
        let prefix = writer.hash.clone().finalize();
        assert!(writer.write(&[1]).is_err());
        assert_eq!(writer.bytes, MAX_PAYLOAD as u64);
        assert_eq!(writer.hash.clone().finalize(), prefix);
        assert_eq!(writer.file.metadata()?.len(), MAX_PAYLOAD as u64);
        assert!(!path.join(META).exists());
        Ok(())
    }

    #[test]
    fn loading_refuses_partial_corrupt_rebound_and_extra_files_without_repair() -> io::Result<()> {
        let f = node::tests::Fixture::new_with_private_source(true, true)?;
        let e = enrollment(&f);
        let a = super::super::lock(&f.client_state)?;
        let g = super::super::update_lock(&f.client_state)?;
        let mut c = source_connection(&f, &a, &g, &e)?;
        let output = f.client_state.join("corruption");
        drop(prepare(
            scope(&f, &a, &g, &e),
            &mut c,
            &baseline(&f, &e)?,
            None,
            &output,
            changed,
        )?);
        let original = fs::read(output.join(PAYLOAD))?;
        let loaded = Intent::load(&output, &e)?;
        let mut corrupt = original.clone();
        corrupt[0] ^= 1;
        fs::write(output.join(PAYLOAD), &corrupt)?;
        assert!(loaded.payload().is_err());
        assert!(Intent::load(&output, &e).is_err());
        assert_eq!(fs::read(output.join(PAYLOAD))?, corrupt);
        fs::write(output.join(PAYLOAD), &original)?;
        let mut wrong = e.clone();
        wrong.writer_id = URL_SAFE_NO_PAD.encode([35_u8; 16]);
        assert!(Intent::load(&output, &wrong).is_err());
        files::write(&output, "extra", b"extra")?;
        assert!(Intent::load(&output, &e).is_err());
        fs::remove_file(output.join("extra"))?;
        fs::remove_file(output.join(META))?;
        assert!(Intent::load(&output, &e).is_err());
        assert!(output.join(PAYLOAD).exists());
        Ok(())
    }

    #[tokio::test]
    async fn private_transaction_round_trip_uses_the_actual_witness_tls_reservation()
    -> io::Result<()> {
        use crate::manage::node::control::{
            Offline,
            witness::{Action, Operation},
        };
        use tokio::net::TcpListener;
        use tokio_util::sync::CancellationToken;
        let f = Arc::new(node::tests::Fixture::new_with_private_source(true, true)?);
        let e = enrollment(&f);
        witness::Enrollment::validate(&e)?;
        super::super::witness::bind(&f.server_state, &e)?;
        let policy = Coordinator::new(
            f.server_state.clone(),
            super::super::load_policy(&f.server_state)?,
            Arc::new(super::super::lock(&f.server_state)?),
        )?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let stop = CancellationToken::new();
        let task = tokio::spawn(node::serve(
            listener,
            f.config(address)?,
            f.server_state.clone(),
            stop.clone(),
            Some(policy),
            None,
            None,
        ));
        let worker = f.clone();
        let endpoint = format!("https://localhost:{}", address.port());
        let handle = tokio::runtime::Handle::current();
        let expected = e.clone();
        let result = tokio::task::spawn_blocking(move || -> io::Result<()> {
            let author = Arc::new(super::super::lock(&worker.client_state)?);
            let gate = super::super::update_lock(&worker.client_state)?;
            let identity = tls::node_identity(&worker.ca, &worker.client_cert, &worker.client_key)?;
            let source = Offline::new(
                &worker.client_state,
                author.clone(),
                &worker.client_id,
                identity,
            )?;
            let previous = handle.block_on(source.request(
                &endpoint,
                &expected.witness_node_id,
                Operation {
                    enrollment: expected.clone(),
                    action: Action::Inspect,
                },
            ))?;
            let bound_scope = scope(&worker, &author, &gate, &expected);
            let mut connection = open(&bound_scope)?;
            initialize(&bound_scope, &mut connection, &previous)?;
            let prepared = prepare(
                scope(&worker, &author, &gate, &expected),
                &mut connection,
                &previous,
                None,
                &worker.client_state.join("real-tls-intent"),
                changed,
            )?;
            let pending = handle.block_on(source.request(
                &endpoint,
                &expected.witness_node_id,
                Operation {
                    enrollment: expected.clone(),
                    action: Action::Reserve(prepared.intent().transition().clone()),
                },
            ))?;
            let committed = prepared.commit(&pending)?;
            let confirmed = handle.block_on(source.request(
                &endpoint,
                &expected.witness_node_id,
                Operation {
                    enrollment: expected.clone(),
                    action: Action::Confirm(committed.intent().transition().clone()),
                },
            ))?;
            assert_eq!(committed.confirm(&confirmed)?, 1);
            assert_eq!(verifier(&connection)?, "journal-fixture-phc");
            Ok(())
        })
        .await
        .map_err(io::Error::other)?;
        stop.cancel();
        task.await.map_err(io::Error::other)??;
        result?;
        let record = super::super::witness::inspect(&f.server_state, &e.binding_id)?;
        assert_eq!(record.phase, Phase::Confirmed);
        assert_eq!(record.sequence, "1");
        Ok(())
    }

    #[test]
    fn batch_payload_reconstructs_the_exact_known_candidate_not_a_new_request() -> io::Result<()> {
        use rusqlite::session::ConflictAction;
        let f = node::tests::Fixture::new_with_private_source(true, true)?;
        let e = enrollment(&f);
        let a = super::super::lock(&f.client_state)?;
        let g = super::super::update_lock(&f.client_state)?;
        let mut c = source_connection(&f, &a, &g, &e)?;
        let output = f.client_state.join("batch");
        let before = content::calculate(&c, None)?;
        let prepared = prepare(
            scope(&f, &a, &g, &e),
            &mut c,
            &baseline(&f, &e)?,
            None,
            &output,
            |tx| {
                changed(tx)?;
                tx.execute("UPDATE peer_audit SET sequence=5000 WHERE sequence=1", [])
                    .map_err(io::Error::other)?;
                for i in 10..1034 {
                    tx.execute("INSERT INTO peer_audit(sequence,entry,action,node_id,authorization_revision) VALUES(?1,'offline','register',?2,1)",rusqlite::params![i,f.server_id]).map_err(io::Error::other)?;
                }
                content::calculate(tx, None)
            },
        )?;
        // The kernel appends its source floor in the same transaction after the
        // business callback. Compare the entire final candidate, including it.
        let expected = content::calculate(&prepared.transaction, None)?;
        assert!(prepared.intent().payload()?.len() < MAX_PAYLOAD);
        drop(prepared);
        assert_eq!(content::calculate(&c, None)?, before);
        let intent = Intent::load(&output, &e)?;
        let payload = intent.payload()?;
        // This fixture has a known untouched preimage. Production replay still
        // needs durable source floors, exact schema checks and restart admission.
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io::Error::other)?;
        tx.apply_strm(
            &mut io::Cursor::new(&*payload),
            None::<fn(&str) -> bool>,
            |_, _| ConflictAction::SQLITE_CHANGESET_ABORT,
        )
        .map_err(io::Error::other)?;
        assert_eq!(content::calculate(&tx, None)?, expected);
        let bad_fk: i64 = tx
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })
            .map_err(io::Error::other)?;
        assert_eq!(bad_fk, 0);
        drop(tx);
        assert_eq!(content::calculate(&c, None)?, before);
        Ok(())
    }

    #[tokio::test]
    async fn lost_wire_replies_preserve_original_intent_before_and_after_local_commit()
    -> io::Result<()> {
        use crate::manage::node::control::{
            Offline,
            witness::{Action, Operation},
        };
        use std::sync::atomic::Ordering;
        use tokio_util::sync::CancellationToken;
        for after_commit in [false, true] {
            let f = Arc::new(node::tests::Fixture::new_with_private_source(true, true)?);
            let e = enrollment(&f);
            super::super::witness::bind(&f.server_state, &e)?;
            let policy = Coordinator::new(
                f.server_state.clone(),
                super::super::load_policy(&f.server_state)?,
                Arc::new(super::super::lock(&f.server_state)?),
            )?;
            let fault = Arc::new(node::tests::CutResponse {
                witness_reserve: !after_commit,
                witness_confirm: after_commit,
                ..Default::default()
            });
            fault.armed.store(true, Ordering::Release);
            let stop = CancellationToken::new();
            let (address, task) =
                node::tests::start_cut_response_node(&f, policy, fault.clone(), stop.clone())
                    .await?;
            let worker = f.clone();
            let expected = e.clone();
            let handle = tokio::runtime::Handle::current();
            let endpoint = format!("https://localhost:{}", address.port());
            let result = tokio::task::spawn_blocking(move || -> io::Result<Transition> {
                let author = Arc::new(super::super::lock(&worker.client_state)?);
                let gate = super::super::update_lock(&worker.client_state)?;
                let source = Offline::new(
                    &worker.client_state,
                    author.clone(),
                    &worker.client_id,
                    tls::node_identity(&worker.ca, &worker.client_cert, &worker.client_key)?,
                )?;
                let previous = handle.block_on(source.request(
                    &endpoint,
                    &expected.witness_node_id,
                    Operation {
                        enrollment: expected.clone(),
                        action: Action::Inspect,
                    },
                ))?;
                let bound_scope = scope(&worker, &author, &gate, &expected);
                let mut connection = open(&bound_scope)?;
                initialize(&bound_scope, &mut connection, &previous)?;
                let path = worker.client_state.join("lost-reply");
                let prepared = prepare(
                    scope(&worker, &author, &gate, &expected),
                    &mut connection,
                    &previous,
                    None,
                    &path,
                    changed,
                )?;
                let transition = prepared.intent().transition().clone();
                let pending = handle.block_on(source.request(
                    &endpoint,
                    &expected.witness_node_id,
                    Operation {
                        enrollment: expected.clone(),
                        action: Action::Reserve(transition.clone()),
                    },
                ));
                if after_commit {
                    let committed = prepared.commit(&pending?)?;
                    let confirmed = handle.block_on(source.request(
                        &endpoint,
                        &expected.witness_node_id,
                        Operation {
                            enrollment: expected.clone(),
                            action: Action::Confirm(transition.clone()),
                        },
                    ));
                    assert!(confirmed.is_err());
                    drop(committed);
                    assert_eq!(verifier(&connection)?, "journal-fixture-phc");
                } else {
                    assert!(pending.is_err());
                    drop(prepared);
                    assert_eq!(verifier(&connection)?, "fixture-phc");
                }
                assert_eq!(Intent::load(&path, &expected)?.transition(), &transition);
                Ok(transition)
            })
            .await
            .map_err(io::Error::other)?;
            stop.cancel();
            task.await.map_err(io::Error::other)??;
            let transition = result?;
            assert_eq!(fault.cuts.load(Ordering::Acquire), 1);
            let record = super::super::witness::inspect(&f.server_state, &e.binding_id)?;
            assert_eq!(
                record.phase,
                if after_commit {
                    Phase::Confirmed
                } else {
                    Phase::Pending
                }
            );
            assert_eq!(record.sequence, transition.sequence);
            assert_eq!(record.commitment, transition.commitment);
        }
        Ok(())
    }
}
