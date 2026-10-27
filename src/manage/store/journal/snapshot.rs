//! A full inert package is sealed by one floor-only Source transaction. The
//! copied database represents N; this seal advances N to N+1 without changing
//! business facts. Later writes invalidate the old seal's current-record match.
//! Neither local evidence nor a matching record authorizes same-ID takeover.

use super::{tracked::Journal, *};
use crate::manage::node::control::witness::{Action, Operation};
use rusqlite::{
    fallible_streaming_iterator::FallibleStreamingIterator, hooks::Action as SqlAction,
    session::ChangesetIter, types::ValueRef,
};

pub(super) const MAX_FLOOR_PAYLOAD: usize = 16 * 1024;

/// Compare the actual captured configuration/static assets with an accepted
/// reference in this exact SQL view. Legacy unbound exports remain explicitly
/// operator-declared, never runtime admission. No witness request is made here.
pub(in crate::manage) fn check_configuration(
    connection: &Connection,
    enrollment: &Enrollment,
    sha256: [u8; 32],
) -> io::Result<()> {
    let state = source::load(connection, SCHEMA_VERSION)?.ok_or_else(denied)?;
    if state.enrollment != *enrollment || state.configuration.is_some_and(|c| c.sha256 != sha256) {
        return Err(denied());
    }
    Ok(())
}

/// Borrow the original author/update guards without exposing the transaction
/// kernel's Scope. Every operation revalidates the actual directory and SQL
/// enrollment; the borrow cannot survive either guard. This grants no startup.
pub(in crate::manage) struct Source<'a> {
    scope: Scope<'a>,
}
impl<'a> Source<'a> {
    pub(in crate::manage) fn new(
        directory: &'a Path,
        author: &'a Guard,
        gate: &'a UpdateGuard,
        enrollment: &'a Enrollment,
    ) -> Self {
        Self {
            scope: Scope {
                directory,
                author,
                gate,
                enrollment,
            },
        }
    }
    fn scope(&self) -> Scope<'_> {
        Scope {
            directory: self.scope.directory,
            author: self.scope.author,
            gate: self.scope.gate,
            enrollment: self.scope.enrollment,
        }
    }
    pub(in crate::manage) fn capture_database(
        &self,
        output: &Path,
        key: [u8; 32],
        request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
    ) -> io::Result<super::super::backup::BackupManifest> {
        capture_database(self.scope(), output, key, request)
    }
    pub(in crate::manage) fn seal(
        &self,
        descriptor: &Descriptor,
        resume: bool,
        evidence: &Path,
        request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
    ) -> io::Result<Proof> {
        seal(self.scope(), descriptor, resume, evidence, request)
    }
}

/// Hashes bind the complete already-validated private package and the original
/// pre-quarantine SQL content. The journal does not hash its own evidence into
/// the package descriptor, avoiding a circular digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Descriptor {
    pub(in crate::manage) snapshot_id: String,
    pub(in crate::manage) package_sha256: String,
    pub(in crate::manage) database_content_sha256: String,
}
impl Descriptor {
    pub(super) fn validate(&self) -> io::Result<()> {
        if !super::super::valid_id(&self.snapshot_id)
            || !digest(&self.package_sha256)
            || !digest(&self.database_content_sha256)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Copy only a confirmed original Source while retaining both offline guards.
/// A pending operation refuses before claiming database output; no implicit
/// reconciliation, business replay, secret recreation or source update occurs.
fn capture_database(
    scope: Scope<'_>,
    output: &Path,
    node_key_sha256: [u8; 32],
    request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
) -> io::Result<super::super::backup::BackupManifest> {
    let mut connection = open(&scope)?;
    let journal = Journal::open(scope, &connection)?;
    let observed = request(journal.operation(Action::Inspect))?;
    journal.ready(&mut connection, &observed)?;
    let scope = journal.scope();
    super::super::backup::create_source_identity_snapshot(
        scope.directory,
        output,
        scope.author,
        scope.gate,
        &mut connection,
        node_key_sha256,
    )
}

/// Seal a newly completed base package, or explicitly reconcile only its exact
/// retained seal when resume is selected. The package must already be checked
/// by its owning exporter. Freshness here is an observation under both guards,
/// never a lease or permission to activate a different copy.
fn seal(
    scope: Scope<'_>,
    descriptor: &Descriptor,
    resume: bool,
    evidence: &Path,
    request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
) -> io::Result<Proof> {
    descriptor.validate()?;
    let mut connection = open(&scope)?;
    let journal = Journal::open(scope, &connection)?;
    let retained = journal
        .pending(&connection)?
        .or(journal.current(&connection)?);
    if retained
        .as_ref()
        .is_some_and(|intent| intent.metadata.snapshot.as_ref() == Some(descriptor))
    {
        Proof {
            intent: journal.load(sequence(
                &retained.as_ref().ok_or_else(invalid)?.transition().sequence,
            )?)?,
        }
        .check_existing(evidence)?;
        if !resume {
            return Err(driver::unresolved());
        }
        journal.reconcile(&mut connection, request, || Ok(()))?;
    } else {
        match fs::symlink_metadata(evidence) {
            Ok(_) => return Err(denied()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let observed = request(journal.operation(Action::Inspect))?;
        journal.ready(&mut connection, &observed)?;
        let prepared = match journal.capture(
            &mut connection,
            &observed,
            CaptureMode::Snapshot(descriptor),
            |_, _| Ok(()),
        )? {
            Captured::Write(value) => value,
            Captured::Read(_) => return Err(invalid()),
        };
        let pending = request(journal.dispatch(&prepared)?).map_err(driver::uncertain)?;
        let committed = prepared.commit(&pending).map_err(driver::uncertain)?;
        journal.finish(committed, request)?;
    }
    let observed = request(journal.operation(Action::Inspect)).map_err(driver::uncertain)?;
    journal
        .ready(&mut connection, &observed)
        .map_err(driver::uncertain)?;
    let intent = journal.current(&connection)?.ok_or_else(invalid)?;
    if intent.metadata.snapshot.as_ref() != Some(descriptor) {
        return Err(denied());
    }
    check_payload(&connection, &intent)?;
    let proof = Proof { intent };
    proof.write(evidence)?;
    Ok(proof)
}

/// Private evidence, not an authenticated record, freshness grant or activation
/// capability. It contains only the original floor-only intent, never a replay
/// of user/password creation. An archive still needs a new actual witness check.
pub(in crate::manage) struct Proof {
    intent: Intent,
}
impl Proof {
    pub(in crate::manage) fn transition(&self) -> &Transition {
        self.intent.transition()
    }

    /// Create or complete only these exact two private evidence files. Existing
    /// partial/corrupt/different contents refuse; nothing is overwritten/deleted.
    fn check_existing(&self, directory: &Path) -> io::Result<()> {
        match fs::symlink_metadata(directory) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        }
        entries(directory, false)?;
        let metadata = serde_json::to_vec(&self.intent.metadata).map_err(|_| invalid())?;
        let payload = self.intent.payload()?;
        for (name, bytes) in [(META, metadata.as_slice()), (PAYLOAD, payload.as_slice())] {
            match fs::symlink_metadata(directory.join(name)) {
                Ok(_) => {
                    if files::read(
                        &directory.join(name),
                        if name == META {
                            MAX_META
                        } else {
                            MAX_FLOOR_PAYLOAD
                        },
                        true,
                    )?
                    .as_slice()
                        != bytes
                    {
                        return Err(denied());
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    fn write(&self, directory: &Path) -> io::Result<()> {
        match fs::symlink_metadata(directory) {
            Ok(_) => files::check_directory(directory, true)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => files::create_directory(directory)?,
            Err(e) => return Err(e),
        }
        entries(directory, false)?;
        let metadata = serde_json::to_vec(&self.intent.metadata).map_err(|_| invalid())?;
        let payload = self.intent.payload()?;
        for (name, bytes) in [(META, metadata.as_slice()), (PAYLOAD, payload.as_slice())] {
            let path = directory.join(name);
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    if files::read(
                        &path,
                        if name == META {
                            MAX_META
                        } else {
                            MAX_FLOOR_PAYLOAD
                        },
                        true,
                    )?
                    .as_slice()
                        != bytes
                    {
                        return Err(denied());
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    files::write(directory, name, bytes)?
                }
                Err(e) => return Err(e),
            }
        }
        entries(directory, true)
    }
}

/// Validate archived binding and exact row transition without writing a page.
/// Full database/quarantine/assets must separately match the package descriptor;
/// this check does not contact the witness or authorize the post-seal floor.
pub(in crate::manage) fn evidence(
    directory: &Path,
    connection: &Connection,
    descriptor: &Descriptor,
    previous_key: Option<[u8; 32]>,
    enrollment: &Enrollment,
) -> io::Result<Proof> {
    entries(directory, true)?;
    let state = source::load(connection, SCHEMA_VERSION)?.ok_or_else(denied)?;
    if state.enrollment != *enrollment {
        return Err(denied());
    }
    let intent = Intent::load(directory, &state.enrollment)?;
    if intent.metadata.snapshot.as_ref() != Some(descriptor)
        || intent.metadata.before_state() != state
        || intent.metadata.recovery_key_sha256 != previous_key
        || intent.metadata.schema_sha256 != content::schema(connection)?
    {
        return Err(denied());
    }
    check_payload(connection, &intent)?;
    Ok(Proof { intent })
}

fn entries(directory: &Path, complete: bool) -> io::Result<()> {
    files::check_directory(directory, true)?;
    let mut count = 0;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if count >= 2 || !matches!(entry.file_name().to_str(), Some(META | PAYLOAD)) {
            return Err(invalid());
        }
        count += 1;
    }
    if complete && count != 2 {
        return Err(invalid());
    }
    Ok(())
}

/// Only one UPDATE of the original source singleton is legal. Snapshot seals
/// preserve the accepted configuration; format 5 advances only that reference.
/// Old/new payloads must bind exact enrollment, pre-floor and next intent nonce;
/// table-count or Reader-effect checks alone cannot establish that transition.
pub(super) fn check_payload(connection: &Connection, intent: &Intent) -> io::Result<()> {
    if intent.metadata.snapshot.is_none() && intent.metadata.format != 5 {
        return Err(invalid());
    }
    let payload = intent.payload()?;
    let delta = replay::delta(connection, &payload)?;
    if !delta.source_only() || delta.effect()? != Effect::Unchanged {
        return Err(denied());
    }
    let mut cursor = io::Cursor::new(payload.as_slice());
    let reader: &mut dyn io::Read = &mut cursor;
    let mut iter = ChangesetIter::start_strm(&reader)
        .map_err(|e| sqlite_error("cannot inspect snapshot floor", e))?;
    let row = iter
        .next()
        .map_err(|e| sqlite_error("cannot read snapshot floor", e))?
        .ok_or_else(invalid)?;
    let op = row
        .op()
        .map_err(|e| sqlite_error("cannot decode snapshot floor", e))?;
    if op.code() != SqlAction::SQLITE_UPDATE
        || op.table_name() != "recovery_source"
        || row.old_value(0).map_err(|_| invalid())? != ValueRef::Integer(1)
    {
        return Err(invalid());
    }
    let decode = |value: ValueRef<'_>| -> io::Result<source::State> {
        let ValueRef::Blob(bytes) = value else {
            return Err(invalid());
        };
        if bytes.len() > 4096 {
            return Err(invalid());
        }
        let state: source::State = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        state.validate()?;
        if serde_json::to_vec(&state).map_err(|_| invalid())? != bytes {
            return Err(invalid());
        }
        Ok(state)
    };
    let before = decode(row.old_value(1).map_err(|_| invalid())?)?;
    let after = decode(row.new_value(1).map_err(|_| invalid())?)?;
    if before != intent.metadata.before_state() || after != intent.metadata.after_state()? {
        return Err(denied());
    }
    if iter.next().map_err(|_| invalid())?.is_some() {
        return Err(invalid());
    }
    Ok(())
}
