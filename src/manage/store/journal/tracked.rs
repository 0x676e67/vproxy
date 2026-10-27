//! Fixed, private operation locators. Each sequence is claimed once; unresolved
//! entries and partial files cannot be overwritten by a replacement request.
//! SQL/filesystem work is blocking. The caller uses a bounded source worker and
//! retains the existing guards across the separate witness network operations.

use super::*;
use crate::manage::node::control::witness::{Action, Operation};

const ROOT: &str = "witness-intents";

mod retention;
pub(super) use retention::check_capacity;
pub(super) use retention::check_capacity_for;

/// Only baseline staging may claim a new root. An established binding never
/// recreates a missing journal, including the baseline's crash-before-first-write
/// window. Existing initial roots must be empty, not another adopted history.
pub(super) fn initialize_root(scope: &Scope<'_>, new: bool) -> io::Result<()> {
    let root = scope.directory.join(ROOT);
    match fs::symlink_metadata(&root) {
        Err(e) if new && e.kind() == io::ErrorKind::NotFound => files::create_directory(&root)?,
        Err(e) => return Err(e),
        Ok(_) => files::check_directory(&root, true)?,
    }
    if new && fs::read_dir(root)?.next().transpose()?.is_some() {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Location {
    format: u8,
    intent_id: String,
    transition: Transition,
}

impl Location {
    fn of(intent: &Intent) -> Self {
        Self {
            format: 1,
            intent_id: intent.metadata.intent_id.clone(),
            transition: intent.transition().clone(),
        }
    }
    fn read(path: &Path, enrollment: &Enrollment) -> io::Result<Self> {
        let bytes = files::read(path, MAX_META, true)?;
        let location: Self = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        location.transition.validate()?;
        if location.format != 1
            || !super::super::valid_id(&location.intent_id)
            || location.transition.witness_node_id != enrollment.witness_node_id
            || location.transition.binding_id != enrollment.binding_id
            || location.transition.writer_id != enrollment.writer_id
            || serde_json::to_vec(&location).map_err(|_| invalid())? != *bytes
        {
            return Err(invalid());
        }
        Ok(location)
    }
}

/// Borrows the existing exclusive source guards. This index is not a second
/// database or a startup/fencing permit. Confirmed obsolete records may be
/// collected through the bounded retirement protocol; unknown output stays.
pub(in crate::manage::store) struct Journal<'a> {
    scope: Scope<'a>,
    root: PathBuf,
    collection_warned: AtomicBool,
}

impl<'a> Journal<'a> {
    /// Inspect the fixed private root staged by baseline initialization. Missing
    /// roots, broad ACLs and incomplete bindings are refused, never recreated.
    pub(in crate::manage::store) fn open(
        scope: Scope<'a>,
        connection: &Connection,
    ) -> io::Result<Self> {
        scope.validate(connection)?;
        scope.state(connection)?;
        let root = scope.directory.join(ROOT);
        files::check_directory(&root, true)?;
        Ok(Self {
            scope,
            root: fs::canonicalize(root)?,
            collection_warned: AtomicBool::new(false),
        })
    }

    pub(super) fn scope(&self) -> Scope<'_> {
        Scope {
            directory: self.scope.directory,
            author: self.scope.author,
            gate: self.scope.gate,
            enrollment: self.scope.enrollment,
        }
    }
    pub(super) fn ensure(&self) -> io::Result<()> {
        self.scope.author.ensure(self.scope.directory)?;
        self.scope.gate.ensure(self.scope.directory)?;
        files::check_directory(&self.root, true)
    }
    fn name(sequence: u64, sent: bool) -> io::Result<String> {
        if sequence == 0 || sequence > i64::MAX as u64 {
            return Err(invalid());
        }
        Ok(if sent {
            format!("sent-{sequence}.json")
        } else {
            format!("{sequence}.json")
        })
    }
    fn check(&self, intent: &Intent) -> io::Result<Location> {
        self.ensure()?;
        intent.metadata.validate(self.scope.enrollment)?;
        let sequence = sequence(&intent.transition().sequence)?;
        let location = Location::read(
            &self.root.join(Self::name(sequence, false)?),
            self.scope.enrollment,
        )?;
        let directory = self.root.join(&location.intent_id);
        files::check_directory(&directory, true)?;
        if location != Location::of(intent) || fs::canonicalize(directory)? != intent.directory {
            return Err(denied());
        }
        Ok(location)
    }

    /// Read one exact original operation by sequence, never by directory scan.
    /// A malformed dispatch marker is not treated as an unsent operation.
    pub(in crate::manage::store) fn load(&self, number: u64) -> io::Result<Intent> {
        self.ensure()?;
        let location = Location::read(
            &self.root.join(Self::name(number, false)?),
            self.scope.enrollment,
        )?;
        if sequence(&location.transition.sequence)? != number {
            return Err(invalid());
        }
        let intent = Intent::load(&self.root.join(&location.intent_id), self.scope.enrollment)?;
        self.check(&intent)?;
        self.was_dispatched(&intent)?;
        Ok(intent)
    }

    /// Load the current committed local intent; zero is only a baseline. This
    /// is for an autocommit connection, not an uncommitted candidate view.
    pub(in crate::manage::store) fn current(
        &self,
        connection: &Connection,
    ) -> io::Result<Option<Intent>> {
        if !connection.is_autocommit() {
            return Err(invalid());
        }
        self.scope.validate(connection)?;
        let state = self.scope.state(connection)?;
        if state.floor.sequence == 0 {
            return Ok(None);
        }
        let intent = self.load(state.floor.sequence)?;
        if intent.metadata.after_state()? != state {
            return Err(denied());
        }
        Ok(Some(intent))
    }

    /// An existing next-sequence locator always wins over a new request. Absence
    /// of a sent marker is not proof that a remote reserve cannot arrive late.
    pub(in crate::manage::store) fn pending(
        &self,
        connection: &Connection,
    ) -> io::Result<Option<Intent>> {
        if !connection.is_autocommit() {
            return Err(invalid());
        }
        self.scope.validate(connection)?;
        let state = self.scope.state(connection)?;
        let Some(next) = state
            .floor
            .sequence
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
        else {
            return Ok(None);
        };
        match fs::symlink_metadata(self.root.join(Self::name(next, false)?)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
            Ok(_) => {
                let intent = self.load(next)?;
                if intent.metadata.before_state() != state {
                    return Err(denied());
                }
                Ok(Some(intent))
            }
        }
    }

    /// Persist the immutable locator after payload readback and before a
    /// dispatch operation can be obtained. Failure rolls back SQL and preserves
    /// newly claimed output. The callback is never run for a claimed sequence.
    /// Requires an autocommit WAL/FULL/FK connection and trusted bounded DML;
    /// actor/CAS checks remain with the callback, which must not alter hooks,
    /// settings or transaction control. The returned candidate is not committed.
    pub(in crate::manage::store) fn prepare<'b, T>(
        &'b self,
        connection: &'b mut Connection,
        previous: &Fetched<Record>,
        change: impl FnOnce(&Transaction<'_>) -> io::Result<T>,
    ) -> io::Result<Prepared<'b, T>> {
        match self.capture(connection, previous, CaptureMode::Write, |tx, _| change(tx))? {
            Captured::Write(prepared) => Ok(prepared),
            Captured::Read(_) => Err(invalid()),
        }
    }

    /// A terminal replay records no changes and rolls back without claiming a
    /// locator. Net-zero *writes* still take strict capture and cannot claim a
    /// sequence. New mutations share the original preparation path.
    pub(super) fn prepare_or_read<'b, T>(
        &'b self,
        connection: &'b mut Connection,
        previous: &Fetched<Record>,
        change: impl FnOnce(&mut Transaction<'_>) -> io::Result<T>,
    ) -> io::Result<Captured<'b, T>> {
        self.capture(connection, previous, CaptureMode::ReadOrWrite, |tx, _| {
            change(tx)
        })
    }

    pub(super) fn capture<'b, T>(
        &'b self,
        connection: &'b mut Connection,
        previous: &Fetched<Record>,
        mode: CaptureMode<'_>,
        change: impl FnOnce(&mut Transaction<'_>, Option<&mut dyn Checkpoints>) -> io::Result<T>,
    ) -> io::Result<Captured<'b, T>> {
        self.ensure()?;
        self.scope.validate(connection)?;
        let state = self.scope.state(connection)?;
        let next = state
            .floor
            .sequence
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64);
        if next.is_none() && matches!(mode, CaptureMode::Write | CaptureMode::Snapshot(_)) {
            return Err(invalid());
        }
        let name = next.map(|n| Self::name(n, false)).transpose()?;
        if let Some(name) = &name {
            match fs::symlink_metadata(self.root.join(name)) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "original source intent must be reconciled before another request",
                    ));
                }
            }
        }
        let previous_intent = self.current(connection)?;
        let id = super::super::random_id()?;
        let output = self.root.join(&id);
        let captured = capture(
            self.scope(),
            connection,
            previous,
            previous_intent.as_ref(),
            &output,
            match mode {
                CaptureMode::Write => Mode::Write(Some(&id)),
                CaptureMode::ReadOrWrite => Mode::ReadOrWrite(&id),
                CaptureMode::History => Mode::History(&id),
                CaptureMode::Snapshot(descriptor) => Mode::Snapshot(&id, descriptor),
                CaptureMode::Configuration {
                    expected_revision,
                    sha256,
                } => Mode::Configuration(&id, expected_revision, sha256),
            },
            change,
        )?;
        let prepared = match captured {
            Captured::Read(value) => return Ok(Captured::Read(value)),
            Captured::Write(prepared) => prepared,
        };
        let location = Location::of(prepared.intent());
        let bytes = serde_json::to_vec(&location).map_err(|_| invalid())?;
        if bytes.len() > MAX_META {
            return Err(invalid());
        }
        files::write(&self.root, &name.ok_or_else(invalid)?, &bytes)?;
        self.check(prepared.intent())?;
        Ok(Captured::Write(prepared))
    }

    /// Observe the private dispatch record. False means only that the file was
    /// not found; it does not authorize cancellation, replacement or rollback.
    pub(in crate::manage::store) fn was_dispatched(&self, intent: &Intent) -> io::Result<bool> {
        let location = self.check(intent)?;
        let path = self
            .root
            .join(Self::name(sequence(&intent.transition().sequence)?, true)?);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
            Ok(_) => {
                if Location::read(&path, self.scope.enrollment)? == location {
                    Ok(true)
                } else {
                    Err(denied())
                }
            }
        }
    }
    fn dispatch_original(&self, intent: &Intent) -> io::Result<Operation> {
        let location = self.check(intent)?;
        if !self.was_dispatched(intent)? {
            let bytes = serde_json::to_vec(&location).map_err(|_| invalid())?;
            files::write(
                &self.root,
                &Self::name(sequence(&intent.transition().sequence)?, true)?,
                &bytes,
            )?;
        }
        if !self.was_dispatched(intent)? {
            return Err(invalid());
        }
        Ok(Operation {
            enrollment: self.scope.enrollment.clone(),
            action: Action::Reserve(intent.transition().clone()),
        })
    }

    /// Obtain only the original Reserve after flushing its sent marker. The
    /// caller sends this exact operation using the existing Offline transport.
    pub(in crate::manage::store) fn dispatch<T>(
        &self,
        prepared: &Prepared<'_, T>,
    ) -> io::Result<Operation> {
        self.scope.validate(&prepared.transaction)?;
        if self.scope.state(&prepared.transaction)? != prepared.intent.metadata.after_state()?
            || recovery::startup_in(&prepared.transaction)?
                != prepared.intent.metadata.recovery_key_sha256
        {
            return Err(denied());
        }
        // Fail before reservation when the saved bytes are already missing or
        // corrupt. A successful earlier prepare is not a new filesystem check.
        prepared.intent().verify_payload()?;
        self.dispatch_original(prepared.intent())
    }

    /// Explicit exact retry of an unreserved/reserved retained operation. A
    /// late older reply cannot authorize a replacement sequence or payload.
    pub(in crate::manage::store) fn dispatch_retained(
        &self,
        connection: &mut Connection,
        intent: &Intent,
        reply: &Fetched<Record>,
    ) -> io::Result<Operation> {
        match inspect_restart(&self.scope(), connection, intent, reply)? {
            Restart::Unreserved | Restart::Reserved => self.dispatch_original(intent),
            _ => Err(denied()),
        }
    }
    pub(in crate::manage::store) fn replay_pending<'b>(
        &'b self,
        connection: &'b mut Connection,
        number: u64,
        pending: &Fetched<Record>,
    ) -> io::Result<Committed<'b, ()>> {
        replay::restore(self.scope(), connection, self.load(number)?, pending)
    }
    pub(in crate::manage::store) fn resume_committed<'b>(
        &'b self,
        connection: &'b mut Connection,
        number: u64,
        pending: &Fetched<Record>,
    ) -> io::Result<Committed<'b, ()>> {
        super::resume_committed(self.scope(), connection, self.load(number)?, pending)
    }
}
