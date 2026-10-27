//! One original-directory publisher, bound to confirmed source floors. This is
//! not a source startup/snapshot/fencing permit. A bounded dedicated caller must
//! retain the borrowed author/update gates and this owner across request waits.

use super::{
    driver::{uncertain, unresolved},
    tracked::Journal,
    *,
};
use crate::access::{Reader, suspension::Suspension};
use crate::manage::{
    node::control::witness::Operation,
    store::{traffic, users},
};

/// Non-secret identity retained *before dispatch*. File absence after a network
/// error cannot erase this binding or authorize a different next operation.
#[derive(Clone, Eq, PartialEq)]
struct Binding {
    transition: Transition,
    before: source::Floor,
    after: source::Floor,
    effect: Effect,
}

impl Binding {
    fn new(intent: &Intent, effect: Effect) -> io::Result<Self> {
        Ok(Self {
            transition: intent.transition().clone(),
            before: intent.metadata.before.clone(),
            after: intent.metadata.after()?,
            effect,
        })
    }
    fn revision(&self, previous: u64) -> io::Result<u64> {
        match self.effect {
            Effect::Unchanged => Ok(previous),
            Effect::Changed { before, after } if before == previous && after > before => Ok(after),
            _ => Err(denied()),
        }
    }
}

/// Creates its Reader from the actual confirmed SQL view and restored traffic
/// registry, never from caller-supplied PolicyData. All live publications belong
/// to this owner. A retained suspension remains available for exact original
/// reconciliation, unlike Native Publication::drop's permanent fail_closed.
pub(in crate::manage::store) struct Owner<'a> {
    journal: Journal<'a>,
    reader: Reader,
    restoration: traffic::Status,
    floor: source::Floor,
    configuration: Option<source::Configuration>,
    revision: u64,
    held: Option<Suspension>,
    binding: Option<Binding>,
    broken: bool,
}

impl<'a> Owner<'a> {
    /// Fresh Inspect and exact local confirmation precede loading policy and
    /// bounded meter seeds under the original guards. Pending operations refuse;
    /// offline reconciliation must finish before constructing a new Reader.
    /// This does not establish full backup/config freshness or old-node fencing.
    #[cfg(test)]
    pub(in crate::manage::store) fn open(
        scope: Scope<'a>,
        connection: &mut Connection,
        request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
    ) -> io::Result<Self> {
        Self::open_configuration(scope, connection, request, None)
    }

    /// A production worker supplies the registered configuration reference.
    /// Check it before witness I/O and again in the confirmed SQL view, before
    /// constructing a Reader or restoring meter seeds. None is only used by
    /// unbound kernel fixtures, never a production startup fallback.
    pub(super) fn open_configuration(
        scope: Scope<'a>,
        connection: &mut Connection,
        request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
        expected: Option<source::Configuration>,
    ) -> io::Result<Self> {
        let journal = Journal::open(scope, connection)?;
        journal.inspect_configuration(connection, expected, request)?;
        let policy = users::read_policy(connection)?;
        let revision = policy.revision;
        let restored = traffic::restore(journal.scope().directory)?;
        let registry = crate::access::traffic::Registry::with_pools(
            restored.credential_seeds,
            restored.pool_seeds,
        )?;
        let reader = Reader::with_traffic(policy, registry)?;
        let state = journal.scope().state(connection)?;
        let floor = state.floor;
        Ok(Self {
            journal,
            reader,
            restoration: restored.status,
            floor,
            configuration: state.configuration,
            revision,
            held: None,
            binding: None,
            broken: false,
        })
    }

    pub(in crate::manage::store) fn reader(&self) -> Reader {
        self.reader.clone()
    }
    pub(in crate::manage::store) fn restoration(&self) -> &traffic::Status {
        &self.restoration
    }

    fn local(&self, connection: &Connection) -> io::Result<source::Floor> {
        self.journal.ensure()?;
        self.journal.scope().validate(connection)?;
        if !connection.is_autocommit() {
            return Err(invalid());
        }
        let state = self.journal.scope().state(connection)?;
        if state.configuration != self.configuration {
            return Err(denied());
        }
        Ok(state.floor)
    }
    fn pause(&mut self) -> io::Result<()> {
        if self.held.is_none() {
            self.held = Some(self.reader.suspend()?);
        }
        self.held
            .as_ref()
            .ok_or_else(unresolved)?
            .ensure(self.revision)
    }
    fn stop(&mut self, error: io::Error) -> io::Error {
        self.broken = true;
        self.reader.fail_closed();
        uncertain(error)
    }
    fn preflight(&self, connection: &Connection) -> io::Result<()> {
        if self.broken
            || self.held.is_some()
            || self.binding.is_some()
            || self.reader.revision()? != self.revision
            || self.local(connection)? != self.floor
            || users::read_state(connection)?.0 != self.revision
        {
            return Err(unresolved());
        }
        Ok(())
    }

    /// Run one new trusted DML request. Bind its exact intent/effect before
    /// dispatch; withhold Reader before COMMIT, and only publish/restore after
    /// exact confirmation. No new request runs while a suspension is retained.
    /// A verified no-change observation preserves the original floor/revision
    /// without a suspension or intent, and rechecks local ownership before return.
    /// Unknown results retain this owner; do not invoke Native fail_closed on
    /// them. Drop/panic or a lost publication ticket stays permanently fenced.
    pub(in crate::manage::store) fn run<T>(
        &mut self,
        connection: &mut Connection,
        request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
        change: impl FnOnce(&mut Transaction<'_>) -> io::Result<T>,
    ) -> io::Result<T> {
        self.run_mode(connection, request, false, |tx, _| change(tx))
    }

    /// History uses segmented capture but retains this original floor, binding
    /// and Reader suspension until the same operation is exactly confirmed.
    pub(super) fn run_mode<T>(
        &mut self,
        connection: &mut Connection,
        request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
        history: bool,
        change: impl FnOnce(&mut Transaction<'_>, Option<&mut dyn Checkpoints>) -> io::Result<T>,
    ) -> io::Result<T> {
        if self.broken || self.held.is_some() || self.binding.is_some() {
            return Err(unresolved());
        }
        if let Err(e) = self.preflight(connection) {
            return Err(self.stop(e));
        }
        let before = self.floor.clone();
        let revision = self.revision;
        let binding = &mut self.binding;
        let held = &mut self.held;
        let reader = &self.reader;
        let outcome = self.journal.run_mode(
            connection,
            request,
            history,
            change,
            |intent, effect| {
                let candidate = Binding::new(intent, effect)?;
                if candidate.before != before {
                    return Err(denied());
                }
                candidate.revision(revision)?;
                *binding = Some(candidate);
                Ok(())
            },
            || {
                let suspension = reader.suspend()?;
                suspension.ensure(revision)?;
                *held = Some(suspension);
                Ok(())
            },
        );
        match outcome {
            Ok(value) => {
                if self.binding.is_none() && self.held.is_none() {
                    if let Err(error) = self.preflight(connection) {
                        return Err(self.stop(error));
                    }
                } else {
                    self.complete(connection)?;
                }
                Ok(value)
            }
            Err(error) => {
                // Definite callback rejection has no dispatch binding and no
                // next locator. Never use error kind alone as rollback proof.
                let clean = self.binding.is_none()
                    && self.held.is_none()
                    && matches!(
                        error.kind(),
                        io::ErrorKind::InvalidInput
                            | io::ErrorKind::NotFound
                            | io::ErrorKind::AlreadyExists
                            | io::ErrorKind::PermissionDenied
                            | io::ErrorKind::WouldBlock
                    )
                    && self
                        .local(connection)
                        .is_ok_and(|floor| floor == self.floor)
                    && users::read_state(connection).is_ok_and(|state| state.0 == self.revision)
                    && self
                        .journal
                        .pending(connection)
                        .is_ok_and(|intent| intent.is_none());
                if clean {
                    return Err(error);
                }
                if let Err(e) = self.pause() {
                    return Err(self.stop(e));
                }
                // A retained dispatch identity is never reconstructed from
                // absence. Before-dispatch preparation failures may leave an
                // indexed original; bind it only when it can be read exactly.
                if self.binding.is_none() {
                    match self.journal.pending(connection) {
                        Ok(Some(intent)) => {
                            let effect = effect(&intent, connection).map_err(uncertain)?;
                            let binding = Binding::new(&intent, effect).map_err(uncertain)?;
                            if binding.before != self.floor
                                || binding.revision(self.revision).is_err()
                            {
                                return Err(self.stop(denied()));
                            }
                            self.binding = Some(binding);
                        }
                        Ok(None) => {}
                        Err(e) => return Err(self.stop(e)),
                    }
                }
                Err(uncertain(error))
            }
        }
    }

    fn verify(&self, connection: &Connection, binding: &Binding) -> io::Result<()> {
        let floor = self.local(connection)?;
        if binding.before != self.floor || (floor != binding.before && floor != binding.after) {
            return Err(denied());
        }
        let intent = self.journal.load(sequence(&binding.transition.sequence)?)?;
        // load rechecks the original canonical metadata and actual payload hash.
        // The retained effect was derived from those commitment-bound bytes
        // before dispatch; do not allocate/normalize the row index again here.
        if intent.transition() != &binding.transition
            || intent.metadata.binding != self.configuration
            || intent.metadata.configuration.is_some()
            || intent.metadata.before != binding.before
            || intent.metadata.after()? != binding.after
            || content::schema(connection)? != intent.metadata.schema_sha256
        {
            return Err(denied());
        }
        let expected = if floor == binding.before {
            self.revision
        } else {
            binding.revision(self.revision)?
        };
        if users::read_state(connection)?.0 != expected {
            return Err(denied());
        }
        Ok(())
    }

    fn complete(&mut self, connection: &Connection) -> io::Result<()> {
        let binding = self.binding.as_ref().ok_or_else(unresolved)?;
        self.verify(connection, binding).map_err(uncertain)?;
        if self.local(connection).map_err(uncertain)? != binding.after {
            return Err(unresolved());
        }
        let revision = binding.revision(self.revision).map_err(uncertain)?;
        let held = self.held.as_mut().ok_or_else(unresolved)?;
        held.ensure(self.revision).map_err(uncertain)?;
        match binding.effect {
            Effect::Unchanged => held.restore(),
            Effect::Changed { .. } => {
                let policy = users::read_policy(connection).map_err(uncertain)?;
                if policy.revision != revision {
                    return Err(unresolved());
                }
                held.publish(policy)
            }
        }
        .map_err(uncertain)?;
        self.floor = binding.after.clone();
        self.revision = revision;
        self.binding = None;
        self.held = None;
        Ok(())
    }

    /// Resolve only this owner's original operation; never return a recovered
    /// secret or run a business callback. Both the retained identity and current
    /// private bytes must match before any network request. Missing files cannot
    /// turn a lost dispatch into a clean predecessor. Fresh confirmation then
    /// permits the actual saved newer policy, or the proven unchanged original.
    pub(in crate::manage::store) fn reconcile(
        &mut self,
        connection: &mut Connection,
        request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
    ) -> io::Result<()> {
        if self.broken {
            return Err(unresolved());
        }
        if let Err(e) = self.pause() {
            return Err(self.stop(e));
        }
        if let Some(binding) = &self.binding {
            self.verify(connection, binding).map_err(uncertain)?;
        } else if self.local(connection).map_err(uncertain)? != self.floor
            || users::read_state(connection).map_err(uncertain)?.0 != self.revision
            || self
                .journal
                .pending(connection)
                .map_err(uncertain)?
                .is_some()
        {
            return Err(unresolved());
        }
        let held = &self.held;
        let revision = self.revision;
        self.journal.reconcile(connection, request, || {
            held.as_ref().ok_or_else(unresolved)?.ensure(revision)
        })?;
        if self.binding.is_some() {
            self.complete(connection)
        } else {
            if self.local(connection).map_err(uncertain)? != self.floor
                || users::read_state(connection).map_err(uncertain)?.0 != self.revision
            {
                return Err(unresolved());
            }
            self.held
                .as_mut()
                .ok_or_else(unresolved)?
                .restore()
                .map_err(uncertain)?;
            self.held = None;
            Ok(())
        }
    }
}

impl Drop for Owner<'_> {
    fn drop(&mut self) {
        self.reader.fail_closed();
    }
}

fn effect(intent: &Intent, connection: &Connection) -> io::Result<Effect> {
    if content::schema(connection)? != intent.metadata.schema_sha256 {
        return Err(denied());
    }
    intent.effect(connection)
}
