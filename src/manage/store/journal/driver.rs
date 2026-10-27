//! Ordered source operations for bounded synchronous workers. The caller owns
//! transport/runtime admission; this module neither spawns tasks nor retries a
//! business request. A worker must outlive cancellation of its requesting wait.

use super::{tracked::Journal, *};
use crate::manage::node::control::witness::{Action, Operation};

impl Journal<'_> {
    pub(super) fn operation(&self, action: Action) -> Operation {
        Operation {
            enrollment: self.scope().enrollment.clone(),
            action,
        }
    }

    /// Prove a confirmed *local* floor, not just a successful network query.
    /// Existing next-sequence output is unresolved even when Inspect still
    /// returns its predecessor: an older Reserve can arrive after that reply.
    pub(super) fn ready(
        &self,
        connection: &mut Connection,
        reply: &Fetched<Record>,
    ) -> io::Result<()> {
        self.ensure()?;
        if self.pending(connection)?.is_some() {
            return Err(unresolved());
        }
        if let Some(intent) = self.current(connection)? {
            if inspect_restart(&self.scope(), connection, &intent, reply)? != Restart::Confirmed {
                return Err(unresolved());
            }
        } else {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| sqlite_error("cannot inspect source baseline", e))?;
            self.scope().authorize(&tx, reply)?;
            let state = self.scope().state(&tx)?;
            if state.floor.sequence != 0
                || reply.value.phase != Phase::Confirmed
                || reply.value.sequence != "0"
                || reply.value.previous.is_some()
                || reply.value.commitment != state.enrollment.baseline
            {
                return Err(unresolved());
            }
        }
        Ok(())
    }

    pub(super) fn finish<T>(
        &self,
        committed: Committed<'_, T>,
        request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
    ) -> io::Result<T> {
        let operation = self.operation(Action::Confirm(committed.intent().transition().clone()));
        let confirmed = request(operation).map_err(uncertain)?;
        let connection = committed.connection;
        let value = committed.confirm(&confirmed).map_err(uncertain)?;
        self.maintain_confirmed(connection, &confirmed);
        Ok(value)
    }

    /// Run one new, trusted bounded DML callback, returning its original result
    /// only after exact confirmation. The existing caller retains author/update
    /// and writer admission through this whole blocking call and publication.
    /// A terminal read with no recorded changes ends by explicit rollback under
    /// the fresh confirmation, without dispatch, a new sequence or publication.
    /// `request` must use the retained Offline capability and a live runtime;
    /// that transport needs its own blocking authorization capacity. Calling it
    /// on the runtime's sole blocking thread starves authorization until the
    /// transport deadline; successful progress needs separate worker capacity.
    ///
    /// This never reconciles a retained operation implicitly. Any error after
    /// dispatch, and every inconclusive initial observation, is `Other` with a
    /// static result-unknown message, even if a network error was PermissionDenied
    /// or WouldBlock. Callers must fail closed, not preserve a stale Reader by
    /// interpreting that error kind as proof of rollback. Pre-dispatch callback
    /// rejection preserves its original error and rolls back normally.
    /// `before_dispatch` binds the immutable original intent/effect before an
    /// operation can be sent, so missing files after a lost reply cannot be
    /// mistaken for proof that no reservation was attempted. It must not write
    /// SQL or change connection state; no candidate connection is exposed.
    /// `before_commit` must withhold live Reader admission before any COMMIT is
    /// possible and retain that suspension through confirmation/publication.
    /// Offline callers with no Reader supply an explicit no-op. A barrier error
    /// leaves the original Pending reservation unresolved; no COMMIT is granted.
    pub(in crate::manage::store) fn run<T>(
        &self,
        connection: &mut Connection,
        request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
        change: impl FnOnce(&mut Transaction<'_>) -> io::Result<T>,
        before_dispatch: impl FnOnce(&Intent, Effect) -> io::Result<()>,
        before_commit: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<T> {
        self.run_mode(
            connection,
            request,
            false,
            |tx, _| change(tx),
            before_dispatch,
            before_commit,
        )
    }

    /// Select only the trusted history capture path; it narrows accepted tables,
    /// not witness/COMMIT admission. Checkpoints remain inside this one request.
    pub(super) fn run_mode<T>(
        &self,
        connection: &mut Connection,
        request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
        history: bool,
        change: impl FnOnce(&mut Transaction<'_>, Option<&mut dyn Checkpoints>) -> io::Result<T>,
        before_dispatch: impl FnOnce(&Intent, Effect) -> io::Result<()>,
        before_commit: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<T> {
        self.ensure().map_err(uncertain)?;
        self.scope().validate(connection).map_err(uncertain)?;
        // Reject a nested SQL view before issuing even an inspection request.
        if !connection.is_autocommit() {
            return Err(invalid());
        }
        let previous = request(self.operation(Action::Inspect)).map_err(uncertain)?;
        self.ready(connection, &previous).map_err(uncertain)?;
        self.maintain_confirmed(connection, &previous);
        let mode = if history {
            CaptureMode::History
        } else {
            CaptureMode::ReadOrWrite
        };
        let prepared = match self.capture(connection, &previous, mode, change)? {
            Captured::Read(value) => return Ok(value),
            Captured::Write(prepared) => prepared,
        };
        before_dispatch(prepared.intent(), prepared.effect.ok_or_else(invalid)?)?;
        let operation = self.dispatch(&prepared)?;
        let pending = request(operation).map_err(uncertain)?;
        let committed = prepared
            .commit_after(&pending, before_commit)
            .map_err(uncertain)?;
        self.finish(committed, request)
    }

    /// Explicitly reconcile only the original retained operation, with at most
    /// one Inspect, one exact Reserve and one Confirm, never a retry loop. No
    /// callback or one-time result is reconstructed. Pending/preimage replays
    /// the original bytes; Pending/postimage only confirms. Confirmed/preimage,
    /// missing/corrupt output or a changed authority stays fenced.
    ///
    /// Success proves the checked local intent is confirmed at this observation,
    /// not permission to start service or accept a backup. Whole-writer runtime,
    /// snapshot/config and infrastructure-fencing checks are separate gates.
    /// `before_reconcile` runs before SQL/network observation: a live caller may
    /// already have a committed-but-unpublished policy. It must withhold Reader
    /// admission or retain its existing suspension until checked publication.
    pub(in crate::manage::store) fn reconcile(
        &self,
        connection: &mut Connection,
        request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
        before_reconcile: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        before_reconcile().map_err(uncertain)?;
        self.ensure().map_err(uncertain)?;
        self.scope().validate(connection).map_err(uncertain)?;
        if !connection.is_autocommit() {
            return Err(invalid());
        }
        let mut observed = request(self.operation(Action::Inspect)).map_err(uncertain)?;
        if let Some(intent) = self.pending(connection).map_err(uncertain)? {
            let state = inspect_restart(&self.scope(), connection, &intent, &observed)
                .map_err(uncertain)?;
            match state {
                Restart::Unreserved => {
                    let operation = self
                        .dispatch_retained(connection, &intent, &observed)
                        .map_err(uncertain)?;
                    observed = request(operation).map_err(uncertain)?;
                }
                Restart::Reserved => {}
                _ => return Err(unresolved()),
            }
            let committed = self
                .replay_pending(
                    connection,
                    sequence(&intent.transition().sequence)?,
                    &observed,
                )
                .map_err(uncertain)?;
            return self.finish(committed, request);
        }
        if let Some(intent) = self.current(connection).map_err(uncertain)? {
            match inspect_restart(&self.scope(), connection, &intent, &observed)
                .map_err(uncertain)?
            {
                Restart::Committed => {
                    let committed = self
                        .resume_committed(
                            connection,
                            sequence(&intent.transition().sequence)?,
                            &observed,
                        )
                        .map_err(uncertain)?;
                    return self.finish(committed, request);
                }
                Restart::Confirmed => {
                    self.maintain_confirmed(connection, &observed);
                    return Ok(());
                }
                _ => return Err(unresolved()),
            }
        }
        self.ready(connection, &observed).map_err(uncertain)
    }
}

pub(super) fn unresolved() -> io::Error {
    // Owner post-confirm checks also use this constructor. Keep their result
    // unknown to callers that must retain an authentication/publication fence.
    uncertain(io::Error::other("source state requires reconciliation"))
}

/// Preserve private diagnostics without exporting their text or allowing the
/// underlying permission/busy kind to masquerade as a pre-commit rejection.
#[derive(Debug, thiserror::Error)]
#[error("source outcome is unresolved; retain and reconcile the original intent")]
struct Uncertain(#[source] io::Error);

/// Classify the driver's retained-outcome marker, not a generic I/O kind.
/// Callers must keep their own authentication fence for this result; a plain
/// pre-dispatch SQL error of kind Other does not imply an uncertain commit.
pub(in crate::manage) fn is_uncertain(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|error| error.is::<Uncertain>())
}

pub(super) fn uncertain(error: io::Error) -> io::Error {
    io::Error::other(Uncertain(error))
}
