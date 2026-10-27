//! Offline configuration CAS. Only a digest is stored locally; the witness
//! receives the original operation commitment, never configuration or keys.
//! Capture/provenance and live startup admission remain the owning caller's job.

use super::{tracked::Journal, *};
use crate::manage::node::control::witness::{Action, Operation};

pub(in crate::manage) use super::super::source::Configuration as Reference;

/// File-author CAS input, not proof that the digest describes a runtime. The
/// owning collector supplies it from its exact private bytes/prepared objects.
pub(in crate::manage) struct Desired {
    pub(in crate::manage) expected_revision: u64,
    pub(in crate::manage) sha256: [u8; 32],
}

/// Read only this exact registered configuration under both original guards.
/// A fresh authenticated Inspect must confirm the original local floor; pending
/// work, rollback, a changed reference or authorization rejects startup without
/// dispatching Reserve/Confirm, restoring policy, or creating an intent.
pub(in crate::manage) fn inspect(
    directory: &Path,
    author: &Guard,
    gate: &UpdateGuard,
    enrollment: &Enrollment,
    expected: Reference,
    request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
) -> io::Result<()> {
    let scope = Scope {
        directory,
        author,
        gate,
        enrollment,
    };
    let mut connection = open(&scope)?;
    let journal = Journal::open(scope, &connection)?;
    journal.inspect_configuration(&mut connection, Some(expected), request)
}

/// Accept actual collected inputs under the existing original-directory gates.
/// Existing pending work refuses; no implicit reconcile or bootstrap occurs.
pub(in crate::manage) fn accept(
    directory: &Path,
    author: &Guard,
    gate: &UpdateGuard,
    enrollment: &Enrollment,
    desired: &Desired,
    request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
) -> io::Result<Reference> {
    let scope = Scope {
        directory,
        author,
        gate,
        enrollment,
    };
    let mut connection = open(&scope)?;
    let journal = Journal::open(scope, &connection)?;
    journal.configure(
        &mut connection,
        desired.expected_revision,
        desired.sha256,
        request,
    )?;
    registered(&journal, &mut connection, desired, request)
}

/// Resume only a retained format-5 operation with this exact digest and CAS.
/// Another pending/current operation, changed input, old/future revision or lost
/// files refuses before network replay; one-time business results are not read.
pub(in crate::manage) fn reconcile(
    directory: &Path,
    author: &Guard,
    gate: &UpdateGuard,
    enrollment: &Enrollment,
    desired: &Desired,
    request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
) -> io::Result<Reference> {
    let scope = Scope {
        directory,
        author,
        gate,
        enrollment,
    };
    let mut connection = open(&scope)?;
    let journal = Journal::open(scope, &connection)?;
    let retained = journal
        .pending(&connection)?
        .or(journal.current(&connection)?)
        .ok_or_else(denied)?;
    let next = desired
        .expected_revision
        .checked_add(1)
        .ok_or_else(denied)?;
    if retained.metadata.format != 5
        || retained.metadata.binding.map_or(0, |b| b.revision) != desired.expected_revision
        || retained.metadata.configuration
            != Some(Reference {
                revision: next,
                sha256: desired.sha256,
            })
    {
        return Err(denied());
    }
    // Match the actual singleton before trusting a floor-only payload's label.
    snapshot::check_payload(&connection, &retained)?;
    journal.reconcile(&mut connection, request, || Ok(()))?;
    registered(&journal, &mut connection, desired, request)
}

fn registered(
    journal: &Journal<'_>,
    connection: &mut Connection,
    desired: &Desired,
    request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
) -> io::Result<Reference> {
    // The operation may already be confirmed. A later network/readback error
    // cannot be reported as a clean pre-dispatch refusal or proof of rollback.
    (|| {
        let observed = request(journal.operation(Action::Inspect))?;
        journal.ready(connection, &observed)?;
        let reference = journal
            .scope()
            .state(connection)?
            .configuration
            .ok_or_else(denied)?;
        if reference.sha256 != desired.sha256
            || (reference.revision != desired.expected_revision
                && desired.expected_revision.checked_add(1) != Some(reference.revision))
        {
            return Err(denied());
        }
        Ok(reference)
    })()
    .map_err(driver::uncertain)
}

impl Journal<'_> {
    /// Shared by startup preflight and the actual Source owner. None remains
    /// only the unbound kernel-fixture contract, never a production fallback.
    pub(super) fn inspect_configuration(
        &self,
        connection: &mut Connection,
        expected: Option<Reference>,
        request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
    ) -> io::Result<()> {
        let check = |connection: &Connection| {
            if let Some(expected) = expected {
                expected.validate()?;
                if self.scope().state(connection)?.configuration != Some(expected) {
                    return Err(denied());
                }
            }
            Ok(())
        };
        check(connection)?;
        let confirmed = request(self.operation(Action::Inspect))?;
        self.ready(connection, &confirmed)?;
        check(connection)
    }

    /// Accept a trusted caller's portable configuration/static-asset digest.
    /// Revision zero means no binding. Even identical bytes require the current
    /// revision and a fresh confirmation; they create no intent or sequence.
    /// Both offline guards remain held, with no live Reader or business callback.
    /// An uncertain reply retains the original operation for explicit reconcile;
    /// this method neither retries it nor grants permission to start a service.
    pub(in crate::manage::store::journal) fn configure(
        &self,
        connection: &mut Connection,
        expected_revision: u64,
        sha256: [u8; 32],
        request: &mut impl FnMut(Operation) -> io::Result<Fetched<Record>>,
    ) -> io::Result<()> {
        self.ensure().map_err(driver::uncertain)?;
        self.scope()
            .validate(connection)
            .map_err(driver::uncertain)?;
        if !connection.is_autocommit() {
            return Err(invalid());
        }
        let previous = request(self.operation(Action::Inspect)).map_err(driver::uncertain)?;
        self.ready(connection, &previous)
            .map_err(driver::uncertain)?;
        let candidate = self.capture(
            connection,
            &previous,
            CaptureMode::Configuration {
                expected_revision,
                sha256,
            },
            |_, _| Ok(()),
        )?;
        let prepared = match candidate {
            Captured::Read(()) => return Ok(()),
            Captured::Write(prepared) => prepared,
        };
        let pending = request(self.dispatch(&prepared)?).map_err(driver::uncertain)?;
        let committed = prepared.commit(&pending).map_err(driver::uncertain)?;
        self.finish(committed, request)
    }
}
