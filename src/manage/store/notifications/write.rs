//! Select the original Native transaction boundary or a held Source transaction.
//! Staged work, including destination secrets, leaves Source only after confirmation.

use super::*;

pub(in crate::manage) enum Writer<'a> {
    Native(&'a Path, &'a UpdateGuard),
    #[cfg(feature = "witness-journal")]
    Source(&'a rusqlite::Transaction<'a>),
}

impl Writer<'_> {
    pub(in crate::manage) fn change(&mut self, actor: &str, input: &Change) -> io::Result<View> {
        match self {
            Self::Native(dir, gate) => super::change(dir, gate, actor, input),
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => {
                let (revision, digest) = validate_change(input)?;
                change_in(tx, actor, input, revision, digest).map(|(value, _)| value)
            }
        }
    }

    pub(in crate::manage) fn retry(&mut self, actor: &str, input: &Retry) -> io::Result<View> {
        match self {
            Self::Native(dir, gate) => super::retry(dir, gate, actor, input),
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => retry_in(tx, actor, input),
        }
    }

    pub(in crate::manage) fn prepare(
        &mut self,
        permission: Option<&RetryFence>,
    ) -> io::Result<Option<Work>> {
        match self {
            Self::Native(dir, gate) => super::prepare(dir, gate, permission),
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => match prepare_in(tx, permission)? {
                Prepared::Idle | Prepared::Interrupted => Ok(None),
                Prepared::Wait(fence) => Ok(Some(Work::Wait(fence))),
                Prepared::Send(attempt) => Ok(Some(Work::Send(attempt))),
            },
        }
    }

    pub(in crate::manage) fn finish(
        &mut self,
        attempt: &Attempt,
        result: (Outcome, Option<u16>),
    ) -> io::Result<()> {
        match self {
            Self::Native(dir, gate) => super::finish(dir, gate, attempt, result),
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => {
                validate_result(result)?;
                finish_in(tx, attempt, result).map(|_| ())
            }
        }
    }
}
