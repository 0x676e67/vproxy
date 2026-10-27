//! History operations select their original Native wrappers or a held Source
//! transaction. RAM publication belongs to the owning worker after confirmation.

use super::*;

pub(in crate::manage) enum Writer<'a> {
    Native(&'a Path, &'a UpdateGuard),
    #[cfg(feature = "witness-journal")]
    Source {
        tx: &'a rusqlite::Transaction<'a>,
        checkpoints: &'a mut dyn crate::manage::store::journal::Checkpoints,
    },
}

impl Writer<'_> {
    pub(in crate::manage) fn start(&mut self, boot: &str) -> io::Result<Commit> {
        match self {
            Self::Native(dir, gate) => super::start(dir, gate, boot),
            #[cfg(feature = "witness-journal")]
            Self::Source { tx, checkpoints } => {
                validate_boot(boot)?;
                start_in_with(tx, boot, Some(*checkpoints)).map(|(value, _)| value)
            }
        }
    }

    pub(in crate::manage) fn receipt(&mut self, batch: &Batch) -> io::Result<Option<Commit>> {
        match self {
            Self::Native(dir, _) => super::receipt(dir, batch),
            #[cfg(feature = "witness-journal")]
            Self::Source { tx, .. } => receipt_from(tx, batch),
        }
    }

    pub(in crate::manage) fn record(
        &mut self,
        batch: &Batch,
        proofs: Option<(&[Arc<crate::manage::observations::Proof>], &[Binding])>,
    ) -> io::Result<Commit> {
        match self {
            Self::Native(dir, gate) => match proofs {
                Some((proofs, bindings)) => {
                    super::record_guarded(dir, gate, batch, proofs, bindings)
                }
                None => super::record(dir, gate, batch),
            },
            #[cfg(feature = "witness-journal")]
            Self::Source { tx, checkpoints } => {
                record_transaction_with(tx, batch, proofs, Some(*checkpoints))
                    .map(|(value, _)| value)
            }
        }
    }

    pub(in crate::manage) fn validate_current(
        &mut self,
        proofs: &[Arc<crate::manage::observations::Proof>],
        bindings: &[Binding],
    ) -> io::Result<()> {
        match self {
            Self::Native(dir, gate) => {
                super::publish_guarded(dir, gate, proofs, bindings, || Ok(()))
            }
            #[cfg(feature = "witness-journal")]
            Self::Source { tx, .. } => super::validate_current(tx, proofs, bindings),
        }
    }

    pub(in crate::manage) fn acknowledge(
        &mut self,
        actor: &str,
        input: &Ack,
    ) -> io::Result<Episode> {
        match self {
            Self::Native(dir, gate) => super::acknowledge(dir, gate, actor, input),
            #[cfg(feature = "witness-journal")]
            Self::Source { tx, checkpoints } => {
                validate_ack(input)?;
                acknowledge_in_with(tx, actor, input, Some(*checkpoints)).map(|(value, _)| value)
            }
        }
    }
}
