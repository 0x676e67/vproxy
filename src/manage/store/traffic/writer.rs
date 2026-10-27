//! A bounded traffic operation uses its original Native wrapper or the Source
//! worker's held transaction. Neither form performs child-node network I/O.

use super::super::{RemoteAuthorization, UpdateGuard, remote_traffic};
use super::*;
use crate::access::traffic::{PoolSnapshot, SeriesSnapshot};

pub(in crate::manage) enum Writer<'a> {
    Native(&'a Path, &'a UpdateGuard),
    #[cfg(feature = "witness-journal")]
    Source(&'a rusqlite::Transaction<'a>),
}

impl Writer<'_> {
    pub(in crate::manage) fn start_run(
        &mut self,
        epoch: &str,
        cursor: u64,
        observed_at: Option<u64>,
    ) -> io::Result<Run> {
        match self {
            Self::Native(dir, gate) => start_run(dir, gate, epoch, cursor, observed_at),
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => write::start_run_in(tx, epoch, cursor, observed_at),
        }
    }

    pub(in crate::manage) fn checkpoint(
        &mut self,
        run: &str,
        observed_at: Option<u64>,
        samples: &[SeriesSnapshot],
        pools: &[PoolSnapshot],
    ) -> io::Result<Status> {
        match self {
            Self::Native(dir, gate) => checkpoint(dir, gate, run, observed_at, samples, pools),
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => {
                write::validate_checkpoint(samples, pools)?;
                write::checkpoint_in(
                    tx,
                    run,
                    observed_at,
                    samples,
                    pools,
                    write::Retention::Batched,
                )
            }
        }
    }

    pub(in crate::manage) fn finish(
        &mut self,
        run: &str,
        observed_at: Option<u64>,
    ) -> io::Result<Status> {
        match self {
            Self::Native(dir, gate) => finish(dir, gate, run, observed_at),
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => write::finish_in(tx, run, observed_at),
        }
    }

    /// Keep a continuity rejection inside the successful transaction result so
    /// Source confirms the quarantine before its caller receives that rejection.
    /// An already-validated quarantine is a read-only business rejection, not a
    /// reason to treat unrelated InvalidData errors as definite failures.
    /// Flatten the inner Result only after awaiting the actual writer.
    pub(in crate::manage) fn import(
        &mut self,
        authorization: &RemoteAuthorization,
        target_revision: u64,
        snapshot: NodeSnapshot,
        observed_at: Option<u64>,
    ) -> io::Result<io::Result<remote_traffic::Source>> {
        match self {
            Self::Native(dir, gate) => Ok(remote_traffic::import(
                dir,
                gate,
                authorization,
                target_revision,
                snapshot,
                observed_at,
            )),
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => {
                let encoded = remote_traffic::encode_import(&snapshot, observed_at)?;
                match remote_traffic::import_in(
                    tx,
                    authorization,
                    target_revision,
                    snapshot,
                    observed_at,
                    encoded,
                ) {
                    Err(error)
                        if error
                            .get_ref()
                            .is_some_and(|source| source.is::<remote_traffic::Quarantined>()) =>
                    {
                        Ok(Err(error))
                    }
                    result => result,
                }
            }
        }
    }

    pub(in crate::manage) fn failed(
        &mut self,
        peer: &str,
        target_revision: u64,
        failure: remote_traffic::Failure,
    ) -> io::Result<()> {
        match self {
            Self::Native(dir, gate) => {
                remote_traffic::failed(dir, gate, peer, target_revision, failure)
            }
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => remote_traffic::failed_in(tx, peer, target_revision, failure),
        }
    }
}
