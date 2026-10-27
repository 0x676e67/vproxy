//! Controller operations select their ordinary wrappers or a held transaction.
//! Native methods preserve their ordinary transactions;
//! Source methods stage the same validated business core in one held transaction.

use super::*;

pub(in crate::manage) enum Writer<'a> {
    Native(&'a Path),
    #[cfg(feature = "witness-journal")]
    Source(&'a rusqlite::Transaction<'a>),
}

impl Writer<'_> {
    pub(in crate::manage) fn configure(
        &mut self,
        administrator: &str,
        peer: &str,
        expected_revision: Option<u64>,
        origin: &str,
        active: bool,
        server_ip: Option<Option<IpAddr>>,
    ) -> io::Result<Target> {
        match self {
            Self::Native(dir) => super::configure(
                dir,
                administrator,
                peer,
                expected_revision,
                origin,
                active,
                server_ip,
            ),
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => {
                validate_configuration(peer, origin, server_ip)?;
                configure_in(
                    tx,
                    administrator,
                    peer,
                    expected_revision,
                    origin,
                    active,
                    server_ip,
                )
            }
        }
    }

    pub(in crate::manage) fn set_state(
        &mut self,
        administrator: &str,
        peer: &str,
        expected_revision: u64,
        active: bool,
        retire: bool,
    ) -> io::Result<Target> {
        match self {
            Self::Native(dir) => {
                super::set_state(dir, administrator, peer, expected_revision, active, retire)
            }
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => {
                validate_state(peer, active, retire)?;
                set_state_in(tx, administrator, peer, expected_revision, active, retire)
            }
        }
    }

    pub(in crate::manage) fn observe(
        &mut self,
        peer: &str,
        target_revision: u64,
        epoch: u64,
        command: u64,
        policy_revision: u64,
    ) -> io::Result<Target> {
        match self {
            Self::Native(dir) => {
                super::observe(dir, peer, target_revision, epoch, command, policy_revision)
            }
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => {
                validate_observation(peer, epoch, command, policy_revision)?;
                observe_in(tx, peer, target_revision, epoch, command, policy_revision)
            }
        }
    }

    pub(in crate::manage) fn enqueue_intent(
        &mut self,
        administrator: &str,
        target_revision: u64,
        command: super::super::ControlIntent,
    ) -> io::Result<Job> {
        match self {
            Self::Native(dir) => {
                super::enqueue_intent(dir, administrator, target_revision, command)
            }
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => {
                endpoints::enqueue_intent_in(tx, administrator, target_revision, command)
            }
        }
    }

    pub(in crate::manage) fn load_delivery(
        &mut self,
        peer: &str,
        job_id: &str,
    ) -> io::Result<Delivery> {
        match self {
            Self::Native(dir) => super::load_delivery(dir, peer, job_id),
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => {
                validate_job(peer, job_id)?;
                load_delivery_in(tx, peer, job_id)
            }
        }
    }

    pub(in crate::manage) fn complete(
        &mut self,
        peer: &str,
        job_id: &str,
        receipt: &super::super::Receipt,
    ) -> io::Result<Job> {
        match self {
            Self::Native(dir) => super::complete(dir, peer, job_id, receipt),
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => {
                validate_job(peer, job_id)?;
                complete_inner_in(tx, peer, job_id, receipt, None)
            }
        }
    }

    pub(in crate::manage) fn complete_user_result(
        &mut self,
        peer: &str,
        job_id: &str,
        target_revision: u64,
        receipt: &super::super::Receipt,
    ) -> io::Result<Job> {
        match self {
            Self::Native(dir) => {
                super::complete_user_result(dir, peer, job_id, target_revision, receipt)
            }
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => {
                validate_job(peer, job_id)?;
                complete_inner_in(tx, peer, job_id, receipt, Some(target_revision))
            }
        }
    }

    pub(in crate::manage) fn complete_endpoint(
        &mut self,
        peer: &str,
        job_id: &str,
        receipt: &super::super::endpoint_control::Receipt,
    ) -> io::Result<Job> {
        match self {
            Self::Native(dir) => super::complete_endpoint(dir, peer, job_id, receipt),
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => {
                validate_job(peer, job_id)?;
                endpoints::complete_endpoint_in(tx, peer, job_id, receipt)
            }
        }
    }

    pub(in crate::manage) fn failed(
        &mut self,
        peer: &str,
        job_id: &str,
        blocked: bool,
        now: u64,
    ) -> io::Result<()> {
        match self {
            Self::Native(dir) => super::failed(dir, peer, job_id, blocked, now),
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => {
                validate_job(peer, job_id)?;
                sql(now)?;
                failed_in(tx, peer, job_id, blocked, now)
            }
        }
    }

    pub(in crate::manage) fn retry(
        &mut self,
        administrator: &str,
        peer: &str,
        job_id: &str,
    ) -> io::Result<Job> {
        match self {
            Self::Native(dir) => super::retry(dir, administrator, peer, job_id),
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => {
                validate_job(peer, job_id)?;
                retry_in(tx, administrator, peer, job_id)
            }
        }
    }

    pub(in crate::manage) fn supersede(
        &mut self,
        administrator: &str,
        peer: &str,
        job_id: &str,
    ) -> io::Result<Job> {
        match self {
            Self::Native(dir) => super::supersede(dir, administrator, peer, job_id),
            #[cfg(feature = "witness-journal")]
            Self::Source(tx) => {
                validate_job(peer, job_id)?;
                supersede_in(tx, administrator, peer, job_id)
            }
        }
    }
}
