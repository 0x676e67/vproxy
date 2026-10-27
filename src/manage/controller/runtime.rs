//! One explicit transient runtime request, never a persistent policy command.
//! Losing a response leaves the original runtime/request namespace unknown;
//! recovery is an exact GET, not another POST or a new request identity.

use super::*;
use crate::manage::drain;

#[derive(Debug, thiserror::Error)]
#[error("remote runtime drain outcome is unknown")]
pub(in crate::manage) struct RuntimeOutcomeUnknown;

fn unknown() -> io::Error {
    io::Error::other(RuntimeOutcomeUnknown)
}

impl Service {
    /// Reauthorize the browser's real administrator and target CAS after peer
    /// admission, then issue exactly one request over the existing verified
    /// mTLS transport. No read slot spans network work. Any lost or unbindable
    /// answer after the attempt is unknown, not proof that nothing happened.
    pub(in crate::manage) async fn drain_runtime(
        self: &Arc<Self>,
        administrator: String,
        peer: String,
        target_revision: u64,
        request: drain::Request,
    ) -> io::Result<drain::Status> {
        request.numbers()?;
        if request.expected_node_id != peer {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime target differs from request",
            ));
        }
        let claim = Arc::new(self.admission.acquire_command(&peer).await?);
        // Share the two mutation pipelines with durable delivery. Together
        // with collector/sampler reads this preserves the existing bounded
        // internal-read admission capacity instead of adding four new writers.
        let command = self
            .commands
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let permit = self
            .network
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let service = self.clone();
        // Once admitted, this one runtime-owned worker retains the peer and
        // network budgets even if the browser stops waiting. It never retries
        // the POST, persists an intent, or starts a recovery GET on its own.
        tokio::spawn(async move {
            let _command = command;
            service
                .runtime_exchange(administrator, target_revision, request, claim, permit)
                .await
        })
        .await
        .map_err(|_| unknown())?
    }

    async fn runtime_exchange(
        self: Arc<Self>,
        administrator: String,
        target_revision: u64,
        request: drain::Request,
        claim: Arc<Claim>,
        permit: OwnedSemaphorePermit,
    ) -> io::Result<drain::Status> {
        let peer = request.expected_node_id.clone();
        let (actor, id) = (administrator.clone(), peer.clone());
        let retained = claim.clone();
        let (target, permit) = self
            .policy
            .read_with_admission(ReadAdmission::Internal, move |directory| {
                let _claim = retained;
                let target = targets::scoped_target(directory, &actor, &id, target_revision)?;
                Ok((target, permit))
            })
            .await?;
        let reply = self
            .contact_with_admission(
                &target,
                Request::RuntimeDrain(control::RuntimeDrain {
                    version: 6,
                    resource: "proxy_runtime".into(),
                    source_administrator_id: administrator.clone(),
                    request: request.clone(),
                }),
                ReadAdmission::Internal,
            )
            .await;

        // This must run even for an error response. After a POST attempt, a
        // changed administrator/target cannot turn uncertainty into a definite
        // denial that invites another write. Keep the claim in its real worker.
        let retained = claim.clone();
        self.policy
            .read_with_admission(ReadAdmission::Internal, move |directory| {
                let (_claim, _permit) = (retained, permit);
                targets::scoped_target(directory, &administrator, &peer, target_revision)
            })
            .await
            .map_err(|_| unknown())?;
        let status = match reply {
            Ok(Reply::Runtime(status)) => *status,
            Err(error) if definitive_refusal(&error) => return Err(error),
            _ => return Err(unknown()),
        };
        status.validate(&target.peer_id).map_err(|_| unknown())?;
        if status.ownership.controller_node_id.as_deref() != Some(&self.node_id)
            || status.ownership.epoch != request.expected_epoch
            || !status.runtime.as_ref().is_some_and(|runtime| {
                runtime.runtime_id == request.runtime_id
                    && runtime.request.as_ref() == Some(&request)
            })
        {
            return Err(unknown());
        }
        let position = (
            decimal(&status.ownership.epoch).map_err(|_| unknown())?,
            decimal(&status.ownership.last_terminal_command).map_err(|_| unknown())?,
            decimal(&status.saved_revision).map_err(|_| unknown())?,
        );
        self.observe_position(&target, position, claim.clone())
            .await
            .map_err(|_| unknown())?;
        Ok(status)
    }
}

/// Only fixed, authenticated pre-transition refusals establish a known result.
/// A malformed body, transport failure, server error or post-check failure does
/// not: the child may already have accepted this runtime/request identity.
fn definitive_refusal(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|error| error.downcast_ref::<control::RemoteError>())
        .is_some_and(|error| {
            matches!(
                (error.status, error.code),
                (404, "node_protocol_unsupported")
                    | (403, "peer_not_authorized")
                    | (
                        409,
                        "target_mismatch"
                            | "controller_epoch_changed"
                            | "policy_conflict"
                            | "proxy_runtime_changed"
                            | "proxy_already_draining"
                            | "proxy_runtime_stopping"
                            | "proxy_runtime_unavailable"
                            | "proxy_admission_not_paused"
                            | "proxy_policy_unavailable"
                            | "proxy_restart_required",
                    )
            )
        })
}
