//! Controller-local delivery of the fixed node policy protocol.
//!
//! Intent is durable before contacting a child. A supervised task, rather than
//! a browser future, owns delivery; cancellation may lose a one-time secret but
//! cannot allocate a new command number or silently execute a different action.

use std::{
    collections::HashMap,
    io,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rustls::ClientConfig;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

mod admission;
mod runtime;
mod secrets;
use admission::{Admission, Claim};
pub(super) use runtime::RuntimeOutcomeUnknown;

use super::{
    node::control::{self, Reply, Request},
    policy::{Coordinator, ReadAdmission},
    store::{
        self,
        targets::{self, Delivery, Job, Target},
    },
};

/// Four total remote exchanges, including reads; only two may be mutations
/// (durable delivery or a transient drain). They do not use proxy capacity.
pub(super) struct Service {
    policy: Arc<Coordinator>,
    tls: Arc<ClientConfig>,
    node_id: String,
    network: Arc<Semaphore>,
    commands: Arc<Semaphore>,
    admission: Admission,
    sender: mpsc::Sender<Work>,
}

struct Work {
    administrator: String,
    target_revision: u64,
    command: store::ControlIntent,
    committed: oneshot::Sender<io::Result<Submitted>>,
    _claim: Claim,
    _permit: OwnedSemaphorePermit,
}

/// Returned only after the intent commits. The optional first response is not
/// retained in the service or database when its browser receiver disappears.
pub(super) struct Submitted {
    pub(super) job: Job,
    pub(super) response: oneshot::Receiver<io::Result<control::DeliveryReply>>,
}

/// Historical creation identity only. Current user state needs a separate
/// authorized read; credentials and one-time secrets cannot be recovered here.
pub(super) struct UserResult {
    pub(super) job: Job,
    pub(super) user_id: String,
}

/// A page may observe only the original retained intent, not whichever action
/// later replaced the peer's single outbox slot.
enum ExpectedJob {
    Endpoint(String),
    Maintenance(String),
}

pub(super) struct Runner {
    service: Arc<Service>,
    receiver: mpsc::Receiver<Work>,
}

impl Service {
    pub(super) fn new(
        policy: Arc<Coordinator>,
        tls: Arc<ClientConfig>,
        node_id: String,
    ) -> (Arc<Self>, Runner) {
        let (sender, receiver) = mpsc::channel(2);
        let service = Arc::new(Self {
            policy,
            tls,
            node_id,
            network: Arc::new(Semaphore::new(4)),
            commands: Arc::new(Semaphore::new(2)),
            admission: Admission::new(),
            sender,
        });
        let runner = Runner {
            service: service.clone(),
            receiver,
        };
        (service, runner)
    }

    #[cfg(test)]
    fn claim(&self, peer: &str) -> io::Result<Claim> {
        self.admission.try_claim(peer)
    }

    /// Schedule an explicitly authorized action. If the HTTP future disappears
    /// after admission, the supervised worker still completes the durable step.
    pub(super) async fn submit<C: Into<store::ControlIntent>>(
        self: &Arc<Self>,
        administrator: String,
        target_revision: u64,
        command: C,
    ) -> io::Result<Submitted> {
        let command = command.into();
        let claim = self.admission.acquire_command(command.target()).await?;
        let permit = self
            .commands
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let (committed, receiver) = oneshot::channel();
        self.sender
            .try_send(Work {
                administrator,
                target_revision,
                command,
                committed,
                _claim: claim,
                _permit: permit,
            })
            .map_err(|_| busy())?;
        receiver.await.map_err(|_| unavailable())?
    }

    /// Read only a configured target. No browser-supplied URL, trust root or
    /// certificate participates in an outbound request. Reads share both the
    /// total network budget and the peer's delivery/observation exclusion.
    pub(super) async fn remote(
        self: &Arc<Self>,
        peer: String,
        operation: Request,
    ) -> io::Result<Reply> {
        if matches!(
            operation,
            Request::Command(_)
                | Request::RoutingCommand(_)
                | Request::PresetCommand(_)
                | Request::EndpointCommand(_)
                | Request::MaintenanceCommand(_)
                | Request::RuntimeDrain(_)
                | Request::CredentialSecret(_)
        ) {
            return Err(denied());
        }
        let claim = self.admission.acquire(&peer).await?;
        let _permit = self
            .network
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let target = self.target(peer).await?;
        let reply = self.contact(&target, operation).await?;
        match &reply {
            Reply::Policy(policy) => self.observe(&target, policy, Arc::new(claim)).await?,
            Reply::Maintenance(status) => {
                if status.ownership.controller_node_id.as_deref() != Some(&self.node_id) {
                    return Err(denied());
                }
                self.observe_position(
                    &target,
                    (
                        decimal(&status.ownership.epoch)?,
                        decimal(&status.ownership.last_terminal_command)?,
                        decimal(&status.saved_revision)?,
                    ),
                    Arc::new(claim),
                )
                .await?;
            }
            Reply::Runtime(status) => {
                if status.ownership.controller_node_id.as_deref() != Some(&self.node_id) {
                    return Err(denied());
                }
                self.observe_position(
                    &target,
                    (
                        decimal(&status.ownership.epoch)?,
                        decimal(&status.ownership.last_terminal_command)?,
                        decimal(&status.saved_revision)?,
                    ),
                    Arc::new(claim),
                )
                .await?;
            }
            _ => {}
        }
        Ok(reply)
    }

    /// Explicit receipt refresh can promote Saved to Applied after a child
    /// restart. It never replays a mutation or asks the child for old secrets.
    pub(super) async fn refresh(self: &Arc<Self>, peer: String) -> io::Result<Job> {
        self.refresh_inner(peer, None).await
    }

    pub(super) async fn refresh_endpoint(
        self: &Arc<Self>,
        peer: String,
        job_id: String,
    ) -> io::Result<Job> {
        self.refresh_inner(peer, Some(ExpectedJob::Endpoint(job_id)))
            .await
    }

    /// Read the exact original maintenance receipt. A replaced slot or another
    /// action is rejected before contacting the child; no mutation is replayed.
    pub(super) async fn refresh_maintenance(
        self: &Arc<Self>,
        peer: String,
        job_id: String,
    ) -> io::Result<Job> {
        self.refresh_inner(peer, Some(ExpectedJob::Maintenance(job_id)))
            .await
    }

    /// Observe one retained CreateUser receipt, never resubmit its command.
    /// Canonical IDs, current target/action and the original epoch/sequence
    /// bound the request. A missing/pruned receipt remains a remote error;
    /// failure does not prove that creation never happened.
    pub(super) async fn user_result(
        self: &Arc<Self>,
        peer: String,
        expected_job_id: String,
    ) -> io::Result<UserResult> {
        if !store::valid_id(&peer) || !store::valid_id(&expected_job_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid node command identity",
            ));
        }
        let claim = self.admission.acquire(&peer).await?;
        let permit = self
            .network
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let target = self.target(peer.clone()).await?;
        let job = self
            .policy
            .read(move |directory| {
                let job = targets::job(directory, &peer)?.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "node command not found")
                })?;
                if job.job_id != expected_job_id {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "node command changed",
                    ));
                }
                if !job.user_creation || job.endpoint.is_some() || job.maintenance.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "node command is not user creation",
                    ));
                }
                if !matches!(
                    job.state,
                    targets::JobState::Pending
                        | targets::JobState::Blocked
                        | targets::JobState::Saved
                        | targets::JobState::Applied
                ) {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "node user result unavailable",
                    ));
                }
                Ok(job)
            })
            .await?;
        let Reply::Receipt(value) = self
            .contact(
                &target,
                Request::Receipt {
                    version: 1,
                    controller_epoch: job.epoch,
                    command_id: job.command_id,
                },
            )
            .await?
        else {
            return Err(invalid());
        };
        let receipt = receipt(&value, 1)?;
        let (job, user_id) = self
            .policy
            .targets_write_guarded((claim, permit), move |writer| {
                // Transfer peer admission into the actual writer worker. A
                // cancelled waiter submits nothing; a cancelled response cannot
                // release the claim while its transaction is still committing.
                let job = writer.complete_user_result(
                    &job.peer_id,
                    &job.job_id,
                    target.revision,
                    &receipt,
                )?;
                Ok((job, receipt.user_id))
            })
            .await?;
        // A rejected receipt is durable metadata even when the requested user
        // result is unavailable. Do not turn this post-commit response decision
        // into a rollback of the Source transaction.
        if !matches!(
            job.state,
            targets::JobState::Saved | targets::JobState::Applied
        ) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "node user result unavailable",
            ));
        }
        let user_id = user_id
            .filter(|id| store::valid_id(id))
            .ok_or_else(invalid)?;
        Ok(UserResult { job, user_id })
    }

    async fn refresh_inner(
        self: &Arc<Self>,
        peer: String,
        expected_job: Option<ExpectedJob>,
    ) -> io::Result<Job> {
        let claim = self.admission.acquire(&peer).await?;
        let permit = self
            .network
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let target = self.target(peer.clone()).await?;
        let job = self
            .policy
            .read(move |directory| targets::job(directory, &peer))
            .await?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "node command not found"))?;
        let matches_expected = match &expected_job {
            None => true,
            Some(ExpectedJob::Endpoint(id)) => job.job_id == *id && job.endpoint.is_some(),
            Some(ExpectedJob::Maintenance(id)) => {
                job.job_id == *id
                    && job.maintenance.is_some()
                    && job.endpoint.is_none()
                    && !job.user_creation
                    && job.routing.is_none()
                    && job.preset.is_none()
            }
        };
        if !matches_expected {
            return Err(invalid());
        }
        let (peer, job_id) = (job.peer_id.clone(), job.job_id.clone());
        // The durable intent, not the page or current software default,
        // determines which receipt vocabulary survives a controller restart.
        let version = self
            .policy
            .read(move |directory| targets::job_version(directory, &peer, &job_id))
            .await?;
        if matches!(&expected_job, Some(ExpectedJob::Endpoint(_))) && version != 4
            || matches!(&expected_job, Some(ExpectedJob::Maintenance(_))) && version != 5
        {
            return Err(invalid());
        }
        if version == 4 {
            let Reply::EndpointReceipt(value) = self
                .contact(
                    &target,
                    Request::EndpointReceipt {
                        controller_epoch: job.epoch,
                        command_id: job.command_id,
                    },
                )
                .await?
            else {
                return Err(invalid());
            };
            let receipt = value.into_store()?;
            return self
                .policy
                .targets_write_guarded((claim, permit), move |writer| {
                    writer.complete_endpoint(&job.peer_id, &job.job_id, &receipt)
                })
                .await;
        }
        let Reply::Receipt(value) = self
            .contact(
                &target,
                Request::Receipt {
                    version,
                    controller_epoch: job.epoch,
                    command_id: job.command_id,
                },
            )
            .await?
        else {
            return Err(invalid());
        };
        let receipt = receipt(&value, version)?;
        self.policy
            .targets_write_guarded((claim, permit), move |writer| {
                writer.complete(&job.peer_id, &job.job_id, &receipt)
            })
            .await
    }

    async fn target(&self, peer: String) -> io::Result<Target> {
        self.target_with_admission(peer, ReadAdmission::Immediate)
            .await
    }

    async fn target_with_admission(
        &self,
        peer: String,
        admission: ReadAdmission,
    ) -> io::Result<Target> {
        let target = self
            .policy
            .read_with_admission(admission, move |directory| targets::get(directory, &peer))
            .await?;
        if !target.active || target.retired || target.rollback_detected {
            return Err(denied());
        }
        Ok(target)
    }

    async fn contact(&self, target: &Target, operation: Request) -> io::Result<Reply> {
        self.contact_with_admission(target, operation, ReadAdmission::Immediate)
            .await
    }

    async fn contact_with_admission(
        &self,
        target: &Target,
        operation: Request,
        admission: ReadAdmission,
    ) -> io::Result<Reply> {
        let scoped_read = matches!(
            &operation,
            Request::Address { .. }
                | Request::EgressAlerts(_)
                | Request::OperationsAlerts(_)
                | Request::OperationsSnapshot
                | Request::Maintenance
                | Request::Runtime
                | Request::RuntimeDrainStatus { .. }
        );
        let reply = match admission {
            ReadAdmission::Immediate => {
                control::request(
                    &self.policy,
                    self.tls.clone(),
                    &target.origin,
                    &target.peer_id,
                    operation,
                )
                .await
            }
            ReadAdmission::Internal => {
                control::request_with_admission(
                    &self.policy,
                    self.tls.clone(),
                    &target.origin,
                    &target.peer_id,
                    operation,
                    admission,
                )
                .await
            }
        };
        // These additive scoped reads must not publish an old target's missing
        // or cursor/availability answer after its registration changes. Keep
        // the error precedence of older operations unchanged.
        if !scoped_read && reply.is_err() {
            return reply;
        }
        let peer = target.peer_id.clone();
        let current = self
            .policy
            .read_with_admission(admission, move |directory| targets::get(directory, &peer))
            .await?;
        if current.revision != target.revision
            || !current.active
            || current.retired
            || current.rollback_detected
        {
            return Err(denied());
        }
        reply
    }

    async fn observe(
        &self,
        target: &Target,
        policy: &control::Policy,
        claim: Arc<Claim>,
    ) -> io::Result<()> {
        if policy.controller_node_id.as_deref() != Some(&self.node_id) {
            return Err(denied());
        }
        let position = (
            decimal(&policy.controller_epoch)?,
            decimal(&policy.last_terminal_command)?,
            decimal(&policy.saved_revision)?,
        );
        self.observe_position(target, position, claim).await
    }

    /// Both policy and maintenance reads carry the same owner-scoped durable
    /// position. Store the position under the original peer claim so a status
    /// observation cannot bypass rollback detection or release its gate early.
    async fn observe_position(
        &self,
        target: &Target,
        (epoch, command, revision): (u64, u64, u64),
        claim: Arc<Claim>,
    ) -> io::Result<()> {
        let peer = target.peer_id.clone();
        let target_revision = target.revision;
        let target = self
            .policy
            .targets_write_guarded(claim, move |writer| {
                writer.observe(&peer, target_revision, epoch, command, revision)
            })
            .await?;
        if target.rollback_detected {
            return Err(denied());
        }
        Ok(())
    }

    async fn deliver(
        &self,
        delivery: Delivery,
        claim: &Arc<Claim>,
    ) -> io::Result<control::DeliveryReply> {
        let peer = delivery.target.peer_id.clone();
        let job_id = delivery.job.job_id.clone();
        // A command permit already bounds this pipeline to two deliveries.
        // Each internal read waits only for its own storage step; no read
        // worker or permit is retained across an outbound request.
        let admission = ReadAdmission::Internal;
        // Both policy preflight and POST share one total deadline. A half-read
        // response or an uncertain target commit keeps the original intent.
        let result = tokio::time::timeout(Duration::from_secs(12), async {
            let _permit = self
                .network
                .clone()
                .try_acquire_owned()
                .map_err(|_| busy())?;
            let Reply::Policy(policy) = self
                .contact_with_admission(&delivery.target, Request::Policy, admission)
                .await?
            else {
                return Err(invalid());
            };
            self.observe(&delivery.target, &policy, claim.clone())
                .await?;
            if decimal(&policy.controller_epoch)? != delivery.command.epoch() {
                return Err(denied());
            }
            let command = delivery.command;
            if let store::ControlIntent::Endpoint(command) = command {
                let Reply::EndpointCommand(reply) = self
                    .contact_with_admission(
                        &delivery.target,
                        Request::EndpointCommand(command.into()),
                        admission,
                    )
                    .await?
                else {
                    return Err(invalid());
                };
                let receipt = reply.receipt.clone().into_store()?;
                let (peer, job_id) = (peer.clone(), job_id.clone());
                let claim = claim.clone();
                self.policy
                    .targets_write_guarded(claim, move |writer| {
                        writer.complete_endpoint(&peer, &job_id, &receipt)
                    })
                    .await?;
                return Ok(control::DeliveryReply::Endpoint(reply));
            }
            let store::ControlIntent::Policy(command) = command else {
                return Err(invalid());
            };
            let version = command.change.control_version();
            let operation = match version {
                1 => Request::Command(control::Command {
                    version,
                    target_node_id: command.target_node_id,
                    resource: "proxy_policy".to_owned(),
                    controller_epoch: command.epoch.to_string(),
                    command_id: command.command_id.to_string(),
                    expected_policy_revision: command.expected_policy_revision.to_string(),
                    source_administrator_id: command.source_administrator_id,
                    mutation: command.change.try_into()?,
                }),
                2 => Request::RoutingCommand(control::RoutingCommand {
                    version,
                    target_node_id: command.target_node_id,
                    resource: "proxy_policy".to_owned(),
                    controller_epoch: command.epoch.to_string(),
                    command_id: command.command_id.to_string(),
                    expected_policy_revision: command.expected_policy_revision.to_string(),
                    source_administrator_id: command.source_administrator_id,
                    mutation: command.change.try_into()?,
                }),
                3 => Request::PresetCommand(control::PresetCommand {
                    version,
                    target_node_id: command.target_node_id,
                    resource: "proxy_policy".to_owned(),
                    controller_epoch: command.epoch.to_string(),
                    command_id: command.command_id.to_string(),
                    expected_policy_revision: command.expected_policy_revision.to_string(),
                    source_administrator_id: command.source_administrator_id,
                    mutation: command.change.try_into()?,
                }),
                5 => Request::MaintenanceCommand(control::MaintenanceCommand {
                    version,
                    target_node_id: command.target_node_id,
                    resource: "proxy_policy".to_owned(),
                    controller_epoch: command.epoch.to_string(),
                    command_id: command.command_id.to_string(),
                    expected_policy_revision: command.expected_policy_revision.to_string(),
                    source_administrator_id: command.source_administrator_id,
                    mutation: control::MaintenanceMutation::try_from(command.change)?,
                }),
                _ => return Err(invalid()),
            };
            let Reply::Command(reply) = self
                .contact_with_admission(&delivery.target, operation, admission)
                .await?
            else {
                return Err(invalid());
            };
            let receipt = receipt(&reply.receipt, version)?;
            let (peer, job_id) = (peer.clone(), job_id.clone());
            let claim = claim.clone();
            self.policy
                .targets_write_guarded(claim, move |writer| {
                    writer.complete(&peer, &job_id, &receipt)
                })
                .await?;
            Ok(control::DeliveryReply::Policy(reply))
        })
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "node delivery timed out",
            ))
        });
        if let Err(error) = &result {
            // Windows may return PermissionDenied for a refused/filtered TCP
            // connection. Transport kind alone does not prove a peer, owner
            // or policy authorization rejection.
            let transport = error
                .get_ref()
                .is_some_and(|error| error.is::<control::TransportError>());
            let blocked = !transport
                && (matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied
                        | io::ErrorKind::InvalidInput
                        | io::ErrorKind::InvalidData
                ) || error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<control::RemoteError>())
                    .is_some_and(|error| {
                        (400..500).contains(&error.status) && !matches!(error.status, 408 | 429)
                    }));
            let now = now()?;
            // Failure to persist retry metadata is surfaced, never converted
            // into a claimed target rejection or successful application.
            let claim = claim.clone();
            self.policy
                .targets_write_guarded(claim, move |writer| {
                    writer.failed(&peer, &job_id, blocked, now)
                })
                .await?;
        }
        result
    }
}

impl Runner {
    /// One supervisor owns every command task. Shutdown stops scheduling and
    /// boundedly drains; an aborted network request leaves its durable job for
    /// the next process, whose retry uses the exact same command identity.
    pub(super) async fn run(mut self, shutdown: CancellationToken) -> io::Result<()> {
        let mut tasks = JoinSet::new();
        // Task IDs, rather than a peer-only set, also cover the tiny interval
        // between releasing a first delivery's claim and joining that task.
        let mut scheduled = HashMap::new();
        let mut retry_offset = 0;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                Some(joined) = tasks.join_next_with_id(), if !tasks.is_empty() => {
                    let (id, ()) = joined.map_err(|_| unavailable())?;
                    scheduled.remove(&id);
                }
                work = self.receiver.recv() => {
                    let Some(work) = work else { break; };
                    let peer = work.command.target().to_owned();
                    let service = self.service.clone();
                    let task = tasks.spawn(async move { service.first(work).await; });
                    scheduled.insert(task.id(), peer);
                }
                _ = interval.tick() => {
                    let now = now()?;
                    let due = self.service.policy.read(move |directory| targets::pending(directory, now)).await;
                    let mut due = match due { Ok(due) => due, Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(error) => return Err(error) };
                    // A full peer queue does not update persistent backoff. A
                    // fixed prefix would therefore keep selecting the same two
                    // busy peers and could starve every later eligible target.
                    let due_count = due.len();
                    if due_count != 0 {
                        retry_offset %= due_count;
                        due.rotate_left(retry_offset);
                    }
                    for delivery in due {
                        // At most two retry tasks may wait for a peer. Do not
                        // hold command/network slots while waiting or await in
                        // this supervisor, which must still handle shutdown.
                        // Two already-admitted first deliveries may coexist.
                        if tasks.len() >= 2 { break; }
                        retry_offset = (retry_offset + 1) % due_count;
                        if scheduled.values().any(|peer| peer == &delivery.target.peer_id) { continue; }
                        let peer = delivery.target.peer_id.clone();
                        let service = self.service.clone();
                        let task = tasks.spawn(async move {
                            let Ok(claim) = service.admission.acquire_command(&delivery.target.peer_id).await else { return; };
                            let Ok(_permit) = service.commands.clone().try_acquire_owned() else { return; };
                            let claim = Arc::new(claim);
                            // The candidate scan preceded admission. Recheck
                            // pause/retirement and exact job under the peer
                            // claim before starting its network operation.
                            let peer = delivery.job.peer_id;
                            let job_id = delivery.job.job_id;
                            if let Ok(delivery) = service.policy.read_with_admission(ReadAdmission::Internal, move |directory|
                                targets::load_delivery(directory, &peer, &job_id)).await {
                                let _ = service.deliver(delivery, &claim).await;
                            }
                        });
                        scheduled.insert(task.id(), peer);
                    }
                }
            }
        }
        self.receiver.close();
        if tokio::time::timeout(Duration::from_secs(4), async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        Ok(())
    }
}

impl Service {
    async fn first(&self, work: Work) {
        let Work {
            administrator,
            target_revision,
            command,
            committed,
            _claim,
            _permit,
        } = work;
        // The outer owner spans first-response delivery; clones below keep
        // peer exclusion alive if a durable worker outlives Runner cancellation.
        let _claim = Arc::new(_claim);
        if matches!(command, store::ControlIntent::Endpoint(_)) {
            // Read-only capability negotiation precedes durable intent. A legacy
            // child is never tested by POSTing an unsupported command.
            let checked = async {
                let _network = self
                    .network
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| busy())?;
                let target = self
                    .target_with_admission(command.target().to_owned(), ReadAdmission::Internal)
                    .await?;
                match self
                    .contact_with_admission(
                        &target,
                        Request::EndpointSettings,
                        ReadAdmission::Internal,
                    )
                    .await?
                {
                    Reply::EndpointSettings(_) => Ok(()),
                    _ => Err(invalid()),
                }
            }
            .await;
            if let Err(error) = checked {
                let _ = committed.send(Err(error));
                return;
            }
        }
        let claim = _claim.clone();
        let queued = self
            .policy
            .targets_write_guarded(claim, move |writer| {
                let job = writer.enqueue_intent(&administrator, target_revision, command)?;
                // Retain the same writer permit for first-delivery lookup.
                // A new read-budget race after commit must not unnecessarily
                // lose the live consumer of a one-time secret.
                let delivery = writer.load_delivery(&job.peer_id, &job.job_id);
                Ok((job, delivery))
            })
            .await;
        let (job, delivery) = match queued {
            Ok(queued) => queued,
            Err(error) => {
                let _ = committed.send(Err(error));
                return;
            }
        };
        let (response, receiver) = oneshot::channel();
        let _ = committed.send(Ok(Submitted {
            job,
            response: receiver,
        }));
        let result = match delivery {
            Ok(delivery) => self.deliver(delivery, &_claim).await,
            Err(error) => Err(error),
        };
        let _ = response.send(result);
        // Explicitly retain peer ownership until after the first-response send.
        drop((_claim, _permit));
    }
}

fn receipt(value: &control::Receipt, version: u8) -> io::Result<store::Receipt> {
    let rejection = value
        .rejection
        .as_deref()
        .map(|code| match code {
            "invalid_policy" => Ok("invalid_policy"),
            "policy_conflict" => Ok("policy_conflict"),
            "resource_not_found" => Ok("resource_not_found"),
            "policy_capacity" => Ok("policy_capacity"),
            _ => Err(invalid()),
        })
        .transpose()?;
    Ok(store::Receipt {
        version,
        epoch: decimal(&value.controller_epoch)?,
        command_id: decimal(&value.command_id)?,
        status: match value.status {
            control::ReceiptStatus::Saved => store::ReceiptStatus::Saved,
            control::ReceiptStatus::Applied => store::ReceiptStatus::Applied,
            control::ReceiptStatus::Rejected => store::ReceiptStatus::Rejected,
        },
        policy_revision: value.policy_revision.as_deref().map(decimal).transpose()?,
        rejection,
        user_id: value.user_id.clone(),
        credential_id: value.credential_id.clone(),
        routing: value.routing.clone(),
        preset: value.preset.clone(),
    })
}

fn decimal(value: &str) -> io::Result<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(invalid)
}

fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| unavailable())
}
fn busy() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "node control capacity is busy")
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "node target ownership or configuration changed",
    )
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid node control reply")
}
fn unavailable() -> io::Error {
    io::Error::other("node control worker unavailable")
}

#[cfg(test)]
pub(in crate::manage) mod tests {
    //! Real controller delivery, durable intent and the child's running data plane.

    mod admission {
        //! Controlled read/write admission interleavings with real store workers.
        //! These do not reproduce a post-command secret-response race or Runner timing.

        use super::*;

        #[test]
        fn ordinary_remote_fails_fast_but_admitted_first_survives_brief_read_saturation()
        -> io::Result<()> {
            let harness = Harness::new()?;
            // Runtime drop joins started blocking work before the earlier-created
            // harness releases database authority or removes its private fixture.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let result = runtime.block_on(async {
                let mut owned = OwnedTasks::new();
                let scenario = async {
                    let stop = CancellationToken::new();
                    let (address, node) = start_node(
                        &harness.fixture,
                        &harness.child,
                        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                        stop.clone(),
                    )
                    .await?;
                    owned.insert("admission child", stop, node);
                    configure_target(&harness, format!("https://localhost:{}", address.port()))
                        .await?;
                    // The runner is deliberately not scheduled: its periodic scan must
                    // not compete with this exact helper-level enqueue interleaving.
                    let (service, _runner) = Service::new(
                        harness.caller.clone(),
                        harness.fixture.client_tls.clone(),
                        harness.fixture.client_id.clone(),
                    );
                    assert!(matches!(
                        service
                            .remote(harness.fixture.server_id.clone(), Request::Policy)
                            .await?,
                        Reply::Policy(_)
                    ));

                    // Each entered acknowledgement comes from inside a real read
                    // worker, after it acquires one of the coordinator's two permits.
                    // Sender drop releases every worker on Err, panic or timeout too.
                    let mut releases = Vec::new();
                    for _ in 0..2 {
                        let (entered, started) = oneshot::channel();
                        let (release, released) = std::sync::mpsc::channel::<()>();
                        let caller = harness.caller.clone();
                        let holder = tokio::spawn(async move {
                            caller
                                .read(move |_| {
                                    let _ = entered.send(());
                                    let _ = released.recv();
                                    Ok(())
                                })
                                .await
                        });
                        owned.insert("admission read holder", CancellationToken::new(), holder);
                        releases.push(release);
                        started.await.map_err(io::Error::other)?;
                    }

                    // No command claim exists yet. Failure is the Immediate local
                    // target read, not peer exclusion or a refused network request.
                    let mut ordinary = Box::pin(
                        service.remote(harness.fixture.server_id.clone(), Request::Policy),
                    );
                    match futures_util::poll!(&mut ordinary) {
                        Poll::Ready(Err(error)) => {
                            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                        }
                        _ => panic!("ordinary remote read must fail without waiting"),
                    }
                    drop(ordinary);

                    let (committed, submitted) = oneshot::channel();
                    let command = harness.command(
                        1,
                        1,
                        store::PolicyChange::CreateUser {
                            name: "Read admission user".into(),
                            protocols: vec![crate::access::Protocol::Http],
                            concurrent_limit: 1,
                        },
                    );
                    let mut first = Box::pin(
                        service.first(Work {
                            administrator: harness.administrator.clone(),
                            target_revision: 1,
                            command: command.into(),
                            committed,
                            _claim: service.claim(&harness.fixture.server_id)?,
                            _permit: service
                                .commands
                                .clone()
                                .try_acquire_owned()
                                .map_err(|_| busy())?,
                        }),
                    );
                    // Enqueue uses the writer, not the exhausted read budget. The later
                    // policy preflight still uses bounded Internal read admission.
                    assert!(futures_util::poll!(&mut first).is_pending());
                    drop(releases);
                    first.await;
                    let submitted = submitted.await.map_err(io::Error::other)??;
                    assert_eq!(submitted.job.command_id, 1);
                    let reply = submitted.response.await.map_err(io::Error::other)??;
                    let reply = policy_reply(reply);
                    assert!(reply.user.is_some());
                    assert!(matches!(
                        reply.receipt.status,
                        control::ReceiptStatus::Saved
                    ));
                    let peer = harness.fixture.server_id.clone();
                    let job = harness
                        .caller
                        .read(move |directory| targets::job(directory, &peer))
                        .await?
                        .ok_or_else(unavailable)?;
                    assert_eq!(job.job_id, submitted.job.job_id);
                    assert_eq!(job.command_id, 1);
                    assert_eq!(job.attempts, 0);
                    assert!(matches!(job.state, targets::JobState::Saved));
                    Ok(())
                };
                let scenario = timeout(Duration::from_secs(10), scenario)
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "read admission test timed out")
                    })
                    .and_then(|result| result);
                owned.finish(scenario).await
            });
            drop(runtime);
            result
        }

        #[test]
        fn target_observation_and_local_edit_share_writer_without_consuming_read_capacity()
        -> io::Result<()> {
            let harness = Harness::new()?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let result = runtime.block_on(async {
                let mut owned = OwnedTasks::new();
                let scenario = async {
                    configure_target(&harness, "https://localhost:1".into()).await?;
                    let (service, _runner) = Service::new(
                        harness.caller.clone(),
                        harness.fixture.client_tls.clone(),
                        harness.fixture.client_id.clone(),
                    );
                    let target =
                        targets::get(&harness.fixture.client_state, &harness.fixture.server_id)?;

                    // Two real readers stay blocked throughout both metadata and user
                    // writes. Sender drop releases them on early return or panic too.
                    let mut releases = Vec::new();
                    for _ in 0..2 {
                        let (entered, started) = oneshot::channel();
                        let (release, released) = std::sync::mpsc::channel::<()>();
                        let caller = harness.caller.clone();
                        let holder = tokio::spawn(async move {
                            caller
                                .read(move |_| {
                                    let _ = entered.send(());
                                    let _ = released.recv();
                                    Ok(())
                                })
                                .await
                        });
                        owned.insert("metadata read holder", CancellationToken::new(), holder);
                        releases.push(release);
                        started.await.map_err(io::Error::other)?;
                    }
                    let writer = harness
                        .caller
                        .write_work()
                        .acquire_owned()
                        .await
                        .map_err(io::Error::other)?;
                    let claim = Arc::new(service.claim(&target.peer_id)?);
                    let mut observation =
                        Box::pin(service.observe_position(&target, (2, 0, 1), claim));
                    // Before the fix this returns Ready(WouldBlock) on the full read
                    // pool. The metadata publisher must instead wait in the writer FIFO.
                    assert!(futures_util::poll!(&mut observation).is_pending());
                    let input = store::operations::Input {
                        expected_node_id: Some(harness.fixture.client_id.clone()),
                        expected_revision: 1,
                        expected_epoch: 1,
                        change: store::operations::UserChange::CreateUser {
                            name: "metadata queue regression".into(),
                            protocols: vec![crate::access::Protocol::Http],
                            concurrent_limit: 1,
                        },
                    };
                    let caller =
                        store::operations::Caller::Administrator(harness.administrator.clone());
                    let mut reservation = Box::pin(
                        harness
                            .caller
                            .reserve_user_operation(caller.clone(), input.clone()),
                    );
                    assert!(futures_util::poll!(&mut reservation).is_pending());
                    drop(writer);
                    observation.await?;
                    let reserved = reservation.await?;
                    assert_eq!(harness.caller.reader().revision()?, 1);
                    let saved = harness
                        .caller
                        .execute_user_operation(caller, reserved.id, input)
                        .await?;
                    assert_eq!(saved.saved_revision, Some(2));
                    assert_eq!(harness.caller.reader().revision()?, 2);
                    let target =
                        targets::get(&harness.fixture.client_state, &harness.fixture.server_id)?;
                    assert_eq!(target.observed_epoch, Some(2));
                    assert_eq!(target.observed_command, Some(0));
                    assert_eq!(target.observed_policy_revision, Some(1));
                    drop(releases);
                    Ok(())
                };
                let scenario = timeout(Duration::from_secs(10), scenario)
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "metadata admission test timed out")
                    })
                    .and_then(|result| result);
                owned.finish(scenario).await
            });
            drop(runtime);
            result
        }
    }
    mod endpoints {
        //! Real mTLS metadata delivery shares policy ordering without publishing policy.
        //! Full listener/CONNECT continuity is additionally exercised by CLI acceptance.

        use super::*;
        use crate::manage::store::{endpoint_control, endpoints::AddressSelection};
        use std::cell::Cell;

        #[test]
        fn mixed_endpoint_delivery_replay_and_outbox_restart_keep_policy_revision_independent()
        -> io::Result<()> {
            let preparing = Instant::now();
            // Certificate/database fixture construction is synchronous preparation,
            // not part of the network scenario's unchanged 30-second deadline.
            let harness = Harness::new()?;
            harness
                .child
                .configure_endpoints(vec![proxy::ListenerView {
                    protocol: proxy::Protocol::Http,
                    bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)),
                    public_address: Some("proxy.example:8080".into()),
                }])?;
            let prepare_elapsed = preparing.elapsed();
            // Runtime teardown waits for already-started blocking work before the
            // fixture deletes its files. Joining an aborted async supervisor alone
            // cannot provide that guarantee for spawn_blocking closures.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
    let started = Instant::now();
    let stage = Cell::new(("configure_endpoint_settings", started));
    let trace = Trace::new();
    let mark = |name| {
        stage.set((name, Instant::now()));
        trace.mark(name);
    };
    mark("configure_endpoint_settings");
    let shutdown = CancellationToken::new();
    let runner_shutdown = shutdown.child_token();
    let restart_shutdown = shutdown.child_token();
    let mut owned = OwnedTasks::new();
    let scenario = timeout(Duration::from_secs(30), async {
        harness
            .child
            .configure_endpoint_settings(&harness.fixture.server_id)
            .await?;
        mark("start_node");
        let (address, node) = start_node(
            &harness.fixture,
            &harness.child,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            shutdown.clone(),
        )
        .await?;
        owned.insert("metadata child node", shutdown.clone(), node);
        mark("configure_target");
        configure_target(&harness, format!("https://localhost:{}", address.port())).await?;
        let (service, runner) = Service::new(
            harness.caller.clone(),
            harness.fixture.client_tls.clone(),
            harness.fixture.client_id.clone(),
        );
        let runner = owned.insert(
            "metadata initial runner",
            runner_shutdown.clone(),
            tokio::spawn(runner.run(runner_shutdown.clone())),
        );
            mark("initial_policy_observation");
            service
                .remote(harness.fixture.server_id.clone(), Request::Policy)
                .await?;
            mark("policy_one_admission");
            wait_peer_idle(&service, &harness.fixture.server_id).await?;
            mark("policy_one_submit");
            let submitted = service
                .submit(
                    harness.administrator.clone(),
                    1,
                    harness.command(
                        1,
                        1,
                        store::PolicyChange::CreateUser {
                            name: "metadata sequence".into(),
                            protocols: vec![crate::access::Protocol::Http],
                            concurrent_limit: 2,
                        },
                    ),
                )
                .await?;
            mark("policy_one_response");
            let created = policy_reply(submitted.response.await.map_err(io::Error::other)??);
            mark("policy_one_response_checks");
            let user = created.user.unwrap().id;
            mark("settings_admission");
            wait_peer_idle(&service, &harness.fixture.server_id).await?;
            mark("settings_observation");
            let Reply::EndpointSettings(settings) = service
                .remote(harness.fixture.server_id.clone(), Request::EndpointSettings)
                .await?
            else {
                return Err(io::Error::other("expected settings"));
            };
            mark("settings_response_checks");
            let before_policy = harness.child.reader().revision()?;
            let command = endpoint_control::Command {
                target_node_id: harness.fixture.server_id.clone(),
                epoch: 2,
                command_id: 2,
                expected_metadata_revision: settings.revision.parse().map_err(io::Error::other)?,
                source_administrator_id: harness.administrator.clone(),
                generation: settings.generation.clone(),
                change: store::endpoints::Change {
                    listener_id: settings.listeners[0].id.clone(),
                    selection: AddressSelection::Hidden,
                },
            };
            mark("metadata_two_admission");
            wait_peer_idle(&service, &harness.fixture.server_id).await?;
            mark("metadata_two_submit");
            let submitted = service
                .submit(harness.administrator.clone(), 1, command.clone())
                .await?;
            let metadata_job = submitted.job.job_id.clone();
            mark("metadata_two_response");
            let control::DeliveryReply::Endpoint(reply) =
                submitted.response.await.map_err(io::Error::other)??
            else {
                return Err(io::Error::other("expected metadata delivery"));
            };
            mark("metadata_two_response_checks");
            assert!(!reply.replayed);
            assert_eq!(reply.receipt.status, "saved");
            assert_eq!(harness.child.reader().revision()?, before_policy);
            // These SQLite observations must not block the current-thread
            // runtime that also drives the real TLS node and controller.
            mark("metadata_two_source_database_observation");
            let directory = harness.fixture.client_state.clone();
            let peer = harness.fixture.server_id.clone();
            let (job, observed_policy_revision) = tokio::task::spawn_blocking(move || {
                Ok::<_, io::Error>((
                    targets::job(&directory, &peer)?,
                    targets::get(&directory, &peer)?.observed_policy_revision,
                ))
            })
            .await
            .map_err(io::Error::other)??;
            mark("metadata_two_source_database_checks");
            let job = job.unwrap();
            assert!(job.policy_revision.is_none() && job.expected_policy_revision.is_none());
            assert_eq!(
                job.metadata_revision,
                command.expected_metadata_revision.checked_add(1)
            );
            assert_eq!(
                observed_policy_revision,
                Some(before_policy)
            );
            // Read each real mTLS receipt namespace; a known other-resource
            // record is 404, not an expired result or an old policy receipt.
            for version in 1..=3 {
                mark("cross_resource_policy_receipt_admission");
                wait_peer_idle(&service, &harness.fixture.server_id).await?;
                mark("cross_resource_policy_receipt_read");
                let error = service.remote(harness.fixture.server_id.clone(), Request::Receipt {
                    version,
                    controller_epoch: 2,
                    command_id: 2,
                }).await.err().ok_or_else(|| io::Error::other("metadata appeared in policy receipt namespace"))?;
                let remote = error.get_ref().and_then(|value| value.downcast_ref::<control::RemoteError>()).ok_or_else(|| io::Error::other("expected typed cross-resource rejection"))?;
                assert_eq!((remote.status, remote.code), (404, "resource_not_found"));
            }
            mark("metadata_receipt_admission");
            wait_peer_idle(&service, &harness.fixture.server_id).await?;
            mark("metadata_receipt_read");
            let Reply::EndpointReceipt(retained) = service.remote(harness.fixture.server_id.clone(), Request::EndpointReceipt {
                controller_epoch: 2,
                command_id: 2,
            }).await? else { return Err(io::Error::other("expected retained metadata receipt")); };
            assert_eq!(retained.into_store()?, reply.receipt.clone().into_store()?);
            mark("cross_resource_metadata_receipt_admission");
            wait_peer_idle(&service, &harness.fixture.server_id).await?;
            mark("cross_resource_metadata_receipt_read");
            let error = service.remote(harness.fixture.server_id.clone(), Request::EndpointReceipt {
                controller_epoch: 2,
                command_id: 1,
            }).await.err().ok_or_else(|| io::Error::other("policy appeared in metadata receipt namespace"))?;
            let remote = error.get_ref().and_then(|value| value.downcast_ref::<control::RemoteError>()).ok_or_else(|| io::Error::other("expected typed cross-resource rejection"))?;
            assert_eq!((remote.status, remote.code), (404, "resource_not_found"));
            mark("metadata_replay_admission");
            wait_peer_idle(&service, &harness.fixture.server_id).await?;
            {
                mark("metadata_replay_peer_claim");
                let _claim = service.claim(&harness.fixture.server_id)?;
                mark("metadata_replay_network_permit");
                let _network = service
                    .network
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| busy())?;
                mark("metadata_exact_replay");
                let Reply::EndpointCommand(replay) = control::request(
                    &harness.caller,
                    harness.fixture.client_tls.clone(),
                    &format!("https://localhost:{}", address.port()),
                    &harness.fixture.server_id,
                    Request::EndpointCommand(command.clone().into()),
                )
                .await?
                else {
                    return Err(io::Error::other("expected metadata replay"));
                };
                mark("metadata_replay_response_checks");
                assert!(replay.replayed);
                assert_eq!(
                    replay.receipt.metadata_revision,
                    reply.receipt.metadata_revision
                );
            }
            // Reconstruct the controller service from durable intent, rather
            // than treating its lost in-process first response as a new action.
            mark("first_controller_drain");
            runner_shutdown.cancel();
            owned.stop_and_join(runner).await?;
            mark("controller_reconstruction");
            drop(service);
            let (service, runner) = Service::new(
                harness.caller.clone(),
                harness.fixture.client_tls.clone(),
                harness.fixture.client_id.clone(),
            );
            owned.insert(
                "metadata restarted runner",
                restart_shutdown.clone(),
                tokio::spawn(runner.run(restart_shutdown.clone())),
            );
                mark("restart_receipt_refresh");
                let recovered = service
                    .refresh_endpoint(harness.fixture.server_id.clone(), metadata_job)
                    .await?;
                mark("restart_receipt_refresh_checks");
                assert_eq!(recovered.command_id, 2);
                assert_eq!(recovered.metadata_revision, job.metadata_revision);
                mark("policy_three_admission");
                wait_peer_idle(&service, &harness.fixture.server_id).await?;
                mark("policy_three_submit");
                let submitted = service
                    .submit(
                        harness.administrator.clone(),
                        1,
                        harness.command(
                            3,
                            before_policy,
                            store::PolicyChange::SetUserActive {
                                id: user,
                                active: false,
                            },
                        ),
                    )
                    .await?;
                mark("policy_three_response");
                let policy = policy_reply(submitted.response.await.map_err(io::Error::other)??);
                mark("policy_three_response_checks");
                assert_eq!(policy.receipt.policy_revision.as_deref(), Some("3"));
                mark("settings_after_policy_three");
                assert_eq!(
                    harness
                        .child
                        .endpoint_settings(&harness.fixture.server_id)
                        .await?
                        .revision,
                    reply.receipt.metadata_revision.unwrap()
                );
                mark("metadata_four_admission");
                wait_peer_idle(&service, &harness.fixture.server_id).await?;
                let mut stale = command;
                stale.command_id = 4;
                mark("metadata_four_submit");
                let submitted = service
                    .submit(harness.administrator.clone(), 1, stale)
                    .await?;
                mark("metadata_four_response");
                let control::DeliveryReply::Endpoint(rejected) =
                    submitted.response.await.map_err(io::Error::other)??
                else {
                    return Err(io::Error::other("expected endpoint rejection"));
                };
                mark("metadata_four_response_checks");
                assert_eq!(
                    rejected.receipt.rejection.as_deref(),
                    Some("endpoint_revision_changed")
                );
                assert_eq!(harness.child.reader().revision()?, 3);
                Ok::<_, io::Error>(())
    })
    .await
    .unwrap_or_else(|_| {
        let (name, entered) = stage.get();
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "metadata delivery fixture deadline: stage={name}, scenario_elapsed_ms={}, stage_elapsed_ms={}, prepare_elapsed_ms={}",
                started.elapsed().as_millis(),
                entered.elapsed().as_millis(),
                prepare_elapsed.as_millis(),
            ),
        ))
    });
    if scenario.is_err() { eprintln!("metadata delivery trace: {}", trace.describe()); }
    owned.finish(scenario).await
    })
        }
    }
    mod maintenance {
        //! Exact retained maintenance identity is checked before any remote observation.

        use super::*;

        #[test]
        fn maintenance_refresh_rejects_wrong_category_and_replaced_slot_before_connecting()
        -> io::Result<()> {
            let harness = Harness::new()?;
            // A held listener makes any accidental outbound TCP connection observable,
            // without a TLS timeout being mistaken for the intended local rejection.
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            listener.set_nonblocking(true)?;
            let origin = format!("https://localhost:{}", listener.local_addr()?.port());
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                timeout(Duration::from_secs(10), async {
            configure_target(&harness, origin).await?;
            let (service, _runner) = Service::new(
                harness.caller.clone(),
                harness.fixture.client_tls.clone(),
                harness.fixture.client_id.clone(),
            );
            let peer = harness.fixture.server_id.clone();
            let command = harness.command(
                1,
                1,
                store::PolicyChange::CreateUser {
                    name: "not maintenance".into(),
                    protocols: vec![crate::access::Protocol::Http],
                    concurrent_limit: 1,
                },
            );
            let actor = harness.administrator.clone();
            let original = harness
                .caller
                .read(move |directory| {
                    targets::observe(directory, &peer, 1, 2, 0, 1)?;
                    targets::enqueue(directory, &actor, 1, command)
                })
                .await?;
            let error = service
                .refresh_maintenance(harness.fixture.server_id.clone(), original.job_id.clone())
                .await
                .err()
                .ok_or_else(|| io::Error::other("user job accepted as maintenance"))?;
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);

            // A trusted high-water observation can retire the old uncertainty;
            // replacing that spent slot must not retarget the original page.
            let peer = harness.fixture.server_id.clone();
            let actor = harness.administrator.clone();
            let old_id = original.job_id.clone();
            let command =
                harness.command(2, 2, store::PolicyChange::SetAdmission { accepting: false });
            let current = harness
                .caller
                .read(move |directory| {
                    targets::observe(directory, &peer, 1, 2, 1, 2)?;
                    targets::supersede(directory, &actor, &peer, &old_id)?;
                    targets::enqueue(directory, &actor, 1, command)
                })
                .await?;
            assert_ne!(current.job_id, original.job_id);
            let error = service
                .refresh_maintenance(harness.fixture.server_id.clone(), original.job_id)
                .await
                .err()
                .ok_or_else(|| io::Error::other("replaced original slot was observed"))?;
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            let peer = harness.fixture.server_id.clone();
            let actor = harness.administrator.clone();
            let old_id = current.job_id.clone();
            let command =
                harness.command(3, 3, store::PolicyChange::SetAdmission { accepting: true });
            let replacement = harness
                .caller
                .read(move |directory| {
                    targets::observe(directory, &peer, 1, 2, 2, 3)?;
                    targets::supersede(directory, &actor, &peer, &old_id)?;
                    targets::enqueue(directory, &actor, 1, command)
                })
                .await?;
            let error = service
                .refresh_maintenance(harness.fixture.server_id.clone(), current.job_id)
                .await
                .err()
                .ok_or_else(|| io::Error::other("replacement maintenance intent was observed"))?;
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            // The existing exact endpoint refresh must not accept this v5 job.
            let error = service
                .refresh_endpoint(
                    harness.fixture.server_id.clone(),
                    replacement.job_id.clone(),
                )
                .await
                .err()
                .ok_or_else(|| io::Error::other("maintenance accepted as endpoint"))?;
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
            );
            assert!(!service.admission.is_active(&harness.fixture.server_id)?);
            assert_eq!(service.network.available_permits(), 4);
            let peer = harness.fixture.server_id.clone();
            let retained = harness
                .caller
                .read(move |directory| targets::job(directory, &peer))
                .await?
                .ok_or_else(|| io::Error::other("current maintenance job disappeared"))?;
            assert_eq!(retained.job_id, replacement.job_id);
            assert!(retained.state == targets::JobState::Pending);
            Ok(())
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "maintenance identity scenario timed out",
            )
        })?
            })
        }

        #[test]
        fn exact_maintenance_refresh_uses_only_the_original_v5_receipt_get() -> io::Result<()> {
            let harness = Harness::new()?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
        let mut owned = OwnedTasks::new();
        let scenario = timeout(Duration::from_secs(10), async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let origin = format!("https://localhost:{}", listener.local_addr()?.port());
            let tls = tokio_rustls::TlsAcceptor::from(harness.fixture.server_tls.clone());
            let node_id = harness.fixture.server_id.clone();
            let stop = CancellationToken::new();
            let shutdown = stop.clone();
            let (observed, observation) = oneshot::channel();
            let task = tokio::spawn(async move {
                tokio::select! {
                    _ = shutdown.cancelled() => Ok(()),
                    result = async {
                        let (stream, _) = listener.accept().await?;
                        let mut stream = tls.accept(stream).await?;
                        let mut request = Vec::new();
                        let mut buffer = [0; 1024];
                        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                            let length = stream.read(&mut buffer).await?;
                            if length == 0 || request.len().saturating_add(length) > 16 * 1024 {
                                return Err(io::Error::other("invalid receipt fixture request"));
                            }
                            request.extend_from_slice(&buffer[..length]);
                        }
                        // A mutation POST, another resource, query or command
                        // sequence cannot receive the fixture's successful reply.
                        if request.split(|byte| *byte == b'\n').next()
                            != Some(b"GET /node/v5/proxy/receipts/2/1 HTTP/1.1\r".as_slice()) {
                            return Err(io::Error::other("refresh did not use the exact receipt GET"));
                        }
                        let bytes = serde_json::to_vec(&serde_json::json!({
                            "version":5,"node_id":node_id,"resource":"proxy_policy",
                            "data":{"controller_epoch":"2","command_id":"1","status":"saved",
                                    "policy_revision":"2","rejection":null,"user_id":null,"credential_id":null}
                        })).map_err(io::Error::other)?;
                        let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len());
                        stream.write_all(headers.as_bytes()).await?;
                        stream.write_all(&bytes).await?;
                        stream.flush().await?;
                        observed.send(()).map_err(|_| io::Error::other("receipt observation cancelled"))?;
                        Ok(())
                    } => result,
                }
            });
            owned.insert("exact maintenance receipt peer", stop, task);
            configure_target(&harness, origin).await?;
            let (service, _runner) = Service::new(
                harness.caller.clone(),
                harness.fixture.client_tls.clone(),
                harness.fixture.client_id.clone(),
            );
            let peer = harness.fixture.server_id.clone();
            let actor = harness.administrator.clone();
            let command = harness.command(1, 1, store::PolicyChange::SetAdmission { accepting: false });
            let original = harness.caller.read(move |directory| {
                targets::observe(directory, &peer, 1, 2, 0, 1)?;
                targets::enqueue(directory, &actor, 1, command)
            }).await?;
            let refreshed = service.refresh_maintenance(
                harness.fixture.server_id.clone(), original.job_id.clone(),
            ).await?;
            observation.await.map_err(io::Error::other)?;
            assert_eq!(refreshed.job_id, original.job_id);
            assert_eq!(refreshed.maintenance, Some(false));
            assert_eq!(refreshed.policy_revision, Some(2));
            assert!(refreshed.state == targets::JobState::Saved);
            assert!(!service.admission.is_active(&harness.fixture.server_id)?);
            assert_eq!(service.network.available_permits(), 4);
            assert_eq!(service.commands.available_permits(), 2);
            Ok(())
        }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "maintenance receipt scenario timed out"))
            .and_then(|result| result);
        owned.finish(scenario).await
    })
        }
    }
    mod peer_admission {
        //! Deterministic peer ordering and one real, non-replayed command delivery.

        use super::super::admission as peer_gate;
        use super::*;

        fn busy_result<T>(result: io::Result<T>) {
            match result {
                Err(error) => assert_eq!(error.kind(), io::ErrorKind::WouldBlock),
                Ok(_) => panic!("peer admission unexpectedly succeeded"),
            }
        }

        #[tokio::test]
        async fn peer_waiters_are_fifo_and_later_observers_cannot_overtake() -> io::Result<()> {
            let admission = peer_gate::Admission::new();
            let peer = "fifo-peer";
            let held = admission.try_claim(peer)?;
            // These reservations model a command, an observer and a second command.
            // Their first polls, rather than task scheduling, fix the arrival order.
            let mut first = Box::pin(admission.acquire_command(peer));
            let mut second = Box::pin(admission.acquire(peer));
            let mut third = Box::pin(admission.acquire_command(peer));
            assert!(futures_util::poll!(&mut first).is_pending());
            assert!(futures_util::poll!(&mut second).is_pending());
            assert!(futures_util::poll!(&mut third).is_pending());
            drop(held);

            // A continuing stream of newly arriving reads cannot take the slot which
            // was assigned to the oldest waiter, even before that waiter is repolled.
            for _ in 0..16 {
                busy_result(admission.try_claim(peer));
                let mut observer = Box::pin(admission.acquire(peer));
                assert!(futures_util::poll!(&mut observer).is_pending());
            }
            assert!(futures_util::poll!(&mut third).is_pending());
            assert!(futures_util::poll!(&mut second).is_pending());
            let Poll::Ready(first_claim) = futures_util::poll!(&mut first) else {
                panic!("the oldest peer waiter must receive the released slot");
            };
            let first_claim = first_claim?;
            drop(first);
            drop(first_claim);
            busy_result(admission.try_claim(peer));
            assert!(futures_util::poll!(&mut third).is_pending());
            let Poll::Ready(second_claim) = futures_util::poll!(&mut second) else {
                panic!("the second peer waiter must keep its FIFO position");
            };
            let second_claim = second_claim?;
            drop(second);
            drop(second_claim);
            busy_result(admission.try_claim(peer));
            let third_claim = third.await?;
            drop(third_claim);
            drop(admission.try_claim(peer)?);
            Ok(())
        }

        #[tokio::test]
        async fn cancelling_a_middle_submission_reclaims_only_its_peer_queue_position()
        -> io::Result<()> {
            let harness = Harness::new()?;
            let (service, mut runner) = Service::new(
                harness.caller.clone(),
                harness.fixture.client_tls.clone(),
                harness.fixture.client_id.clone(),
            );
            let peer = &harness.fixture.server_id;
            let held = service.claim(peer)?;
            let mut earlier = Vec::new();
            for _ in 0..3 {
                let mut waiter = Box::pin(service.admission.acquire(peer));
                assert!(futures_util::poll!(&mut waiter).is_pending());
                earlier.push(waiter);
            }
            let mut cancelled = Box::pin(service.submit(
                harness.administrator.clone(),
                1,
                harness.command(
                    1,
                    1,
                    store::PolicyChange::CreateUser {
                        name: "Cancelled peer waiter".into(),
                        protocols: vec![crate::access::Protocol::Http],
                        concurrent_limit: 1,
                    },
                ),
            ));
            assert!(futures_util::poll!(&mut cancelled).is_pending());
            let mut later = Vec::new();
            for _ in 4..peer_gate::MAX_PEER_WAITERS {
                let mut waiter = Box::pin(service.admission.acquire(peer));
                assert!(futures_util::poll!(&mut waiter).is_pending());
                later.push(waiter);
            }
            let mut overflow = Box::pin(service.admission.acquire(peer));
            let Poll::Ready(result) = futures_util::poll!(&mut overflow) else {
                panic!("a full peer queue must reject without waiting");
            };
            busy_result(result);
            drop(overflow);
            assert_eq!(service.network.available_permits(), 4);
            assert_eq!(service.commands.available_permits(), 2);
            drop(service.claim(&harness.fixture.client_id)?);

            // Cancellation occurs before Work is sent. It must not leave a command
            // permit, durable intent or a hole which lets its replacement overtake.
            drop(cancelled);
            assert!(matches!(
                runner.receiver.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            // Seven observers still occupy their complete share. The cancelled
            // command's reserved position is available only to another command.
            let mut observer = Box::pin(service.admission.acquire(peer));
            let Poll::Ready(result) = futures_util::poll!(&mut observer) else {
                panic!("observers must not consume the reserved command position");
            };
            busy_result(result);
            drop(observer);
            let mut replacement = Box::pin(service.admission.acquire_command(peer));
            assert!(futures_util::poll!(&mut replacement).is_pending());
            drop(held);
            for mut waiter in earlier.into_iter().chain(later) {
                assert!(futures_util::poll!(&mut replacement).is_pending());
                let Poll::Ready(claim) = futures_util::poll!(&mut waiter) else {
                    panic!("cancellation must preserve surviving peer waiter order");
                };
                drop(claim?);
            }
            drop(replacement.await?);
            drop(service.claim(peer)?);
            assert!(matches!(
                runner.receiver.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            let destination = peer.clone();
            assert!(
                harness
                    .caller
                    .read(move |directory| targets::job(directory, &destination))
                    .await?
                    .is_none()
            );
            assert_eq!(service.network.available_permits(), 4);
            assert_eq!(service.commands.available_permits(), 2);
            Ok(())
        }

        #[tokio::test]
        async fn full_global_peer_queue_does_not_block_an_idle_peer_and_timeout_reclaims_budget()
        -> io::Result<()> {
            let admission = peer_gate::Admission::new();
            // Labels are internal admission identities only: no target lookup, TLS or
            // request is performed for these peers.
            let peers = (0..5)
                .map(|index| format!("full-peer-{index}"))
                .collect::<Vec<_>>();
            let mut held = Vec::new();
            let mut waiters = Vec::new();
            for (peer, observer_count) in peers.iter().zip([7, 7, 7, 7, 2]) {
                held.push(admission.try_claim(peer)?);
                for _ in 0..observer_count {
                    let mut waiter = Box::pin(admission.acquire(peer));
                    assert!(futures_util::poll!(&mut waiter).is_pending());
                    waiters.push(waiter);
                }
            }
            assert_eq!(waiters.len(), peer_gate::MAX_WAITERS - 2);
            // This peer has only two local observers. Rejection therefore proves the
            // global observation limit, not the per-peer or total waiting bound.
            let mut observer_overflow = Box::pin(admission.acquire(&peers[4]));
            let Poll::Ready(result) = futures_util::poll!(&mut observer_overflow) else {
                panic!("observers must not consume the global command reservations");
            };
            busy_result(result);
            drop(observer_overflow);
            // Thirty readers exhaust their global share, but commands may still join
            // the same FIFO in each of two peers' final waiting positions.
            let mut command_waiters = Vec::new();
            for peer in peers.iter().take(2) {
                let mut waiter = Box::pin(admission.acquire_command(peer));
                assert!(futures_util::poll!(&mut waiter).is_pending());
                command_waiters.push(waiter);
            }
            assert_eq!(
                waiters.len() + command_waiters.len(),
                peer_gate::MAX_WAITERS
            );
            let other = "contended-extra-peer";
            held.push(admission.try_claim(other)?);
            let mut overflow = Box::pin(admission.acquire_command(other));
            let Poll::Ready(result) = futures_util::poll!(&mut overflow) else {
                panic!("a full global peer queue must reject without waiting");
            };
            busy_result(result);
            drop(overflow);
            // An uncontended peer does not require a waiting reservation. Hot peers
            // cannot turn the pending budget into a global network/command lock.
            drop(admission.acquire("idle-peer").await?);

            let expired = waiters.remove(0);
            let result = timeout(Duration::from_secs(10), expired)
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "peer waiter did not expire")
                })?;
            busy_result(result);
            // Other waiters have not been repolled. Exactly the expired reader returns
            // both a total position and an observer position for this contended peer.
            let mut replacement = Box::pin(admission.acquire(other));
            assert!(futures_util::poll!(&mut replacement).is_pending());
            drop(replacement);
            drop(waiters);
            drop(command_waiters);
            drop(held);
            for peer in &peers {
                drop(admission.try_claim(peer)?);
            }
            drop(admission.try_claim(other)?);
            Ok(())
        }

        #[test]
        fn a_submission_waiting_for_its_peer_delivers_the_original_command_once() -> io::Result<()>
        {
            let harness = Harness::new()?;
            // Drop joins blocking work before the earlier-created private fixture.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let result = runtime.block_on(async {
                let mut owned = OwnedTasks::new();
                let scenario = async {
                    let stop = CancellationToken::new();
                    let (address, node) = start_node(
                        &harness.fixture,
                        &harness.child,
                        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                        stop.clone(),
                    )
                    .await?;
                    owned.insert("peer admission child", stop, node);
                    configure_target(&harness, format!("https://localhost:{}", address.port()))
                        .await?;
                    let (service, mut runner) = Service::new(
                        harness.caller.clone(),
                        harness.fixture.client_tls.clone(),
                        harness.fixture.client_id.clone(),
                    );
                    assert!(matches!(
                        service
                            .remote(harness.fixture.server_id.clone(), Request::Policy)
                            .await?,
                        Reply::Policy(_)
                    ));
                    let held = service.claim(&harness.fixture.server_id)?;
                    let mut submission = Box::pin(service.submit(
                        harness.administrator.clone(),
                        1,
                        harness.command(
                            1,
                            1,
                            store::PolicyChange::CreateUser {
                                name: "FIFO delivered user".into(),
                                protocols: vec![crate::access::Protocol::Http],
                                concurrent_limit: 1,
                            },
                        ),
                    ));
                    assert!(futures_util::poll!(&mut submission).is_pending());
                    assert!(matches!(
                        runner.receiver.try_recv(),
                        Err(mpsc::error::TryRecvError::Empty)
                    ));
                    assert_eq!(service.commands.available_permits(), 2);
                    assert_eq!(service.network.available_permits(), 4);
                    drop(held);
                    assert!(futures_util::poll!(&mut submission).is_pending());
                    let work = runner.receiver.recv().await.ok_or_else(unavailable)?;
                    let first_service = service.clone();
                    // First-only supervision isolates the exact arrival interleaving
                    // from Runner's independent retry scanner. No write is resubmitted.
                    let first = tokio::spawn(async move {
                        first_service.first(work).await;
                        Ok(())
                    });
                    let first = owned.insert(
                        "peer admission first delivery",
                        CancellationToken::new(),
                        first,
                    );
                    let submitted = submission.await?;
                    assert_eq!(submitted.job.command_id, 1);
                    let job_id = submitted.job.job_id;
                    let reply = policy_reply(submitted.response.await.map_err(io::Error::other)??);
                    assert!(reply.user.is_some());
                    assert!(matches!(
                        reply.receipt.status,
                        control::ReceiptStatus::Saved
                    ));
                    owned.stop_and_join(first).await?;
                    let destination = harness.fixture.server_id.clone();
                    let job = harness
                        .caller
                        .read(move |directory| targets::job(directory, &destination))
                        .await?
                        .ok_or_else(unavailable)?;
                    assert_eq!(job.job_id, job_id);
                    assert_eq!(job.command_id, 1);
                    assert_eq!(job.attempts, 0);
                    assert!(matches!(job.state, targets::JobState::Saved));
                    let Reply::Policy(policy) = service
                        .remote(harness.fixture.server_id.clone(), Request::Policy)
                        .await?
                    else {
                        return Err(invalid());
                    };
                    assert_eq!(policy.last_terminal_command, "1");
                    assert_eq!(policy.saved_revision, "2");
                    assert_eq!(policy.user_count, 1);
                    assert!(matches!(
                        runner.receiver.try_recv(),
                        Err(mpsc::error::TryRecvError::Empty)
                    ));
                    assert_eq!(service.commands.available_permits(), 2);
                    assert_eq!(service.network.available_permits(), 4);
                    Ok(())
                };
                let scenario = timeout(Duration::from_secs(10), scenario)
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "peer delivery test timed out")
                    })
                    .and_then(|result| result);
                owned.finish(scenario).await
            });
            drop(runtime);
            result
        }
    }
    mod routing {
        //! A real TLS target switches between the fixed vocabularies in one global
        //! command namespace. Browser cancellation must not repeat an IP allocation.

        use super::*;
        use crate::access::routing::RoutePermission;

        /// This sequential current-thread fixture waits before its first attempt, never
        /// retries a submitted command. The next call must immediately poll claim in
        /// the same task poll; this is not a reservation on a multi-thread runtime.
        /// Bound only this idle wait, leaving response and network budgets unchanged.
        async fn wait_admission(
            service: &Service,
            peer: &str,
            stage: &'static str,
        ) -> io::Result<()> {
            timeout(Duration::from_secs(8), wait_peer_idle(service, peer))
                .await
                .map_err(|_| {
                    at_stage(
                        stage,
                        io::Error::new(io::ErrorKind::TimedOut, "routing peer admission timed out"),
                    )
                })?
                .map_err(|error| at_stage(stage, error))
        }

        async fn deliver(
            service: &Arc<Service>,
            harness: &Harness,
            id: u64,
            revision: u64,
            change: store::PolicyChange,
        ) -> io::Result<control::CommandReply> {
            wait_admission(
                service,
                &harness.fixture.server_id,
                "routing command peer admission",
            )
            .await?;
            let submitted = service
                .submit(
                    harness.administrator.clone(),
                    1,
                    harness.command(id, revision, change),
                )
                .await
                .map_err(|error| at_stage("routing command submission", error))?;
            let reply = timeout(Duration::from_secs(8), submitted.response)
                .await
                .map_err(|error| {
                    at_stage("routing first response deadline", io::Error::other(error))
                })?
                .map_err(|error| {
                    at_stage("routing first response channel", io::Error::other(error))
                })?
                .map_err(|error| at_stage("routing command delivery", error))?;
            Ok(policy_reply(reply))
        }

        #[tokio::test(flavor = "current_thread")]
        async fn versioned_routing_delivery_recovers_ids_after_source_restart_without_reexecution()
        -> io::Result<()> {
            let harness = Harness::new()?;
            let child_shutdown = CancellationToken::new();
            let (address, node) = start_node(
                &harness.fixture,
                &harness.child,
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                child_shutdown.clone(),
            )
            .await?;
            let source_shutdown = CancellationToken::new();
            let (service, runner) = Service::new(
                harness.caller.clone(),
                harness.fixture.client_tls.clone(),
                harness.fixture.client_id.clone(),
            );
            let mut source = Some(tokio::spawn(runner.run(source_shutdown.clone())));
            let work = async {
                configure_target(&harness, format!("https://localhost:{}", address.port())).await?;
                wait_admission(
                    &service,
                    &harness.fixture.server_id,
                    "initial policy peer admission",
                )
                .await?;
                assert!(matches!(
                    service
                        .remote(harness.fixture.server_id.clone(), Request::Policy)
                        .await
                        .map_err(|error| at_stage("initial policy read", error))?,
                    Reply::Policy(_)
                ));
                let user = deliver(
                    &service,
                    &harness,
                    1,
                    1,
                    store::PolicyChange::CreateUser {
                        name: "Routing principal".into(),
                        protocols: vec![crate::access::Protocol::Http],
                        concurrent_limit: 2,
                    },
                )
                .await?
                .user
                .unwrap()
                .id;
                let prefix = deliver(
                    &service,
                    &harness,
                    2,
                    2,
                    store::PolicyChange::CreatePrefix {
                        name: "Loopback inventory".into(),
                        cidr: "127.0.0.0/8".parse().unwrap(),
                    },
                )
                .await?;
                assert!(
                    prefix.user.is_none() && prefix.credential.is_none() && prefix.secret.is_none()
                );
                let prefix_id = prefix.receipt.routing.as_ref().unwrap().id.clone();
                assert!(matches!(
                    prefix.routing,
                    Some(crate::manage::views::Entity::Prefix(_))
                ));
                let address = deliver(
                    &service,
                    &harness,
                    3,
                    3,
                    store::PolicyChange::CreateAddress {
                        name: "Concrete source".into(),
                        ip: "127.0.0.2".parse().unwrap(),
                        prefix_id: Some(prefix_id.clone()),
                    },
                )
                .await?;
                let address_id = address.receipt.routing.unwrap().id;
                let pool = deliver(
                    &service,
                    &harness,
                    4,
                    4,
                    store::PolicyChange::CreatePool {
                        name: "Shared v4 pool".into(),
                        family: crate::access::routing::AddressFamily::V4,
                    },
                )
                .await?;
                let pool_id = pool.receipt.routing.unwrap().id;
                deliver(
                    &service,
                    &harness,
                    5,
                    5,
                    store::PolicyChange::AddPoolMember {
                        pool_id: pool_id.clone(),
                        address_id: address_id.clone(),
                    },
                )
                .await?;
                let permission = deliver(
                    &service,
                    &harness,
                    6,
                    6,
                    store::PolicyChange::SetRoutePermission {
                        permission: RoutePermission {
                            user_id: user.clone(),
                            legacy_allowed: false,
                            exits: vec![],
                            pools: vec![pool_id.clone()],
                        },
                    },
                )
                .await?;
                assert!(permission.receipt.user_id.is_none());
                assert_eq!(permission.receipt.routing.unwrap().id, user);
                assert!(matches!(
                    permission.routing,
                    Some(crate::manage::views::Entity::Permission(_))
                ));

                let peer = harness.fixture.server_id.clone();
                wait_admission(&service, &peer, "prefix page peer admission").await?;
                let Reply::PrefixesPage(page) = service
                    .remote(
                        peer.clone(),
                        Request::PrefixesPage {
                            after: None,
                            limit: 1,
                        },
                    )
                    .await
                    .map_err(|error| at_stage("prefix page read", error))?
                else {
                    return Err(invalid());
                };
                assert_eq!(page.revision, "7");
                assert_eq!(page.items.len(), 1);
                assert_eq!(page.items[0].id, prefix_id);
                wait_admission(&service, &peer, "pool members peer admission").await?;
                let Reply::PoolMembersPage(page) = service
                    .remote(
                        peer.clone(),
                        Request::PoolMembersPage {
                            pool_id: pool_id.clone(),
                            after: None,
                            limit: 50,
                        },
                    )
                    .await
                    .map_err(|error| at_stage("pool members read", error))?
                else {
                    return Err(invalid());
                };
                assert_eq!(page.items, [address_id]);
                wait_admission(&service, &peer, "user routing peer admission").await?;
                let Reply::UserRouting(view) = service
                    .remote(
                        peer.clone(),
                        Request::UserRouting {
                            user_id: user.clone(),
                        },
                    )
                    .await
                    .map_err(|error| at_stage("user routing read", error))?
                else {
                    return Err(invalid());
                };
                assert!(!view.permission.legacy_allowed);
                assert_eq!(
                    view.permission.pools.as_slice(),
                    std::slice::from_ref(&pool_id)
                );

                wait_admission(&service, &peer, "lost response submission peer admission").await?;
                let lost = service
                    .submit(
                        harness.administrator.clone(),
                        1,
                        harness.command(
                            7,
                            7,
                            store::PolicyChange::CreateAddress {
                                name: "Lost first response".into(),
                                ip: "127.0.0.3".parse().unwrap(),
                                prefix_id: None,
                            },
                        ),
                    )
                    .await
                    .map_err(|error| at_stage("lost response submission", error))?;
                drop(lost.response);
                let completed = wait_job(
                    &harness.fixture.client_state,
                    &peer,
                    targets::JobState::Saved,
                    7,
                )
                .await
                .map_err(|error| at_stage("lost response saved job observation", error))?;
                let recovered_id = completed.routing.as_ref().unwrap().id.clone();
                // Stop the supervised source without stopping the independent target.
                // A new service must derive receipt version from the original intent.
                source_shutdown.cancel();
                source.take().unwrap().await.map_err(io::Error::other)??;
                let (resumed, runner) = Service::new(
                    harness.caller.clone(),
                    harness.fixture.client_tls.clone(),
                    harness.fixture.client_id.clone(),
                );
                let resumed_shutdown = CancellationToken::new();
                let resumed_task = tokio::spawn(runner.run(resumed_shutdown.clone()));
                let resumed_work = async {
                    wait_admission(&resumed, &peer, "receipt after restart peer admission").await?;
                    let job = resumed
                        .refresh(peer.clone())
                        .await
                        .map_err(|error| at_stage("receipt after restart", error))?;
                    assert_eq!(job.job_id, completed.job_id);
                    assert_eq!(job.routing.as_ref().unwrap().id, recovered_id);
                    wait_admission(&resumed, &peer, "addresses after restart peer admission")
                        .await?;
                    let Reply::AddressesPage(page) = resumed
                        .remote(
                            peer.clone(),
                            Request::AddressesPage {
                                after: None,
                                limit: 50,
                            },
                        )
                        .await
                        .map_err(|error| at_stage("addresses after restart read", error))?
                    else {
                        return Err(invalid());
                    };
                    assert_eq!(page.items.len(), 2);
                    assert_eq!(
                        page.items
                            .iter()
                            .filter(|value| value.id == recovered_id)
                            .count(),
                        1
                    );
                    assert_eq!(page.revision, "8");

                    // Returning to v1 after v2 uses the same CAS/sequence, not a
                    // parallel command counter. Only the target creates this secret.
                    let credential = deliver(
                        &resumed,
                        &harness,
                        8,
                        8,
                        store::PolicyChange::CreateCredential {
                            user_id: user.clone(),
                        },
                    )
                    .await?;
                    assert!(credential.routing.is_none() && credential.receipt.routing.is_none());
                    source_database_has_no_secret(
                        &harness.fixture.client_state,
                        credential.secret.as_deref().unwrap(),
                    )
                    .await?;
                    let rejected = deliver(
                        &resumed,
                        &harness,
                        9,
                        9,
                        store::PolicyChange::CreateAddress {
                            name: "Duplicate IP".into(),
                            ip: "127.0.0.3".parse().unwrap(),
                            prefix_id: None,
                        },
                    )
                    .await?;
                    assert!(rejected.receipt.status == control::ReceiptStatus::Rejected);
                    assert!(rejected.routing.is_none() && rejected.receipt.routing.is_none());
                    assert!(rejected.user.is_none() && rejected.secret.is_none());
                    wait_admission(&resumed, &peer, "rejected receipt peer admission").await?;
                    let job = resumed
                        .refresh(peer.clone())
                        .await
                        .map_err(|error| at_stage("rejected receipt", error))?;
                    assert!(job.state == targets::JobState::Rejected);
                    assert!(job.routing.is_none());
                    let preset = deliver(
                        &resumed,
                        &harness,
                        10,
                        9,
                        store::PolicyChange::SetUserPresets {
                            presets: crate::access::presets::UserPreset {
                                user_id: user.clone(),
                                default_preset: Some(crate::ebpf::Profile::Linux),
                                allowed_presets: vec![crate::ebpf::Profile::Linux],
                            },
                        },
                    )
                    .await?;
                    assert!(
                        preset.user.is_none()
                            && preset.routing.is_none()
                            && preset.secret.is_none()
                    );
                    assert_eq!(preset.receipt.preset.as_ref().unwrap().id, user);
                    assert!(matches!(
                        preset.presets,
                        Some(crate::access::presets::PresetEntity::User(_))
                    ));
                    deliver(
                        &resumed,
                        &harness,
                        11,
                        10,
                        store::PolicyChange::SetPoolPreset {
                            preset: crate::access::presets::PoolPreset {
                                pool_id: pool_id.clone(),
                                default_preset: Some(crate::ebpf::Profile::Windows),
                            },
                        },
                    )
                    .await?;
                    wait_admission(&resumed, &peer, "preset receipt peer admission").await?;
                    let restored = resumed
                        .refresh(peer.clone())
                        .await
                        .map_err(|error| at_stage("preset receipt", error))?;
                    assert_eq!(restored.preset.as_ref().unwrap().id, pool_id);
                    assert_eq!(restored.policy_revision, Some(11));
                    wait_admission(&resumed, &peer, "user presets peer admission").await?;
                    let Reply::UserPresets(actual) = resumed
                        .remote(
                            peer.clone(),
                            Request::UserPresets {
                                user_id: user.clone(),
                            },
                        )
                        .await
                        .map_err(|error| at_stage("user presets read", error))?
                    else {
                        return Err(invalid());
                    };
                    assert_eq!(actual.revision, "11");
                    assert_eq!(
                        actual.presets.allowed_presets,
                        [crate::ebpf::Profile::Linux]
                    );
                    // The same durable sequence returns to v1 after v3. No new
                    // namespace or downgrade of preset commands is introduced.
                    let ordinary = deliver(
                        &resumed,
                        &harness,
                        12,
                        11,
                        store::PolicyChange::SetUserActive {
                            id: user,
                            active: false,
                        },
                    )
                    .await?;
                    assert!(ordinary.receipt.preset.is_none() && ordinary.presets.is_none());
                    assert_eq!(
                        store::policy_status(&harness.fixture.server_state)?.revision,
                        12
                    );
                    Ok(())
                }
                .await;
                resumed_shutdown.cancel();
                resumed_task.await.map_err(io::Error::other)??;
                resumed_work
            }
            .await;
            source_shutdown.cancel();
            if let Some(source) = source {
                source.await.map_err(io::Error::other)??;
            }
            child_shutdown.cancel();
            node.await.map_err(io::Error::other)??;
            work
        }
    }
    mod runtime {
        //! Runtime requests use their own exact identity, never the durable command
        //! slot. The real forwarding result below is consumed before claiming drained.

        use super::*;
        use crate::manage::drain;
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        fn id(value: u8) -> String {
            URL_SAFE_NO_PAD.encode([value; 16])
        }

        /// Consume one bounded fixture request, including its complete JSON body.
        /// Returning only the request line keeps authentication headers out of asserts.
        pub(super) async fn read_request(
            stream: &mut (impl tokio::io::AsyncRead + Unpin),
        ) -> io::Result<(String, Vec<u8>)> {
            let mut bytes = Vec::new();
            let mut buffer = [0; 1024];
            let end = loop {
                if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    break index + 4;
                }
                let read = stream.read(&mut buffer).await?;
                if read == 0 || bytes.len().saturating_add(read) > 16 * 1024 {
                    return Err(invalid());
                }
                bytes.extend_from_slice(&buffer[..read]);
            };
            let head = std::str::from_utf8(&bytes[..end]).map_err(|_| invalid())?;
            let line = head.lines().next().ok_or_else(invalid)?.to_owned();
            let length = head
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map_or(Ok(0), |(_, value)| {
                    value.trim().parse::<usize>().map_err(|_| invalid())
                })?;
            if length > 16 * 1024 {
                return Err(invalid());
            }
            while bytes.len() - end < length {
                let read = stream.read(&mut buffer).await?;
                if read == 0 || bytes.len().saturating_add(read) > 32 * 1024 {
                    return Err(invalid());
                }
                bytes.extend_from_slice(&buffer[..read]);
            }
            Ok((line, bytes[end..end + length].to_vec()))
        }

        #[test]
        fn runtime_drain_uses_one_explicit_request_and_preserves_node_control() -> io::Result<()> {
            let harness = Harness::new()?;
            let config = harness.fixture.write(
                "controller-runtime-proxy.json",
                br#"{"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"}],"workers":1}"#,
            )?;
            let prepared = proxy::tests::ephemeral(proxy::load(&config)?);
            let executor = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let mut running = None;
            let result = executor.block_on(async {
                running = Some(proxy::start(
                    prepared,
                    harness.child.reader(),
                    harness.child_author.clone(),
                )?);
                let forwarding = running.as_mut().unwrap();
                forwarding.ready().await?;
                let lifecycle = forwarding.lifecycle();
                harness.child.configure_runtime(lifecycle.clone())?;
                harness.child.activate().await?;
                let mut owned = OwnedTasks::new();
                let scenario = timeout(Duration::from_secs(30), async {
                    let stop = CancellationToken::new();
                    let (address, node) = start_node(
                        &harness.fixture,
                        &harness.child,
                        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                        stop.clone(),
                    )
                    .await?;
                    owned.insert("runtime controller child", stop, node);
                    configure_target(&harness, format!("https://localhost:{}", address.port()))
                        .await?;
                    let (service, mut runner) = Service::new(
                        harness.caller.clone(),
                        harness.fixture.client_tls.clone(),
                        harness.fixture.client_id.clone(),
                    );
                    let peer = harness.fixture.server_id.clone();
                    let Reply::Runtime(initial) =
                        service.remote(peer.clone(), Request::Runtime).await?
                    else {
                        return Err(invalid());
                    };
                    assert!(matches!(
                        initial.runtime.as_ref().unwrap().phase,
                        drain::Phase::Serving
                    ));
                    // Deliver only this one durable pause. No retry scanner can create
                    // extra observations or claim the peer during the runtime checks.
                    let task = owned.insert(
                        "runtime pause delivery",
                        CancellationToken::new(),
                        tokio::spawn(async move {
                            let work = runner.receiver.recv().await.ok_or_else(unavailable)?;
                            runner.service.first(work).await;
                            Ok(())
                        }),
                    );
                    let submitted = service
                        .submit(
                            harness.administrator.clone(),
                            1,
                            harness.command(
                                1,
                                1,
                                store::PolicyChange::SetAdmission { accepting: false },
                            ),
                        )
                        .await?;
                    let pause_job_id = submitted.job.job_id;
                    let _ = policy_reply(submitted.response.await.map_err(io::Error::other)??);
                    owned.stop_and_join(task).await?;
                    assert!(!harness.child.reader().admission()?.accepting);
                    let Reply::Runtime(paused) =
                        service.remote(peer.clone(), Request::Runtime).await?
                    else {
                        return Err(invalid());
                    };
                    let request = drain::Request {
                        expected_node_id: peer.clone(),
                        expected_epoch: "2".into(),
                        expected_revision: "2".into(),
                        runtime_id: paused.runtime.as_ref().unwrap().runtime_id.clone(),
                        request_id: id(3),
                    };
                    let forbidden = service
                        .remote(
                            peer.clone(),
                            Request::RuntimeDrain(control::RuntimeDrain {
                                version: 6,
                                resource: "proxy_runtime".into(),
                                source_administrator_id: harness.administrator.clone(),
                                request: request.clone(),
                            }),
                        )
                        .await
                        .err()
                        .unwrap();
                    assert_eq!(forbidden.kind(), io::ErrorKind::PermissionDenied);
                    assert!(!forwarding.handle().is_graceful_shutdown_requested());
                    let accepted = service
                        .drain_runtime(
                            harness.administrator.clone(),
                            peer.clone(),
                            1,
                            request.clone(),
                        )
                        .await?;
                    assert_eq!(
                        accepted.runtime.as_ref().unwrap().request.as_ref(),
                        Some(&request)
                    );
                    assert!(forwarding.handle().is_quiescing());
                    let completion = forwarding.finished().await;
                    assert!(lifecycle.complete(&completion)?);
                    completion?;
                    let exact = || Request::RuntimeDrainStatus {
                        runtime_id: request.runtime_id.clone(),
                        request_id: request.request_id.clone(),
                    };
                    let Reply::Runtime(finished) = service.remote(peer.clone(), exact()).await?
                    else {
                        return Err(invalid());
                    };
                    assert!(matches!(
                        finished.runtime.as_ref().unwrap().phase,
                        drain::Phase::Drained
                    ));
                    assert_eq!(
                        finished.runtime.as_ref().unwrap().request.as_ref(),
                        Some(&request)
                    );
                    assert_eq!(finished.saved_revision, "2");
                    assert_eq!(finished.ownership.last_terminal_command, "1");
                    assert!(matches!(
                        service.remote(peer.clone(), Request::Policy).await?,
                        Reply::Policy(_)
                    ));
                    let target_peer = peer.clone();
                    let job = harness
                        .caller
                        .read(move |directory| targets::job(directory, &target_peer))
                        .await?
                        .unwrap();
                    assert_eq!(job.job_id, pause_job_id);
                    assert_eq!(job.command_id, 1);
                    let other = drain::Request {
                        request_id: id(4),
                        ..request.clone()
                    };
                    let error = service
                        .drain_runtime(harness.administrator.clone(), peer.clone(), 1, other)
                        .await
                        .err()
                        .unwrap();
                    let remote = error
                        .get_ref()
                        .and_then(|error| error.downcast_ref::<control::RemoteError>())
                        .unwrap();
                    assert_eq!(
                        (remote.status, remote.code),
                        (409, "proxy_already_draining")
                    );

                    // A changed local target CAS is rejected before contacting a child;
                    // it cannot relabel the original request or allocate a new identity.
                    let (actor, target_peer) = (harness.administrator.clone(), peer.clone());
                    harness
                        .caller
                        .read(move |directory| {
                            targets::set_state(directory, &actor, &target_peer, 1, false, false)
                        })
                        .await?;
                    let error = service
                        .drain_runtime(
                            harness.administrator.clone(),
                            peer.clone(),
                            1,
                            request.clone(),
                        )
                        .await
                        .err()
                        .unwrap();
                    assert!(
                        !error
                            .get_ref()
                            .is_some_and(|error| error.is::<RuntimeOutcomeUnknown>())
                    );
                    assert_eq!(
                        lifecycle.snapshot()?.intent.unwrap().request_id,
                        request.request_id
                    );
                    let (actor, target_peer) = (harness.administrator.clone(), peer.clone());
                    harness
                        .caller
                        .read(move |directory| {
                            targets::set_state(directory, &actor, &target_peer, 2, true, false)
                        })
                        .await?;
                    harness
                        .child
                        .set_owner(administrator(&harness.fixture.server_state)?, 2, None)
                        .await?;
                    assert_eq!(
                        service
                            .remote(peer.clone(), exact())
                            .await
                            .err()
                            .unwrap()
                            .kind(),
                        io::ErrorKind::PermissionDenied
                    );
                    assert!(!service.admission.is_active(&peer)?);
                    assert_eq!(service.network.available_permits(), 4);
                    Ok(())
                })
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "controller runtime scenario timed out",
                    )
                })
                .and_then(|result| result);
                owned.finish(scenario).await
            });
            // A listener result is not worker-runtime destruction. Finish the retained
            // real runtime outside the control executor, even when the scenario fails.
            let cleanup = running.map(|running| running.finish());
            executor.shutdown_timeout(Duration::from_secs(5));
            let cleanup = cleanup.map_or(Ok(()), |cleanup| {
                assert!(cleanup.runtime_stopped);
                cleanup.result
            });
            result.and(cleanup)
        }

        #[test]
        fn changed_target_after_the_single_post_keeps_the_original_outcome_unknown()
        -> io::Result<()> {
            let harness = Harness::new()?;
            let executor = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            executor.block_on(async {
        let mut owned = OwnedTasks::new();
        let scenario = timeout(Duration::from_secs(15), async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let origin = format!("https://localhost:{}", listener.local_addr()?.port());
            let tls = tokio_rustls::TlsAcceptor::from(harness.fixture.server_tls.clone());
            configure_target(&harness, origin).await?;
            let request = drain::Request { expected_node_id: harness.fixture.server_id.clone(), expected_epoch: "2".into(),
                expected_revision: "2".into(), runtime_id: id(3), request_id: id(4) };
            let expected = request.clone();
            let (actor, peer, owner) = (harness.administrator.clone(), harness.fixture.server_id.clone(), harness.fixture.client_id.clone());
            let caller = harness.caller.clone();
            let stop = CancellationToken::new();
            let shutdown = stop.clone();
            let (sent, observed) = oneshot::channel();
            let server = tokio::spawn(async move {
                tokio::select! {
                    _ = shutdown.cancelled() => Ok(()),
                    result = async {
                        let (stream, _) = listener.accept().await?;
                        let mut stream = tls.accept(stream).await?;
                        let (line, bytes) = read_request(&mut stream).await?;
                        assert_eq!(line, "POST /node/v6/proxy/runtime/drain HTTP/1.1");
                        let command: control::RuntimeDrain = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                        assert_eq!(command.request, expected);
                        assert_eq!(command.source_administrator_id, actor);
                        let body = serde_json::to_vec(&serde_json::json!({
                            "version":6,"node_id":peer,"resource":"proxy_runtime","data":{
                                "node_id":peer,"ownership":{"controller_node_id":owner,"epoch":"2","last_terminal_command":"1"},
                                "saved_revision":"2","saved_accepting":false,"runtime":{
                                    "runtime_id":expected.runtime_id,"phase":"draining","request":expected,"active_operations":"0"
                                }
                            }
                        })).map_err(io::Error::other)?;
                        let headers = format!("HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                        stream.write_all(headers.as_bytes()).await?;
                        stream.write_all(&body[..body.len() - 1]).await?;
                        stream.flush().await?;
                        // The authenticated POST has reached the peer and its
                        // complete response is withheld until local CAS changes.
                        caller.read(move |directory| targets::set_state(directory, &actor, &peer, 1, false, false)).await?;
                        stream.write_all(&body[body.len() - 1..]).await?;
                        stream.flush().await?;
                        sent.send(()).map_err(|_| unavailable())?;
                        Ok(())
                    } => result,
                }
            });
            let task = owned.insert("post-response target change peer", stop, server);
            let (service, _runner) = Service::new(harness.caller.clone(), harness.fixture.client_tls.clone(), harness.fixture.client_id.clone());
            let error = service.drain_runtime(harness.administrator.clone(), harness.fixture.server_id.clone(), 1, request).await.err().unwrap();
            assert!(error.get_ref().is_some_and(|error| error.is::<RuntimeOutcomeUnknown>()));
            assert_eq!(error.to_string(), "remote runtime drain outcome is unknown");
            observed.await.map_err(io::Error::other)?;
            owned.stop_and_join(task).await?;
            assert!(!service.admission.is_active(&harness.fixture.server_id)?);
            assert_eq!(service.network.available_permits(), 4);
            assert!(targets::job(&harness.fixture.client_state, &harness.fixture.server_id)?.is_none());
            Ok(())
        }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "runtime target fencing scenario timed out"))
            .and_then(|result| result);
        owned.finish(scenario).await
    })
        }

        #[test]
        fn cancelling_the_browser_wait_keeps_the_single_worker_claim_until_exact_recovery()
        -> io::Result<()> {
            let harness = Harness::new()?;
            let executor = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            executor.block_on(async {
        let mut owned = OwnedTasks::new();
        let scenario = timeout(Duration::from_secs(15), async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            configure_target(&harness, format!("https://localhost:{}", listener.local_addr()?.port())).await?;
            let tls = tokio_rustls::TlsAcceptor::from(harness.fixture.server_tls.clone());
            let request = drain::Request { expected_node_id: harness.fixture.server_id.clone(), expected_epoch: "2".into(),
                expected_revision: "2".into(), runtime_id: id(3), request_id: id(4) };
            let expected = request.clone();
            let (peer, owner) = (harness.fixture.server_id.clone(), harness.fixture.client_id.clone());
            let (observed, observation) = oneshot::channel();
            let (release, released) = oneshot::channel();
            let stop = CancellationToken::new();
            let shutdown = stop.clone();
            let server = tokio::spawn(async move {
                tokio::select! {
                    _ = shutdown.cancelled() => Ok(()),
                    result = async {
                        let body = serde_json::to_vec(&serde_json::json!({
                            "version":6,"node_id":peer,"resource":"proxy_runtime","data":{
                                "node_id":peer,"ownership":{"controller_node_id":owner,"epoch":"2","last_terminal_command":"1"},
                                "saved_revision":"2","saved_accepting":false,"runtime":{
                                    "runtime_id":expected.runtime_id,"phase":"draining","request":expected,"active_operations":"0"
                                }
                            }
                        })).map_err(io::Error::other)?;
                        let (stream, _) = listener.accept().await?;
                        let mut stream = tls.accept(stream).await?;
                        let (line, bytes) = read_request(&mut stream).await?;
                        assert_eq!(line, "POST /node/v6/proxy/runtime/drain HTTP/1.1");
                        let command: control::RuntimeDrain = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                        assert_eq!(command.request, expected);
                        observed.send(()).map_err(|_| unavailable())?;
                        released.await.map_err(io::Error::other)?;
                        let headers = format!("HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                        stream.write_all(headers.as_bytes()).await?;
                        stream.write_all(&body).await?;
                        stream.flush().await?;
                        drop(stream);
                        // The next contact must be the caller's explicit exact
                        // GET, not an automatic second POST by the worker.
                        let (stream, _) = listener.accept().await?;
                        let mut stream = tls.accept(stream).await?;
                        let (line, bytes) = read_request(&mut stream).await?;
                        assert_eq!(line, format!("GET /node/v6/proxy/runtime/drains/{}/{} HTTP/1.1", expected.runtime_id, expected.request_id));
                        assert!(bytes.is_empty());
                        let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                        stream.write_all(headers.as_bytes()).await?;
                        stream.write_all(&body).await?;
                        stream.flush().await?;
                        Ok(())
                    } => result,
                }
            });
            let server = owned.insert("cancelled runtime request peer", stop, server);
            let (service, _runner) = Service::new(harness.caller.clone(), harness.fixture.client_tls.clone(), harness.fixture.client_id.clone());
            let (caller, actor, peer, input) = (service.clone(), harness.administrator.clone(), harness.fixture.server_id.clone(), request.clone());
            let cancel = CancellationToken::new();
            let cancelled = cancel.clone();
            let waiting = tokio::spawn(async move {
                tokio::select! {
                    _ = cancelled.cancelled() => Ok(()),
                    result = caller.drain_runtime(actor, peer, 1, input) => result.map(|_| ()),
                }
            });
            let waiting = owned.insert("cancelled browser wait", cancel.clone(), waiting);
            observation.await.map_err(io::Error::other)?;
            assert!(service.admission.is_active(&harness.fixture.server_id)?);
            assert_eq!(service.network.available_permits(), 3);
            assert_eq!(service.commands.available_permits(), 1);
            cancel.cancel();
            owned.stop_and_join(waiting).await?;
            assert!(service.admission.is_active(&harness.fixture.server_id)?);
            assert_eq!(service.network.available_permits(), 3);
            assert_eq!(service.commands.available_permits(), 1);
            release.send(()).map_err(|_| unavailable())?;
            wait_peer_idle(&service, &harness.fixture.server_id).await?;
            assert_eq!(service.commands.available_permits(), 2);
            let Reply::Runtime(recovered) = service.remote(harness.fixture.server_id.clone(), Request::RuntimeDrainStatus {
                runtime_id: request.runtime_id.clone(), request_id: request.request_id.clone(),
            }).await? else { return Err(invalid()); };
            assert_eq!(recovered.runtime.as_ref().unwrap().request.as_ref(), Some(&request));
            assert!(matches!(recovered.runtime.as_ref().unwrap().phase, drain::Phase::Draining));
            owned.stop_and_join(server).await?;
            assert_eq!(service.network.available_permits(), 4);
            assert_eq!(service.commands.available_permits(), 2);
            assert!(targets::job(&harness.fixture.client_state, &harness.fixture.server_id)?.is_none());
            Ok(())
        }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "cancelled runtime request scenario timed out"))
            .and_then(|result| result);
        owned.finish(scenario).await
    })
        }
    }
    mod search {
        //! Search uses the real controller admission path and registered mTLS target.
        //! Bulk rows are fixture-only metadata; no proxy credential is generated.

        use std::cell::Cell;

        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        use super::*;
        use crate::manage::user_search::{Mode, Query};

        const TERM: &str = "MaTcH_100% & +/?#";

        fn seed_users(harness: &Harness) -> io::Result<Vec<String>> {
            let mut ids: Vec<_> = (1..=60_u8)
                .map(|value| URL_SAFE_NO_PAD.encode([value; 16]))
                .collect();
            ids.sort();
            let mut connection =
                rusqlite::Connection::open(harness.fixture.server_state.join("management.sqlite3"))
                    .map_err(io::Error::other)?;
            let transaction = connection.transaction().map_err(io::Error::other)?;
            for (index, id) in ids.iter().enumerate() {
                let name = if matches!(index, 25 | 39 | 59) {
                    format!("match_100% & +/?# {index}")
                } else {
                    format!("Other {index}")
                };
                let deleted = index == 59;
                transaction
                    .execute(
                        "INSERT INTO proxy_users
                 (id, name, active, deleted, protocols, concurrent_limit, revision)
                 VALUES (?1, ?2, ?3, ?4, 1, 1, 1)",
                        rusqlite::params![id, name, !deleted, deleted],
                    )
                    .map_err(io::Error::other)?;
                transaction
                    .execute(
                        "INSERT INTO routing_permissions (user_id, legacy_allowed) VALUES (?1, 1)",
                        [id],
                    )
                    .map_err(io::Error::other)?;
                transaction
                    .execute(
                        "INSERT INTO user_presets (user_id, default_preset, allowed_mask)
                 VALUES (?1, NULL, 0)",
                        [id],
                    )
                    .map_err(io::Error::other)?;
            }
            transaction.commit().map_err(io::Error::other)?;
            store::load_policy(&harness.fixture.server_state)?;
            Ok(ids)
        }

        fn query(after: Option<String>) -> io::Result<Query> {
            Query::new(Mode::Name, TERM.into(), false, 1, after)
        }

        fn rejection(error: io::Error) -> io::Result<(u16, &'static str)> {
            error
                .get_ref()
                .and_then(|error| error.downcast_ref::<control::RemoteError>())
                .map(|remote| (remote.status, remote.code))
                .ok_or_else(|| io::Error::other("expected typed remote search rejection"))
        }

        #[tokio::test]
        async fn search_service_enforces_admission_and_rechecks_target_snapshot_and_owner()
        -> io::Result<()> {
            let harness = Harness::new()?;
            let ids = seed_users(&harness)?;
            let shutdown = CancellationToken::new();
            let (address, node) = start_node(
                &harness.fixture,
                &harness.child,
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                shutdown.clone(),
            )
            .await?;
            let origin = format!("https://localhost:{}", address.port());
            let stage = Cell::new("configure target");
            let outcome = timeout(Duration::from_secs(25), async {
                configure_target(&harness, origin.clone()).await?;
                // Read-only Service requests do not need the mutation/retry runner.
                // Avoid adding its independent scanner claims to this admission test.
                let (service, _runner) = Service::new(
                    harness.caller.clone(),
                    harness.fixture.client_tls.clone(),
                    harness.fixture.client_id.clone(),
                );
                let peer = &harness.fixture.server_id;

                stage.set("network budget rejection");
                let permits = service
                    .network
                    .clone()
                    .acquire_many_owned(4)
                    .await
                    .map_err(io::Error::other)?;
                let error = service
                    .remote(peer.clone(), Request::UsersSearch(query(None)?))
                    .await
                    .err()
                    .ok_or_else(|| io::Error::other("search bypassed the network budget"))?;
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                drop(permits);

                stage.set("peer claim rejection");
                // Acquiring this claim also proves the early network rejection above
                // released its claim instead of leaving the target permanently busy.
                let claim = service.claim(peer)?;
                let error = service
                    .remote(peer.clone(), Request::UsersSearch(query(None)?))
                    .await
                    .err()
                    .ok_or_else(|| io::Error::other("search bypassed the active peer claim"))?;
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                drop(claim);

                stage.set("ordinary first page");
                let Reply::UsersPage(first_users) = service
                    .remote(
                        peer.clone(),
                        Request::UsersPage {
                            after: None,
                            limit: 25,
                            include_deleted: false,
                        },
                    )
                    .await?
                else {
                    return Err(io::Error::other("expected ordinary user page"));
                };
                assert_eq!(first_users.items.len(), 25);
                assert!(
                    first_users
                        .items
                        .iter()
                        .zip(&ids)
                        .all(|(user, id)| &user.id == id)
                );

                stage.set("search outside the old first page");
                let Reply::UsersSearch(first) = service
                    .remote(peer.clone(), Request::UsersSearch(query(None)?))
                    .await?
                else {
                    return Err(io::Error::other("expected first search page"));
                };
                assert_eq!(first.revision, "1");
                assert_eq!(first.items.len(), 1);
                assert_eq!(first.items[0].id, ids[25]);
                let cursor = first
                    .next_cursor
                    .ok_or_else(|| io::Error::other("expected search continuation"))?;
                let continuation = query(Some(cursor))?;

                stage.set("search continuation");
                let Reply::UsersSearch(second) = service
                    .remote(peer.clone(), Request::UsersSearch(continuation.clone()))
                    .await?
                else {
                    return Err(io::Error::other("expected second search page"));
                };
                assert_eq!(second.items.len(), 1);
                assert_eq!(second.items[0].id, ids[39]);
                assert!(second.next_cursor.is_none());

                stage.set("explicit deleted-user search");
                let Reply::UsersSearch(history) = service
                    .remote(
                        peer.clone(),
                        Request::UsersSearch(Query::new(Mode::Name, TERM.into(), true, 50, None)?),
                    )
                    .await?
                else {
                    return Err(io::Error::other("expected search including deleted users"));
                };
                assert_eq!(history.items.len(), 3);
                assert_eq!(history.items[2].id, ids[59]);
                assert!(history.items[2].deleted);

                stage.set("real policy revision change");
                // One actual node command changes the read snapshot. It is sent once,
                // not replayed or retried, and is not a Service mutation-runner test.
                let Reply::Command(changed) = control::request(
                    &harness.caller,
                    harness.fixture.client_tls.clone(),
                    &origin,
                    peer,
                    Request::Command(control::Command {
                        version: 1,
                        target_node_id: peer.clone(),
                        resource: "proxy_policy".into(),
                        controller_epoch: "2".into(),
                        command_id: "1".into(),
                        expected_policy_revision: "1".into(),
                        source_administrator_id: harness.administrator.clone(),
                        mutation: control::Mutation::SetUserActive {
                            id: ids[25].clone(),
                            active: false,
                        },
                    }),
                )
                .await?
                else {
                    return Err(io::Error::other("expected policy change reply"));
                };
                assert_eq!(changed.receipt.policy_revision.as_deref(), Some("2"));

                stage.set("stale cursor rejection");
                let error = service
                    .remote(peer.clone(), Request::UsersSearch(continuation.clone()))
                    .await
                    .err()
                    .ok_or_else(|| io::Error::other("search accepted a stale cursor"))?;
                assert_eq!(rejection(error)?, (409, "user_search_changed"));
                let Reply::UsersSearch(restarted) = service
                    .remote(peer.clone(), Request::UsersSearch(query(None)?))
                    .await?
                else {
                    return Err(io::Error::other("expected explicitly restarted search"));
                };
                assert_eq!(restarted.revision, "2");
                assert!(!restarted.items[0].active);

                stage.set("current owner revocation");
                harness
                    .child
                    .set_owner(administrator(&harness.fixture.server_state)?, 2, None)
                    .await?;
                for query in [continuation, query(None)?] {
                    let error = service
                        .remote(peer.clone(), Request::UsersSearch(query))
                        .await
                        .err()
                        .ok_or_else(|| {
                            io::Error::other("former owner retained user-search access")
                        })?;
                    // A genuine old cursor must not disclose stale-snapshot details
                    // after this TLS peer has ceased to own the target.
                    assert_eq!(rejection(error)?, (403, "peer_not_authorized"));
                }
                Ok::<_, io::Error>(())
            })
            .await;
            shutdown.cancel();
            let stopped = node.await.map_err(io::Error::other)?;
            outcome.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("controller search deadline at {}", stage.get()),
                )
            })??;
            stopped
        }
    }
    mod secrets {
        //! A complete, valid password reply must not bypass source-side authorization
        //! changes while its final byte is still withheld by the authenticated peer.
        use super::*;
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        #[test]
        fn saved_password_is_discarded_after_source_target_or_administrator_changes()
        -> io::Result<()> {
            for (remove_actor, pause_target) in [(false, true), (false, false), (true, false)] {
                let harness = Harness::new()?;
                // Keep the original administrator and audit subjects intact. The
                // removable reader has no durable operations or foreign-key references;
                // deleting the fixture's sole administrator would test DB protection,
                // not this response's final actor authorization.
                let selected_actor = if remove_actor {
                    let id = URL_SAFE_NO_PAD.encode([9; 16]);
                    let connection = rusqlite::Connection::open(
                        harness.fixture.client_state.join("management.sqlite3"),
                    )
                    .map_err(io::Error::other)?;
                    connection.execute("INSERT INTO administrators(id,username,password_hash) VALUES (?1,'transient-reader','fixture-phc')", [&id]).map_err(io::Error::other)?;
                    id
                } else {
                    harness.administrator.clone()
                };
                let executor = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                executor.block_on(async {
            let mut owned = OwnedTasks::new();
            let scenario = timeout(Duration::from_secs(15), async {
                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                configure_target(&harness, format!("https://localhost:{}", listener.local_addr()?.port())).await?;
                let tls = tokio_rustls::TlsAcceptor::from(harness.fixture.server_tls.clone());
                let (actor, peer, caller) = (selected_actor.clone(), harness.fixture.server_id.clone(), harness.caller.clone());
                let input = || control::CredentialSecretRead::new(harness.fixture.server_id.clone(), URL_SAFE_NO_PAD.encode([3;16]), URL_SAFE_NO_PAD.encode([4;16]), "2".into(), "1".into());
                let (service, _runner) = Service::new(harness.caller.clone(), harness.fixture.client_tls.clone(), harness.fixture.client_id.clone());
                // Generic remote reads cannot impersonate the browser actor or
                // silently drop the inspected target-registration assertion.
                assert_eq!(service.remote(peer.clone(), Request::CredentialSecret(input()?)).await.err().unwrap().kind(), io::ErrorKind::PermissionDenied);
                let stop = CancellationToken::new();
                let shutdown = stop.clone();
                let server = tokio::spawn(async move {
                    tokio::select! {
                        _ = shutdown.cancelled() => Ok(()),
                        result = async {
                            let (stream, _) = listener.accept().await?;
                            let mut stream = tls.accept(stream).await?;
                            let (line, bytes) = super::runtime::read_request(&mut stream).await?;
                            let selected: control::CredentialSecretRead = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                            assert_eq!(line, format!("POST /node/v7/proxy/credentials/{}/secret HTTP/1.1", selected.credential_id));
                            let body = serde_json::to_vec(&serde_json::json!({
                                "version":7,"node_id":peer,"resource":"proxy_credential_secret","data":{
                                    "credential_id":selected.credential_id,"user_id":selected.user_id,
                                    "controller_epoch":"2","verifier_revision":"1","secret":"A".repeat(43)
                                }
                            })).map_err(io::Error::other)?;
                            let head = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                            stream.write_all(head.as_bytes()).await?;
                            stream.write_all(&body[..body.len()-1]).await?;
                            stream.flush().await?;
                            caller.read(move |directory| {
                                if remove_actor {
                                    let connection = rusqlite::Connection::open(directory.join("management.sqlite3")).map_err(io::Error::other)?;
                                    connection.execute("DELETE FROM administrators WHERE id=?1", [&actor]).map_err(io::Error::other)?;
                                } else {
                                    let target = targets::set_state(directory, &actor, &peer, 1, !pause_target, false)?;
                                    assert_eq!(target.revision, 2);
                                    assert_eq!(target.active, !pause_target);
                                }
                                Ok(())
                            }).await?;
                            stream.write_all(&body[body.len()-1..]).await?;
                            stream.flush().await?;
                            Ok(())
                        } => result,
                    }
                });
                let task = owned.insert("password source fencing peer", stop, server);
                let error = service.credential_secret(selected_actor, 1, input()?).await.err().unwrap();
                let kind = if remove_actor || pause_target { io::ErrorKind::PermissionDenied } else { io::ErrorKind::AlreadyExists };
                assert_eq!(error.kind(), kind, "actor_removed={remove_actor}, target_paused={pause_target}: {error}");
                assert!(!error.to_string().contains(&"A".repeat(43)));
                owned.stop_and_join(task).await?;
                assert!(!service.admission.is_active(&harness.fixture.server_id)?);
                assert_eq!(service.network.available_permits(), 4);
                assert!(targets::job(&harness.fixture.client_state, &harness.fixture.server_id)?.is_none());
                Ok(())
            }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "password source fencing scenario timed out")).and_then(|result| result);
            owned.finish(scenario).await
        })?;
            }
            Ok(())
        }
    }
    #[cfg(feature = "witness-journal")]
    mod source {
        //! Source controllers use the actual node service plus its existing test-only
        //! loopback witness. This is not an independent production failure domain.

        use super::*;
        use crate::manage::store::{endpoint_control, journal::SourceFixture};

        async fn fixture(fault: node::tests::CutResponse) -> io::Result<SourceFixture> {
            SourceFixture::new_with(fault, |f| {
                let actor = administrator(&f.server_state)?;
                store::set_owner(
                    &f.server_state,
                    &store::update_lock(&f.server_state)?,
                    &actor,
                    1,
                    Some(&f.client_id),
                )?;
                Ok(())
            })
            .await
        }

        async fn configure(live: &SourceFixture) -> io::Result<()> {
            let (actor, peer, origin) = (
                live.administrator.clone(),
                live.fixture.server_id.clone(),
                live.endpoint.clone(),
            );
            live.source
                .targets_write(move |writer| {
                    writer.configure(&actor, &peer, None, &origin, true, None)
                })
                .await?;
            let peer = live.fixture.server_id.clone();
            live.source
                .targets_write(move |writer| writer.observe(&peer, 1, 2, 0, 1))
                .await?;
            Ok(())
        }

        fn service(live: &SourceFixture) -> (Arc<Service>, Runner) {
            Service::new(
                live.source.clone(),
                live.fixture.client_tls.clone(),
                live.fixture.client_id.clone(),
            )
        }

        fn command(
            live: &SourceFixture,
            id: u64,
            revision: u64,
            change: store::PolicyChange,
        ) -> store::Command {
            store::Command {
                target_node_id: live.fixture.server_id.clone(),
                epoch: 2,
                command_id: id,
                expected_policy_revision: revision,
                source_administrator_id: live.administrator.clone(),
                change,
            }
        }

        fn create_user() -> store::PolicyChange {
            store::PolicyChange::CreateUser {
                name: "source controller user".into(),
                protocols: vec![crate::access::Protocol::Http],
                concurrent_limit: 2,
            }
        }

        async fn job(live: &SourceFixture) -> io::Result<Job> {
            let peer = live.fixture.server_id.clone();
            live.source
                .read(move |dir| targets::job(dir, &peer)?.ok_or_else(invalid))
                .await
        }

        #[tokio::test]
        async fn source_target_cas_repeats_and_retry_supersession_keep_original_intent_and_floors()
        -> io::Result<()> {
            let live = fixture(Default::default()).await?;
            let result = async {
                configure(&live).await?;
                assert_eq!(live.floor()?.sequence, "2");
                let (peer, wrong_actor) = (
                    live.fixture.server_id.clone(),
                    live.fixture.server_id.clone(),
                );
                assert_eq!(
                    live.source
                        .targets_write(move |w| w.set_state(&wrong_actor, &peer, 1, false, false))
                        .await
                        .err()
                        .map(|e| e.kind()),
                    Some(io::ErrorKind::PermissionDenied)
                );
                assert_eq!(live.floor()?.sequence, "2");
                let (peer, actor, origin) = (
                    live.fixture.server_id.clone(),
                    live.administrator.clone(),
                    live.endpoint.clone(),
                );
                assert!(
                    live.source
                        .targets_write(
                            move |w| w.configure(&actor, &peer, None, &origin, true, None)
                        )
                        .await
                        .is_err()
                );
                let peer = live.fixture.server_id.clone();
                live.source
                    .targets_write(move |w| w.observe(&peer, 1, 2, 0, 1))
                    .await?;
                assert_eq!(live.floor()?.sequence, "2");
                let cmd = command(&live, 1, 1, create_user());
                let actor = live.administrator.clone();
                let saved = live
                    .source
                    .targets_write(move |w| w.enqueue_intent(&actor, 1, cmd.into()))
                    .await?;
                let id = saved.job_id.clone();
                let (peer, actor, origin) = (
                    live.fixture.server_id.clone(),
                    live.administrator.clone(),
                    live.endpoint.clone(),
                );
                assert!(
                    live.source
                        .targets_write(move |w| w.configure(
                            &actor,
                            &peer,
                            Some(1),
                            &origin,
                            true,
                            None
                        ))
                        .await
                        .is_err()
                );
                let (peer, old) = (live.fixture.server_id.clone(), id.clone());
                live.source
                    .targets_write(move |w| w.failed(&peer, &old, true, i64::MAX as u64 - 1))
                    .await?;
                assert_eq!(job(&live).await?.state, targets::JobState::Blocked);
                let (peer, actor, old) = (
                    live.fixture.server_id.clone(),
                    live.administrator.clone(),
                    id.clone(),
                );
                let retried = live
                    .source
                    .targets_write(move |w| w.retry(&actor, &peer, &old))
                    .await?;
                assert_eq!(
                    (
                        retried.job_id.as_str(),
                        retried.command_id,
                        retried.attempts
                    ),
                    (id.as_str(), 1, 0)
                );
                let (peer, actor, old) = (
                    live.fixture.server_id.clone(),
                    live.administrator.clone(),
                    id.clone(),
                );
                assert!(
                    live.source
                        .targets_write(move |w| w.supersede(&actor, &peer, &old))
                        .await
                        .is_err()
                );
                let peer = live.fixture.server_id.clone();
                live.source
                    .targets_write(move |w| w.observe(&peer, 1, 3, 0, 1))
                    .await?;
                let (peer, actor, old) = (
                    live.fixture.server_id.clone(),
                    live.administrator.clone(),
                    id.clone(),
                );
                let replaced = live
                    .source
                    .targets_write(move |w| w.supersede(&actor, &peer, &old))
                    .await?;
                assert_eq!(
                    (replaced.job_id.as_str(), replaced.state),
                    (id.as_str(), targets::JobState::Superseded)
                );
                let (peer, actor) = (live.fixture.server_id.clone(), live.administrator.clone());
                let paused = live
                    .source
                    .targets_write(move |w| w.set_state(&actor, &peer, 1, false, true))
                    .await?;
                assert!(paused.retired && !paused.active);
                assert_eq!(
                    (paused.observed_epoch, paused.observed_command),
                    (Some(3), Some(0))
                );
                let (peer, actor, origin) = (
                    live.fixture.server_id.clone(),
                    live.administrator.clone(),
                    live.endpoint.clone(),
                );
                let restored = live
                    .source
                    .targets_write(move |w| {
                        w.configure(
                            &actor,
                            &peer,
                            Some(2),
                            &origin,
                            true,
                            Some(Some("192.0.2.10".parse().map_err(|_| invalid())?)),
                        )
                    })
                    .await?;
                assert_eq!(restored.revision, 3);
                let peer = live.fixture.server_id.clone();
                let rollback = live
                    .source
                    .targets_write(move |w| w.observe(&peer, 3, 2, 0, 1))
                    .await?;
                assert!(rollback.rollback_detected);
                let floor = live.floor()?.sequence;
                let peer = live.fixture.server_id.clone();
                live.source
                    .targets_write(move |w| w.observe(&peer, 3, 2, 0, 1))
                    .await?;
                assert_eq!(live.floor()?.sequence, floor);
                assert_eq!(live.source.reader().revision()?, 1);
                Ok(())
            }
            .await;
            let closed = live.close().await;
            result.and(closed)
        }

        #[tokio::test]
        async fn source_controller_mixed_endpoint_policy_delivery_and_receipt_repeats_use_real_mtls()
        -> io::Result<()> {
            let live = fixture(Default::default()).await?;
            let mut owned = OwnedTasks::new();
            let result = async {
                live.remote.configure_endpoints(vec![proxy::ListenerView {
                    protocol: proxy::Protocol::Http,
                    bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 18080)),
                    public_address: Some("default.example:18080".into()),
                }])?;
                live.remote
                    .configure_endpoint_settings(&live.fixture.server_id)
                    .await?;
                configure(&live).await?;
                let (service, runner) = service(&live);
                let stop = CancellationToken::new();
                owned.insert(
                    "source mixed runner",
                    stop.clone(),
                    tokio::spawn(runner.run(stop)),
                );
                let settings = live.remote.endpoint_inventory()?;
                let metadata = store::endpoints::read(&live.fixture.server_state)?;
                let endpoint = endpoint_control::Command {
                    target_node_id: live.fixture.server_id.clone(),
                    epoch: 2,
                    command_id: 1,
                    expected_metadata_revision: metadata.revision,
                    source_administrator_id: live.administrator.clone(),
                    generation: settings.digest,
                    change: store::endpoints::Change {
                        listener_id: settings.listeners[0].id.clone(),
                        selection: store::endpoints::AddressSelection::Hidden,
                    },
                };
                let submitted = service
                    .submit(live.administrator.clone(), 1, endpoint)
                    .await?;
                let endpoint_job = submitted.job.job_id.clone();
                let reply = submitted.response.await.map_err(io::Error::other)??;
                assert!(matches!(reply, control::DeliveryReply::Endpoint(_)));
                assert_eq!(live.remote.reader().revision()?, 1);
                assert_eq!(job(&live).await?.metadata_revision, Some(3));
                wait_peer_idle(&service, &live.fixture.server_id).await?;
                let submitted = service
                    .submit(
                        live.administrator.clone(),
                        1,
                        command(&live, 2, 1, create_user()),
                    )
                    .await?;
                let user_job = submitted.job.job_id.clone();
                let reply = policy_reply(submitted.response.await.map_err(io::Error::other)??);
                let user = reply.user.ok_or_else(invalid)?.id;
                assert_eq!(live.remote.reader().revision()?, 2);
                wait_peer_idle(&service, &live.fixture.server_id).await?;
                assert!(
                    service
                        .refresh_endpoint(live.fixture.server_id.clone(), endpoint_job)
                        .await
                        .is_err()
                );
                wait_peer_idle(&service, &live.fixture.server_id).await?;
                let recovered = service
                    .user_result(live.fixture.server_id.clone(), user_job.clone())
                    .await?;
                assert_eq!(
                    (recovered.job.job_id, recovered.user_id),
                    (user_job.clone(), user)
                );
                // Timestamp changes may create real history updates; exact same-tick
                // repeats may be read-only. Both must succeed without a net-zero error.
                for _ in 0..4 {
                    wait_peer_idle(&service, &live.fixture.server_id).await?;
                    assert_eq!(
                        service
                            .refresh(live.fixture.server_id.clone())
                            .await?
                            .job_id,
                        user_job
                    );
                }
                assert_eq!(live.source.reader().revision()?, 1);
                Ok(())
            }
            .await;
            let drained = owned.finish(result).await;
            let closed = live.close().await;
            drained.and(closed)
        }

        #[tokio::test]
        async fn source_unknown_enqueue_keeps_peer_guard_and_blocks_delivery_until_original_reconcile()
        -> io::Result<()> {
            let pause = Arc::new(node::tests::ResponsePause::default());
            let live = fixture(node::tests::CutResponse {
                witness_confirm: true,
                witness_sequence: Some(3),
                pause: Some(pause.clone()),
                cut_after_pause: true,
                ..Default::default()
            })
            .await?;
            let result = async {
                configure(&live).await?;
                let (service, _runner) = service(&live);
                let claim = Arc::new(service.claim(&live.fixture.server_id)?);
                let capacity = service
                    .commands
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(io::Error::other)?;
                let actor = live.administrator.clone();
                let cmd = command(&live, 1, 1, create_user());
                live.arm();
                let mut queued = Box::pin(
                    live.source
                        .targets_write_guarded((claim, capacity), move |w| {
                            w.enqueue_intent(&actor, 1, cmd.into())
                        }),
                );
                assert!(futures_util::poll!(&mut queued).is_pending());
                timeout(Duration::from_secs(15), pause.entered.notified())
                    .await
                    .map_err(io::Error::other)?;
                let pending = job(&live).await?;
                assert_eq!(pending.state, targets::JobState::Pending);
                drop(queued);
                assert!(service.claim(&live.fixture.server_id).is_err());
                assert_eq!(service.commands.available_permits(), 1);
                assert!(store::update_lock(&live.fixture.client_state).is_err());
                assert_eq!(
                    control::request(
                        &live.source,
                        live.fixture.client_tls.clone(),
                        &live.endpoint,
                        &live.fixture.server_id,
                        Request::Policy
                    )
                    .await
                    .err()
                    .map(|e| e.kind()),
                    Some(io::ErrorKind::WouldBlock)
                );
                pause.release.notify_one();
                timeout(Duration::from_secs(15), async {
                    while service.commands.available_permits() != 2 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .map_err(io::Error::other)?;
                assert!(live.source.reader().revision().is_err());
                let (peer, id) = (live.fixture.server_id.clone(), pending.job_id.clone());
                let delivery = live
                    .source
                    .read(move |dir| targets::load_delivery(dir, &peer, &id))
                    .await?;
                let claim = Arc::new(service.claim(&live.fixture.server_id)?);
                let permit = service
                    .commands
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(io::Error::other)?;
                assert!(service.deliver(delivery, &claim).await.is_err());
                drop((claim, permit));
                assert_eq!(
                    store::policy_status(&live.fixture.server_state)?.user_count,
                    0
                );
                live.source.reconcile_source().await?;
                let (peer, id) = (live.fixture.server_id.clone(), pending.job_id.clone());
                let delivery = live
                    .source
                    .read(move |dir| targets::load_delivery(dir, &peer, &id))
                    .await?;
                let claim = Arc::new(service.claim(&live.fixture.server_id)?);
                let _permit = service
                    .commands
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(io::Error::other)?;
                assert!(matches!(
                    service.deliver(delivery, &claim).await?,
                    control::DeliveryReply::Policy(_)
                ));
                assert_eq!(
                    store::policy_status(&live.fixture.server_state)?.user_count,
                    1
                );
                assert_eq!(job(&live).await?.job_id, pending.job_id);
                assert_eq!(live.source.reader().revision()?, 1);
                Ok(())
            }
            .await;
            pause.release.notify_one();
            let closed = live.close().await;
            result.and(closed)
        }

        #[tokio::test]
        async fn source_lost_receipt_confirmation_withholds_one_time_secret_and_never_recreates_credential()
        -> io::Result<()> {
            let live = fixture(node::tests::CutResponse {
                witness_confirm: true,
                witness_sequence: Some(6),
                witness_only: true,
                ..Default::default()
            })
            .await?;
            let mut owned = OwnedTasks::new();
            let result = async {
                configure(&live).await?;
                let (service, runner) = service(&live);
                let stop = CancellationToken::new();
                owned.insert(
                    "source credential runner",
                    stop.clone(),
                    tokio::spawn(runner.run(stop)),
                );
                let submitted = service
                    .submit(
                        live.administrator.clone(),
                        1,
                        command(&live, 1, 1, create_user()),
                    )
                    .await?;
                let created = policy_reply(submitted.response.await.map_err(io::Error::other)??);
                let user = created.user.ok_or_else(invalid)?.id;
                assert_eq!(live.floor()?.sequence, "4");
                wait_peer_idle(&service, &live.fixture.server_id).await?;
                live.arm();
                let submitted = service
                    .submit(
                        live.administrator.clone(),
                        1,
                        command(
                            &live,
                            2,
                            2,
                            store::PolicyChange::CreateCredential { user_id: user },
                        ),
                    )
                    .await?;
                let id = submitted.job.job_id;
                assert!(submitted.response.await.map_err(io::Error::other)?.is_err());
                assert!(live.source.reader().revision().is_err());
                assert_eq!(job(&live).await?.state, targets::JobState::Saved);
                assert_eq!(
                    store::policy_status(&live.fixture.server_state)?.credential_count,
                    1
                );
                live.source.reconcile_source().await?;
                wait_peer_idle(&service, &live.fixture.server_id).await?;
                let recovered = service.refresh(live.fixture.server_id.clone()).await?;
                assert_eq!(
                    (recovered.job_id.as_str(), recovered.state),
                    (id.as_str(), targets::JobState::Saved)
                );
                assert_eq!(
                    store::policy_status(&live.fixture.server_state)?.credential_count,
                    1
                );
                assert_eq!(live.source.reader().revision()?, 1);
                Ok(())
            }
            .await;
            let drained = owned.finish(result).await;
            let closed = live.close().await;
            drained.and(closed)
        }

        #[tokio::test]
        async fn source_user_result_keeps_rejected_receipt_when_post_commit_result_is_unavailable()
        -> io::Result<()> {
            let live = SourceFixture::new_with(Default::default(), |f| {
                let actor = administrator(&f.server_state)?;
                let gate = store::update_lock(&f.server_state)?;
                store::apply_policy(&f.server_state, &actor, 1, create_user(), &gate)?;
                store::set_owner(&f.server_state, &gate, &actor, 1, Some(&f.client_id))?;
                Ok(())
            })
            .await?;
            let result = async {
                // Model a stale but previously valid observed policy position. The
                // actual child's current revision is already two; it rejects this CAS.
                configure(&live).await?;
                let cmd = command(&live, 1, 1, create_user());
                let wire = control::Command {
                    version: 1,
                    target_node_id: cmd.target_node_id.clone(),
                    resource: "proxy_policy".into(),
                    controller_epoch: "2".into(),
                    command_id: "1".into(),
                    expected_policy_revision: "1".into(),
                    source_administrator_id: cmd.source_administrator_id.clone(),
                    mutation: cmd.change.clone().try_into()?,
                };
                let actor = live.administrator.clone();
                let queued = live
                    .source
                    .targets_write(move |w| w.enqueue_intent(&actor, 1, cmd.into()))
                    .await?;
                let Reply::Command(reply) = control::request(
                    &live.source,
                    live.fixture.client_tls.clone(),
                    &live.endpoint,
                    &live.fixture.server_id,
                    Request::Command(wire),
                )
                .await?
                else {
                    return Err(invalid());
                };
                assert!(matches!(
                    reply.receipt.status,
                    control::ReceiptStatus::Rejected
                ));
                let (service, _runner) = service(&live);
                assert_eq!(
                    service
                        .user_result(live.fixture.server_id.clone(), queued.job_id.clone())
                        .await
                        .err()
                        .map(|e| e.kind()),
                    Some(io::ErrorKind::NotFound)
                );
                let saved = job(&live).await?;
                assert_eq!(
                    (saved.job_id, saved.state),
                    (queued.job_id, targets::JobState::Rejected)
                );
                assert_eq!(live.floor()?.sequence, "4");
                assert_eq!(live.source.reader().revision()?, 1);
                assert_eq!(
                    store::policy_status(&live.fixture.server_state)?.user_count,
                    1
                );
                Ok(())
            }
            .await;
            let closed = live.close().await;
            result.and(closed)
        }
    }
    pub(in crate::manage) mod tasks {
        //! Test supervisors outlive the cancellable scenario, and the fixture outlives
        //! their explicit async cleanup. Drop is only a panic/forgotten-cleanup fallback.

        use std::{io, time::Duration};

        use tokio::task::{JoinError, JoinHandle};
        use tokio_util::sync::CancellationToken;

        struct OwnedTask {
            name: &'static str,
            stop: CancellationToken,
            handle: Option<JoinHandle<io::Result<()>>>,
        }

        pub(in crate::manage) struct OwnedTasks {
            entries: Vec<OwnedTask>,
        }

        impl OwnedTasks {
            pub(in crate::manage) fn new() -> Self {
                Self {
                    entries: Vec::new(),
                }
            }

            /// Register immediately after spawning, before another fallible/await point.
            /// Indices remain stable across controller/node restarts; completed slots
            /// are not reused, so an old generation cannot address the replacement.
            pub(in crate::manage) fn insert(
                &mut self,
                name: &'static str,
                stop: CancellationToken,
                handle: JoinHandle<io::Result<()>>,
            ) -> usize {
                let index = self.entries.len();
                self.entries.push(OwnedTask {
                    name,
                    stop,
                    handle: Some(handle),
                });
                index
            }

            /// Cancelling this wait retains the handle in its original slot. Only a
            /// completed join clears ownership; taking the handle before awaiting it
            /// would detach the task if the enclosing scenario timed out.
            pub(super) async fn stop_and_join(&mut self, index: usize) -> io::Result<()> {
                let task = self.entries.get_mut(index).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "Unknown controller test task")
                })?;
                task.stop.cancel();
                Self::join(task).await.map_err(io::Error::other)?
            }

            pub(super) fn is_finished(&self, index: usize) -> bool {
                self.entries
                    .get(index)
                    .is_some_and(|task| task.handle.as_ref().is_none_or(JoinHandle::is_finished))
            }

            /// Stop every supervisor, then join all of them even if one reports an
            /// error. Ten seconds is teardown grace, not a larger scenario deadline.
            /// A scenario error keeps its original kind/source; cleanup diagnostics
            /// contain only the static task label and error kind.
            pub(in crate::manage) async fn finish(
                &mut self,
                scenario: io::Result<()>,
            ) -> io::Result<()> {
                self.finish_with_grace(scenario, Duration::from_secs(10))
                    .await
            }

            async fn join(task: &mut OwnedTask) -> Result<io::Result<()>, JoinError> {
                let Some(handle) = task.handle.as_mut() else {
                    return Ok(Ok(()));
                };
                let result = handle.await;
                task.handle = None;
                result
            }

            async fn finish_with_grace(
                &mut self,
                scenario: io::Result<()>,
                grace: Duration,
            ) -> io::Result<()> {
                for task in &self.entries {
                    task.stop.cancel();
                }
                let mut failure = None;
                let drained = tokio::time::timeout(grace, async {
                    for task in &mut self.entries {
                        let result = Self::join(task)
                            .await
                            .map_err(io::Error::other)
                            .and_then(|result| result);
                        if let Err(error) = result {
                            cleanup_error(&mut failure, task.name, error);
                        }
                    }
                })
                .await;
                if drained.is_err() {
                    cleanup_error(
                        &mut failure,
                        "teardown_grace",
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Controller test cleanup grace expired",
                        ),
                    );
                    for task in &self.entries {
                        if let Some(handle) = &task.handle {
                            handle.abort();
                        }
                    }
                    // Abort is only a request. Reap every async task before allowing
                    // its fixture to drop. This does not interrupt an already-started
                    // spawn_blocking operation or provide a hard thread-kill deadline.
                    for task in &mut self.entries {
                        match Self::join(task).await {
                            Ok(Ok(())) => {}
                            Err(error) if error.is_cancelled() => {}
                            Ok(Err(error)) => cleanup_error(&mut failure, task.name, error),
                            Err(error) => {
                                cleanup_error(&mut failure, task.name, io::Error::other(error))
                            }
                        }
                    }
                }
                scenario?;
                failure.map_or(Ok(()), Err)
            }
        }

        fn cleanup_error(first: &mut Option<io::Error>, name: &'static str, error: io::Error) {
            eprintln!(
                "controller test cleanup: stage={name}, kind={:?}",
                error.kind()
            );
            if first.is_none() {
                *first = Some(error);
            }
        }

        impl Drop for OwnedTasks {
            fn drop(&mut self) {
                // Async joining cannot happen in Drop. Normal timeout/Err paths must
                // call finish outside the scenario; this is only an unwinding fallback.
                for task in &self.entries {
                    task.stop.cancel();
                    if let Some(handle) = &task.handle {
                        handle.abort();
                    }
                }
            }
        }

        #[cfg(test)]
        mod tests {
            use std::{
                fmt,
                future::pending,
                net::{Ipv4Addr, SocketAddr},
            };

            use tokio::{net::TcpListener, sync::oneshot};

            use super::*;
            use crate::manage::controller::{
                Service,
                tests::{Harness, start_node},
            };

            #[derive(Debug)]
            struct ScenarioFailure;

            impl fmt::Display for ScenarioFailure {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("Injected controller scenario failure")
                }
            }

            impl std::error::Error for ScenarioFailure {}

            #[test]
            fn real_supervisors_are_joined_after_scenario_timeout_or_error_before_fixture_drop()
            -> io::Result<()> {
                for timed_out in [true, false] {
                    let harness = Harness::new()?;
                    let directory = harness.fixture.server_state.clone();
                    // Joining async supervisors cannot prove their already-started
                    // blocking work has stopped. Runtime drop waits for that work while
                    // the harness/authority still exist, including on assertion unwind.
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    let checked = runtime.block_on(async {
                        let mut tasks = OwnedTasks::new();
                        let mut observed = Vec::new();
                        let mut address = None;
                        let mut service = None;
                        let scenario = async {
                            let stop = CancellationToken::new();
                            let (bound, node) = start_node(
                                &harness.fixture,
                                &harness.child,
                                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                                stop.clone(),
                            )
                            .await?;
                            observed.push(node.abort_handle());
                            tasks.insert("fault_node", stop, node);
                            address = Some(bound);
                            let (client, runner) = Service::new(
                                harness.caller.clone(),
                                harness.fixture.client_tls.clone(),
                                harness.fixture.client_id.clone(),
                            );
                            service = Some(client);
                            let stop = CancellationToken::new();
                            let runner = tokio::spawn(runner.run(stop.clone()));
                            observed.push(runner.abort_handle());
                            tasks.insert("fault_runner", stop, runner);
                            // Both real supervisors are scheduled, but no data-plane or
                            // delivery mutation is needed to prove resource ownership.
                            tokio::task::yield_now().await;
                            if timed_out {
                                match tokio::time::timeout(
                                    Duration::ZERO,
                                    pending::<io::Result<()>>(),
                                )
                                .await
                                {
                                    Ok(result) => result,
                                    Err(error) => {
                                        Err(io::Error::new(io::ErrorKind::TimedOut, error))
                                    }
                                }
                            } else {
                                Err(io::Error::new(
                                    io::ErrorKind::ConnectionAborted,
                                    ScenarioFailure,
                                ))
                            }
                        }
                        .await;
                        let error = tasks.finish(scenario).await.err().unwrap();
                        if timed_out {
                            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                            assert!(error.get_ref().unwrap().is::<tokio::time::error::Elapsed>());
                        } else {
                            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
                            assert!(error.get_ref().unwrap().is::<ScenarioFailure>());
                        }
                        assert_eq!(observed.len(), 2);
                        assert!(observed.iter().all(tokio::task::AbortHandle::is_finished));
                        assert!(tasks.entries.iter().all(|task| task.handle.is_none()));
                        assert!((0..tasks.entries.len()).all(|index| tasks.is_finished(index)));
                        assert!(directory.is_dir(), "Fixture must survive the async joins");
                        let listener = TcpListener::bind(address.unwrap()).await?;
                        drop(listener);
                        drop(service);
                        drop(tasks);
                        Ok::<_, io::Error>(())
                    });
                    drop(runtime);
                    let Harness {
                        fixture,
                        child,
                        caller,
                        child_author,
                        ..
                    } = harness;
                    drop(child);
                    drop(caller);
                    drop(child_author);
                    assert!(directory.is_dir());
                    drop(fixture);
                    assert!(!directory.exists());
                    checked?;
                }
                Ok(())
            }

            struct Dropped(Option<oneshot::Sender<()>>);

            impl Drop for Dropped {
                fn drop(&mut self) {
                    if let Some(sender) = self.0.take() {
                        let _ = sender.send(());
                    }
                }
            }

            #[tokio::test]
            async fn expired_cleanup_grace_aborts_and_joins_without_replacing_scenario_error()
            -> io::Result<()> {
                for scenario_failed in [false, true] {
                    let mut tasks = OwnedTasks::new();
                    let (entered, started) = oneshot::channel();
                    let (dropped, mut removed) = oneshot::channel();
                    let task = tokio::spawn(async move {
                        let _notice = Dropped(Some(dropped));
                        let _ = entered.send(());
                        pending::<io::Result<()>>().await
                    });
                    let observed = task.abort_handle();
                    let index =
                        tasks.insert("ignores_cancellation", CancellationToken::new(), task);
                    started.await.map_err(io::Error::other)?;
                    // Model cancellation during a scenario's intermediate drain, not
                    // only cancellation before teardown starts. The handle must remain
                    // owned when this borrowed join future is dropped by timeout.
                    assert!(
                        tokio::time::timeout(Duration::ZERO, tasks.stop_and_join(index))
                            .await
                            .is_err()
                    );
                    assert!(tasks.entries[index].handle.is_some());
                    assert!(!tasks.is_finished(index));
                    let scenario = if scenario_failed {
                        Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            ScenarioFailure,
                        ))
                    } else {
                        Ok(())
                    };
                    let error = tasks
                        .finish_with_grace(scenario, Duration::ZERO)
                        .await
                        .err()
                        .unwrap();
                    if scenario_failed {
                        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
                        assert!(error.get_ref().unwrap().is::<ScenarioFailure>());
                    } else {
                        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                    }
                    assert!(observed.is_finished());
                    assert!(tasks.is_finished(index));
                    assert!(tasks.entries[index].handle.is_none());
                    assert!(
                        removed.try_recv().is_ok(),
                        "abort must be joined, not just requested"
                    );
                }
                Ok(())
            }
        }
    }
    mod trace {
        //! Bounded, non-secret diagnostics owned outside cancellable test scenarios.

        use std::{
            cell::{Cell, RefCell},
            collections::VecDeque,
            fmt::Write as _,
            sync::{Arc, Mutex},
            time::Instant,
        };

        use super::{Job, Service};

        const CAPACITY: usize = 64;

        /// A read boundary, not a claim about the controller's internal network stage.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(super) enum ReadEvent {
            Start,
            Snapshot,
            Missing,
            WouldBlock,
            StoreError,
            WorkerError,
        }

        /// Per-read stamps survive cancellation of the awaiting scenario. Missing stamps
        /// mean only that this observer did not record the boundary, not that work is
        /// still queued or running. No lock spans the job or its await.
        #[derive(Clone)]
        pub(super) struct ReadTiming(Arc<Mutex<ReadStamps>>);

        #[derive(Clone, Copy)]
        struct ReadStamps {
            queued: Instant,
            entered: Option<Instant>,
            returned: Option<Instant>,
            resumed: Option<Instant>,
        }

        impl ReadTiming {
            pub(super) fn new(queued: Instant) -> Self {
                Self(Arc::new(Mutex::new(ReadStamps {
                    queued,
                    entered: None,
                    returned: None,
                    resumed: None,
                })))
            }

            pub(super) fn entered(&self) {
                if let Ok(mut stamps) = self.0.try_lock() {
                    stamps.entered = Some(Instant::now());
                }
            }

            pub(super) fn returned(&self) {
                if let Ok(mut stamps) = self.0.try_lock() {
                    stamps.returned = Some(Instant::now());
                }
            }

            pub(super) fn resumed(&self) {
                if let Ok(mut stamps) = self.0.try_lock() {
                    stamps.resumed = Some(Instant::now());
                }
            }

            fn describe(&self, output: &mut String) {
                // Copy under a nonwaiting lock, then release it before formatting.
                let snapshot = self.0.try_lock().ok().map(|stamps| *stamps);
                let Some(stamps) = snapshot else {
                    output.push_str(",timing_at_report=unknown");
                    return;
                };
                let _ = write!(
                    output,
                    ",timing_at_report={{entered={},returned={},await={}",
                    if stamps.entered.is_some() {
                        "entered_observed"
                    } else {
                        "entered_not_observed"
                    },
                    if stamps.returned.is_some() {
                        "returned_observed"
                    } else {
                        "returned_not_observed"
                    },
                    if stamps.resumed.is_some() {
                        "resumed_observed"
                    } else {
                        "await_not_observed"
                    },
                );
                // Queue time starts at the original read boundary, so it also includes
                // observer/dispatch work before spawn_blocking. The job interval includes
                // OS/DB work and preemption, not just SQLite; the final interval includes
                // the blocking closure's tail work and await scheduling.
                for (name, start, end) in [
                    ("queue_to_enter_us", Some(stamps.queued), stamps.entered),
                    ("entered_to_returned_us", stamps.entered, stamps.returned),
                    ("returned_to_resumed_us", stamps.returned, stamps.resumed),
                ] {
                    let duration = start
                        .zip(end)
                        .and_then(|(start, end)| end.checked_duration_since(start));
                    let _ = write!(output, ",{name}=");
                    if let Some(duration) = duration {
                        let _ = write!(output, "{}", duration.as_micros());
                    } else {
                        output.push_str("unknown");
                    }
                }
                output.push('}');
            }
        }

        /// Copies only fixed public job metadata and a shared timing observer; never
        /// retains a Job, payload or key. Other fields describe the event, not report time.
        #[derive(Clone)]
        pub(super) struct Observation {
            pub(super) event: ReadEvent,
            pub(super) command_id: Option<u64>,
            pub(super) state: Option<&'static str>,
            pub(super) attempts: Option<u32>,
            pub(super) next_attempt: Option<u64>,
            pub(super) observed_unix: Option<u64>,
            pub(super) read_elapsed_ms: Option<u128>,
            pub(super) read_in_flight: bool,
            timing: ReadTiming,
        }

        impl Observation {
            pub(super) fn new(
                event: ReadEvent,
                job: Option<&Job>,
                read_elapsed_ms: Option<u128>,
                observed_unix: Option<u64>,
                timing: &ReadTiming,
            ) -> Self {
                Self {
                    event,
                    command_id: job.map(|job| job.command_id),
                    state: job.map(|job| job.state.as_str()),
                    attempts: job.map(|job| job.attempts),
                    next_attempt: job.map(|job| job.next_attempt),
                    observed_unix,
                    read_elapsed_ms,
                    read_in_flight: event == ReadEvent::Start,
                    timing: timing.clone(),
                }
            }
        }

        /// Instantaneous local hints. These separate samples are not a linearized
        /// admission decision and must not replace the test's durable-state assertions.
        #[derive(Clone, Copy)]
        pub(super) struct Activity {
            pub(super) peer_claimed: Option<bool>,
            pub(super) network_available: usize,
            pub(super) commands_available: usize,
            pub(super) runner_finished: bool,
            pub(super) node_finished: bool,
        }

        impl Activity {
            /// No waiting, SQL or network work is added to an observation. Contended or
            /// poisoned claim locks are recorded as unknown rather than changing flow.
            pub(super) fn capture(
                service: &Service,
                peer: &str,
                runner_finished: bool,
                node_finished: bool,
            ) -> Self {
                Self {
                    peer_claimed: service.admission.try_is_active(peer),
                    network_available: service.network.available_permits(),
                    commands_available: service.commands.available_permits(),
                    runner_finished,
                    node_finished,
                }
            }
        }

        struct Event {
            elapsed_ms: u128,
            stage: &'static str,
            observation: Option<Observation>,
            activity: Option<Activity>,
        }

        /// Kept by the test outside its timeout future, so cancellation cannot erase the
        /// last observations. Only the newest 64 entries survive; loss is explicit.
        pub(super) struct Trace {
            started: Instant,
            entries: RefCell<VecDeque<Event>>,
            dropped: Cell<u64>,
        }

        impl Trace {
            pub(super) fn new() -> Self {
                Self {
                    started: Instant::now(),
                    entries: RefCell::new(VecDeque::with_capacity(CAPACITY)),
                    dropped: Cell::new(0),
                }
            }

            pub(super) fn mark(&self, stage: &'static str) {
                self.push(stage, None, None);
            }

            pub(super) fn observe(
                &self,
                stage: &'static str,
                observation: Observation,
                activity: Activity,
            ) {
                self.push(stage, Some(observation), Some(activity));
            }

            fn push(
                &self,
                stage: &'static str,
                observation: Option<Observation>,
                activity: Option<Activity>,
            ) {
                let mut entries = self.entries.borrow_mut();
                if entries.len() == CAPACITY {
                    entries.pop_front();
                    self.dropped.set(self.dropped.get().saturating_add(1));
                }
                entries.push_back(Event {
                    elapsed_ms: self.started.elapsed().as_millis(),
                    stage,
                    observation,
                    activity,
                });
            }

            /// Format cached event fields and a nonwaiting timing snapshot at report
            /// time. No store read is added; missing boundaries do not imply work stopped
            /// or that an in-flight write did not commit.
            pub(super) fn describe(&self) -> String {
                let entries = self.entries.borrow();
                let mut output = format!("trace_dropped={},trace=[", self.dropped.get());
                for entry in entries.iter() {
                    let _ = write!(output, "{{ms={},stage={}", entry.elapsed_ms, entry.stage);
                    if let Some(read) = entry.observation.as_ref() {
                        let _ = write!(
                            output,
                            ",read={:?},command_id={:?},state={:?},attempts={:?},next_attempt={:?},observed_unix={:?},read_ms={:?},read_in_flight_at_event={}",
                            read.event,
                            read.command_id,
                            read.state,
                            read.attempts,
                            read.next_attempt,
                            read.observed_unix,
                            read.read_elapsed_ms,
                            read.read_in_flight,
                        );
                        read.timing.describe(&mut output);
                    }
                    if let Some(activity) = entry.activity {
                        let _ = write!(
                            output,
                            ",peer_claimed={:?},network_available={},commands_available={},runner_finished={},node_finished={}",
                            activity.peer_claimed,
                            activity.network_available,
                            activity.commands_available,
                            activity.runner_finished,
                            activity.node_finished,
                        );
                    }
                    output.push_str("};");
                }
                output.push(']');
                output
            }
        }

        #[test]
        fn read_timing_reports_ordered_intervals_and_unknown_boundaries() -> std::io::Result<()> {
            use std::time::Duration;

            let queued = Instant::now();
            let timing = ReadTiming::new(queued);
            let trace = Trace::new();
            trace.push(
                "read",
                Some(Observation::new(
                    ReadEvent::Start,
                    None,
                    None,
                    None,
                    &timing,
                )),
                None,
            );
            let initial = trace.describe();
            assert!(initial.contains("read_in_flight_at_event=true"));
            assert!(initial.contains("timing_at_report={entered=entered_not_observed,returned=returned_not_observed,await=await_not_observed,queue_to_enter_us=unknown,entered_to_returned_us=unknown,returned_to_resumed_us=unknown}"));

            let at = |micros| {
                queued
                    .checked_add(Duration::from_micros(micros))
                    .ok_or_else(|| std::io::Error::other("test instant overflow"))
            };
            {
                let mut stamps = timing
                    .0
                    .lock()
                    .map_err(|_| std::io::Error::other("test timing poisoned"))?;
                stamps.entered = Some(at(10)?);
                stamps.returned = Some(at(30)?);
                stamps.resumed = Some(at(60)?);
            }
            let completed = trace.describe();
            // The retained Start remains an at-event fact while its shared snapshot is
            // read at report time, including submillisecond intervals.
            assert!(completed.contains("read_in_flight_at_event=true"));
            assert!(completed.contains("timing_at_report={entered=entered_observed,returned=returned_observed,await=resumed_observed,queue_to_enter_us=10,entered_to_returned_us=20,returned_to_resumed_us=30}"));
            {
                let mut stamps = timing
                    .0
                    .lock()
                    .map_err(|_| std::io::Error::other("test timing poisoned"))?;
                stamps.entered = Some(at(30)?);
                stamps.returned = Some(at(10)?);
                stamps.resumed = None;
            }
            let reversed = trace.describe();
            assert!(reversed.contains("await=await_not_observed,queue_to_enter_us=30,entered_to_returned_us=unknown,returned_to_resumed_us=unknown"));
            let guard = timing
                .0
                .lock()
                .map_err(|_| std::io::Error::other("test timing poisoned"))?;
            assert!(trace.describe().contains("timing_at_report=unknown"));
            drop(guard);
            Ok(())
        }
    }

    use tasks::OwnedTasks;
    use trace::{Activity, Trace};

    fn policy_reply(value: control::DeliveryReply) -> control::CommandReply {
        match value {
            control::DeliveryReply::Policy(value) => *value,
            control::DeliveryReply::Endpoint(_) => {
                panic!("policy fixture received an endpoint result")
            }
        }
    }

    use std::{
        fs,
        future::{Future as _, poll_fn},
        net::{Ipv4Addr, SocketAddr},
        path::Path,
        task::Poll,
        time::Instant,
    };

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
        time::timeout,
    };

    use super::*;
    use crate::manage::{
        node::{self, tests::Fixture},
        proxy,
    };

    struct Harness {
        fixture: Fixture,
        child: Arc<Coordinator>,
        caller: Arc<Coordinator>,
        child_author: Arc<store::Guard>,
        administrator: String,
    }

    fn administrator(directory: &Path) -> io::Result<String> {
        rusqlite::Connection::open(directory.join("management.sqlite3"))
            .map_err(io::Error::other)?
            .query_row("SELECT id FROM administrators", [], |row| row.get(0))
            .map_err(io::Error::other)
    }

    fn coordinator(directory: &Path) -> io::Result<Arc<Coordinator>> {
        Coordinator::new(
            directory.to_owned(),
            store::load_policy(directory)?,
            Arc::new(store::lock(directory)?),
        )
    }

    impl Harness {
        fn new() -> io::Result<Self> {
            let fixture = Fixture::new(true, true)?;
            let child_author = Arc::new(store::lock(&fixture.server_state)?);
            let child = Coordinator::new(
                fixture.server_state.clone(),
                store::load_policy(&fixture.server_state)?,
                child_author.clone(),
            )?;
            let caller = coordinator(&fixture.client_state)?;
            let administrator = administrator(&fixture.client_state)?;
            let gate = store::update_lock(&fixture.server_state)?;
            store::set_owner(
                &fixture.server_state,
                &gate,
                &self::administrator(&fixture.server_state)?,
                1,
                Some(&fixture.client_id),
            )?;
            drop(gate);
            Ok(Self {
                fixture,
                child,
                caller,
                child_author,
                administrator,
            })
        }

        fn command(&self, id: u64, revision: u64, change: store::PolicyChange) -> store::Command {
            store::Command {
                target_node_id: self.fixture.server_id.clone(),
                epoch: 2,
                command_id: id,
                expected_policy_revision: revision,
                source_administrator_id: self.administrator.clone(),
                change,
            }
        }
    }

    async fn start_node(
        fixture: &Fixture,
        policy: &Arc<Coordinator>,
        address: SocketAddr,
        shutdown: CancellationToken,
    ) -> io::Result<(SocketAddr, tokio::task::JoinHandle<io::Result<()>>)> {
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let config = fixture.config(address)?;
        let directory = fixture.server_state.clone();
        let policy = policy.clone();
        Ok((
            address,
            tokio::spawn(node::serve(
                listener,
                config,
                directory,
                shutdown,
                Some(policy),
                None,
                None,
            )),
        ))
    }

    async fn configure_target(harness: &Harness, origin: String) -> io::Result<()> {
        let (actor, peer) = (
            harness.administrator.clone(),
            harness.fixture.server_id.clone(),
        );
        harness
            .caller
            .read(move |directory| {
                targets::configure(directory, &actor, &peer, None, &origin, true, None)
            })
            .await?;
        Ok(())
    }

    /// Observe one durable snapshot at a time without consuming the production
    /// coordinator's read permits. This assertion is not a concurrent-read load test.
    async fn wait_job(
        directory: &Path,
        peer: &str,
        state: targets::JobState,
        command_id: u64,
    ) -> io::Result<Job> {
        wait_job_observed(directory, peer, state, command_id, |_| {}).await
    }

    /// The synchronous observer receives fixed non-secret fields and shared timing
    /// stamps. It may update a caller-owned cache without adding store reads or
    /// extending deadlines.
    async fn wait_job_observed(
        directory: &Path,
        peer: &str,
        state: targets::JobState,
        command_id: u64,
        mut observe: impl FnMut(trace::Observation),
    ) -> io::Result<Job> {
        let started = Instant::now();
        let started_unix = now().ok();
        let mut observations = 0_u32;
        let mut would_block_reads = 0_u32;
        let mut last_job = None;
        let mut last_observed_unix = None;
        let mut last_read_millis = None;
        let mut read_in_flight = None;
        let result = timeout(Duration::from_secs(8), async {
            loop {
                let directory = directory.to_owned();
                let peer = peer.to_owned();
                let read_started = Instant::now();
                let timing = trace::ReadTiming::new(read_started);
                read_in_flight = Some(read_started);
                observe(trace::Observation::new(
                    trace::ReadEvent::Start,
                    last_job.as_ref(),
                    None,
                    last_observed_unix,
                    &timing,
                ));
                let worker_timing = timing.clone();
                let joined = tokio::task::spawn_blocking(move || {
                    worker_timing.entered();
                    let result = targets::job(&directory, &peer);
                    worker_timing.returned();
                    result
                })
                .await;
                timing.resumed();
                last_read_millis = Some(read_started.elapsed().as_millis());
                read_in_flight = None;
                let result = match joined {
                    Ok(result) => result,
                    Err(error) => {
                        observe(trace::Observation::new(
                            trace::ReadEvent::WorkerError,
                            last_job.as_ref(),
                            last_read_millis,
                            last_observed_unix,
                            &timing,
                        ));
                        return Err(io::Error::other(error));
                    }
                };
                match result {
                    Ok(job) => {
                        observations = observations.saturating_add(1);
                        last_observed_unix = now().ok();
                        observe(trace::Observation::new(
                            if job.is_some() {
                                trace::ReadEvent::Snapshot
                            } else {
                                trace::ReadEvent::Missing
                            },
                            job.as_ref(),
                            last_read_millis,
                            last_observed_unix,
                            &timing,
                        ));
                        match job {
                            Some(job) if job.state == state && job.command_id == command_id => {
                                return Ok(job);
                            }
                            job => last_job = job,
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        would_block_reads = would_block_reads.saturating_add(1);
                        observe(trace::Observation::new(
                            trace::ReadEvent::WouldBlock,
                            last_job.as_ref(),
                            last_read_millis,
                            last_observed_unix,
                            &timing,
                        ));
                    }
                    Err(error) => {
                        observe(trace::Observation::new(
                            trace::ReadEvent::StoreError,
                            last_job.as_ref(),
                            last_read_millis,
                            last_observed_unix,
                            &timing,
                        ));
                        return Err(error);
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        result.map_err(|_| {
        // Keep only observations already made inside the original deadline.
        // A fresh DB read here could block and obscure the timed-out state.
        let last = last_job.as_ref().map_or_else(
            || "none".to_owned(),
            |job| {
                format!(
                    "state={},command_id={},job_id={},attempts={},next_attempt={},policy_revision={:?},outcome_code={:?}",
                    job.state.as_str(), job.command_id, job.job_id, job.attempts,
                    job.next_attempt, job.policy_revision, job.outcome_code,
                )
            },
        );
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "controller job did not reach its expected state: expected_state={},command_id={},elapsed_ms={},observations={},would_block_reads={},last_read_ms={:?},read_in_flight_ms={:?},started_unix={:?},last_observed_unix={:?},timeout_unix={:?},last_job=[{last}]",
                state.as_str(), command_id, started.elapsed().as_millis(), observations,
                would_block_reads, last_read_millis,
                read_in_flight.map(|started| started.elapsed().as_millis()),
                started_unix, last_observed_unix, now().ok(),
            ),
        )
    })?
    }

    /// Scan artifacts for a nonempty fixture secret without blocking its node.
    /// A caller cancelling this wait must keep the fixture alive until blocking
    /// work finishes, for example by dropping its runtime before the fixture.
    async fn source_database_has_no_secret(directory: &Path, secret: &str) -> io::Result<()> {
        let directory = directory.to_owned();
        // Blocking work may finish after the scenario is cancelled. It owns and
        // clears its secret copy rather than borrowing the caller's value.
        let secret = zeroize::Zeroizing::new(secret.to_owned());
        tokio::task::spawn_blocking(move || {
            for name in [
                "management.sqlite3",
                "management.sqlite3-wal",
                "management.sqlite3-shm",
            ] {
                match fs::read(directory.join(name)) {
                    Ok(bytes) => assert!(
                        !bytes
                            .windows(secret.len())
                            .any(|value| value == secret.as_bytes()),
                        "one-time secret must not be in controller database artifacts"
                    ),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        })
        .await
        .map_err(io::Error::other)?
    }

    /// Keep the original I/O kind/source, but never format response bodies or SQL.
    struct TestStage {
        stage: &'static str,
        source: io::Error,
    }

    impl std::fmt::Debug for TestStage {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("TestStage")
                .field("stage", &self.stage)
                .field("kind", &self.source.kind())
                .finish_non_exhaustive()
        }
    }

    impl std::fmt::Display for TestStage {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "{} ({:?})", self.stage, self.source.kind())
        }
    }

    impl std::error::Error for TestStage {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.source)
        }
    }

    fn at_stage(stage: &'static str, source: io::Error) -> io::Error {
        io::Error::new(source.kind(), TestStage { stage, source })
    }

    /// Synchronize this sequential current-thread test with peer-claim release.
    ///
    /// The caller must immediately poll remote/submit after this returns: its claim
    /// is uncontended and completes in the same runtime poll. This is neither a
    /// production admission API nor an atomic reservation on a multi-thread runtime.
    /// A stale retry scan can otherwise hold a legitimate short-lived claim even
    /// after the durable job looks settled. Do not retry any submitted operation.
    /// The enclosing scenario deadline bounds this wait. A short sleep avoids
    /// repeatedly locking the claim set while the scanner awaits blocking I/O.
    async fn wait_peer_idle(service: &Service, peer: &str) -> io::Result<()> {
        loop {
            if !service
                .admission
                .is_active(peer)
                .map_err(|error| at_stage("wait for peer claim release", error))?
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn service_delivery_uses_real_policy_preserves_secrets_and_survives_browser_cancellation()
    -> io::Result<()> {
        let harness = Harness::new()?;
        let port = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
            .local_addr()?
            .port();
        let config = harness.fixture.write(
            "controller-proxy.json",
            format!(
                r#"{{"workers":1,"listeners":[{{"protocol":"http","bind":"127.0.0.1:{port}"}}]}}"#
            )
            .as_bytes(),
        )?;
        let mut proxy = proxy::start(
            proxy::load(&config)?,
            harness.child.reader(),
            harness.child_author.clone(),
        )?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let shutdown = CancellationToken::new();
        let phase = std::cell::Cell::new(("managed proxy readiness", Instant::now()));
        let trace = Trace::new();
        let mark = |name| {
            phase.set((name, Instant::now()));
            trace.mark(name);
        };
        mark("managed proxy readiness");
        let mut owned = OwnedTasks::new();
        let result = runtime.block_on(async {
            let work = async {
                proxy
                    .ready()
                    .await
                    .map_err(|error| at_stage("managed proxy readiness", error))?;
                mark("child policy activation");
                harness
                    .child
                    .activate()
                    .await
                    .map_err(|error| at_stage("child policy activation", error))?;
                mark("child node listener startup");
                let (address, node) = start_node(
                    &harness.fixture,
                    &harness.child,
                    SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                    shutdown.clone(),
                )
                .await
                .map_err(|error| at_stage("child node listener startup", error))?;
                let node = owned.insert("child node", shutdown.clone(), node);
                let origin = format!("https://localhost:{}", address.port());
                mark("controller target configuration");
                configure_target(&harness, origin.clone())
                    .await
                    .map_err(|error| at_stage("controller target configuration", error))?;
                let (service, runner) = Service::new(
                    harness.caller.clone(),
                    harness.fixture.client_tls.clone(),
                    harness.fixture.client_id.clone(),
                );
                let task = owned.insert(
                    "controller runner",
                    shutdown.clone(),
                    tokio::spawn(runner.run(shutdown.clone())),
                );
                mark("initial policy admission");
                wait_peer_idle(&service, &harness.fixture.server_id).await?;
                mark("initial policy observation");
                assert!(matches!(
                    service
                        .remote(harness.fixture.server_id.clone(), Request::Policy)
                        .await
                        .map_err(|error| at_stage("initial policy observation", error))?,
                    Reply::Policy(_)
                ));
                mark("create-user admission");
                wait_peer_idle(&service, &harness.fixture.server_id).await?;
                mark("create-user submit");
                let submitted = service
                    .submit(
                        harness.administrator.clone(),
                        1,
                        harness.command(
                            1,
                            1,
                            store::PolicyChange::CreateUser {
                                name: "Controlled user".into(),
                                protocols: vec![crate::access::Protocol::Http],
                                concurrent_limit: 2,
                            },
                        ),
                    )
                    .await
                    .map_err(|error| at_stage("create-user admission", error))?;
                mark("create-user response");
                let created = submitted
                    .response
                    .await
                    .map_err(|error| {
                        at_stage("create-user response receiver", io::Error::other(error))
                    })?
                    .map_err(|error| at_stage("create-user delivery", error))?;
                let user = policy_reply(created).user.unwrap().id;
                mark("create-credential admission");
                wait_peer_idle(&service, &harness.fixture.server_id).await?;
                mark("create-credential submit");
                let submitted = service
                    .submit(
                        harness.administrator.clone(),
                        1,
                        harness.command(
                            2,
                            2,
                            store::PolicyChange::CreateCredential {
                                user_id: user.clone(),
                            },
                        ),
                    )
                    .await
                    .map_err(|error| at_stage("create-credential admission", error))?;
                mark("create-credential response");
                let created = submitted
                    .response
                    .await
                    .map_err(|error| {
                        at_stage(
                            "create-credential response receiver",
                            io::Error::other(error),
                        )
                    })?
                    .map_err(|error| at_stage("create-credential delivery", error))?;
                let mut created = policy_reply(created);
                let secret = created.secret.take().unwrap();
                let credential = created.credential.take().unwrap();
                mark("create-credential source secret scan");
                source_database_has_no_secret(&harness.fixture.client_state, &secret).await?;
                mark("real proxy origin setup");
                let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                let echo_address = echo.local_addr()?;
                let echo = tokio::spawn(async move {
                    let (mut stream, _) = echo.accept().await?;
                    let mut bytes = [0; 4096];
                    let _ = stream.read(&mut bytes).await?;
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await
                });
                let request = || {
                    crate::oneself::test_http_client_builder()
                        .unwrap()
                        .proxy(
                            reqwest::Proxy::http(format!("http://127.0.0.1:{port}"))
                                .unwrap()
                                .basic_auth(&credential.login, &secret),
                        )
                        .timeout(Duration::from_secs(3))
                        .build()
                        .unwrap()
                        .get(format!("http://{echo_address}/"))
                };
                mark("real proxy authentication response");
                assert_eq!(
                    request().send().await.map_err(io::Error::other)?.status(),
                    http::StatusCode::OK
                );
                mark("real proxy origin drain");
                echo.await.map_err(io::Error::other)??;
                mark("cancelled-browser rotation admission");
                // Closing the browser's first-result receiver must not abandon the
                // accepted rotate, nor make the scheduler allocate command four.
                wait_peer_idle(&service, &harness.fixture.server_id).await?;
                mark("cancelled-browser rotation submit");
                let submitted = service
                    .submit(
                        harness.administrator.clone(),
                        1,
                        harness.command(
                            3,
                            3,
                            store::PolicyChange::RotateCredential {
                                id: credential.id.clone(),
                            },
                        ),
                    )
                    .await
                    .map_err(|error| at_stage("rotate-credential admission", error))?;
                let job_id = submitted.job.job_id;
                drop(submitted.response);
                mark("cancelled-browser rotation receipt observation");
                let applied = wait_job_observed(
                    &harness.fixture.client_state,
                    &harness.fixture.server_id,
                    targets::JobState::Applied,
                    3,
                    |observation| {
                        trace.observe(
                            "rotation receipt",
                            observation,
                            Activity::capture(
                                &service,
                                &harness.fixture.server_id,
                                owned.is_finished(task),
                                owned.is_finished(node),
                            ),
                        )
                    },
                )
                .await?;
                assert_eq!(applied.job_id, job_id);
                assert_eq!(applied.command_id, 3);
                assert_eq!(harness.child.reader().revision()?, 4);
                mark("rotated credential authentication rejection");
                assert_eq!(
                    request().send().await.map_err(io::Error::other)?.status(),
                    // Rotation invalidates the supplied secret rather than
                    // denying an otherwise authenticated user (RFC 9110 §15.5.8).
                    http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
                );
                let wire = control::Command {
                    version: 1,
                    target_node_id: harness.fixture.server_id.clone(),
                    resource: "proxy_policy".into(),
                    controller_epoch: "2".into(),
                    command_id: "3".into(),
                    expected_policy_revision: "3".into(),
                    source_administrator_id: harness.administrator.clone(),
                    mutation: control::Mutation::RotateCredential { id: credential.id },
                };
                mark("fixed-command replay admission");
                wait_peer_idle(&service, &harness.fixture.server_id).await?;
                let replayed = {
                    // Raw Command requests deliberately bypass remote(), which
                    // rejects mutations. Retain its same peer/network admission:
                    // waiting once before connect would leave another scheduling
                    // window for stale-scan rechecks to contend with TLS auth reads.
                    mark("fixed-command replay peer claim");
                    let _claim = service
                        .claim(&harness.fixture.server_id)
                        .map_err(|error| at_stage("fixed-command replay peer admission", error))?;
                    mark("fixed-command replay network permit");
                    let _permit =
                        service.network.clone().try_acquire_owned().map_err(|_| {
                            at_stage("fixed-command replay network admission", busy())
                        })?;
                    mark("fixed-command replay request");
                    let Reply::Command(replayed) = control::request(
                        &harness.caller,
                        harness.fixture.client_tls.clone(),
                        &origin,
                        &harness.fixture.server_id,
                        Request::Command(wire),
                    )
                    .await
                    .map_err(|error| at_stage("fixed-command replay request", error))?
                    else {
                        return Err(at_stage("fixed-command replay reply type", invalid()));
                    };
                    replayed
                };
                assert!(replayed.replayed && replayed.secret.is_none());
                assert_eq!(harness.child.reader().revision()?, 4);
                mark("network budget acquisition");
                // Full budgets reject before touching durable intent, and release
                // peer ownership even on this early WouldBlock path.
                let permits = service
                    .network
                    .clone()
                    .acquire_many_owned(4)
                    .await
                    .map_err(io::Error::other)?;
                mark("network-budget rejection admission");
                wait_peer_idle(&service, &harness.fixture.server_id).await?;
                mark("network-budget rejection request");
                assert_eq!(
                    service
                        .remote(harness.fixture.server_id.clone(), Request::Policy)
                        .await
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::WouldBlock
                );
                drop(permits);
                mark("network-budget release admission");
                wait_peer_idle(&service, &harness.fixture.server_id).await?;
                mark("network-budget release policy observation");
                service
                    .remote(harness.fixture.server_id.clone(), Request::Policy)
                    .await
                    .map_err(|error| {
                        at_stage("policy observation after network-budget release", error)
                    })?;
                mark("command budget acquisition");
                let permits = service
                    .commands
                    .clone()
                    .acquire_many_owned(2)
                    .await
                    .map_err(io::Error::other)?;
                mark("command-budget rejection admission");
                wait_peer_idle(&service, &harness.fixture.server_id).await?;
                mark("command-budget rejection submit");
                assert_eq!(
                    service
                        .submit(
                            harness.administrator.clone(),
                            1,
                            harness.command(
                                4,
                                4,
                                store::PolicyChange::SetUserActive {
                                    id: user.clone(),
                                    active: false
                                }
                            )
                        )
                        .await
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::WouldBlock
                );
                drop(permits);
                mark("accepted-command cancellation admission");
                wait_peer_idle(&service, &harness.fixture.server_id).await?;
                // Poll exactly through queue admission, then cancel before the
                // supervised runner gets another turn. No timing sleeps or race.
                mark("accepted-command queue poll and cancellation");
                {
                    let mut submit = Box::pin(service.submit(
                        harness.administrator.clone(),
                        1,
                        harness.command(
                            4,
                            4,
                            store::PolicyChange::SetUserActive {
                                id: user,
                                active: false,
                            },
                        ),
                    ));
                    poll_fn(|context| {
                        assert!(submit.as_mut().poll(context).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                }
                mark("accepted-command receipt observation");
                let applied = wait_job_observed(
                    &harness.fixture.client_state,
                    &harness.fixture.server_id,
                    targets::JobState::Applied,
                    4,
                    |observation| {
                        trace.observe(
                            "cancelled admission receipt",
                            observation,
                            Activity::capture(
                                &service,
                                &harness.fixture.server_id,
                                owned.is_finished(task),
                                owned.is_finished(node),
                            ),
                        )
                    },
                )
                .await?;
                assert_eq!(applied.command_id, 4);
                assert_eq!(harness.child.reader().revision()?, 5);
                mark("accepted-command source secret scan");
                source_database_has_no_secret(&harness.fixture.client_state, &secret).await?;
                mark("controller runner drain");
                shutdown.cancel();
                owned
                    .stop_and_join(task)
                    .await
                    .map_err(|error| at_stage("controller runner shutdown", error))?;
                mark("child node drain");
                owned
                    .stop_and_join(node)
                    .await
                    .map_err(|error| at_stage("child node shutdown", error))?;
                Ok::<_, io::Error>(())
            };
            let scenario = timeout(Duration::from_secs(25), work)
                .await
                .unwrap_or_else(|_| {
                    let (stage, started) = phase.get();
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "controller deadline at {stage}, phase elapsed {:?}",
                            started.elapsed()
                        ),
                    ))
                });
            // Keep this bounded, non-secret measurement visible when libtest
            // captures successful tests. The normal CI guard need not rerun the
            // scenario or change its test arguments to retain the observation.
            let output = format!("controller delivery trace: {}\n", trace.describe());
            let _ = std::io::Write::write_all(&mut std::io::stderr().lock(), output.as_bytes());
            owned.finish(scenario).await
        });
        shutdown.cancel();
        proxy.shutdown();
        let drained = runtime.block_on(proxy.finished());
        let finished = proxy.finish().result;
        result?;
        drained.map_err(|error| at_stage("managed proxy drain", error))?;
        finished.map_err(|error| at_stage("managed proxy finish", error))
    }

    #[test]
    fn cancelled_policy_observation_keeps_peer_claim_until_queued_store_work_finishes()
    -> io::Result<()> {
        let harness = Harness::new()?;
        // Runtime drop waits for submitted blocking work before the earlier-created
        // fixture is removed, including if a controlled-interleaving assertion fails.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()?;
        let (service, _runner) = Service::new(
            harness.caller.clone(),
            harness.fixture.client_tls.clone(),
            harness.fixture.client_id.clone(),
        );
        let peer = harness.fixture.server_id.clone();
        let checked = runtime.block_on(async {
            // No node listener or outbound request is needed: exercise the real
            // observation store path with a fixed controller-bound policy fixture.
            configure_target(&harness, "https://localhost:24443".into()).await?;
            let destination = peer.clone();
            let target = harness
                .caller
                .read(move |directory| targets::get(directory, &destination))
                .await?;
            assert!(target.observed_epoch.is_none());
            let policy = control::Policy {
                controller_node_id: Some(harness.fixture.client_id.clone()),
                controller_epoch: "2".into(),
                last_terminal_command: "0".into(),
                saved_revision: "1".into(),
                applied_revision: None,
                durable_applied_revision: None,
                proxy_running: false,
                user_count: 0,
                credential_count: 0,
            };
            let (entered, started) = oneshot::channel();
            let (release, released) = std::sync::mpsc::channel::<()>();
            let blocker = tokio::task::spawn_blocking(move || {
                entered.send(()).map_err(|_| unavailable())?;
                // Sender drop on any error or assertion also releases this worker;
                // no failed test may strand runtime teardown behind its own gate.
                let _ = released.recv();
                Ok::<_, io::Error>(())
            });
            timeout(Duration::from_secs(8), started)
                .await
                .map_err(|_| at_stage("observation blocker entry", unavailable()))?
                .map_err(io::Error::other)?;

            let mut cancelled = Box::pin(async {
                let claim = Arc::new(service.claim(&peer)?);
                service.observe(&target, &policy, claim.clone()).await
            });
            // Coordinator::read has no await before spawn_blocking. Its first poll
            // submits the actual observation behind the sole occupied worker. This
            // proves queued-work ownership, not that SQL has already started.
            assert!(futures_util::poll!(&mut cancelled).is_pending());
            drop(cancelled);
            assert_eq!(
                service.claim(&peer).err().unwrap().kind(),
                io::ErrorKind::WouldBlock,
                "caller cancellation must not release an outstanding observation's peer claim"
            );
            let other = service.claim(&harness.fixture.client_id)?;
            drop(other);
            release.send(()).map_err(|_| unavailable())?;
            blocker.await.map_err(io::Error::other)??;
            Ok::<_, io::Error>(())
        });
        // Cancelling the read discards its JoinHandle, not its blocking operation.
        // Join all runtime-owned work instead of assuming blocking-queue FIFO order
        // or polling the claim with a sleep before checking durable completion.
        drop(runtime);
        checked?;
        let claim = service.claim(&peer)?;
        drop(claim);
        let observed = targets::get(&harness.fixture.client_state, &peer)?;
        assert_eq!(observed.observed_epoch, Some(2));
        assert_eq!(observed.observed_command, Some(0));
        assert_eq!(observed.observed_policy_revision, Some(1));
        assert!(!observed.rollback_detected);
        Ok(())
    }

    #[test]
    fn stale_pending_candidate_claim_rejects_admission_until_async_recheck_releases_it()
    -> io::Result<()> {
        // This is a controlled helper-level interleaving of the real store and
        // Service admission/recheck methods, not a deterministic full Runner race.
        fn intent_rows(directory: &Path) -> io::Result<Vec<Vec<rusqlite::types::Value>>> {
            let connection = rusqlite::Connection::open_with_flags(
                directory.join("management.sqlite3"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .map_err(io::Error::other)?;
            let mut values = Vec::new();
            for query in [
                "SELECT * FROM control_outbox ORDER BY peer_id",
                "SELECT * FROM controller_audit ORDER BY sequence",
            ] {
                let mut statement = connection.prepare(query).map_err(io::Error::other)?;
                let columns = statement.column_count();
                let rows = statement
                    .query_map([], |row| {
                        (0..columns)
                            .map(|column| row.get(column))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .map_err(io::Error::other)?;
                for row in rows {
                    values.push(row.map_err(io::Error::other)?);
                }
            }
            Ok(values)
        }

        let harness = Harness::new()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let shutdown = CancellationToken::new();
        let result = runtime.block_on(async {
            let (address, node) = start_node(
                &harness.fixture,
                &harness.child,
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                shutdown.clone(),
            )
            .await?;
            let work = async {
                configure_target(&harness, format!("https://localhost:{}", address.port())).await?;
                let (service, runner) = Service::new(
                    harness.caller.clone(),
                    harness.fixture.client_tls.clone(),
                    harness.fixture.client_id.clone(),
                );
                service
                    .remote(harness.fixture.server_id.clone(), Request::Policy)
                    .await
                    .map_err(|error| at_stage("stale-candidate initial observation", error))?;
                let command = harness.command(
                    1,
                    1,
                    store::PolicyChange::CreateUser {
                        name: "Stale candidate user".into(),
                        protocols: vec![crate::access::Protocol::Http],
                        concurrent_limit: 1,
                    },
                );
                targets::enqueue(
                    &harness.fixture.client_state,
                    &harness.administrator,
                    1,
                    command,
                )?;
                let mut candidates = targets::pending(&harness.fixture.client_state, now()?)?;
                assert_eq!(candidates.len(), 1);
                let stale = candidates.pop().unwrap();
                assert!(stale.job.state == targets::JobState::Pending);
                let delivery = targets::load_delivery(
                    &harness.fixture.client_state,
                    &stale.job.peer_id,
                    &stale.job.job_id,
                )?;
                // Deliver the exact command through the real mTLS child and persist
                // its receipt before resuming admission of the old scan candidate.
                let delivery_claim = Arc::new(service.claim(&delivery.target.peer_id)?);
                let reply = service
                    .deliver(delivery, &delivery_claim)
                    .await
                    .map_err(|error| at_stage("stale-candidate setup delivery", error))?;
                drop(delivery_claim);
                let user_id = policy_reply(reply).user.unwrap().id;
                let job = targets::job(&harness.fixture.client_state, &harness.fixture.server_id)?
                    .unwrap();
                // API-only child: Saved is settled but never claims Applied/running.
                assert!(job.state == targets::JobState::Saved);
                assert_eq!(job.command_id, 1);
                let before = intent_rows(&harness.fixture.client_state)?;

                // Match Runner admission order, then hold its asynchronous exact
                // recheck continuation with test-owned channels. No production hook
                // or wall-clock scheduling assumption is needed.
                let permit = service
                    .commands
                    .clone()
                    .try_acquire_owned()
                    .map_err(io::Error::other)?;
                let claim = service.claim(&stale.target.peer_id)?;
                let (checked, observed) = oneshot::channel();
                let (release, released) = oneshot::channel();
                let caller = harness.caller.clone();
                let recheck = tokio::spawn(async move {
                    let (_permit, _claim) = (permit, claim);
                    caller
                        .read(move |directory| {
                            let result = targets::load_delivery(
                                directory,
                                &stale.job.peer_id,
                                &stale.job.job_id,
                            );
                            let _ = checked.send(result.as_ref().err().map(io::Error::kind));
                            // Dropping release on any assertion/error also unblocks
                            // this worker; failure cannot strand a blocking thread.
                            released.blocking_recv().map_err(|_| unavailable())?;
                            result
                        })
                        .await
                });
                assert_eq!(
                    observed.await.map_err(io::Error::other)?,
                    Some(io::ErrorKind::AlreadyExists)
                );
                assert_eq!(
                    service
                        .remote(harness.fixture.server_id.clone(), Request::Policy)
                        .await
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::WouldBlock
                );
                assert_eq!(
                    service
                        .submit(
                            harness.administrator.clone(),
                            1,
                            harness.command(
                                2,
                                2,
                                store::PolicyChange::SetUserActive {
                                    id: user_id.clone(),
                                    active: false,
                                },
                            ),
                        )
                        .await
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::WouldBlock
                );
                // Compare full durable intent/audit rows in RAM; never format the
                // private command payload if this assertion fails.
                assert!(intent_rows(&harness.fixture.client_state)? == before);
                release.send(()).map_err(|_| unavailable())?;
                assert_eq!(
                    recheck
                        .await
                        .map_err(io::Error::other)?
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::AlreadyExists
                );
                assert!(intent_rows(&harness.fixture.client_state)? == before);
                service
                    .remote(harness.fixture.server_id.clone(), Request::Policy)
                    .await
                    .map_err(|error| at_stage("observation after stale-claim release", error))?;
                let task = tokio::spawn(runner.run(shutdown.clone()));
                let submitted = service
                    .submit(
                        harness.administrator.clone(),
                        1,
                        harness.command(
                            2,
                            2,
                            store::PolicyChange::SetUserActive {
                                id: user_id,
                                active: false,
                            },
                        ),
                    )
                    .await
                    .map_err(|error| at_stage("admission after stale-claim release", error))?;
                submitted
                    .response
                    .await
                    .map_err(io::Error::other)?
                    .map_err(|error| at_stage("delivery after stale-claim release", error))?;
                let job = targets::job(&harness.fixture.client_state, &harness.fixture.server_id)?
                    .unwrap();
                assert!(job.state == targets::JobState::Saved);
                assert_eq!(job.command_id, 2);
                shutdown.cancel();
                task.await.map_err(io::Error::other)??;
                Ok::<_, io::Error>(())
            };
            let result = timeout(Duration::from_secs(25), work).await.map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "stale-candidate test timed out")
            });
            shutdown.cancel();
            node.await.map_err(io::Error::other)??;
            result?
        });
        shutdown.cancel();
        result
    }

    #[test]
    fn post_commit_truncated_credential_reply_recovers_only_receipt_then_explicit_rotation()
    -> io::Result<()> {
        use crate::manage::node::tests::{CutResponse, start_cut_response_node};
        use std::sync::atomic::Ordering;
        let harness = Harness::new()?;
        let port = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
            .local_addr()?
            .port();
        let config = harness.fixture.write(
            "cut-proxy.json",
            format!(
                r#"{{"workers":1,"listeners":[{{"protocol":"http","bind":"127.0.0.1:{port}"}}]}}"#
            )
            .as_bytes(),
        )?;
        let mut proxy = proxy::start(
            proxy::load(&config)?,
            harness.child.reader(),
            harness.child_author.clone(),
        )?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let shutdown = CancellationToken::new();
        // Retain only static stages outside the cancellable work. A deadline must
        // not erase the last boundary or perform a fresh read of private state.
        let phase = std::cell::Cell::new(("post-commit proxy readiness", Instant::now()));
        let trace = Trace::new();
        let mark = |name| {
            phase.set((name, Instant::now()));
            trace.mark(name);
        };
        let result = runtime.block_on(async {
        let work = async {
            mark("post-commit proxy readiness");
            proxy.ready().await?;
            mark("post-commit child policy activation");
            harness.child.activate().await?;
            let fault = Arc::new(CutResponse::default());
            mark("post-commit fault node startup");
            let (address, node) = start_cut_response_node(
                &harness.fixture,
                harness.child.clone(),
                fault.clone(),
                shutdown.clone(),
            )
            .await?;
            mark("post-commit target configuration");
            configure_target(&harness, format!("https://localhost:{}", address.port())).await?;
            mark("post-commit initial controller startup");
            let (service, runner) = Service::new(
                harness.caller.clone(),
                harness.fixture.client_tls.clone(),
                harness.fixture.client_id.clone(),
            );
            let runner_stop = shutdown.child_token();
            // First delivery is deliberately isolated from the retry scanner.
            // Otherwise a slow fixture/database can let the legitimate retry
            // recover Applied before this test observes its Pending checkpoint.
            // Recovery below still runs the ordinary production supervisor.
            let mut first_delivery = runner;
            let first_stop = runner_stop.clone();
            let runner = tokio::spawn(async move {
                loop {
                    let work = tokio::select! {
                        biased;
                        _ = first_stop.cancelled() => break,
                        work = first_delivery.receiver.recv() => work,
                    };
                    let Some(work) = work else {
                        break;
                    };
                    first_delivery.service.first(work).await;
                }
                Ok::<_, io::Error>(())
            });
            mark("post-commit initial policy observation");
            service
                .remote(harness.fixture.server_id.clone(), Request::Policy)
                .await?;
            mark("post-commit create-user submit");
            let submitted = service
                .submit(
                    harness.administrator.clone(),
                    1,
                    harness.command(
                        1,
                        1,
                        store::PolicyChange::CreateUser {
                            name: "Truncated credential user".into(),
                            protocols: vec![crate::access::Protocol::Http],
                            concurrent_limit: 1,
                        },
                    ),
                )
                .await?;
            mark("post-commit create-user response");
            let user = policy_reply(submitted
                .response
                .await
                .map_err(io::Error::other)??)
                .user
                .unwrap()
                .id;
            fault.armed.store(true, Ordering::Release);
            mark("post-commit truncated-credential submit");
            let submitted = service
                .submit(
                    harness.administrator.clone(),
                    1,
                    harness.command(
                        2,
                        2,
                        store::PolicyChange::CreateCredential {
                            user_id: user.clone(),
                        },
                    ),
                )
                .await?;
            let job_id = submitted.job.job_id;
            mark("post-commit truncated-credential response");
            let error = submitted
                .response
                .await
                .map_err(io::Error::other)?
                .err()
                .unwrap();
            mark("post-commit initial controller drain");
            runner_stop.cancel();
            runner.await.map_err(io::Error::other)??;
            mark("post-commit body failure checks");
            // Body-stage failure proves real HTTP headers were received: this
            // is neither a synthetic rejection nor a pre-commit connect error.
            assert!(
                error
                    .get_ref()
                    .is_some_and(|error| error.is::<control::TransportError>())
            );
            assert_eq!(error.to_string(), "node control transport failed (body)");
            assert_eq!(fault.cuts.load(Ordering::Acquire), 1);
            let peer = harness.fixture.server_id.clone();
            mark("post-commit pending job observation");
            let pending = harness
                .caller
                .read(move |directory| targets::job(directory, &peer))
                .await?
                .unwrap();
            mark("post-commit pending job checks");
            assert!(
                pending.state == targets::JobState::Pending,
                "first body failure job state={}, attempts={}, policy_revision={:?}",
                pending.state.as_str(),
                pending.attempts,
                pending.policy_revision,
            );
            assert_eq!(pending.job_id, job_id);
            assert_eq!(pending.command_id, 2);
            assert_eq!(pending.expected_policy_revision, Some(2));
            mark("post-commit child status observation");
            let status = harness.child.status().await?;
            assert_eq!(status.saved_revision, 3);
            assert_eq!(status.applied_revision, Some(3));
            assert_eq!(status.credential_count, 1);
            mark("post-commit child credential observation");
            let credentials = harness
                .child
                .read(|directory| store::list_credentials(directory, None, None, 50))
                .await?;
            assert_eq!(credentials.items.len(), 1);
            let credential = credentials.items.into_iter().next().unwrap();
            assert_eq!(credential.verifier_revision, 1);
            mark("post-commit controller reconstruction");
            drop(service);
            // A new runner knows only durable intent. Its same-command replay
            // cannot recover the discarded original credential secret.
            let (service, runner) = Service::new(
                harness.caller.clone(),
                harness.fixture.client_tls.clone(),
                harness.fixture.client_id.clone(),
            );
            let runner_stop = shutdown.child_token();
            let runner = tokio::spawn(runner.run(runner_stop.clone()));
            mark("post-commit recovered receipt observation");
            let applied = wait_job(
                &harness.fixture.client_state,
                &harness.fixture.server_id,
                targets::JobState::Applied,
                2,
            )
            .await
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "{error}; recovery_runner_finished={},fault_node_finished={},cuts={},replay_without_secret={}",
                        runner.is_finished(), node.is_finished(),
                        fault.cuts.load(Ordering::Acquire),
                        fault.replay_without_secret.load(Ordering::Acquire),
                    ),
                )
            })?;
            mark("post-commit recovered receipt checks");
            assert_eq!(applied.job_id, job_id);
            assert_eq!(applied.policy_revision, Some(3));
            assert!(fault.replay_without_secret.load(Ordering::Acquire));
            mark("post-commit recovered child status");
            let status = harness.child.status().await?;
            assert_eq!(status.saved_revision, 3);
            assert_eq!(status.credential_count, 1);
            mark("post-commit explicit rotation submit");
            let submitted = service
                .submit(
                    harness.administrator.clone(),
                    1,
                    harness.command(
                        3,
                        3,
                        store::PolicyChange::RotateCredential {
                            id: credential.id.clone(),
                        },
                    ),
                )
                .await?;
            mark("post-commit explicit rotation response");
            let mut rotated = policy_reply(submitted.response.await.map_err(io::Error::other)??);
            assert!(!rotated.replayed);
            let secret = rotated.secret.take().unwrap();
            assert!(rotated.secret_available);
            assert_eq!(rotated.receipt.policy_revision.as_deref(), Some("4"));
            assert_eq!(rotated.credential.as_ref().unwrap().id, credential.id);
            mark("post-commit rotated secret source scan");
            source_database_has_no_secret(&harness.fixture.client_state, &secret).await?;
            mark("post-commit proxy origin setup");
            let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = echo.local_addr()?;
            let echo = tokio::spawn(async move {
                let (mut stream, _) = echo.accept().await?;
                let mut bytes = [0; 4096];
                let _ = stream.read(&mut bytes).await?;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
            });
            mark("post-commit rotated credential authentication");
            let response = crate::oneself::test_http_client_builder().unwrap()
                .proxy(
                    reqwest::Proxy::http(format!("http://127.0.0.1:{port}"))
                        .unwrap()
                        .basic_auth(&credential.login, &secret),
                )
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap()
                .get(format!("http://{address}/"))
                .send()
                .await
                .map_err(io::Error::other)?;
            assert_eq!(response.status(), http::StatusCode::OK);
            mark("post-commit proxy origin drain");
            echo.await.map_err(io::Error::other)??;
            mark("post-commit final child status");
            let status = harness.child.status().await?;
            assert_eq!(status.saved_revision, 4);
            assert_eq!(status.credential_count, 1);
            assert_eq!(fault.cuts.load(Ordering::Acquire), 1);
            mark("post-commit recovery controller drain");
            runner_stop.cancel();
            shutdown.cancel();
            runner.await.map_err(io::Error::other)??;
            mark("post-commit fault node drain");
            node.await.map_err(io::Error::other)??;
            Ok::<_, io::Error>(())
        };
        let scenario = timeout(Duration::from_secs(25), work)
            .await
            .unwrap_or_else(|_| {
                let (stage, entered) = phase.get();
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "post-commit truncation deadline at {stage}, phase elapsed {:?}",
                        entered.elapsed()
                    ),
                ))
            });
        if scenario.is_err() {
            eprintln!("post-commit truncation trace: {}", trace.describe());
        }
        scenario
    });
        shutdown.cancel();
        proxy.shutdown();
        let drained = runtime.block_on(proxy.finished());
        let finished = proxy.finish().result;
        result?;
        drained?;
        finished
    }

    #[test]
    fn controller_restart_recovers_the_same_pending_command_on_the_original_endpoint()
    -> io::Result<()> {
        let stage = |name: &'static str, error: io::Error| {
            io::Error::new(
                error.kind(),
                format!("controller restart stage={name}: {error}"),
            )
        };
        let Harness {
            fixture,
            child,
            caller,
            child_author,
            administrator,
        } = Harness::new()?;
        let port = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
            .local_addr()?
            .port();
        let config = fixture.write(
            "restart-proxy.json",
            format!(
                r#"{{"workers":1,"listeners":[{{"protocol":"http","bind":"127.0.0.1:{port}"}}]}}"#
            )
            .as_bytes(),
        )?;
        let mut proxy = proxy::start(proxy::load(&config)?, child.reader(), child_author)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let cleanup = CancellationToken::new();
        let trace = Trace::new();
        trace.mark("proxy readiness");
        let mut owned = OwnedTasks::new();
        let result = runtime.block_on(async {
            let work = async {
                proxy.ready().await?;
                trace.mark("child activation");
                child.activate().await?;
                let node_stop = cleanup.child_token();
                trace.mark("initial child startup");
                let (address, node) = start_node(
                    &fixture,
                    &child,
                    SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                    node_stop.clone(),
                )
                .await?;
                let node = owned.insert("initial child node", node_stop.clone(), node);
                let origin = format!("https://localhost:{}", address.port());
                let (actor, peer, endpoint) = (
                    administrator.clone(),
                    fixture.server_id.clone(),
                    origin.clone(),
                );
                caller
                    .read(move |directory| {
                        targets::configure(directory, &actor, &peer, None, &endpoint, true, None)
                    })
                    .await?;
                let (service, runner) = Service::new(
                    caller.clone(),
                    fixture.client_tls.clone(),
                    fixture.client_id.clone(),
                );
                let runner_stop = cleanup.child_token();
                let runner = owned.insert(
                    "initial controller runner",
                    runner_stop.clone(),
                    tokio::spawn(runner.run(runner_stop.clone())),
                );
                trace.mark("initial policy observation");
                service
                    .remote(fixture.server_id.clone(), Request::Policy)
                    .await
                    .map_err(|error| stage("initial_policy", error))?;
                // A known observation precedes the outage. Pending configuration
                // cannot be repointed, so recovery must rebind this exact origin.
                node_stop.cancel();
                trace.mark("initial child drain");
                owned.stop_and_join(node).await?;
                let command = store::Command {
                    target_node_id: fixture.server_id.clone(),
                    epoch: 2,
                    command_id: 1,
                    expected_policy_revision: 1,
                    source_administrator_id: administrator.clone(),
                    change: store::PolicyChange::CreateUser {
                        name: "Recovered user".into(),
                        protocols: vec![crate::access::Protocol::Http],
                        concurrent_limit: 1,
                    },
                };
                let submitted = service
                    .submit(administrator.clone(), 1, command)
                    .await
                    .map_err(|error| stage("first_submit", error))?;
                trace.mark("offline first response");
                let job_id = submitted.job.job_id;
                let failure = submitted
                    .response
                    .await
                    .map_err(io::Error::other)?
                    .err()
                    .unwrap();
                assert!(
                    failure
                        .get_ref()
                        .is_some_and(|error| error.is::<control::TransportError>()),
                    "stopped listener must be a transport failure, not a node rejection"
                );
                // Stop retry scheduling before the read below can yield. A retry
                // already admitted before this continuation may still drain.
                runner_stop.cancel();
                trace.mark("initial controller drain");
                owned.stop_and_join(runner).await?;
                let peer = fixture.server_id.clone();
                trace.mark("quiescent pending observation");
                let pending = caller
                    .read(move |directory| targets::job(directory, &peer))
                    .await
                    .map_err(|error| stage("pending_observation", error))?
                    .unwrap();
                assert!(pending.state == targets::JobState::Pending);
                assert_eq!(pending.job_id, job_id);
                assert_eq!(pending.command_id, 1);
                assert_eq!(child.reader().revision()?, 1);
                drop(service);
                drop(caller);
                trace.mark("controller identity reload");
                // Rebuild the local reader/author and reload the exact TLS identity
                // from durable files. No in-memory delivery object is reused.
                let caller = coordinator(&fixture.client_state)?;
                let tls = super::super::tls::node_client_config(
                    &fixture.ca,
                    &fixture.client_cert,
                    &fixture.client_key,
                )?;
                let expected_local_id = store::inspect(&fixture.client_state)?.node_id;
                assert_eq!(expected_local_id, fixture.client_id);
                let (service, runner) = Service::new(caller.clone(), tls, expected_local_id);
                let node_stop = cleanup.child_token();
                trace.mark("rebound child startup");
                let (rebound, node) =
                    start_node(&fixture, &child, address, node_stop.clone()).await?;
                let node = owned.insert("restarted child node", node_stop.clone(), node);
                assert_eq!(rebound, address);
                let runner_stop = cleanup.child_token();
                let runner = owned.insert(
                    "restarted controller runner",
                    runner_stop.clone(),
                    tokio::spawn(runner.run(runner_stop.clone())),
                );
                trace.mark("restarted controller recovery");
                let applied = wait_job_observed(
                    &fixture.client_state,
                    &fixture.server_id,
                    targets::JobState::Applied,
                    1,
                    |observation| {
                        trace.observe(
                            "recovery receipt",
                            observation,
                            Activity::capture(
                                &service,
                                &fixture.server_id,
                                owned.is_finished(runner),
                                owned.is_finished(node),
                            ),
                        )
                    },
                )
                .await
                .map_err(|error| stage("recovered_applied", error))?;
                assert_eq!(applied.job_id, job_id);
                assert_eq!(applied.epoch, 2);
                assert_eq!(applied.expected_policy_revision, Some(1));
                assert_eq!(applied.policy_revision, Some(2));
                assert_eq!(child.reader().revision()?, 2);
                // Applied becomes visible at the SQLite commit, before the retry
                // task necessarily resumes and releases its peer claim. Drain the
                // real recovery worker before the separate verification read.
                runner_stop.cancel();
                trace.mark("recovered controller drain");
                owned
                    .stop_and_join(runner)
                    .await
                    .map_err(|error| stage("recovery_drain", error))?;
                let Reply::UsersPage(page) = service
                    .remote(
                        fixture.server_id.clone(),
                        Request::UsersPage {
                            after: None,
                            limit: 50,
                            include_deleted: false,
                        },
                    )
                    .await
                    .map_err(|error| stage("recovered_users", error))?
                else {
                    return Err(invalid());
                };
                assert_eq!(page.items.len(), 1);
                assert_eq!(page.items[0].name, "Recovered user");
                node_stop.cancel();
                trace.mark("recovered child drain");
                owned.stop_and_join(node).await?;
                Ok::<_, io::Error>(())
            };
            let scenario = timeout(Duration::from_secs(25), work)
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "controller restart test timed out",
                    ))
                });
            if scenario.is_err() {
                eprintln!("controller restart trace: {}", trace.describe());
            }
            owned.finish(scenario).await
        });
        cleanup.cancel();
        proxy.shutdown();
        let drained = runtime.block_on(proxy.finished());
        let finished = proxy.finish().result;
        result?;
        drained?;
        finished
    }

    #[test]
    fn user_result_survives_lost_first_response_and_rebuild_without_replaying_creation()
    -> io::Result<()> {
        let harness = Harness::new()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let shutdown = CancellationToken::new();
            let mut owned = OwnedTasks::new();
            let stage = std::cell::Cell::new("start user-result node");
            let scenario = timeout(Duration::from_secs(30), async {
                let (address, node) = start_node(
                    &harness.fixture,
                    &harness.child,
                    SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                    shutdown.clone(),
                )
                .await?;
                owned.insert("user-result child", shutdown.clone(), node);
                configure_target(&harness, format!("https://localhost:{}", address.port())).await?;
                let (service, mut runner) = Service::new(
                    harness.caller.clone(),
                    harness.fixture.client_tls.clone(),
                    harness.fixture.client_id.clone(),
                );
                stage.set("observe original policy");
                service
                    .remote(harness.fixture.server_id.clone(), Request::Policy)
                    .await?;
                // One real admitted delivery, with no retry scanner or retained
                // first-response object available to the rebuilt Service below.
                let first = owned.insert(
                    "user-result first delivery",
                    shutdown.child_token(),
                    tokio::spawn(async move {
                        let work = runner.receiver.recv().await.ok_or_else(unavailable)?;
                        runner.service.first(work).await;
                        Ok(())
                    }),
                );
                stage.set("admit creation and lose browser response");
                let submitted = service
                    .submit(
                        harness.administrator.clone(),
                        1,
                        harness.command(
                            1,
                            1,
                            store::PolicyChange::CreateUser {
                                name: "Recovered exact user".into(),
                                protocols: vec![crate::access::Protocol::Http],
                                concurrent_limit: 1,
                            },
                        ),
                    )
                    .await?;
                let job_id = submitted.job.job_id;
                assert!(submitted.job.user_creation);
                drop(submitted.response);
                owned.stop_and_join(first).await?;
                drop(service);
                let (service, _runner) = Service::new(
                    harness.caller.clone(),
                    harness.fixture.client_tls.clone(),
                    harness.fixture.client_id.clone(),
                );
                let peer = harness.fixture.server_id.clone();
                stage.set("rebuild discovers retained creation");
                let directory = harness.fixture.client_state.clone();
                let destination = peer.clone();
                let current =
                    tokio::task::spawn_blocking(move || targets::job(&directory, &destination))
                        .await
                        .map_err(io::Error::other)??
                        .ok_or_else(unavailable)?;
                assert!(current.user_creation && current.state == targets::JobState::Saved);
                assert_eq!(current.job_id, job_id);
                assert_eq!(
                    service
                        .user_result("bad-id".into(), job_id.clone())
                        .await
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::InvalidInput
                );
                let other_job_id = if job_id == "AAAAAAAAAAAAAAAAAAAAAA" {
                    "AQEBAQEBAQEBAQEBAQEBAQ"
                } else {
                    "AAAAAAAAAAAAAAAAAAAAAA"
                };
                assert_eq!(
                    service
                        .user_result(peer.clone(), other_job_id.to_owned())
                        .await
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::AlreadyExists
                );
                let permits = service
                    .network
                    .clone()
                    .acquire_many_owned(4)
                    .await
                    .map_err(io::Error::other)?;
                assert_eq!(
                    service
                        .user_result(peer.clone(), job_id.clone())
                        .await
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::WouldBlock
                );
                drop(permits);
                let claim = service.claim(&peer)?;
                assert_eq!(
                    service
                        .user_result(peer.clone(), job_id.clone())
                        .await
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::WouldBlock
                );
                drop(claim);

                stage.set("recover historical user identity");
                let recovered = service.user_result(peer.clone(), job_id.clone()).await?;
                assert_eq!(recovered.job.job_id, job_id);
                assert!(
                    recovered.job.user_creation && recovered.job.state == targets::JobState::Saved
                );
                let user_id = recovered.user_id;
                let Reply::UsersPage(users) = service
                    .remote(
                        peer.clone(),
                        Request::UsersPage {
                            after: None,
                            limit: 25,
                            include_deleted: false,
                        },
                    )
                    .await?
                else {
                    return Err(invalid());
                };
                assert_eq!(users.items.len(), 1);
                assert_eq!(users.items[0].id, user_id);
                assert_eq!(users.items[0].name, "Recovered exact user");
                assert_eq!(harness.child.reader().revision()?, 2);
                let status = harness.child.status().await?;
                assert_eq!(status.user_count, 1);
                assert_eq!(status.credential_count, 0);

                stage.set("repeat only the historical receipt read");
                assert_eq!(
                    service
                        .user_result(peer.clone(), job_id.clone())
                        .await?
                        .user_id,
                    user_id
                );
                assert_eq!(harness.child.reader().revision()?, 2);

                stage.set("owner revocation denies the retained result");
                harness
                    .child
                    .set_owner(administrator(&harness.fixture.server_state)?, 2, None)
                    .await?;
                let error = service
                    .user_result(peer.clone(), job_id.clone())
                    .await
                    .err()
                    .unwrap();
                let remote = error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<control::RemoteError>())
                    .ok_or_else(|| io::Error::other("expected typed owner rejection"))?;
                assert_eq!((remote.status, remote.code), (403, "peer_not_authorized"));

                stage.set("replacement and wrong action reject without network");
                let destination = peer.clone();
                let actor = harness.administrator.clone();
                let command = harness.command(
                    2,
                    2,
                    store::PolicyChange::SetUserActive {
                        id: user_id,
                        active: false,
                    },
                );
                let replacement = harness
                    .caller
                    .read(move |directory| targets::enqueue(directory, &actor, 1, command))
                    .await?;
                assert!(!replacement.user_creation);
                assert_eq!(
                    service
                        .user_result(peer.clone(), job_id)
                        .await
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::AlreadyExists
                );
                assert_eq!(
                    service
                        .user_result(destination, replacement.job_id)
                        .await
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::InvalidInput
                );
                assert_eq!(harness.child.reader().revision()?, 2);
                Ok::<_, io::Error>(())
            })
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("user-result deadline at {}", stage.get()),
                ))
            });
            owned.finish(scenario).await
        })
    }
}
