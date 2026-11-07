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
            .targets_write_guarded((claim, permit), move |dir| {
                // Transfer peer admission into the actual writer worker. A
                // cancelled waiter submits nothing; a cancelled response cannot
                // release the claim while its transaction is still committing.
                let job = crate::manage::store::targets::complete_user_result(
                    dir,
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
        // into a rollback of the committed transaction.
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
                .targets_write_guarded((claim, permit), move |dir| {
                    crate::manage::store::targets::complete_endpoint(
                        dir,
                        &job.peer_id,
                        &job.job_id,
                        &receipt,
                    )
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
            .targets_write_guarded((claim, permit), move |dir| {
                crate::manage::store::targets::complete(dir, &job.peer_id, &job.job_id, &receipt)
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
            .targets_write_guarded(claim, move |dir| {
                crate::manage::store::targets::observe(
                    dir,
                    &peer,
                    target_revision,
                    epoch,
                    command,
                    revision,
                )
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
                    .targets_write_guarded(claim, move |dir| {
                        crate::manage::store::targets::complete_endpoint(
                            dir, &peer, &job_id, &receipt,
                        )
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
                    mutation: command.change.try_into().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::Unsupported,
                            "version-one node control does not support routing mutations",
                        )
                    })?,
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
                    mutation: command.change.try_into().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "version-three preset action required",
                        )
                    })?,
                }),
                5 => Request::MaintenanceCommand(control::MaintenanceCommand {
                    version,
                    target_node_id: command.target_node_id,
                    resource: "proxy_policy".to_owned(),
                    controller_epoch: command.epoch.to_string(),
                    command_id: command.command_id.to_string(),
                    expected_policy_revision: command.expected_policy_revision.to_string(),
                    source_administrator_id: command.source_administrator_id,
                    mutation: control::MaintenanceMutation::try_from(command.change).map_err(
                        |_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "version-five admission action required",
                            )
                        },
                    )?,
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
                .targets_write_guarded(claim, move |dir| {
                    crate::manage::store::targets::complete(dir, &peer, &job_id, &receipt)
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
                .targets_write_guarded(claim, move |dir| {
                    crate::manage::store::targets::failed(dir, &peer, &job_id, blocked, now)
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
            .targets_write_guarded(claim, move |dir| {
                let job = crate::manage::store::targets::enqueue_intent(
                    dir,
                    &administrator,
                    target_revision,
                    command,
                )?;
                // Retain the same writer permit for first-delivery lookup.
                // A new read-budget race after commit must not unnecessarily
                // lose the live consumer of a one-time secret.
                let delivery =
                    crate::manage::store::targets::load_delivery(dir, &job.peer_id, &job.job_id);
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
    //! Real controller delivery and durable recovery after a lost response.

    fn policy_reply(value: control::DeliveryReply) -> control::CommandReply {
        match value {
            control::DeliveryReply::Policy(value) => *value,
            control::DeliveryReply::Endpoint(_) => {
                panic!("policy fixture received an endpoint result")
            }
        }
    }

    use std::{fs, path::Path};

    use tokio::time::timeout;

    use super::*;
    use crate::manage::node::tests::Fixture;

    struct Harness {
        fixture: Fixture,
        child: Arc<Coordinator>,
        caller: Arc<Coordinator>,
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

    async fn wait_job(
        directory: &Path,
        peer: &str,
        state: targets::JobState,
        command_id: u64,
    ) -> io::Result<Job> {
        timeout(Duration::from_secs(8), async {
            loop {
                let directory = directory.to_owned();
                let peer = peer.to_owned();
                // Keep SQLite off the async executor; retry only read contention.
                let result = tokio::task::spawn_blocking(move || targets::job(&directory, &peer))
                    .await
                    .map_err(io::Error::other)?;
                match result {
                    Ok(Some(job)) if job.state == state && job.command_id == command_id => {
                        return Ok(job);
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(io::Error::other)?
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

    #[test]
    fn post_commit_truncated_credential_reply_recovers_only_receipt_then_explicit_rotation()
    -> io::Result<()> {
        use crate::manage::node::tests::{CutResponse, start_cut_response_node};
        use std::sync::atomic::Ordering;
        let harness = Harness::new()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let shutdown = CancellationToken::new();
        let result = runtime.block_on(async {
        let work = async {
            harness.child.activate().await?;
            let fault = Arc::new(CutResponse::default());
            let (address, node) = start_cut_response_node(
                &harness.fixture,
                harness.child.clone(),
                fault.clone(),
                shutdown.clone(),
            )
            .await?;
            configure_target(&harness, format!("https://localhost:{}", address.port())).await?;
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
            service
                .remote(harness.fixture.server_id.clone(), Request::Policy)
                .await?;
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
            let user = policy_reply(submitted
                .response
                .await
                .map_err(io::Error::other)??)
                .user
                .unwrap()
                .id;
            fault.armed.store(true, Ordering::Release);
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
            let error = submitted
                .response
                .await
                .map_err(io::Error::other)?
                .err()
                .unwrap();
            runner_stop.cancel();
            runner.await.map_err(io::Error::other)??;
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
            let pending = harness
                .caller
                .read(move |directory| targets::job(directory, &peer))
                .await?
                .unwrap();
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
            let status = harness.child.status().await?;
            assert_eq!(status.saved_revision, 3);
            assert_eq!(status.applied_revision, Some(3));
            assert_eq!(status.credential_count, 1);
            let credentials = harness
                .child
                .read(|directory| store::list_credentials(directory, None, None, 50))
                .await?;
            assert_eq!(credentials.items.len(), 1);
            let credential = credentials.items.into_iter().next().unwrap();
            assert_eq!(credential.verifier_revision, 1);
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
            assert_eq!(applied.job_id, job_id);
            assert_eq!(applied.policy_revision, Some(3));
            assert!(fault.replay_without_secret.load(Ordering::Acquire));
            let status = harness.child.status().await?;
            assert_eq!(status.saved_revision, 3);
            assert_eq!(status.credential_count, 1);
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
            let mut rotated = policy_reply(submitted.response.await.map_err(io::Error::other)??);
            assert!(!rotated.replayed);
            let secret = rotated.secret.take().unwrap();
            assert!(rotated.secret_available);
            assert_eq!(rotated.receipt.policy_revision.as_deref(), Some("4"));
            assert_eq!(rotated.credential.as_ref().unwrap().id, credential.id);
            source_database_has_no_secret(&harness.fixture.client_state, &secret).await?;
            let status = harness.child.status().await?;
            assert_eq!(status.saved_revision, 4);
            assert_eq!(status.credential_count, 1);
            assert_eq!(fault.cuts.load(Ordering::Acquire), 1);
            runner_stop.cancel();
            shutdown.cancel();
            runner.await.map_err(io::Error::other)??;
            node.await.map_err(io::Error::other)??;
            Ok::<_, io::Error>(())
        };
        timeout(Duration::from_secs(25), work)
            .await
            .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "post-commit truncation deadline")))
    });
        shutdown.cancel();
        result
    }
}
