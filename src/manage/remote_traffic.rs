//! Shared bounded pulls of configured nodes' totals and optional own alerts.
//! The existing controller owns TLS, peer exclusion and network budgets; this
//! runner never creates another trust domain, proxy path or arbitrary RPC queue.

use super::{
    controller,
    node::control::{self, Reply, Request},
    observations,
    policy::Coordinator,
    store::{remote_traffic::Failure, targets},
};
use std::{collections::VecDeque, io, sync::Arc, time::Duration};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// At most128 candidate IDs and two active pulls. Slow/unavailable nodes delay
/// freshness, not the proxy runtime; an in-progress cycle never queues another.
pub(super) struct Runner {
    policy: Arc<Coordinator>,
    controller: Arc<controller::Service>,
    observations: Option<observations::Handle>,
}
impl Runner {
    pub(super) fn new(policy: Arc<Coordinator>, controller: Arc<controller::Service>) -> Self {
        Self {
            policy,
            controller,
            observations: None,
        }
    }

    /// Both reads use the same two workers and controller admission. Reads for
    /// one peer are sequential so they cannot continually exclude each other.
    pub(super) fn with_observations(mut self, observations: observations::Handle) -> Self {
        self.observations = Some(observations);
        self
    }
    pub(super) async fn run(self, shutdown: CancellationToken) -> io::Result<()> {
        let mut next_cycle = tokio::time::Instant::now();
        let mut tasks = JoinSet::new();
        let mut pending = VecDeque::new();
        loop {
            tokio::select! {
                biased;
                _=shutdown.cancelled()=>break,
                result=tasks.join_next(),if !tasks.is_empty()=>{
                    if result.is_some_and(|result|result.is_err()){tracing::warn!("remote observation worker did not complete");}
                    if tasks.is_empty() && pending.is_empty() { next_cycle = tokio::time::Instant::now() + Duration::from_secs(30); }
                },
                _=tokio::time::sleep_until(next_cycle),if tasks.is_empty()&&pending.is_empty()=>{
                    next_cycle = tokio::time::Instant::now() + Duration::from_secs(30);
                    match candidates(&self.policy).await {
                        Ok(targets) => {
                            if let Some(observations) = &self.observations
                                && let Err(error) = observations.reconcile(&targets) {
                                tracing::warn!(kind=?error.kind(), "remote operations directory reconciliation delayed");
                            }
                            pending=targets.into();
                        }
                        Err(error)=>tracing::warn!(kind=?error.kind(),"remote observation target scan delayed")
                    }
                }
            }
            while tasks.len() < 2 {
                let Some(target) = pending.pop_front() else {
                    break;
                };
                let policy = self.policy.clone();
                let controller = self.controller.clone();
                let observations = self.observations.clone();
                tasks.spawn(async move {
                    pull(policy, controller.clone(), target.clone()).await;
                    if let Some(observations) = observations {
                        pull_observations(controller, observations, target).await;
                    }
                });
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        // An already-started blocking import owns its gate/author until commit;
        // aborting this network task cannot release those owners prematurely.
        Ok(())
    }
}

async fn pull_observations(
    controller: Arc<controller::Service>,
    observations: observations::Handle,
    target: targets::Target,
) {
    let started = std::time::Instant::now();
    let result = async {
        let Reply::OperationsSnapshot(value) = controller
            .remote(target.peer_id.clone(), Request::OperationsSnapshot)
            .await?
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected operations snapshot response",
            ));
        };
        let value = *value;
        observations.accept(
            observations::Proof {
                target_revision: target.revision,
                authorization: value.authorization,
            },
            value.value,
            started,
        )
    }
    .await;
    if let Err(error) = result {
        if error.kind() == io::ErrorKind::WouldBlock {
            return;
        }
        let failure = observation_failure(&error);
        if let Err(error) = observations.failed(&target.peer_id, target.revision, failure) {
            tracing::warn!(kind=?error.kind(), "remote operations cache update delayed");
        }
    }
}

fn observation_failure(error: &io::Error) -> observations::Failure {
    use observations::Failure;
    if error
        .get_ref()
        .is_some_and(|source| source.is::<control::TransportError>())
    {
        return Failure::Unavailable;
    }
    if let Some(error) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<control::RemoteError>())
    {
        return match error.code {
            "operations_alerts_capacity" => Failure::Capacity,
            "operations_alerts_unsupported"
            | "node_protocol_unsupported"
            | "management_upgrade_required" => Failure::Unsupported,
            "peer_not_authorized" | "peer_authorization_changed" => Failure::NotAuthorized,
            _ => Failure::Unavailable,
        };
    }
    match error.kind() {
        io::ErrorKind::Unsupported => Failure::Unsupported,
        io::ErrorKind::PermissionDenied => Failure::NotAuthorized,
        // A malformed new response must not revive an older accepted payload
        // through the valid-but-bounded-history Incomplete classification.
        io::ErrorKind::InvalidData => Failure::Unavailable,
        _ => Failure::Unavailable,
    }
}

async fn candidates(policy: &Arc<Coordinator>) -> io::Result<Vec<targets::Target>> {
    policy
        .read(|directory| {
            let mut values = Vec::new();
            let mut after = None;
            loop {
                let page = targets::list(directory, after.as_deref(), 25, false)?;
                values.extend(page.items.into_iter().filter(|target| {
                    target.active && !target.retired && !target.rollback_detected
                }));
                if values.len() > 128 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "remote traffic target capacity exceeded",
                    ));
                }
                match page.next_cursor {
                    Some(cursor) if after.as_deref() != Some(cursor.as_str()) => {
                        after = Some(cursor)
                    }
                    Some(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "remote target cursor did not advance",
                        ));
                    }
                    None => break,
                }
            }
            Ok(values)
        })
        .await
}

async fn pull(
    policy: Arc<Coordinator>,
    controller: Arc<controller::Service>,
    target: targets::Target,
) {
    let peer = target.peer_id.clone();
    let revision = target.revision;
    let result = async {
        let Reply::TrafficSnapshot(value) = controller
            .remote(peer.clone(), Request::TrafficSnapshot)
            .await?
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected remote traffic response",
            ));
        };
        let value = *value;
        policy
            .traffic_write(move |writer| {
                writer.import(
                    &value.authorization,
                    revision,
                    value.value,
                    super::traffic::now(),
                )
            })
            .await??;
        Ok::<_, io::Error>(())
    }
    .await;
    if let Err(error) = result {
        // Busy commands keep priority: do not replace a genuine remote error
        // with a local admission failure, or classify Windows TCP EACCES as an
        // authenticated node permission rejection.
        if error.kind() == io::ErrorKind::WouldBlock {
            return;
        }
        let failure = classify(&error);
        let _ = policy
            .traffic_write(move |writer| writer.failed(&peer, revision, failure))
            .await;
    }
}

pub(super) fn classify(error: &io::Error) -> Failure {
    if error
        .get_ref()
        .is_some_and(|source| source.is::<control::TransportError>())
    {
        return Failure::Unavailable;
    }
    if let Some(error) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<control::RemoteError>())
    {
        return match error.code {
            "traffic_unsupported" | "node_protocol_unsupported" | "management_upgrade_required" => {
                Failure::Unsupported
            }
            "peer_not_authorized" | "peer_authorization_changed" => Failure::NotAuthorized,
            _ => Failure::Unavailable,
        };
    }
    match error.kind() {
        io::ErrorKind::Unsupported => Failure::Unsupported,
        io::ErrorKind::PermissionDenied => Failure::NotAuthorized,
        io::ErrorKind::InvalidData => Failure::Continuity,
        _ => Failure::Unavailable,
    }
}
