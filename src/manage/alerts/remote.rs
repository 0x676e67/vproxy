//! Cold projection of authenticated bounded snapshots into this observer's
//! existing state machine. It never performs network or SQLite work.

use super::*;
use crate::manage::{
    observations,
    store::alerts::{Target, history::Binding},
};

const SELF_CODES: &[&str] = &[
    "egress_address_unavailable",
    "egress_connection_refused",
    "egress_timed_out",
    "egress_permission_denied",
    "egress_network_unreachable",
    "egress_failed",
    "egress_family_mismatch",
    "health_catalog_unavailable",
    "health_catalog_stale",
    "https_identity_unavailable",
    "https_identity_expiring",
    "https_identity_expired",
    "https_identity_not_yet_valid",
    "https_identity_metadata_unavailable",
    "acme_attempt_unavailable",
    "acme_review_required",
    "acme_worker_stopped",
    "node_tls_identity_unavailable",
    "node_tls_identity_expiring",
    "node_tls_identity_expired",
    "node_tls_identity_not_yet_valid",
    "node_tls_identity_metadata_unavailable",
    "proxy_tls_identity_unavailable",
    "proxy_tls_identity_expiring",
    "proxy_tls_identity_expired",
    "proxy_tls_identity_not_yet_valid",
    "proxy_tls_identity_metadata_unavailable",
    "proxy_not_running",
    "policy_publication_unavailable",
    "policy_not_applied",
    "proxy_drain_failed",
    "proxy_drain_interrupted",
    "traffic_checkpoint_failed",
    "traffic_checkpoint_stale",
    "traffic_loss_possible",
    "traffic_history_gap",
    "traffic_time_uncertain",
];

impl Runner {
    /// Enable only after startup has required schema22 and the configured node
    /// controller. Existing/legacy monitors keep their original behavior.
    pub(in crate::manage) fn enable_remote_observation(&mut self, handle: observations::Handle) {
        self.observations = Some(handle);
        self.shared
            .remote_observation
            .store(true, Ordering::Release);
    }

    pub(super) fn remote_observation_facts(
        &self,
        frame: &mut Frame,
        targets: &[Target],
        now: Instant,
    ) {
        let Some(handle) = &self.observations else {
            return;
        };
        let snapshot = match handle.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                frame.fail(collect::Failure::RemoteObservation(error.kind()));
                return;
            }
        };
        let sources = snapshot
            .sources
            .iter()
            .map(|source| (source.peer_id.as_str(), source))
            .collect::<BTreeMap<_, _>>();
        frame.complete.insert(Kind::RemoteObservation);
        for target in targets {
            if target.id == self.node_id {
                frame.fail(collect::Failure::RemoteInvalid);
                continue;
            }
            frame.remote_bindings.push(Binding {
                peer_id: target.id.clone(),
                target_revision: target.revision,
                authorization_revision: target.authorization_revision,
                active: target.active,
                retired: target.retired,
                rollback: target.rollback,
                peer_active: target.peer_active,
            });
            if !target.active || target.retired || !target.peer_active {
                frame.remote_complete.insert(target.id.clone());
                continue;
            }
            let source = sources.get(target.id.as_str()).copied();
            let mut failure = source.and_then(|source| source.failure);
            let observation = source.and_then(|source| source.observation.as_deref());
            if target.rollback
                || source.is_some_and(|source| source.target_revision != target.revision)
                || observation.is_some_and(|observation| {
                    observation.proof.target_revision != target.revision
                        || observation.proof.authorization.authorization_revision
                            != target.authorization_revision
                        || observation.proof.authorization.node_id != target.id
                })
            {
                failure = Some(observations::Failure::Changed);
            }
            if failure.is_none() {
                failure = match observation {
                    None => Some(observations::Failure::Pending),
                    Some(observation) if observation.collection_error => {
                        Some(observations::Failure::Incomplete)
                    }
                    Some(observation) if !observation.complete(now.into_std()) => {
                        Some(if observation.dropped != 0 {
                            observations::Failure::Incomplete
                        } else {
                            observations::Failure::Stale
                        })
                    }
                    Some(_) => None,
                };
                if failure.is_none() && observation.is_some_and(|value| value.dropped != 0) {
                    failure = Some(observations::Failure::Incomplete);
                }
            }
            // A new source has no failure episode yet. Its missing first
            // observation still makes aggregate zero counts unconfirmed.
            if failure == Some(observations::Failure::Pending) {
                frame.error = true;
            }
            frame.facts.push(Fact {
                key: collect::key(Kind::RemoteObservation, &target.id, None, "operations"),
                lineage: format!("{}:{}", target.revision, target.authorization_revision),
                stamp: format!(
                    "{}:{}",
                    source.map_or(0, |source| source.sequence),
                    failure.map_or("ready", observations::Failure::code)
                ),
                sequence: None,
                check: None,
                target: None,
                outcome: match failure {
                    Some(observations::Failure::Pending) => Outcome::Unknown,
                    Some(failure) => Outcome::Failure(failure.code()),
                    None => Outcome::Success,
                },
            });
            let import_allowed = failure.is_none()
                || failure == Some(observations::Failure::Incomplete)
                    && observation.is_some_and(|value| value.complete(now.into_std()));
            if !import_allowed {
                continue;
            }
            let Some(observation) = observation else {
                continue;
            };
            let mut facts = Vec::with_capacity(observation.active.len() + observation.recent.len());
            let valid = observation
                .active
                .iter()
                .chain(&observation.recent)
                .all(|item| {
                    let Some(code) = SELF_CODES.iter().copied().find(|code| *code == item.code)
                    else {
                        return false;
                    };
                    let id = item
                        .id
                        .parse::<u64>()
                        .ok()
                        .filter(|id| *id > 0 && id.to_string() == item.id);
                    if id.is_none()
                        || item.origin_node_id != target.id
                        || matches!(
                            item.kind,
                            Kind::RemoteTraffic | Kind::RemoteJob | Kind::RemoteObservation
                        )
                    {
                        return false;
                    }
                    // Explicit Unmonitored is represented by absence from this
                    // complete set, never translated to a healthy observation.
                    if item.status == Status::Unmonitored {
                        return true;
                    }
                    let sequence = item
                        .evidence_sequence
                        .as_deref()
                        .and_then(|value| value.parse::<u64>().ok())
                        .filter(|sequence| *sequence > 0);
                    // Item age measures the last distinct evidence, not the
                    // source monitor's latest confirmation. A still-loaded
                    // expiring certificate can keep the same sequence for
                    // days. The complete snapshot's monotonic age already
                    // bounds transport/collection freshness; retain the
                    // producer's per-item freshness and sequence separately.
                    let fresh = sequence.is_some() && item.evidence_fresh;
                    facts.push(Fact {
                        key: collect::key(
                            item.kind,
                            &target.id,
                            item.resource_id.as_deref(),
                            &format!("source:{}:{}", observation.boot_id, item.id),
                        ),
                        lineage: format!(
                            "{}:{}:{}:{}",
                            target.revision,
                            target.authorization_revision,
                            observation.boot_id,
                            item.id
                        ),
                        stamp: format!(
                            "{}:{}:{}",
                            item.evidence_sequence.as_deref().unwrap_or("none"),
                            item.code,
                            if item.status == Status::Active {
                                "active"
                            } else {
                                "recovered"
                            }
                        ),
                        sequence,
                        check: item.check,
                        target: item.target,
                        outcome: if !fresh {
                            Outcome::Unknown
                        } else if item.status == Status::Active {
                            Outcome::Failure(code)
                        } else {
                            Outcome::Success
                        },
                    });
                    true
                });
            if valid {
                frame.remote_complete.insert(target.id.clone());
                frame.remote_proofs.push(observation.proof.clone());
                frame.facts.extend(facts);
            } else {
                if let Some(diagnostic) = frame.facts.last_mut() {
                    diagnostic.outcome = Outcome::Unknown;
                }
                frame.fail(collect::Failure::RemoteInvalid);
            }
        }
    }
}
