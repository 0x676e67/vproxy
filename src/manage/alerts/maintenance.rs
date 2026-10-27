//! Planned maintenance qualifies only from a coherent saved pause and the
//! exact original runtime intent. It never changes policy or recovers a fault.

use super::collect::key;
use super::*;
use crate::{
    access::AdmissionState,
    manage::{proxy, store},
};

impl Runner {
    /// A Web listener owner is an optional, dynamically configured producer.
    /// Intentional stop and in-flight bind/drain are unknown policy evidence;
    /// only actual failure emits not-running. Running delegates to the existing
    /// publication/maintenance projection without inventing a second policy.
    pub(super) fn service_policy_fact(
        &mut self,
        frame: &mut Frame,
        service: &proxy::service::View,
        revision: u64,
    ) -> bool {
        use proxy::service::Phase;
        if service.phase == Phase::Running && service.cleanup_confirmed {
            return true;
        }
        self.pending_policy = None;
        frame.complete.insert(Kind::Policy);
        frame.facts.push(Fact {
            key: key(Kind::Policy, &self.node_id, None, "policy"),
            lineage: revision.to_string(),
            stamp: format!("{}:{:?}", service.generation, service.phase),
            sequence: None,
            check: None,
            target: None,
            outcome: if service.phase == Phase::Failed || !service.cleanup_confirmed {
                Outcome::Failure("proxy_not_running")
            } else {
                Outcome::Unknown
            },
        });
        false
    }

    /// Project a stable before/after observation from the collector's one SQL
    /// await. No lease count, HTTP request or independent snapshot participates.
    pub(super) fn runtime_policy_facts(
        &mut self,
        frame: &mut Frame,
        snapshot: &store::alerts::Snapshot,
        publication: Option<AdmissionState>,
        running: bool,
        runtime: Option<&proxy::View>,
        now: Instant,
    ) {
        let planned = !running
            && runtime.is_some_and(|runtime| {
                matches!(
                    runtime.phase,
                    proxy::Phase::Draining | proxy::Phase::Drained
                ) && !runtime.stopping
                    && paused_intent(&self.node_id, snapshot, publication, runtime)
            });
        let transitioning = runtime.is_some_and(|runtime| {
            runtime.stopping || running && runtime.phase != proxy::Phase::Serving
        });
        if planned || transitioning {
            self.pending_policy = None;
            frame.complete.insert(Kind::Policy);
            frame.facts.push(Fact {
                key: key(Kind::Policy, &self.node_id, None, "policy"),
                lineage: snapshot.policy_revision.to_string(),
                stamp: String::new(),
                sequence: None,
                check: None,
                target: None,
                // Same-lineage failures remain stale. Maintenance is neither
                // policy recovery nor evidence that the source left scope.
                outcome: Outcome::Unknown,
            });
        } else {
            self.policy_fact(
                frame,
                snapshot.policy_revision,
                publication.map(|state| state.revision),
                running,
                now,
            );
        }
        if !self.proxy_expected {
            return;
        }
        if let Some(runtime) = runtime {
            let (sequence, outcome) = match runtime.phase {
                proxy::Phase::Serving => (0, Outcome::Unknown),
                proxy::Phase::Draining => (1, Outcome::Unknown),
                proxy::Phase::Drained => (2, Outcome::Unknown),
                proxy::Phase::Interrupted => (3, Outcome::Failure("proxy_drain_interrupted")),
                proxy::Phase::Failed => (4, Outcome::Failure("proxy_drain_failed")),
            };
            frame.facts.push(Fact {
                key: key(Kind::Policy, &self.node_id, None, "runtime"),
                lineage: format!("{}:{}", self.shared.boot_id, runtime.runtime_id),
                stamp: sequence.to_string(),
                sequence: Some(sequence),
                check: None,
                target: None,
                outcome,
            });
        }
    }
}

/// Ownership and the whole-policy CAS remain part of the maintenance proof.
/// Late policy writes, withdrawn control, absent old-schema metadata or an
/// unavailable Reader cannot borrow an earlier request's planned status.
fn paused_intent(
    node: &str,
    snapshot: &store::alerts::Snapshot,
    publication: Option<AdmissionState>,
    runtime: &proxy::View,
) -> bool {
    let (Some(saved), Some(published), Some(intent)) = (
        snapshot.admission.as_ref(),
        publication,
        runtime.intent.as_ref(),
    ) else {
        return false;
    };
    !saved.accepting
        && !published.accepting
        && saved.node_id == node
        && intent.node_id == node
        && intent.epoch == saved.ownership.epoch
        && intent.revision == snapshot.policy_revision
        && published.revision == snapshot.policy_revision
        && match &intent.actor {
            proxy::DrainActor::Local { .. } => saved.ownership.controller_node_id.is_none(),
            proxy::DrainActor::Remote {
                controller_node_id, ..
            } => saved.ownership.controller_node_id.as_ref() == Some(controller_node_id),
        }
}
