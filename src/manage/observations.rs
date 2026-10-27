//! Bounded, process-local cache of authenticated node operations snapshots.
//!
//! This is not a history replica. Only active incidents and terminal evidence
//! needed to end previously observed incidents survive a pull. The alert runner
//! rechecks the registration and TLS proof before journalling or publishing.

use super::{
    alerts,
    store::{self, targets::Target},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub(super) const MAX_SOURCES: usize = 128;
pub(super) const MAX_ITEMS: usize = 4096;
pub(super) const STALE: Duration = Duration::from_secs(90);

/// Actual authenticated response identity, never a JSON identity assertion.
/// Persistence must check both fields again under the policy update gate.
pub(super) struct Proof {
    pub(super) target_revision: u64,
    pub(super) authorization: store::RemoteAuthorization,
}

/// Fixed collection failures, separate from the monitored node's own health.
/// A local admission failure is skipped instead of overwriting a source error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Failure {
    Pending,
    Unavailable,
    Unsupported,
    NotAuthorized,
    Stale,
    Changed,
    Capacity,
    Incomplete,
}

impl Failure {
    pub(super) const fn code(self) -> &'static str {
        match self {
            Self::Pending => "remote_observation_pending",
            Self::Unavailable => "remote_observation_unavailable",
            Self::Unsupported => "remote_observation_unsupported",
            Self::NotAuthorized => "remote_observation_not_authorized",
            Self::Stale => "remote_observation_stale",
            Self::Changed => "remote_observation_changed",
            Self::Capacity => "remote_observation_capacity",
            Self::Incomplete => "remote_observation_incomplete",
        }
    }
}

/// One accepted response. Ages start before transport, so network, queueing and
/// publication time cannot make old evidence appear newly sampled. Recent items
/// are filtered to episodes seen active here, not advertised as remote history.
pub(super) struct Observation {
    pub(super) proof: Arc<Proof>,
    pub(super) boot_id: String,
    pub(super) revision: u64,
    pub(super) received_at: Instant,
    pub(super) source_age_millis: Option<u64>,
    pub(super) collection_error: bool,
    pub(super) dropped: u64,
    pub(super) active: Vec<alerts::Alert>,
    pub(super) recent: Vec<alerts::Alert>,
}

impl Observation {
    pub(super) fn age_millis(&self, now: Instant) -> Option<u64> {
        self.source_age_millis?.checked_add(
            u64::try_from(now.saturating_duration_since(self.received_at).as_millis()).ok()?,
        )
    }

    pub(super) fn complete(&self, now: Instant) -> bool {
        !self.collection_error
            && self
                .age_millis(now)
                .is_some_and(|age| u128::from(age) < STALE.as_millis())
    }
}

/// A saved target and its most recent accepted response or bounded failure.
/// Keeping the previous response on a failed pull preserves incident identity;
/// it is not permission to publish that response after authorization changes.
pub(super) struct Source {
    pub(super) peer_id: String,
    pub(super) target_revision: u64,
    pub(super) sequence: u64,
    pub(super) observation: Option<Arc<Observation>>,
    pub(super) failure: Option<Failure>,
}

pub(super) struct Snapshot {
    pub(super) sources: Vec<Arc<Source>>,
}

#[derive(Clone, Default)]
pub(super) struct Handle(Arc<Mutex<Cache>>);

#[derive(Default)]
struct Cache {
    sources: BTreeMap<String, Arc<Source>>,
    items: usize,
    sequence: u64,
}

impl Handle {
    /// Copy at most128 shared source handles without holding a lock during
    /// network, database, projection or per-incident work.
    pub(super) fn snapshot(&self) -> io::Result<Snapshot> {
        let cache = self.0.lock().map_err(|_| unavailable())?;
        Ok(Snapshot {
            sources: cache.sources.values().cloned().collect(),
        })
    }

    /// Reconcile one bounded directory read. Removed targets release their RAM
    /// budget; the journal independently verifies retirement before ending an
    /// incident. A changed target never inherits the old target's response.
    pub(super) fn reconcile(&self, targets: &[Target]) -> io::Result<()> {
        if targets.len() > MAX_SOURCES {
            return Err(unavailable());
        }
        let mut cache = self.0.lock().map_err(|_| unavailable())?;
        let peers: BTreeSet<_> = targets
            .iter()
            .map(|target| target.peer_id.as_str())
            .collect();
        if peers.len() != targets.len() {
            return Err(unavailable());
        }
        cache
            .sources
            .retain(|peer, _| peers.contains(peer.as_str()));
        cache.items = cache
            .sources
            .values()
            .map(|source| item_count(source.observation.as_deref()))
            .sum();
        for target in targets {
            let previous = cache.sources.get(&target.peer_id);
            if previous.is_some_and(|source| source.target_revision == target.revision) {
                continue;
            }
            let failure = if previous.is_some() {
                Failure::Changed
            } else {
                Failure::Pending
            };
            let old_count = previous.map_or(0, |source| item_count(source.observation.as_deref()));
            let sequence = cache.next_sequence()?;
            cache.items = cache.items.checked_sub(old_count).ok_or_else(unavailable)?;
            cache.sources.insert(
                target.peer_id.clone(),
                Arc::new(Source {
                    peer_id: target.peer_id.clone(),
                    target_revision: target.revision,
                    sequence,
                    observation: None,
                    failure: Some(failure),
                }),
            );
        }
        Ok(())
    }

    /// Accept a strictly decoded TLS response for the still-current target.
    /// At most4096 retained items are admitted globally. Two transport workers
    /// may additionally hold512 decoded items each; there is no paged staging.
    /// Capacity failure retains the previous response, marked unavailable.
    pub(super) fn accept(
        &self,
        proof: Proof,
        value: alerts::NodeSnapshot,
        started: Instant,
    ) -> io::Result<()> {
        let peer = &proof.authorization.node_id;
        if peer != &value.node_id || value.active.len() > 256 || value.recent.len() > 256 {
            return Err(unavailable());
        }
        let revision = value.revision.parse::<u64>().map_err(|_| unavailable())?;
        let dropped = value.dropped.parse::<u64>().map_err(|_| unavailable())?;
        let source_age_millis = value
            .age_millis
            .as_deref()
            .map(str::parse::<u64>)
            .transpose()
            .map_err(|_| unavailable())?;
        let mut cache = self.0.lock().map_err(|_| unavailable())?;
        let Some(previous) = cache.sources.get(peer).cloned() else {
            return Ok(());
        };
        if previous.target_revision != proof.target_revision {
            return Ok(());
        }
        if previous
            .observation
            .as_ref()
            .is_some_and(|old| old.boot_id == value.boot_id && revision < old.revision)
        {
            return cache.failed(peer, proof.target_revision, Failure::Changed);
        }
        // Terminal evidence is useful only for incidents this observer saw
        // active in this source boot. Do not backfill somebody else's history.
        let tracked: BTreeSet<_> = previous
            .observation
            .as_ref()
            .filter(|old| old.boot_id == value.boot_id)
            .into_iter()
            .flat_map(|old| {
                old.active
                    .iter()
                    .chain(&old.recent)
                    .map(|item| item.id.as_str())
            })
            .collect();
        let recent: Vec<_> = value
            .recent
            .into_iter()
            .filter(|item| tracked.contains(item.id.as_str()))
            .collect();
        let old_count = item_count(previous.observation.as_deref());
        let new_count = value
            .active
            .len()
            .checked_add(recent.len())
            .ok_or_else(unavailable)?;
        let remaining = cache.items.checked_sub(old_count).ok_or_else(unavailable)?;
        let total = remaining.checked_add(new_count).ok_or_else(unavailable)?;
        if total > MAX_ITEMS {
            return cache.failed(peer, proof.target_revision, Failure::Capacity);
        }
        let sequence = cache.next_sequence()?;
        let observation = Arc::new(Observation {
            proof: Arc::new(proof),
            boot_id: value.boot_id,
            revision,
            received_at: started,
            source_age_millis,
            collection_error: value.collection_error,
            dropped,
            active: value.active,
            recent,
        });
        let failure = if !observation.complete(Instant::now()) && !observation.collection_error {
            Some(Failure::Stale)
        } else if observation.collection_error || observation.dropped != 0 {
            Some(Failure::Incomplete)
        } else {
            None
        };
        cache.items = total;
        cache.sources.insert(
            previous.peer_id.clone(),
            Arc::new(Source {
                peer_id: previous.peer_id.clone(),
                target_revision: previous.target_revision,
                sequence,
                observation: Some(observation),
                failure,
            }),
        );
        Ok(())
    }

    pub(super) fn failed(&self, peer: &str, revision: u64, failure: Failure) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|_| unavailable())?
            .failed(peer, revision, failure)
    }
}

impl Cache {
    fn next_sequence(&mut self) -> io::Result<u64> {
        self.sequence = self.sequence.checked_add(1).ok_or_else(unavailable)?;
        Ok(self.sequence)
    }

    fn failed(&mut self, peer: &str, revision: u64, failure: Failure) -> io::Result<()> {
        let Some(previous) = self.sources.get(peer).cloned() else {
            return Ok(());
        };
        if previous.target_revision != revision || previous.failure == Some(failure) {
            return Ok(());
        }
        let sequence = self.next_sequence()?;
        self.sources.insert(
            peer.to_owned(),
            Arc::new(Source {
                peer_id: previous.peer_id.clone(),
                target_revision: revision,
                sequence,
                observation: previous.observation.clone(),
                failure: Some(failure),
            }),
        );
        Ok(())
    }
}

fn item_count(observation: Option<&Observation>) -> usize {
    observation.map_or(0, |value| value.active.len() + value.recent.len())
}

fn unavailable() -> io::Error {
    io::Error::other("remote operations observations are unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "AAECAwQFBgcICQoLDA0ODw";
    const BOOT: &str = "AQECAwQFBgcICQoLDA0ODw";

    fn target(peer: &str, revision: u64) -> Target {
        Target {
            peer_id: peer.into(),
            name: "test".into(),
            origin: "https://localhost:8444".into(),
            server_ip: None,
            active: true,
            retired: false,
            revision,
            observed_epoch: None,
            observed_command: None,
            observed_policy_revision: None,
            rollback_detected: false,
        }
    }

    fn proof(peer: &str, revision: u64) -> Proof {
        Proof {
            target_revision: revision,
            authorization: store::RemoteAuthorization {
                node_id: peer.into(),
                authorization_revision: 1,
                leaf: Arc::from([1_u8]),
            },
        }
    }

    fn alert(peer: &str, id: usize, status: alerts::Status) -> alerts::Alert {
        alerts::Alert {
            id: id.to_string(),
            kind: alerts::Kind::Policy,
            origin_node_id: peer.into(),
            resource_id: None,
            check: None,
            target: None,
            status,
            code: "policy_refresh_pending".into(),
            first_observed_at_unix_ms: Some("1".into()),
            last_observed_at_unix_ms: Some("2".into()),
            ended_at_unix_ms: (status != alerts::Status::Active).then(|| "3".into()),
            age_millis: "0".into(),
            evidence_sequence: Some("1".into()),
            evidence_fresh: true,
        }
    }

    fn snapshot(peer: &str, active: usize) -> alerts::NodeSnapshot {
        alerts::NodeSnapshot {
            node_id: peer.into(),
            boot_id: BOOT.into(),
            revision: "1".into(),
            observed_at_unix_ms: Some("1".into()),
            age_millis: Some("0".into()),
            collection_error: false,
            coverage: alerts::LocalCoverage {
                local_egress: false,
                local_traffic: false,
                local_proxy_expected: false,
                local_management_https: false,
                local_node_tls: false,
                local_proxy_tls: false,
            },
            active_count: active as u32,
            recent_count: 0,
            dropped: "0".into(),
            active: (1..=active)
                .map(|id| alert(peer, id, alerts::Status::Active))
                .collect(),
            recent: vec![],
        }
    }

    #[test]
    fn directory_change_fences_late_success_and_failure() -> io::Result<()> {
        let handle = Handle::default();
        handle.reconcile(&[target(PEER, 1)])?;
        handle.accept(proof(PEER, 1), snapshot(PEER, 2), Instant::now())?;
        handle.reconcile(&[target(PEER, 2)])?;
        handle.accept(proof(PEER, 1), snapshot(PEER, 3), Instant::now())?;
        handle.failed(PEER, 1, Failure::Unavailable)?;
        let current = handle.snapshot()?;
        assert_eq!(current.sources.len(), 1);
        assert_eq!(current.sources[0].failure, Some(Failure::Changed));
        assert!(current.sources[0].observation.is_none());
        assert_eq!(handle.0.lock().map_err(|_| unavailable())?.items, 0);
        handle.reconcile(&[])?;
        handle.accept(proof(PEER, 2), snapshot(PEER, 1), Instant::now())?;
        assert!(handle.snapshot()?.sources.is_empty());
        Ok(())
    }

    #[test]
    fn failed_pull_retains_identity_but_not_healthy_status() -> io::Result<()> {
        let handle = Handle::default();
        handle.reconcile(&[target(PEER, 1)])?;
        handle.accept(proof(PEER, 1), snapshot(PEER, 1), Instant::now())?;
        let previous = handle.snapshot()?.sources[0]
            .observation
            .clone()
            .ok_or_else(unavailable)?;
        handle.failed(PEER, 1, Failure::Unavailable)?;
        let current = handle.snapshot()?;
        assert_eq!(current.sources[0].failure, Some(Failure::Unavailable));
        assert!(Arc::ptr_eq(
            &previous,
            current.sources[0]
                .observation
                .as_ref()
                .ok_or_else(unavailable)?
        ));
        let sequence = current.sources[0].sequence;
        handle.failed(PEER, 1, Failure::Unavailable)?;
        assert_eq!(handle.snapshot()?.sources[0].sequence, sequence);
        Ok(())
    }

    #[test]
    fn terminal_evidence_only_matches_previously_active_source_boot() -> io::Result<()> {
        let handle = Handle::default();
        handle.reconcile(&[target(PEER, 1)])?;
        handle.accept(proof(PEER, 1), snapshot(PEER, 1), Instant::now())?;
        let mut recovered = snapshot(PEER, 0);
        recovered.revision = "2".into();
        recovered.recent = vec![
            alert(PEER, 1, alerts::Status::Recovered),
            alert(PEER, 2, alerts::Status::Recovered),
        ];
        recovered.recent_count = 2;
        handle.accept(proof(PEER, 1), recovered, Instant::now())?;
        let current = handle.snapshot()?;
        let observed = current.sources[0]
            .observation
            .as_ref()
            .ok_or_else(unavailable)?;
        assert_eq!(observed.recent.len(), 1);
        assert_eq!(observed.recent[0].id, "1");
        // A delayed journal may not have consumed the terminal evidence yet.
        // A repeated successful pull must not drop the already tracked episode.
        let mut repeated = snapshot(PEER, 0);
        repeated.revision = "2".into();
        repeated.recent = vec![alert(PEER, 1, alerts::Status::Recovered)];
        repeated.recent_count = 1;
        handle.accept(proof(PEER, 1), repeated, Instant::now())?;
        assert_eq!(
            handle.snapshot()?.sources[0]
                .observation
                .as_ref()
                .ok_or_else(unavailable)?
                .recent
                .len(),
            1
        );
        let mut restarted = snapshot(PEER, 0);
        restarted.boot_id = "AgECAwQFBgcICQoLDA0ODw".into();
        restarted.recent = vec![alert(PEER, 1, alerts::Status::Recovered)];
        restarted.recent_count = 1;
        handle.accept(proof(PEER, 1), restarted, Instant::now())?;
        assert!(
            handle.snapshot()?.sources[0]
                .observation
                .as_ref()
                .ok_or_else(unavailable)?
                .recent
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn full_cache_refresh_replaces_instead_of_temporarily_double_counting() -> io::Result<()> {
        let handle = Handle::default();
        let targets: Vec<_> = (0..17)
            .map(|index| target(&format!("test-peer-{index}"), 1))
            .collect();
        handle.reconcile(&targets)?;
        for item in &targets[..16] {
            handle.accept(
                proof(&item.peer_id, 1),
                snapshot(&item.peer_id, 256),
                Instant::now(),
            )?;
        }
        assert_eq!(handle.0.lock().map_err(|_| unavailable())?.items, MAX_ITEMS);
        handle.accept(
            proof(&targets[0].peer_id, 1),
            snapshot(&targets[0].peer_id, 256),
            Instant::now(),
        )?;
        handle.accept(
            proof(&targets[16].peer_id, 1),
            snapshot(&targets[16].peer_id, 1),
            Instant::now(),
        )?;
        let current = handle.snapshot()?;
        assert_eq!(
            current
                .sources
                .iter()
                .find(|source| source.peer_id == targets[16].peer_id)
                .ok_or_else(unavailable)?
                .failure,
            Some(Failure::Capacity)
        );
        assert_eq!(handle.0.lock().map_err(|_| unavailable())?.items, MAX_ITEMS);
        handle.reconcile(&targets[1..])?;
        handle.accept(
            proof(&targets[16].peer_id, 1),
            snapshot(&targets[16].peer_id, 1),
            Instant::now(),
        )?;
        assert_eq!(
            handle.0.lock().map_err(|_| unavailable())?.items,
            MAX_ITEMS - 255
        );
        Ok(())
    }

    #[test]
    fn transport_time_missing_clock_and_drops_never_become_fresh() -> io::Result<()> {
        let handle = Handle::default();
        handle.reconcile(&[target(PEER, 1)])?;
        let started = Instant::now().checked_sub(STALE).ok_or_else(unavailable)?;
        handle.accept(proof(PEER, 1), snapshot(PEER, 1), started)?;
        assert_eq!(handle.snapshot()?.sources[0].failure, Some(Failure::Stale));
        let mut value = snapshot(PEER, 1);
        value.age_millis = None;
        handle.accept(proof(PEER, 1), value, Instant::now())?;
        assert_eq!(handle.snapshot()?.sources[0].failure, Some(Failure::Stale));
        let mut value = snapshot(PEER, 1);
        value.dropped = "1".into();
        handle.accept(proof(PEER, 1), value, Instant::now())?;
        assert_eq!(
            handle.snapshot()?.sources[0].failure,
            Some(Failure::Incomplete)
        );
        assert!(
            handle.snapshot()?.sources[0]
                .observation
                .as_ref()
                .ok_or_else(unavailable)?
                .complete(Instant::now())
        );
        Ok(())
    }
}
