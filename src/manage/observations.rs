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
