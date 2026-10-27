//! In-process operations incidents derived from existing, bounded observations.
//!
//! This monitor never probes, contacts a node or repairs policy. On schema21,
//! accepted incident transitions are journaled before publishing their RAM view.
//! A healthy observation closes only its own incident episode; losing evidence
//! does not turn a failure into recovery. Process restart deliberately starts a
//! new boot; durable history cannot restore current freshness or prove recovery.

mod collect;
mod journal;
mod maintenance;
mod remote;

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use super::store::alerts::history::{EndReason, Observation, Transition, TransitionKind};
use super::{acme, certificates, health, policy::Coordinator, traffic};

const MAX_ACTIVE: usize = 6_144;
const MAX_REMOTE: usize = 4_096;
const MAX_REMOTE_SOURCES: usize = 128;
const MAX_TOTAL: usize = 12_288;
// The actual source bound is 1024 addresses × five checks, 128 targets ×
// traffic/job, plus catalog, policy, checkpoint, three continuity facts and
// at most eighteen loaded TLS identities with metadata/validity slots, plus
// the two local ACME attempt/worker slots.
// Both active incidents and remembered healthy evidence stay below this cap;
// authoritative retirement removes remembered keys instead of leaking history.
const MAX_RECENT: usize = 256;
const MAX_PAGE: u32 = 16;
const INTERVAL: Duration = Duration::from_secs(5);
// A fully escaped maximum cursor still fits before individual query decoding.
const MAX_QUERY_BYTES: usize = 768;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    EgressCheck,
    HealthCatalog,
    ManagementHttps,
    NodeTls,
    ProxyTls,
    Policy,
    TrafficCheckpoint,
    TrafficContinuity,
    RemoteTraffic,
    RemoteJob,
    /// This observer cannot obtain current evidence from a selected peer. It
    /// does not assert that the peer's proxy or any of its own sources failed.
    RemoteObservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    Active,
    Recovered,
    Unmonitored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Filter {
    Active,
    Recent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PageError {
    InvalidQuery,
    Changed,
    Unavailable,
}

pub(super) struct Query {
    pub(super) filter: Filter,
    pub(super) after: Option<String>,
    pub(super) limit: u32,
}

impl Query {
    /// Parse only observation state, a bounded opaque cursor and page size.
    /// This does not read a monitor or accept a remote destination.
    pub(super) fn parse(raw: Option<&str>) -> Result<Self, PageError> {
        let raw = raw.unwrap_or_default();
        if raw.len() > MAX_QUERY_BYTES {
            return Err(PageError::InvalidQuery);
        }
        let mut filter = None;
        let mut after = None;
        let mut limit = None;
        for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
            match key.as_ref() {
                "state" if filter.is_none() => {
                    filter = Some(match value.as_ref() {
                        "active" => Filter::Active,
                        "recent" => Filter::Recent,
                        _ => return Err(PageError::InvalidQuery),
                    });
                }
                "after" if after.is_none() => {
                    if value.is_empty() || value.len() > 160 || !value.is_ascii() {
                        return Err(PageError::InvalidQuery);
                    }
                    after = Some(value.into_owned());
                }
                "limit" if limit.is_none() => {
                    let parsed = value.parse::<u32>().map_err(|_| PageError::InvalidQuery)?;
                    if !(1..=MAX_PAGE).contains(&parsed) || parsed.to_string() != value.as_ref() {
                        return Err(PageError::InvalidQuery);
                    }
                    limit = Some(parsed);
                }
                _ => return Err(PageError::InvalidQuery),
            }
        }
        Ok(Self {
            filter: filter.unwrap_or(Filter::Active),
            after,
            limit: limit.unwrap_or(10),
        })
    }

    /// Validate a cursor against the source's boot and egress-only revision.
    /// Local all-source cursors belong to another namespace and are rejected.
    pub(super) fn egress_offset(&self, boot: &str, revision: u64) -> Result<usize, PageError> {
        scoped_cursor(
            self.after.as_deref(),
            boot,
            revision,
            self.filter.egress_code(),
            ["egress-active", "egress-recent"],
        )
    }

    /// A node-self page is distinct from both the local administrator's full
    /// inventory and the older independently counted egress projection.
    pub(super) fn node_offset(&self, boot: &str, revision: u64) -> Result<usize, PageError> {
        scoped_cursor(
            self.after.as_deref(),
            boot,
            revision,
            self.filter.node_code(),
            ["node-active", "node-recent"],
        )
    }
}

#[derive(Clone, Copy, Serialize)]
pub(super) struct Coverage {
    pub(super) local_egress: bool,
    pub(super) local_traffic: bool,
    pub(super) local_proxy_expected: bool,
    /// Actual local browser identity metadata is covered, or the legacy ACME
    /// source is present. Coverage is not a trust or readiness assertion.
    pub(super) local_management_https: bool,
    pub(super) local_node_tls: bool,
    pub(super) local_proxy_tls: bool,
    /// Local registered-target/cache/job facts remain covered even without an
    /// outbound collector. That configuration becomes its own precise issue;
    /// it never becomes a claim that the remote node or proxy is offline.
    pub(super) remote_cached: bool,
    pub(super) remote_egress: bool,
    pub(super) remote_observation: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Alert {
    pub(super) id: String,
    pub(super) kind: Kind,
    pub(super) origin_node_id: String,
    pub(super) resource_id: Option<String>,
    pub(super) check: Option<health::CheckKind>,
    pub(super) target: Option<SocketAddr>,
    pub(super) status: Status,
    pub(super) code: String,
    pub(super) first_observed_at_unix_ms: Option<String>,
    pub(super) last_observed_at_unix_ms: Option<String>,
    pub(super) ended_at_unix_ms: Option<String>,
    pub(super) age_millis: String,
    pub(super) evidence_sequence: Option<String>,
    pub(super) evidence_fresh: bool,
}

#[derive(Serialize)]
pub(super) struct Page {
    pub(super) boot_id: String,
    pub(super) revision: String,
    pub(super) observed_at_unix_ms: Option<String>,
    pub(super) age_millis: Option<String>,
    pub(super) collection_error: bool,
    pub(super) coverage: Coverage,
    pub(super) active_count: u32,
    pub(super) recent_count: u32,
    pub(super) dropped: String,
    pub(super) items: Vec<Alert>,
    pub(super) next_cursor: Option<String>,
}

/// Only this node's egress observations. Counts and errors describe this
/// projection, not the node's remote directory or other management services.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EgressPage {
    pub(super) node_id: String,
    pub(super) boot_id: String,
    pub(super) revision: String,
    pub(super) observed_at_unix_ms: Option<String>,
    pub(super) age_millis: Option<String>,
    pub(super) collection_error: bool,
    pub(super) monitored: bool,
    pub(super) active_count: u32,
    pub(super) recent_count: u32,
    pub(super) dropped: String,
    pub(super) items: Vec<Alert>,
    pub(super) next_cursor: Option<String>,
}

/// Configured sources on the selected node, without its downstream directory
/// or cache coverage. A true flag is not evidence that a service is healthy.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LocalCoverage {
    pub(super) local_egress: bool,
    pub(super) local_traffic: bool,
    pub(super) local_proxy_expected: bool,
    pub(super) local_management_https: bool,
    pub(super) local_node_tls: bool,
    pub(super) local_proxy_tls: bool,
}

/// A bounded view of this node's own incidents, not a recursively forwarded
/// fleet view or durable history. IDs and revisions share the local monitor;
/// gaps and conservative cursor invalidation can reflect excluded activity.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NodePage {
    pub(super) node_id: String,
    pub(super) boot_id: String,
    pub(super) revision: String,
    pub(super) observed_at_unix_ms: Option<String>,
    pub(super) age_millis: Option<String>,
    pub(super) collection_error: bool,
    pub(super) coverage: LocalCoverage,
    pub(super) active_count: u32,
    pub(super) recent_count: u32,
    pub(super) dropped: String,
    pub(super) items: Vec<Alert>,
    pub(super) next_cursor: Option<String>,
}

/// One atomic node-self inventory. Capacity is rejected, never truncated into
/// an apparently complete sample. This is not a remote-history replication API.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NodeSnapshot {
    pub(super) node_id: String,
    pub(super) boot_id: String,
    pub(super) revision: String,
    pub(super) observed_at_unix_ms: Option<String>,
    pub(super) age_millis: Option<String>,
    pub(super) collection_error: bool,
    pub(super) coverage: LocalCoverage,
    pub(super) active_count: u32,
    pub(super) recent_count: u32,
    pub(super) dropped: String,
    pub(super) active: Vec<Alert>,
    pub(super) recent: Vec<Alert>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotError {
    Unavailable,
    Capacity,
}

#[derive(Clone)]
pub(super) struct Handle(Arc<Shared>);

pub(super) struct Runner {
    policy: Arc<Coordinator>,
    node_id: String,
    health: Option<health::Handle>,
    traffic: Option<traffic::Handle>,
    acme: Option<acme::Handle>,
    certificates: Option<certificates::Handle>,
    proxy_expected: bool,
    remote_collector_available: bool,
    shared: Arc<Shared>,
    remote_clocks: BTreeMap<String, collect::RemoteClock>,
    certificate_clocks: BTreeMap<Key, collect::CertificateClock>,
    pending_policy: Option<(String, Instant)>,
    started: Instant,
    // Fixed local classifications only, never retained io::Error messages.
    collection_failures: Vec<collect::Failure>,
    history_enabled: bool,
    history_started: bool,
    history_sequence: u64,
    history_pending: Option<Arc<journal::Prepared>>,
    history_failure: Option<io::ErrorKind>,
    history_blocked: bool,
    observations: Option<super::observations::Handle>,
}

struct Shared {
    boot_id: String,
    coverage: Coverage,
    state: Mutex<Arc<State>>,
    available: AtomicBool,
    remote_observation: AtomicBool,
}

/// One supervised writer updates this bounded projection. HTTP readers only
/// clone a small page; neither path holds this mutex across I/O or an await.
#[derive(Clone)]
struct State {
    node_id: String,
    // Internal accepted-frame identity. Error overlays advance page revisions,
    // but never this generation or source clocks, IDs and evidence sequences.
    generation: u64,
    revision: u64,
    next_id: u64,
    evidence: u64,
    completed: Option<Instant>,
    observed_at: Option<u64>,
    collection_error: bool,
    // Published with the accepted frame, never ahead of its incidents/history.
    // None retains startup coverage until a complete TLS inventory is accepted.
    proxy_tls: Option<bool>,
    active: BTreeMap<Key, Incident>,
    recent: VecDeque<Incident>,
    known: BTreeMap<Key, Evidence>,
    dropped: u64,
    // Count only discarded episodes from the node-self export. Shared ring
    // eviction by another source can lose a local episode, but an excluded
    // episode's own eviction is not a gap in this projection.
    local_dropped: u64,
    egress: EgressMetadata,
}

/// Local metadata over the same incident/evidence storage; no second monitor
/// or retained copy of the egress inventory is needed.
#[derive(Clone)]
struct EgressMetadata {
    revision: u64,
    // Gaps must describe only exported episodes/metadata, not other services.
    next_id: u64,
    evidence: u64,
    completed: Option<Instant>,
    observed_at: Option<u64>,
    collection_error: bool,
    dropped: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
/// Stable issue identity within a source: kind, node, resource and check slot.
/// A changed source generation is tracked separately so it cannot prove that
/// an older resource or process recovered.
struct Key {
    kind: Kind,
    origin: String,
    resource: Option<String>,
    slot: String,
}

impl Key {
    fn mirrored(&self, node_id: &str) -> bool {
        self.origin != node_id
            && !matches!(
                self.kind,
                Kind::RemoteTraffic | Kind::RemoteJob | Kind::RemoteObservation
            )
    }

    fn budget(&self, node_id: &str) -> usize {
        if self.kind == Kind::RemoteObservation {
            2
        } else if self.mirrored(node_id) {
            1
        } else {
            0
        }
    }

    fn covered(&self, node_id: &str, local: &BTreeSet<Kind>, remote: &BTreeSet<String>) -> bool {
        if self.mirrored(node_id) {
            remote.contains(&self.origin)
        } else {
            local.contains(&self.kind)
        }
    }

    fn local_egress(&self, node_id: &str) -> bool {
        self.origin == node_id && matches!(self.kind, Kind::EgressCheck | Kind::HealthCatalog)
    }

    fn local_operation(&self, node_id: &str) -> bool {
        self.origin == node_id
            && match self.kind {
                Kind::EgressCheck
                | Kind::HealthCatalog
                | Kind::ManagementHttps
                | Kind::NodeTls
                | Kind::ProxyTls
                | Kind::Policy
                | Kind::TrafficCheckpoint
                | Kind::TrafficContinuity => true,
                Kind::RemoteTraffic | Kind::RemoteJob | Kind::RemoteObservation => false,
            }
    }
}

/// Last accepted non-unknown evidence, including healthy sources without an
/// active incident. Keeping it prevents duplicate or regressed samples from
/// creating a new episode or refreshing the previous observation time.
#[derive(Clone)]
struct Evidence {
    /// Boot/epoch, resource revision and address identity as applicable.
    lineage: String,
    /// Source-specific equality token; wall time alone never makes it newer.
    stamp: String,
    sequence: u64,
}

/// An episode retains its original failure reason when ended. Recovered means
/// newer same-lineage success; Unmonitored deliberately makes no health claim.
#[derive(Clone)]
struct Incident {
    id: u64,
    // The all-source ID remains stable for the local management page.
    egress_id: Option<u64>,
    key: Key,
    check: Option<health::CheckKind>,
    target: Option<SocketAddr>,
    status: Status,
    code: &'static str,
    first: Option<u64>,
    last: Option<u64>,
    ended: Option<u64>,
    changed: Instant,
    sequence: u64,
    fresh: bool,
}

#[derive(Clone, Copy)]
enum Outcome {
    Failure(&'static str),
    Success,
    Unknown,
}

/// A source observation before it changes the projection. Probe sequences are
/// supplied by health; stamped metadata transitions receive a process-local
/// acceptance sequence. These numbers are not command or policy revisions.
struct Fact {
    key: Key,
    lineage: String,
    stamp: String,
    sequence: Option<u64>,
    check: Option<health::CheckKind>,
    target: Option<SocketAddr>,
    outcome: Outcome,
}

#[derive(Default)]
/// One collection round, possibly partial. Only a complete current inventory
/// may prove that an absent source left scope; a failed read cannot do so.
struct Frame {
    facts: Vec<Fact>,
    // Only a complete current inventory can prove that a resource left scope.
    // A failed or stale read is deliberately absent from this set.
    complete: BTreeSet<Kind>,
    // A complete local source never retires an unread peer's same-kind issue.
    remote_complete: BTreeSet<String>,
    remote_proofs: Vec<Arc<super::observations::Proof>>,
    remote_bindings: Vec<super::store::alerts::history::Binding>,
    error: bool,
    failures: Vec<collect::Failure>,
    // Captured directly after the health read, before unrelated storage awaits.
    egress: Option<EgressCollection>,
}

struct EgressCollection {
    completed: Instant,
    observed_at: Option<u64>,
    error: bool,
}

/// Construct owners without reading storage, starting work or making requests.
/// The caller supervises `Runner::run` with the other management services.
#[allow(clippy::too_many_arguments)]
pub(super) fn new(
    policy: Arc<Coordinator>,
    node_id: String,
    health: Option<health::Handle>,
    traffic: Option<traffic::Handle>,
    proxy_expected: bool,
    remote_collector_available: bool,
    acme: Option<acme::Handle>,
    certificates: Option<certificates::Handle>,
) -> io::Result<(Handle, Runner)> {
    if !super::store::valid_id(&node_id) {
        return Err(unavailable());
    }
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|_| unavailable())?;
    let tls_coverage = certificates.as_ref().map(certificates::Handle::coverage);
    let shared = Arc::new(Shared {
        boot_id: URL_SAFE_NO_PAD.encode(random),
        coverage: Coverage {
            local_egress: health.is_some(),
            local_traffic: proxy_expected && traffic.is_some(),
            local_proxy_expected: proxy_expected,
            local_management_https: tls_coverage.is_some_and(|coverage| coverage.management)
                || acme.is_some(),
            local_node_tls: tls_coverage.is_some_and(|coverage| coverage.node),
            local_proxy_tls: tls_coverage.is_some_and(|coverage| coverage.proxy),
            remote_cached: true,
            remote_egress: false,
            remote_observation: false,
        },
        state: Mutex::new(Arc::new(State::new(node_id.clone()))),
        available: AtomicBool::new(true),
        remote_observation: AtomicBool::new(false),
    });
    Ok((
        Handle(shared.clone()),
        Runner {
            policy,
            node_id,
            health,
            traffic,
            acme,
            certificates,
            proxy_expected,
            remote_collector_available,
            shared,
            remote_clocks: BTreeMap::new(),
            certificate_clocks: BTreeMap::new(),
            pending_policy: None,
            started: Instant::now(),
            collection_failures: Vec::new(),
            history_enabled: false,
            history_started: false,
            history_sequence: 0,
            history_pending: None,
            history_failure: None,
            history_blocked: false,
            observations: None,
        },
    ))
}

impl Shared {
    fn state(&self) -> io::Result<MutexGuard<'_, Arc<State>>> {
        if !self.available.load(Ordering::Acquire) {
            return Err(unavailable());
        }
        self.state.lock().map_err(|_| unavailable())
    }

    fn snapshot(&self) -> io::Result<Arc<State>> {
        let state = self.state()?;
        Ok(Arc::clone(&state))
    }

    /// The only expensive copy and state calculation happen outside this lock.
    /// Replaced maps are dropped outside it as well, keeping readers bounded.
    fn publish(&self, expected: &Arc<State>, next: State) -> io::Result<()> {
        let mut state = self.state()?;
        if !Arc::ptr_eq(&state, expected) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "observation changed",
            ));
        }
        let previous = std::mem::replace(&mut *state, Arc::new(next));
        drop(state);
        drop(previous);
        Ok(())
    }

    #[cfg(test)]
    fn apply(&self, frame: Frame, now: Instant, wall: Option<u64>) -> io::Result<()> {
        let current = self.snapshot()?;
        let mut next = (*current).clone();
        next.apply(frame, now, wall)?;
        self.publish(&current, next)
    }
}

impl Runner {
    /// Enable only after startup has established schema21. Legacy schemas keep
    /// the existing RAM monitor and never attempt journal startup or writes.
    pub(super) fn enable_history(&mut self) {
        self.history_enabled = true;
    }
    /// One round at a time; missed ticks are skipped rather than queued. A read
    /// already admitted to spawn_blocking keeps its original permit/author on
    /// cancellation. No detached async tasks or independent I/O budgets exist.
    pub(super) async fn run(mut self, shutdown: CancellationToken) -> io::Result<()> {
        let mut interval = tokio::time::interval(INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return Ok(()),
                _ = interval.tick() => {}
            }
            if shutdown.is_cancelled() || self.history_before_collect().await {
                continue;
            }
            let frame = tokio::select! {
                biased;
                _ = shutdown.cancelled() => return Ok(()),
                frame = self.collect() => frame,
            };
            if !shutdown.is_cancelled() {
                self.accept_frame(frame).await?;
            }
        }
    }
}

impl Handle {
    fn coverage(&self, state: &State) -> Coverage {
        let mut coverage = self.0.coverage;
        coverage.local_proxy_tls = state.proxy_tls.unwrap_or(coverage.local_proxy_tls);
        coverage.remote_observation = self.0.remote_observation.load(Ordering::Acquire);
        coverage
    }
    /// Snapshot this node's eight source kinds under one existing RAM lock.
    /// Neither downstream mirrors nor collector diagnostics can recurse.
    pub(super) fn node_snapshot(&self) -> Result<NodeSnapshot, SnapshotError> {
        let state = self.0.state().map_err(|_| SnapshotError::Unavailable)?;
        let local = |incident: &&Incident| incident.key.local_operation(&state.node_id);
        let active_count = state.active.values().filter(local).count();
        let recent_count = state.recent.iter().filter(local).count();
        if active_count > 256 || recent_count > 256 {
            return Err(SnapshotError::Capacity);
        }
        let now = Instant::now();
        let coverage = self.coverage(&state);
        Ok(NodeSnapshot {
            node_id: state.node_id.clone(),
            boot_id: self.0.boot_id.clone(),
            revision: state.revision.to_string(),
            observed_at_unix_ms: state.observed_at.map(|value| value.to_string()),
            age_millis: state
                .completed
                .map(|time| millis(now.saturating_duration_since(time))),
            collection_error: state.collection_error,
            coverage: LocalCoverage {
                local_egress: coverage.local_egress,
                local_traffic: coverage.local_traffic,
                local_proxy_expected: coverage.local_proxy_expected,
                local_management_https: coverage.local_management_https,
                local_node_tls: coverage.local_node_tls,
                local_proxy_tls: coverage.local_proxy_tls,
            },
            active_count: u32::try_from(active_count).map_err(|_| SnapshotError::Unavailable)?,
            recent_count: u32::try_from(recent_count).map_err(|_| SnapshotError::Unavailable)?,
            dropped: state.local_dropped.to_string(),
            active: state
                .active
                .values()
                .filter(local)
                .map(|incident| incident.view(now))
                .collect(),
            recent: state
                .recent
                .iter()
                .rev()
                .filter(local)
                .map(|incident| incident.view(now))
                .collect(),
        })
    }

    /// Read at most sixteen incidents under the observation mutex. Cursor
    /// binds boot, filter and membership/evidence revision; changed snapshots
    /// return `Changed`, never silently skip incidents between pages. Ages are
    /// computed from monotonic time and do not themselves advance revision.
    pub(super) fn page(
        &self,
        filter: Filter,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Page, PageError> {
        if !(1..=MAX_PAGE).contains(&limit) {
            return Err(PageError::InvalidQuery);
        }
        let state = self.0.state().map_err(|_| PageError::Unavailable)?;
        let offset = cursor(after, &self.0.boot_id, state.revision, filter)?;
        let count = match filter {
            Filter::Active => state.active.len(),
            Filter::Recent => state.recent.len(),
        };
        if offset > count {
            return Err(PageError::InvalidQuery);
        }
        let now = Instant::now();
        let limit = usize::try_from(limit).map_err(|_| PageError::InvalidQuery)?;
        let items = match filter {
            Filter::Active => state
                .active
                .values()
                .skip(offset)
                .take(limit)
                .map(|incident| incident.view(now))
                .collect::<Vec<_>>(),
            Filter::Recent => state
                .recent
                .iter()
                .rev()
                .skip(offset)
                .take(limit)
                .map(|incident| incident.view(now))
                .collect::<Vec<_>>(),
        };
        let next = offset
            .checked_add(items.len())
            .ok_or(PageError::Unavailable)?;
        Ok(Page {
            boot_id: self.0.boot_id.clone(),
            revision: state.revision.to_string(),
            observed_at_unix_ms: state.observed_at.map(|value| value.to_string()),
            age_millis: state
                .completed
                .map(|time| millis(now.saturating_duration_since(time))),
            collection_error: state.collection_error,
            coverage: self.coverage(&state),
            active_count: u32::try_from(state.active.len()).map_err(|_| PageError::Unavailable)?,
            recent_count: u32::try_from(state.recent.len()).map_err(|_| PageError::Unavailable)?,
            dropped: state.dropped.to_string(),
            items,
            next_cursor: (next < count).then(|| {
                format!(
                    "{}:{}:{}:{}",
                    self.0.boot_id,
                    state.revision,
                    filter.code(),
                    next
                )
            }),
        })
    }

    /// Read at most sixteen local egress incidents from the same state lock.
    /// Filtering precedes counts and offsets. Sampling time/error belongs only
    /// to health reads; absent, failed or stale evidence never proves recovery.
    pub(super) fn egress_page(
        &self,
        filter: Filter,
        after: Option<&str>,
        limit: u32,
    ) -> Result<EgressPage, PageError> {
        if !(1..=MAX_PAGE).contains(&limit) {
            return Err(PageError::InvalidQuery);
        }
        let state = self.0.state().map_err(|_| PageError::Unavailable)?;
        let offset = scoped_cursor(
            after,
            &self.0.boot_id,
            state.egress.revision,
            filter.egress_code(),
            ["egress-active", "egress-recent"],
        )?;
        let local = |incident: &&Incident| incident.key.local_egress(&state.node_id);
        let active_count = state.active.values().filter(local).count();
        let recent_count = state.recent.iter().filter(local).count();
        let count = match filter {
            Filter::Active => active_count,
            Filter::Recent => recent_count,
        };
        if offset > count {
            return Err(PageError::InvalidQuery);
        }
        let now = Instant::now();
        let limit = usize::try_from(limit).map_err(|_| PageError::InvalidQuery)?;
        let items = match filter {
            Filter::Active => state
                .active
                .values()
                .filter(local)
                .skip(offset)
                .take(limit)
                .map(|incident| incident.egress_view(now))
                .collect::<Result<Vec<_>, _>>()?,
            Filter::Recent => state
                .recent
                .iter()
                .rev()
                .filter(local)
                .skip(offset)
                .take(limit)
                .map(|incident| incident.egress_view(now))
                .collect::<Result<Vec<_>, _>>()?,
        };
        let next = offset
            .checked_add(items.len())
            .ok_or(PageError::Unavailable)?;
        Ok(EgressPage {
            node_id: state.node_id.clone(),
            boot_id: self.0.boot_id.clone(),
            revision: state.egress.revision.to_string(),
            observed_at_unix_ms: state.egress.observed_at.map(|value| value.to_string()),
            age_millis: state
                .egress
                .completed
                .map(|time| millis(now.saturating_duration_since(time))),
            collection_error: state.egress.collection_error,
            monitored: self.0.coverage.local_egress,
            active_count: u32::try_from(active_count).map_err(|_| PageError::Unavailable)?,
            recent_count: u32::try_from(recent_count).map_err(|_| PageError::Unavailable)?,
            dropped: state.egress.dropped.to_string(),
            items,
            next_cursor: (next < count).then(|| {
                format!(
                    "{}:{}:{}:{}",
                    self.0.boot_id,
                    state.egress.revision,
                    filter.egress_code(),
                    next
                )
            }),
        })
    }

    /// Filter before counting and paging under the existing short snapshot
    /// lock. No collection, network or SQLite work starts here. Overall
    /// collector errors/age are conservative: an empty page without applicable
    /// current evidence cannot establish health or recovery.
    pub(super) fn node_page(
        &self,
        filter: Filter,
        after: Option<&str>,
        limit: u32,
    ) -> Result<NodePage, PageError> {
        if !(1..=MAX_PAGE).contains(&limit) {
            return Err(PageError::InvalidQuery);
        }
        let state = self.0.state().map_err(|_| PageError::Unavailable)?;
        let offset = scoped_cursor(
            after,
            &self.0.boot_id,
            state.revision,
            filter.node_code(),
            ["node-active", "node-recent"],
        )?;
        let local = |incident: &&Incident| incident.key.local_operation(&state.node_id);
        let active_count = state.active.values().filter(local).count();
        let recent_count = state.recent.iter().filter(local).count();
        let count = match filter {
            Filter::Active => active_count,
            Filter::Recent => recent_count,
        };
        if offset > count {
            return Err(PageError::InvalidQuery);
        }
        let now = Instant::now();
        let limit = usize::try_from(limit).map_err(|_| PageError::InvalidQuery)?;
        let items = match filter {
            Filter::Active => state
                .active
                .values()
                .filter(local)
                .skip(offset)
                .take(limit)
                .map(|incident| incident.view(now))
                .collect::<Vec<_>>(),
            Filter::Recent => state
                .recent
                .iter()
                .rev()
                .filter(local)
                .skip(offset)
                .take(limit)
                .map(|incident| incident.view(now))
                .collect::<Vec<_>>(),
        };
        let next = offset
            .checked_add(items.len())
            .ok_or(PageError::Unavailable)?;
        let coverage = self.coverage(&state);
        Ok(NodePage {
            node_id: state.node_id.clone(),
            boot_id: self.0.boot_id.clone(),
            revision: state.revision.to_string(),
            observed_at_unix_ms: state.observed_at.map(|value| value.to_string()),
            age_millis: state
                .completed
                .map(|time| millis(now.saturating_duration_since(time))),
            collection_error: state.collection_error,
            coverage: LocalCoverage {
                local_egress: coverage.local_egress,
                local_traffic: coverage.local_traffic,
                local_proxy_expected: coverage.local_proxy_expected,
                local_management_https: coverage.local_management_https,
                local_node_tls: coverage.local_node_tls,
                local_proxy_tls: coverage.local_proxy_tls,
            },
            active_count: u32::try_from(active_count).map_err(|_| PageError::Unavailable)?,
            recent_count: u32::try_from(recent_count).map_err(|_| PageError::Unavailable)?,
            dropped: state.local_dropped.to_string(),
            items,
            next_cursor: (next < count).then(|| {
                format!(
                    "{}:{}:{}:{next}",
                    self.0.boot_id,
                    state.revision,
                    filter.node_code()
                )
            }),
        })
    }
}

impl Filter {
    fn code(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Recent => "recent",
        }
    }

    pub(super) fn egress_code(self) -> &'static str {
        match self {
            Self::Active => "egress-active",
            Self::Recent => "egress-recent",
        }
    }

    pub(super) fn node_code(self) -> &'static str {
        match self {
            Self::Active => "node-active",
            Self::Recent => "node-recent",
        }
    }
}

fn cursor(
    after: Option<&str>,
    boot: &str,
    revision: u64,
    filter: Filter,
) -> Result<usize, PageError> {
    scoped_cursor(after, boot, revision, filter.code(), ["active", "recent"])
}

fn scoped_cursor(
    after: Option<&str>,
    boot: &str,
    revision: u64,
    filter: &str,
    allowed_filters: [&str; 2],
) -> Result<usize, PageError> {
    let Some(after) = after else {
        return Ok(0);
    };
    if after.len() > 160 {
        return Err(PageError::InvalidQuery);
    }
    let parts = after.split(':').collect::<Vec<_>>();
    if parts.len() != 4 || !super::store::valid_id(parts[0]) || !allowed_filters.contains(&parts[2])
    {
        return Err(PageError::InvalidQuery);
    }
    let parsed_revision = decimal(parts[1])?;
    let offset = usize::try_from(decimal(parts[3])?).map_err(|_| PageError::InvalidQuery)?;
    if parts[0] != boot || parsed_revision != revision || parts[2] != filter {
        return Err(PageError::Changed);
    }
    Ok(offset)
}

fn decimal(value: &str) -> Result<u64, PageError> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(PageError::InvalidQuery);
    }
    value.parse().map_err(|_| PageError::InvalidQuery)
}

impl State {
    fn new(node_id: String) -> Self {
        Self {
            node_id,
            generation: 0,
            revision: 1,
            next_id: 0,
            evidence: 0,
            completed: None,
            observed_at: None,
            collection_error: false,
            proxy_tls: None,
            active: BTreeMap::new(),
            recent: VecDeque::new(),
            known: BTreeMap::new(),
            dropped: 0,
            local_dropped: 0,
            egress: EgressMetadata {
                revision: 1,
                next_id: 0,
                evidence: 0,
                completed: None,
                observed_at: None,
                collection_error: false,
                dropped: 0,
            },
        }
    }

    /// Apply one round without I/O. Unknown inputs retain prior incidents;
    /// source replacement retires them, and only newer applicable successes
    /// recover them. Counter exhaustion fails the supervised monitor rather
    /// than wrapping IDs or accepting an ambiguous paging revision.
    #[cfg(test)]
    fn apply(&mut self, frame: Frame, now: Instant, wall: Option<u64>) -> io::Result<()> {
        self.apply_with_events(frame, now, wall).map(|_| ())
    }

    fn apply_with_events(
        &mut self,
        mut frame: Frame,
        now: Instant,
        wall: Option<u64>,
    ) -> io::Result<Vec<Transition>> {
        let mut events = Vec::new();
        // Count once per frame. Remote inventories cannot consume the existing
        // local-source budget, nor turn admission into an O(N²) map scan.
        let mut counts = [0_usize; 3];
        let limits = [MAX_ACTIVE, MAX_REMOTE, MAX_REMOTE_SOURCES];
        for key in self.known.keys() {
            let group = key.budget(&self.node_id);
            counts[group] = counts[group].checked_add(1).ok_or_else(unavailable)?;
            if counts[group] > limits[group] {
                return Err(unavailable());
            }
        }
        let incoming = frame
            .facts
            .iter()
            .map(|fact| &fact.key)
            .collect::<BTreeSet<_>>();
        let retained_remote = self
            .known
            .keys()
            .filter(|key| {
                key.mirrored(&self.node_id)
                    && (!frame.remote_complete.contains(&key.origin) || incoming.contains(key))
            })
            .count();
        let added_remote = incoming
            .iter()
            .filter(|key| key.mirrored(&self.node_id) && !self.known.contains_key(*key))
            .count();
        if retained_remote
            .checked_add(added_remote)
            .is_none_or(|count| count > MAX_REMOTE)
        {
            // Never partially retire a source and then drop its replacement
            // incidents for capacity. Preserve all old mirrors as stale.
            frame.remote_complete.clear();
            frame.remote_proofs.clear();
            frame.facts.retain(|fact| !fact.key.mirrored(&self.node_id));
            frame.fail(collect::Failure::RemoteCapacity);
        }
        self.generation = self.generation.checked_add(1).ok_or_else(unavailable)?;
        let mut changed = self.collection_error != frame.error;
        if frame.complete.contains(&Kind::ProxyTls) {
            let proxy_tls = frame
                .facts
                .iter()
                .any(|fact| fact.key.kind == Kind::ProxyTls && fact.key.origin == self.node_id);
            changed |= self.proxy_tls != Some(proxy_tls);
            self.proxy_tls = Some(proxy_tls);
        }
        let mut egress_changed = false;
        let egress_read = frame.egress.is_some();
        if let Some(collection) = frame.egress {
            egress_changed = self.egress.collection_error != collection.error;
            self.egress.collection_error = collection.error;
            if !collection.error {
                self.egress.completed = Some(collection.completed);
                self.egress.observed_at = collection.observed_at;
            }
        }
        self.collection_error = frame.error;
        if !frame.error {
            self.completed = Some(now);
            self.observed_at = wall;
        }
        let seen = frame
            .facts
            .iter()
            .map(|fact| fact.key.clone())
            .collect::<BTreeSet<_>>();
        for incident in self.active.values_mut() {
            let local_egress = incident.key.local_egress(&self.node_id);
            if !incident
                .key
                .covered(&self.node_id, &frame.complete, &frame.remote_complete)
                && incident.fresh
                && (!local_egress || egress_read)
            {
                incident.fresh = false;
                changed = true;
                egress_changed |= local_egress;
            }
        }
        let departed = self
            .known
            .keys()
            .filter(|key| {
                key.covered(&self.node_id, &frame.complete, &frame.remote_complete)
                    && !seen.contains(*key)
            })
            .cloned()
            .collect::<Vec<_>>();
        for key in departed {
            self.known.remove(&key);
            let group = key.budget(&self.node_id);
            counts[group] = counts[group].checked_sub(1).ok_or_else(unavailable)?;
            let (closed, scoped) = self.close(&key, Status::Unmonitored, now, wall, &mut events)?;
            changed |= closed;
            egress_changed |= scoped;
        }
        for fact in frame.facts {
            let local_egress = fact.key.local_egress(&self.node_id);
            if self
                .known
                .get(&fact.key)
                .is_some_and(|known| known.lineage != fact.lineage)
            {
                let (closed, scoped) =
                    self.close(&fact.key, Status::Unmonitored, now, wall, &mut events)?;
                changed |= closed;
                egress_changed |= scoped;
                self.known.remove(&fact.key);
                let group = fact.key.budget(&self.node_id);
                counts[group] = counts[group].checked_sub(1).ok_or_else(unavailable)?;
            }
            if matches!(fact.outcome, Outcome::Unknown) {
                if let Some(active) = self.active.get_mut(&fact.key)
                    && active.fresh
                {
                    active.fresh = false;
                    changed = true;
                    egress_changed |= local_egress;
                }
                continue;
            }
            let previous = self.known.get(&fact.key);
            // Repeated snapshots, wall-clock changes and sequence regression
            // cannot refresh evidence or resolve an earlier failure.
            let repeated = previous.is_some_and(|known| known.stamp == fact.stamp);
            if previous.is_some_and(|known| {
                fact.sequence.is_some_and(|sequence| {
                    sequence < known.sequence || sequence == known.sequence && !repeated
                })
            }) {
                if let Some(active) = self.active.get_mut(&fact.key)
                    && active.fresh
                {
                    active.fresh = false;
                    changed = true;
                    egress_changed |= local_egress;
                }
                continue;
            }
            if repeated {
                if let Outcome::Failure(code) = fact.outcome
                    && let Some(active) = self.active.get_mut(&fact.key)
                    && code == active.code
                    && !active.fresh
                {
                    active.fresh = true;
                    changed = true;
                    egress_changed |= local_egress;
                }
                continue;
            }
            let group = fact.key.budget(&self.node_id);
            let new_key = !self.known.contains_key(&fact.key);
            if new_key && (counts[group] == limits[group] || self.known.len() == MAX_TOTAL) {
                self.dropped = self.dropped.checked_add(1).ok_or_else(unavailable)?;
                if fact.key.local_operation(&self.node_id) {
                    self.local_dropped =
                        self.local_dropped.checked_add(1).ok_or_else(unavailable)?;
                }
                if local_egress {
                    self.egress.dropped =
                        self.egress.dropped.checked_add(1).ok_or_else(unavailable)?;
                    egress_changed = true;
                }
                changed = true;
                continue;
            }
            if let Some(active) = self.active.get_mut(&fact.key)
                && !active.fresh
            {
                active.fresh = true;
                changed = true;
                egress_changed |= local_egress;
            }
            let sequence = match fact.sequence {
                Some(sequence) => sequence,
                None if local_egress => {
                    self.egress.evidence = self
                        .egress
                        .evidence
                        .checked_add(1)
                        .ok_or_else(unavailable)?;
                    self.egress.evidence
                }
                None => {
                    self.evidence = self.evidence.checked_add(1).ok_or_else(unavailable)?;
                    self.evidence
                }
            };
            if new_key {
                counts[group] = counts[group].checked_add(1).ok_or_else(unavailable)?;
            }
            self.known.insert(
                fact.key.clone(),
                Evidence {
                    lineage: fact.lineage.clone(),
                    stamp: fact.stamp,
                    sequence,
                },
            );
            match fact.outcome {
                Outcome::Success => {
                    if self
                        .active
                        .get(&fact.key)
                        .is_some_and(|active| sequence > active.sequence)
                    {
                        if let Some(active) = self.active.get_mut(&fact.key) {
                            active.last = wall;
                            active.sequence = sequence;
                        }
                        let (closed, scoped) =
                            self.close(&fact.key, Status::Recovered, now, wall, &mut events)?;
                        changed |= closed;
                        egress_changed |= scoped;
                    }
                }
                Outcome::Failure(code) => {
                    if let Some(active) = self.active.get_mut(&fact.key) {
                        let reason_changed = active.code != code;
                        active.code = code;
                        active.last = wall;
                        active.changed = now;
                        active.sequence = sequence;
                        if reason_changed {
                            journal::push(
                                &mut events,
                                active.transition(TransitionKind::ReasonChanged, wall),
                            )?;
                        }
                    } else if self.active.len() < MAX_TOTAL {
                        self.next_id = self.next_id.checked_add(1).ok_or_else(unavailable)?;
                        let egress_id = if local_egress {
                            self.egress.next_id =
                                self.egress.next_id.checked_add(1).ok_or_else(unavailable)?;
                            Some(self.egress.next_id)
                        } else {
                            None
                        };
                        let key = fact.key.clone();
                        let incident = Incident {
                            id: self.next_id,
                            egress_id,
                            key: fact.key,
                            check: fact.check,
                            target: fact.target,
                            status: Status::Active,
                            code,
                            first: wall,
                            last: wall,
                            ended: None,
                            changed: now,
                            sequence,
                            fresh: true,
                        };
                        journal::push(
                            &mut events,
                            incident.transition(TransitionKind::Opened, wall),
                        )?;
                        self.active.insert(key, incident);
                    } else {
                        self.dropped = self.dropped.checked_add(1).ok_or_else(unavailable)?;
                        if fact.key.local_operation(&self.node_id) {
                            self.local_dropped =
                                self.local_dropped.checked_add(1).ok_or_else(unavailable)?;
                        }
                        if local_egress {
                            self.egress.dropped =
                                self.egress.dropped.checked_add(1).ok_or_else(unavailable)?;
                        }
                    }
                    changed = true;
                    egress_changed |= local_egress;
                }
                Outcome::Unknown => {}
            }
        }
        if changed {
            self.revision = self.revision.checked_add(1).ok_or_else(unavailable)?;
        }
        if egress_changed {
            self.egress.revision = self
                .egress
                .revision
                .checked_add(1)
                .ok_or_else(unavailable)?;
        }
        Ok(events)
    }

    // Report both visible projections, including a local episode evicted by an
    // unrelated source from their shared bounded history ring.
    fn close(
        &mut self,
        key: &Key,
        status: Status,
        now: Instant,
        wall: Option<u64>,
        events: &mut Vec<Transition>,
    ) -> io::Result<(bool, bool)> {
        let Some(mut incident) = self.active.remove(key) else {
            return Ok((false, false));
        };
        let mut egress_changed = incident.key.local_egress(&self.node_id);
        incident.status = status;
        if status == Status::Unmonitored {
            incident.fresh = false;
        }
        incident.ended = wall;
        incident.changed = now;
        journal::push(
            events,
            incident.transition(
                if status == Status::Recovered {
                    TransitionKind::Recovered
                } else {
                    TransitionKind::Unmonitored
                },
                wall,
            ),
        )?;
        if self.recent.len() == MAX_RECENT {
            if let Some(evicted) = self.recent.pop_front() {
                if evicted.key.local_operation(&self.node_id) {
                    self.local_dropped =
                        self.local_dropped.checked_add(1).ok_or_else(unavailable)?;
                }
                if evicted.key.local_egress(&self.node_id) {
                    self.egress.dropped =
                        self.egress.dropped.checked_add(1).ok_or_else(unavailable)?;
                    egress_changed = true;
                }
            }
            self.dropped = self.dropped.checked_add(1).ok_or_else(unavailable)?;
        }
        self.recent.push_back(incident);
        Ok((true, egress_changed))
    }
}

impl Incident {
    fn transition(&self, kind: TransitionKind, observed_at_unix_ms: Option<u64>) -> Transition {
        Transition {
            kind,
            observation: Observation {
                incident_id: self.id,
                kind: self.key.kind,
                origin_node_id: self.key.origin.clone(),
                resource_id: self.key.resource.clone(),
                slot: self.key.slot.clone(),
                check: self.check,
                target: self.target,
                code: self.code.to_owned(),
                first_observed_at_unix_ms: self.first,
                last_observed_at_unix_ms: self.last,
                evidence_sequence: Some(self.sequence),
            },
            observed_at_unix_ms,
            ended_reason: (kind == TransitionKind::Unmonitored)
                .then_some(EndReason::SourceUnmonitored),
        }
    }

    fn view(&self, now: Instant) -> Alert {
        self.view_with_id(now, self.id)
    }

    fn egress_view(&self, now: Instant) -> Result<Alert, PageError> {
        let id = self.egress_id.ok_or(PageError::Unavailable)?;
        Ok(self.view_with_id(now, id))
    }

    fn view_with_id(&self, now: Instant, id: u64) -> Alert {
        Alert {
            id: id.to_string(),
            kind: self.key.kind,
            origin_node_id: self.key.origin.clone(),
            resource_id: self.key.resource.clone(),
            check: self.check,
            target: self.target,
            status: self.status,
            code: self.code.to_owned(),
            first_observed_at_unix_ms: self.first.map(|value| value.to_string()),
            last_observed_at_unix_ms: self.last.map(|value| value.to_string()),
            ended_at_unix_ms: self.ended.map(|value| value.to_string()),
            age_millis: millis(now.saturating_duration_since(self.changed)),
            evidence_sequence: Some(self.sequence.to_string()),
            evidence_fresh: self.fresh,
        }
    }
}

fn millis(duration: Duration) -> String {
    u64::try_from(duration.as_millis())
        .unwrap_or(u64::MAX)
        .to_string()
}

fn wall_time() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}

fn unavailable() -> io::Error {
    io::Error::other("operations observations unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::store;

    mod certificates {
        //! Fixed loaded-leaf observations exercise ordering and scope without opening
        //! a certificate file, listener, TLS connection or existing database.

        use super::*;
        use crate::manage::{certificates as tls, proxy::Protocol};

        const ENDPOINT: &str = "AQEBAQEBAQEBAQEBAQEBAQ";
        const OTHER: &str = "AgICAgICAgICAgICAgICAg";

        fn loaded(fingerprint: &str, before: i64, after: i64) -> tls::State {
            tls::State::Loaded(tls::Descriptor {
                sha256: fingerprint.repeat(64),
                not_before_unix_s: before,
                not_after_unix_s: after,
            })
        }

        fn entry(role: tls::Role, state: tls::State) -> tls::Entry {
            tls::Entry {
                role,
                source: tls::Source::Manual,
                id: (role == tls::Role::Proxy).then(|| ENDPOINT.to_owned()),
                protocol: (role == tls::Role::Proxy).then_some(Protocol::Https),
                state,
                valid_now: None,
            }
        }

        fn snapshot(role: tls::Role, state: tls::State, wall: Option<i64>) -> tls::Snapshot {
            let mut entries = vec![
                entry(tls::Role::Management, tls::State::Disabled),
                entry(tls::Role::Node, tls::State::Disabled),
            ];
            match role {
                tls::Role::Management => entries[0] = entry(role, state),
                tls::Role::Node => entries[1] = entry(role, state),
                tls::Role::Proxy => entries.push(entry(role, state)),
            }
            tls::Snapshot {
                node_id: NODE.into(),
                observed_at_unix_s: wall,
                entries,
            }
        }

        fn collect(runner: &mut Runner, snapshot: tls::Snapshot) -> Frame {
            let mut frame = Frame::default();
            runner.certificate_snapshot_facts(&mut frame, snapshot, true);
            frame
        }

        fn runner(fixture: &Fixture) -> io::Result<Runner> {
            let (_, mut runner) = fixture.runner(false, false)?;
            runner.node_id = NODE.into();
            Ok(runner)
        }

        fn incident<'a>(state: &'a State, kind: Kind, slot: &str) -> Option<&'a Incident> {
            state
                .active
                .values()
                .find(|incident| incident.key.kind == kind && incident.key.slot == slot)
        }

        #[test]
        fn roles_classify_validity_inclusive_endpoints_and_separate_metadata_from_tls()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let mut runner = runner(&fixture)?;
            for (role, kind, prefix) in [
                (
                    tls::Role::Management,
                    Kind::ManagementHttps,
                    "https_identity",
                ),
                (tls::Role::Node, Kind::NodeTls, "node_tls_identity"),
                (tls::Role::Proxy, Kind::ProxyTls, "proxy_tls_identity"),
            ] {
                for (wall, suffix) in [
                    (99, Some("not_yet_valid")),
                    (100, None),
                    (200, Some("expiring")),
                    (605_000, Some("expiring")),
                    (605_001, Some("expired")),
                ] {
                    let frame = collect(
                        &mut runner,
                        snapshot(role, loaded("a", 100, 605_000), Some(wall)),
                    );
                    assert!(!frame.error);
                    let fact = frame
                        .facts
                        .iter()
                        .find(|fact| fact.key.kind == kind && fact.key.slot == "certificate")
                        .expect("certificate fact");
                    assert!(fact.check.is_none() && fact.target.is_none());
                    assert_eq!(
                        fact.key.resource.as_deref(),
                        (role == tls::Role::Proxy).then_some(ENDPOINT)
                    );
                    match suffix {
                        Some(suffix) => assert!(
                            matches!(fact.outcome, Outcome::Failure(code) if code == format!("{prefix}_{suffix}"))
                        ),
                        None => assert!(matches!(fact.outcome, Outcome::Success)),
                    }
                }
                let frame = collect(
                    &mut runner,
                    snapshot(role, tls::State::Unavailable, Some(100)),
                );
                assert!(frame.error);
                assert!(frame.facts.iter().any(|fact| fact.key.kind == kind && fact.key.slot == "metadata" && matches!(fact.outcome, Outcome::Failure(code) if code == format!("{prefix}_metadata_unavailable"))));
                assert!(frame.facts.iter().any(|fact| fact.key.kind == kind
                    && fact.key.slot == "certificate"
                    && matches!(fact.outcome, Outcome::Unknown)));
            }
            let frame = collect(
                &mut runner,
                snapshot(tls::Role::Management, tls::State::Pending, None),
            );
            assert!(!frame.error);
            assert!(frame.facts.iter().any(|fact| matches!(
                fact.outcome,
                Outcome::Failure("https_identity_unavailable")
            )));
            let signed = collect(
                &mut runner,
                snapshot(tls::Role::Node, loaded("b", i64::MIN, i64::MAX), Some(0)),
            );
            assert!(
                !signed.error,
                "wide signed validity intervals must not overflow subtraction"
            );
            Ok(())
        }

        #[test]
        fn same_fingerprint_clock_rollback_and_metadata_recovery_cannot_clear_expiry()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let mut runner = runner(&fixture)?;
            let mut state = State::new(NODE.into());
            let now = Instant::now();
            let observation = |fingerprint, seconds| {
                snapshot(
                    tls::Role::Node,
                    loaded(fingerprint, 100, 605_000),
                    Some(seconds),
                )
            };
            state.apply(collect(&mut runner, observation("a", 99)), now, Some(99))?;
            assert_eq!(
                incident(&state, Kind::NodeTls, "certificate")
                    .expect("future certificate")
                    .code,
                "node_tls_identity_not_yet_valid"
            );
            state.apply(collect(&mut runner, observation("a", 100)), now, Some(100))?;
            assert!(
                state.active.is_empty(),
                "natural forward time recovers not-yet-valid on the same leaf"
            );
            assert_eq!(state.recent.len(), 1);
            assert_eq!(state.recent[0].status, Status::Recovered);
            state.apply(collect(&mut runner, observation("a", 200)), now, Some(200))?;
            let id = incident(&state, Kind::NodeTls, "certificate")
                .expect("warning")
                .id;
            let revision = state.revision;
            state.apply(collect(&mut runner, observation("a", 201)), now, Some(201))?;
            assert_eq!(state.revision, revision);
            state.apply(
                collect(&mut runner, observation("a", 605_001)),
                now,
                Some(300),
            )?;
            assert_eq!(
                incident(&state, Kind::NodeTls, "certificate")
                    .expect("expired")
                    .id,
                id
            );
            state.apply(
                collect(
                    &mut runner,
                    snapshot(tls::Role::Node, tls::State::Unavailable, Some(100)),
                ),
                now,
                Some(400),
            )?;
            assert!(incident(&state, Kind::NodeTls, "metadata").is_some());
            assert!(
                !incident(&state, Kind::NodeTls, "certificate")
                    .expect("retained expiry")
                    .fresh
            );
            state.apply(collect(&mut runner, observation("a", 100)), now, Some(100))?;
            assert!(
                incident(&state, Kind::NodeTls, "metadata").is_none(),
                "metadata can recover independently"
            );
            let expired = incident(&state, Kind::NodeTls, "certificate")
                .expect("clock rollback retains expiry");
            assert_eq!(expired.id, id);
            assert_eq!(expired.code, "node_tls_identity_expired");
            assert!(!expired.fresh);
            state.apply(collect(&mut runner, observation("b", 100)), now, Some(101))?;
            assert!(state.active.is_empty());
            assert_eq!(state.recent.len(), 3);
            assert!(
                state
                    .recent
                    .iter()
                    .all(|incident| incident.status == Status::Recovered)
            );
            Ok(())
        }

        #[test]
        fn unknown_clock_incomplete_inventory_and_counter_exhaustion_preserve_episodes()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let mut runner = runner(&fixture)?;
            let mut state = State::new(NODE.into());
            let now = Instant::now();
            state.apply(
                collect(
                    &mut runner,
                    snapshot(tls::Role::Proxy, loaded("a", 0, 100), Some(101)),
                ),
                now,
                Some(1),
            )?;
            let id = incident(&state, Kind::ProxyTls, "certificate")
                .expect("expired proxy")
                .id;
            let unknown = collect(
                &mut runner,
                snapshot(tls::Role::Proxy, loaded("a", 0, 100), None),
            );
            assert!(unknown.error);
            state.apply(unknown, now, None)?;
            assert_eq!(
                incident(&state, Kind::ProxyTls, "certificate")
                    .expect("unknown clock")
                    .id,
                id
            );
            for invalid in [
                tls::Snapshot {
                    node_id: OTHER.into(),
                    ..snapshot(tls::Role::Proxy, tls::State::Disabled, Some(1))
                },
                tls::Snapshot {
                    entries: Vec::new(),
                    ..snapshot(tls::Role::Proxy, tls::State::Disabled, Some(1))
                },
            ] {
                let failed = collect(&mut runner, invalid);
                assert!(failed.error && failed.complete.is_empty());
                state.apply(failed, now, Some(2))?;
                assert_eq!(
                    incident(&state, Kind::ProxyTls, "certificate")
                        .expect("invalid inventory")
                        .id,
                    id
                );
            }
            // A failed source read supplies no complete TLS kind; it is not an empty
            // successful snapshot and may not retire the old proxy endpoint.
            state.apply(
                Frame {
                    error: true,
                    failures: vec![collect::Failure::Certificates(io::ErrorKind::Other)],
                    ..Frame::default()
                },
                now,
                Some(3),
            )?;
            let key = runner
                .certificate_clocks
                .keys()
                .find(|key| key.kind == Kind::ProxyTls)
                .expect("proxy clock")
                .clone();
            runner
                .certificate_clocks
                .insert(key, collect::CertificateClock::exhausted());
            let exhausted = collect(
                &mut runner,
                snapshot(tls::Role::Proxy, loaded("b", 0, i64::MAX), Some(5)),
            );
            assert!(exhausted.error);
            assert!(
                exhausted
                    .failures
                    .contains(&collect::Failure::CertificateSequenceExhausted)
            );
            state.apply(exhausted, now, Some(4))?;
            assert_eq!(
                incident(&state, Kind::ProxyTls, "certificate")
                    .expect("exhausted clock")
                    .id,
                id
            );
            assert!(state.recent.is_empty());
            Ok(())
        }

        #[test]
        fn disabled_and_removed_endpoints_retire_without_claiming_recovery_and_clocks_stay_bounded()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let mut runner = runner(&fixture)?;
            let now = Instant::now();
            let mut state = State::new(NODE.into());
            state.apply(
                collect(
                    &mut runner,
                    snapshot(tls::Role::Proxy, loaded("a", 0, 1), Some(2)),
                ),
                now,
                Some(1),
            )?;
            assert_eq!(state.proxy_tls, Some(true));
            let retiring = collect(
                &mut runner,
                snapshot(tls::Role::Proxy, tls::State::Disabled, Some(2)),
            );
            // Collection alone cannot publish coverage ahead of its accepted frame.
            assert!(
                handle(state.clone())
                    .node_snapshot()
                    .expect("old accepted inventory")
                    .coverage
                    .local_proxy_tls
            );
            state.apply(retiring, now, Some(2))?;
            assert_eq!(state.proxy_tls, Some(false));
            assert!(
                !handle(state.clone())
                    .page(Filter::Active, None, 16)
                    .expect("new accepted inventory")
                    .coverage
                    .local_proxy_tls
            );
            assert!(state.active.is_empty());
            assert_eq!(state.recent[0].status, Status::Unmonitored);
            assert!(runner.certificate_clocks.is_empty());
            let mut full = snapshot(tls::Role::Node, loaded("a", 0, i64::MAX), Some(2));
            full.entries[0].state = loaded("a", 0, i64::MAX);
            for number in 0..tls::MAX_PROXY {
                let mut proxy = entry(tls::Role::Proxy, loaded("a", 0, i64::MAX));
                proxy.id = Some(URL_SAFE_NO_PAD.encode((number as u128).to_be_bytes()));
                full.entries.push(proxy);
            }
            let frame = collect(&mut runner, full.clone());
            assert!(!frame.error);
            assert_eq!(runner.certificate_clocks.len(), tls::MAX_PROXY + 2);
            full.entries
                .push(entry(tls::Role::Proxy, loaded("a", 0, i64::MAX)));
            assert!(collect(&mut runner, full).error);
            assert_eq!(runner.certificate_clocks.len(), tls::MAX_PROXY + 2);
            Ok(())
        }

        #[tokio::test]
        async fn loaded_handle_is_authoritative_without_duplicate_acme_certificate_or_lost_attempt()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let certificates = tls::Handle::new(
                fixture.node.clone(),
                tls::ManagementSource::Manual(loaded("a", i64::MIN, i64::MAX)),
                tls::State::Disabled,
                crate::manage::proxy::Certificates::default(),
            )?;
            let (handle, mut runner) = new(
                fixture.policy.as_ref().expect("fixture policy").clone(),
                fixture.node.clone(),
                None,
                None,
                false,
                false,
                Some(acme::Handle::testing()),
                Some(certificates.clone()),
            )?;
            // The legacy ACME handle is cold, but its absent certificate must not
            // override or duplicate the actual loaded management descriptor.
            runner.collect_once().await?;
            let page = handle
                .page(Filter::Active, None, 16)
                .expect("actual loaded page");
            assert!(page.coverage.local_management_https);
            assert!(!page.coverage.local_node_tls && !page.coverage.local_proxy_tls);
            assert!(!page.collection_error);
            assert_eq!(page.active_count, 0);
            assert_eq!(runner.certificate_clocks.len(), 1);

            let mut frame = Frame::default();
            runner.management_https_observation_facts(
                &mut frame,
                acme::Observation {
                    certificate: None,
                    activation_seq: u64::MAX,
                    result_seq: 1,
                    last_failure: Some(acme::Failure::AttemptUnavailable),
                    stopped: true,
                },
                Some(1),
            );
            assert!(
                frame
                    .facts
                    .iter()
                    .all(|fact| fact.key.slot != "certificate")
            );
            assert!(
                !frame.error,
                "legacy activation counters cannot poison actual loaded metadata"
            );
            let acme_complete = frame.complete.remove(&Kind::ManagementHttps);
            runner.certificate_snapshot_facts(&mut frame, certificates.snapshot()?, acme_complete);
            assert_eq!(
                frame
                    .facts
                    .iter()
                    .filter(|fact| fact.key.slot == "certificate")
                    .count(),
                1
            );
            handle.0.apply(frame, Instant::now(), Some(1))?;
            let page = handle
                .page(Filter::Active, None, 16)
                .expect("ACME attempt page");
            assert_eq!(page.active_count, 2);
            assert!(
                page.items
                    .iter()
                    .any(|incident| incident.code == "acme_attempt_unavailable")
            );
            assert!(
                page.items
                    .iter()
                    .any(|incident| incident.code == "acme_worker_stopped")
            );
            assert!(
                page.items
                    .iter()
                    .all(|incident| !incident.code.starts_with("https_identity"))
            );
            Ok(())
        }
    }
    mod collection {
        use std::io::Write;

        use super::*;
        use crate::manage::policy::ReadStage;

        #[tokio::test]
        async fn malformed_private_store_is_an_operation_failure_not_read_admission()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let (handle, mut runner) = fixture.runner(false, false)?;
            runner.collect_once().await?;
            assert!(runner.collection_failures.is_empty());

            // Only this fresh fixture is damaged. The real storage parser must reject
            // it rather than publish an empty policy/target inventory as healthy.
            let connection =
                rusqlite::Connection::open(fixture.directory.join("management.sqlite3"))
                    .map_err(io::Error::other)?;
            connection
                .execute_batch(
                    "PRAGMA ignore_check_constraints=ON;
             UPDATE proxy_policy_state SET revision=0 WHERE singleton=1;",
                )
                .map_err(io::Error::other)?;
            drop(connection);
            runner.collect_once().await?;
            assert_eq!(
                runner.collection_failures,
                [collect::Failure::Policy(
                    ReadStage::Operation,
                    io::ErrorKind::InvalidData,
                )],
            );
            assert!(
                handle
                    .page(Filter::Active, None, 16)
                    .unwrap()
                    .collection_error
            );
            assert!(
                !handle
                    .egress_page(Filter::Active, None, 16)
                    .unwrap()
                    .collection_error,
                "policy storage failure must not change the health-only projection",
            );

            let connection =
                rusqlite::Connection::open(fixture.directory.join("management.sqlite3"))
                    .map_err(io::Error::other)?;
            connection
                .execute(
                    "UPDATE proxy_policy_state SET revision=1 WHERE singleton=1",
                    [],
                )
                .map_err(io::Error::other)?;
            drop(connection);
            runner.collect_once().await?;
            assert!(runner.collection_failures.is_empty());
            assert!(
                !handle
                    .page(Filter::Active, None, 16)
                    .unwrap()
                    .collection_error
            );
            Ok(())
        }

        #[derive(Clone, Default)]
        struct LogBuffer(Arc<Mutex<Vec<u8>>>);

        impl Write for LogBuffer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0
                    .lock()
                    .map_err(|_| unavailable())?
                    .extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        #[test]
        fn collection_logs_track_changed_causes_without_repeating_or_recovering_incidents()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let (_, mut runner) = fixture.runner(false, false)?;
            runner.shared.apply(
                frame(vec![fact(1, Outcome::Failure("egress_failed"))]),
                Instant::now(),
                Some(1),
            )?;
            let log = LogBuffer::default();
            let writer = log.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::INFO)
                .without_time()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            // Keep shared callsites interested when parallel tests have no subscriber;
            // the existing HTTP secrecy tests use the same scoped-dispatch boundary.
            let _parallel_dispatch =
                tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
            tracing::subscriber::with_default(subscriber, || {
                let mut failed = Frame {
                    error: true,
                    failures: vec![collect::Failure::Policy(
                        ReadStage::Admission,
                        io::ErrorKind::WouldBlock,
                    )],
                    ..Frame::default()
                };
                runner.report_collection(&Frame::default());
                runner.report_collection(&failed);
                runner.report_collection(&failed);
                failed.failures = vec![collect::Failure::TrafficUnavailable];
                runner.report_collection(&failed);
                runner.report_collection(&Frame::default());
                runner.report_collection(&Frame::default());
            });
            let bytes = log.0.lock().map_err(|_| unavailable())?.clone();
            let text = String::from_utf8(bytes).map_err(io::Error::other)?;
            assert_eq!(text.lines().count(), 3, "{text}");
            assert_eq!(text.matches("collection incomplete").count(), 2);
            assert_eq!(text.matches("collection resumed").count(), 1);
            assert!(text.contains("Policy(Admission, WouldBlock)"));
            assert!(text.contains("TrafficUnavailable"));
            assert!(runner.collection_failures.is_empty());
            let state = runner.shared.state()?;
            assert_eq!(state.active.len(), 1);
            assert!(state.recent.is_empty());
            Ok(())
        }
    }
    mod egress {
        use super::*;

        const FOREIGN: &str = "AQAAAAAAAAAAAAAAAAAAAA";

        fn collection(now: Instant, wall: u64, error: bool) -> EgressCollection {
            EgressCollection {
                completed: now,
                observed_at: Some(wall),
                error,
            }
        }

        fn other(number: u64) -> Fact {
            Fact {
                key: Key {
                    kind: Kind::RemoteJob,
                    origin: FOREIGN.into(),
                    resource: Some(FOREIGN.into()),
                    slot: number.to_string(),
                },
                lineage: "foreign-directory-job".into(),
                stamp: number.to_string(),
                sequence: Some(number),
                check: None,
                target: None,
                outcome: Outcome::Failure("remote_job_blocked"),
            }
        }

        fn other_frame(facts: Vec<Fact>) -> Frame {
            Frame {
                facts,
                complete: BTreeSet::from([Kind::RemoteJob]),
                ..Frame::default()
            }
        }

        #[test]
        fn egress_counts_offsets_and_serialization_exclude_foreign_and_unrelated_sources()
        -> io::Result<()> {
            let now = Instant::now();
            let mut facts = Vec::new();
            for slot in ["a", "b", "c"] {
                let mut local = fact(1, Outcome::Failure("egress_failed"));
                local.key.slot = slot.into();
                facts.push(local);
            }
            let mut catalog = fact(1, Outcome::Failure("health_catalog_stale"));
            catalog.key.kind = Kind::HealthCatalog;
            catalog.key.resource = None;
            catalog.check = None;
            facts.push(catalog);
            let mut foreign = fact(1, Outcome::Failure("foreign_egress_secret"));
            foreign.key.origin = FOREIGN.into();
            facts.push(foreign);
            facts.push(other(1));
            let mut state = State::new(NODE.into());
            state.apply(frame(facts), now, Some(1))?;
            let handle = handle(state);
            let first = handle.egress_page(Filter::Active, None, 2).expect("first");
            assert_eq!(first.active_count, 4);
            assert_eq!(first.recent_count, 0);
            assert_eq!(first.items.len(), 2);
            let second = handle
                .egress_page(Filter::Active, first.next_cursor.as_deref(), 2)
                .expect("second");
            assert_eq!(second.items.len(), 2);
            assert!(second.next_cursor.is_none());
            assert!(first.items.iter().chain(&second.items).all(|row| {
                row.origin_node_id == NODE
                    && matches!(row.kind, Kind::EgressCheck | Kind::HealthCatalog)
            }));
            let encoded = serde_json::to_string(&first)?;
            for excluded in [
                FOREIGN,
                "foreign_egress_secret",
                "remote_job_blocked",
                "coverage",
            ] {
                assert!(
                    !encoded.contains(excluded),
                    "excluded field/value: {excluded}"
                );
            }
            let mut json = serde_json::to_value(&first)?;
            assert!(serde_json::from_value::<EgressPage>(json.clone()).is_ok());
            json["remote_directory"] = serde_json::json!([]);
            assert!(serde_json::from_value::<EgressPage>(json).is_err());
            let mut json = serde_json::to_value(&first)?;
            json["items"][0]["remote_directory"] = serde_json::json!([]);
            assert!(serde_json::from_value::<EgressPage>(json).is_err());
            Ok(())
        }

        #[test]
        fn egress_cursors_and_shared_query_keep_scope_filter_and_snapshot_fences() -> io::Result<()>
        {
            let mut state = State::new(NODE.into());
            let mut second = fact(1, Outcome::Failure("egress_failed"));
            second.key.slot = "second".into();
            state.apply(
                frame(vec![fact(1, Outcome::Failure("egress_failed")), second]),
                Instant::now(),
                None,
            )?;
            let handle = handle(state);
            let local = handle.page(Filter::Active, None, 1).expect("local");
            let scoped = handle.egress_page(Filter::Active, None, 1).expect("egress");
            let scoped_cursor = scoped.next_cursor.as_deref().expect("egress cursor");
            let query =
                Query::parse(Some(&format!("after={scoped_cursor}&limit=1"))).expect("query");
            assert_eq!(
                query.egress_offset(NODE, scoped.revision.parse().unwrap()),
                Ok(1)
            );
            assert_eq!(
                query.egress_offset(FOREIGN, scoped.revision.parse().unwrap()),
                Err(PageError::Changed)
            );
            assert_eq!(query.egress_offset(NODE, 0), Err(PageError::Changed));
            assert!(matches!(
                handle.egress_page(Filter::Active, local.next_cursor.as_deref(), 1),
                Err(PageError::InvalidQuery)
            ));
            assert!(matches!(
                handle.page(Filter::Active, Some(scoped_cursor), 1),
                Err(PageError::InvalidQuery)
            ));
            assert!(matches!(
                handle.egress_page(Filter::Recent, Some(scoped_cursor), 1),
                Err(PageError::Changed)
            ));
            for invalid in [
                "state=active&state=recent",
                "after=",
                "limit=0",
                "limit=17",
                "limit=01",
                "node=anything",
                "limit=1&limit=2",
                "after=%FF",
            ] {
                assert!(Query::parse(Some(invalid)).is_err(), "query: {invalid}");
            }
            let default = Query::parse(None).expect("defaults");
            assert_eq!(default.filter, Filter::Active);
            assert_eq!(default.limit, 10);
            assert!(default.after.is_none());
            Ok(())
        }

        #[test]
        fn egress_sampling_metadata_ignores_unrelated_failures_and_preserves_failed_health_time()
        -> io::Result<()> {
            let now = Instant::now();
            let mut state = State::new(NODE.into());
            let mut observed = frame(vec![fact(1, Outcome::Failure("egress_failed"))]);
            observed.egress = Some(collection(now, 10, false));
            observed.error = true;
            state.apply(observed, now + Duration::from_secs(5), Some(15))?;
            assert!(state.collection_error);
            assert!(!state.egress.collection_error);
            assert_eq!(state.egress.completed, Some(now));
            assert_eq!(state.egress.observed_at, Some(10));
            let revision = state.egress.revision;
            let mut unrelated = other_frame(vec![other(1)]);
            unrelated.error = true;
            state.apply(unrelated, now + Duration::from_secs(10), Some(20))?;
            assert_eq!(state.egress.revision, revision);
            assert_eq!(state.egress.completed, Some(now));
            assert_eq!(state.egress.observed_at, Some(10));
            assert!(!state.egress.collection_error);
            assert!(
                state
                    .active
                    .values()
                    .find(|incident| incident.key.local_egress(NODE))
                    .unwrap()
                    .fresh
            );
            state.apply(
                Frame {
                    error: true,
                    egress: Some(collection(now + Duration::from_secs(20), 30, true)),
                    ..Frame::default()
                },
                now + Duration::from_secs(20),
                Some(30),
            )?;
            assert!(state.egress.collection_error);
            assert!(state.egress.revision > revision);
            assert_eq!(state.egress.completed, Some(now));
            assert_eq!(state.egress.observed_at, Some(10));
            let page = handle(state)
                .egress_page(Filter::Active, None, 16)
                .expect("failed read page");
            assert_eq!(page.active_count, 1);
            assert!(!page.items[0].evidence_fresh);
            assert!(page.collection_error);
            assert_eq!(page.observed_at_unix_ms.as_deref(), Some("10"));
            Ok(())
        }

        #[test]
        fn egress_export_preserves_unknown_replacement_retirement_and_new_success_semantics()
        -> io::Result<()> {
            for replacement in [false, true] {
                let now = Instant::now();
                let handle = handle(State::new(NODE.into()));
                handle.0.apply(
                    frame(vec![fact(1, Outcome::Failure("egress_failed"))]),
                    now,
                    Some(1),
                )?;
                handle
                    .0
                    .apply(frame(vec![fact(2, Outcome::Unknown)]), now, Some(2))?;
                let page = handle
                    .egress_page(Filter::Active, None, 16)
                    .expect("unknown");
                assert_eq!(page.active_count, 1);
                assert!(!page.items[0].evidence_fresh);
                let mut success = fact(3, Outcome::Success);
                if replacement {
                    success.lineage = "replacement".into();
                }
                handle.0.apply(frame(vec![success]), now, Some(3))?;
                let page = handle.egress_page(Filter::Recent, None, 16).expect("ended");
                assert_eq!(page.active_count, 0);
                assert_eq!(page.recent_count, 1);
                assert_eq!(
                    page.items[0].status,
                    if replacement {
                        Status::Unmonitored
                    } else {
                        Status::Recovered
                    }
                );
                assert_eq!(page.items[0].evidence_fresh, !replacement);
            }
            let handle = handle(State::new(NODE.into()));
            handle.0.apply(
                frame(vec![fact(1, Outcome::Failure("egress_failed"))]),
                Instant::now(),
                Some(1),
            )?;
            handle.0.apply(frame(Vec::new()), Instant::now(), Some(2))?;
            let page = handle
                .egress_page(Filter::Recent, None, 16)
                .expect("retired");
            assert_eq!(page.items[0].status, Status::Unmonitored);
            assert!(!page.items[0].evidence_fresh);
            Ok(())
        }

        #[test]
        fn egress_history_reports_only_its_own_shared_ring_evictions() -> io::Result<()> {
            let now = Instant::now();
            let mut state = State::new(NODE.into());
            state.apply(
                frame(vec![fact(1, Outcome::Failure("egress_failed"))]),
                now,
                None,
            )?;
            state.apply(frame(Vec::new()), now, None)?;
            let revision = state.egress.revision;
            for number in 1..MAX_RECENT as u64 {
                state.apply(other_frame(vec![other(number)]), now, None)?;
                state.apply(other_frame(Vec::new()), now, None)?;
            }
            assert_eq!(state.egress.revision, revision);
            assert_eq!(state.egress.dropped, 0);
            state.apply(other_frame(vec![other(MAX_RECENT as u64)]), now, None)?;
            state.apply(other_frame(Vec::new()), now, None)?;
            assert_eq!(state.egress.dropped, 1);
            assert!(state.egress.revision > revision);
            let revision = state.egress.revision;
            state.apply(other_frame(vec![other(MAX_RECENT as u64 + 1)]), now, None)?;
            state.apply(other_frame(Vec::new()), now, None)?;
            assert_eq!(state.egress.dropped, 1);
            assert_eq!(state.egress.revision, revision);
            let page = handle(state)
                .egress_page(Filter::Recent, None, 16)
                .expect("history");
            assert_eq!(page.recent_count, 0);
            assert_eq!(page.dropped, "1");
            assert!(page.items.is_empty());
            Ok(())
        }

        #[test]
        fn egress_episode_and_metadata_sequences_do_not_disclose_unrelated_activity()
        -> io::Result<()> {
            fn scenario(interleaved: bool) -> io::Result<State> {
                let now = Instant::now();
                let mut state = State::new(NODE.into());
                for number in 1..=3 {
                    if interleaved {
                        let mut episode = other(number);
                        episode.sequence = None;
                        let mut metadata = other(number);
                        metadata.key.kind = Kind::Policy;
                        metadata.key.origin = NODE.into();
                        metadata.key.resource = None;
                        metadata.key.slot = "policy".into();
                        metadata.sequence = None;
                        metadata.outcome = Outcome::Success;
                        state.apply(other_frame(vec![episode, metadata]), now, Some(number))?;
                    }
                    let outcome = if number == 2 {
                        Outcome::Success
                    } else {
                        Outcome::Failure("egress_failed")
                    };
                    let mut catalog = fact(number, outcome);
                    catalog.key.kind = Kind::HealthCatalog;
                    catalog.key.resource = None;
                    catalog.key.slot = "catalog".into();
                    catalog.check = None;
                    catalog.sequence = None;
                    if number != 2 {
                        catalog.outcome = Outcome::Failure("health_catalog_stale");
                    }
                    state.apply(
                        Frame {
                            facts: vec![catalog, fact(number, outcome)],
                            complete: BTreeSet::from([Kind::EgressCheck, Kind::HealthCatalog]),
                            egress: Some(collection(now, number, false)),
                            ..Frame::default()
                        },
                        now,
                        Some(number),
                    )?;
                }
                Ok(state)
            }

            let baseline = scenario(false)?;
            let interleaved = scenario(true)?;
            assert!(interleaved.next_id > baseline.next_id);
            assert!(interleaved.evidence > baseline.evidence);
            assert_eq!(interleaved.egress.next_id, baseline.egress.next_id);
            assert_eq!(interleaved.egress.evidence, baseline.egress.evidence);
            let baseline = handle(baseline);
            let interleaved = handle(interleaved);
            for filter in [Filter::Active, Filter::Recent] {
                let baseline_page = baseline.egress_page(filter, None, 16).expect("baseline");
                let interleaved_page = interleaved
                    .egress_page(filter, None, 16)
                    .expect("interleaved");
                let project = |page: EgressPage| {
                    page.items
                        .into_iter()
                        .map(|row| (row.kind, row.id, row.evidence_sequence, row.status))
                        .collect::<Vec<_>>()
                };
                assert_eq!(project(interleaved_page), project(baseline_page));
            }
            let original = interleaved
                .page(Filter::Active, None, 16)
                .expect("all sources");
            let state = interleaved.0.state()?;
            let incident = state
                .active
                .values()
                .find(|incident| incident.key.local_egress(NODE))
                .expect("local incident");
            let row = original
                .items
                .iter()
                .find(|row| row.origin_node_id == NODE && row.kind == incident.key.kind)
                .expect("all-source local row");
            assert_eq!(row.id, incident.id.to_string());
            assert_ne!(row.id, incident.egress_id.expect("scoped ID").to_string());
            Ok(())
        }
    }
    mod maintenance {
        use super::*;
        use crate::{access::AdmissionState, manage::proxy};

        fn observed(node: &str) -> (store::alerts::Snapshot, AdmissionState, proxy::View) {
            (
                store::alerts::Snapshot {
                    policy_revision: 2,
                    targets: Vec::new(),
                    admission: Some(store::alerts::Admission {
                        node_id: node.into(),
                        ownership: store::Ownership {
                            controller_node_id: None,
                            epoch: 1,
                            last_terminal_command: 0,
                        },
                        accepting: false,
                    }),
                },
                AdmissionState {
                    revision: 2,
                    accepting: false,
                },
                proxy::View {
                    runtime_id: URL_SAFE_NO_PAD.encode([11; 16]),
                    phase: proxy::Phase::Draining,
                    stopping: false,
                    intent: Some(proxy::DrainIntent {
                        node_id: node.into(),
                        request_id: URL_SAFE_NO_PAD.encode([12; 16]),
                        epoch: 1,
                        revision: 2,
                        actor: proxy::DrainActor::Local {
                            administrator_id: URL_SAFE_NO_PAD.encode([13; 16]),
                        },
                    }),
                },
            )
        }

        #[test]
        fn web_service_stop_is_not_failure_and_failed_bind_is_observed() -> io::Result<()> {
            let fixture = Fixture::new()?;
            let (_, mut runner) = fixture.runner(true, false)?;
            let mut service = proxy::service::View::default();
            let mut state = State::new(fixture.node.clone());
            let now = Instant::now();
            for phase in [
                proxy::service::Phase::Stopped,
                proxy::service::Phase::Starting,
                proxy::service::Phase::Stopping,
            ] {
                service.phase = phase;
                let mut frame = Frame::default();
                assert!(!runner.service_policy_fact(&mut frame, &service, 2));
                state.apply(frame, now, Some(10))?;
                assert!(state.active.is_empty());
            }
            service.phase = proxy::service::Phase::Failed;
            let mut frame = Frame::default();
            assert!(!runner.service_policy_fact(&mut frame, &service, 2));
            state.apply(frame, now, Some(20))?;
            assert_eq!(
                state.active.values().next().expect("actual failure").code,
                "proxy_not_running"
            );
            service.phase = proxy::service::Phase::Starting;
            let mut frame = Frame::default();
            runner.service_policy_fact(&mut frame, &service, 2);
            state.apply(frame, now, Some(30))?;
            assert!(
                !state
                    .active
                    .values()
                    .next()
                    .expect("not recovered by starting")
                    .fresh
            );
            service.phase = proxy::service::Phase::Running;
            assert!(runner.service_policy_fact(&mut Frame::default(), &service, 2));
            service.cleanup_confirmed = false;
            let mut frame = Frame::default();
            assert!(!runner.service_policy_fact(&mut frame, &service, 2));
            assert!(
                frame
                    .facts
                    .iter()
                    .any(|fact| matches!(fact.outcome, Outcome::Failure("proxy_not_running")))
            );
            Ok(())
        }

        fn collect(
            runner: &mut Runner,
            saved: &store::alerts::Snapshot,
            published: Option<AdmissionState>,
            running: bool,
            runtime: &proxy::View,
            now: Instant,
        ) -> Frame {
            let mut frame = Frame::default();
            runner.runtime_policy_facts(&mut frame, saved, published, running, Some(runtime), now);
            frame
        }

        #[test]
        fn planned_drain_does_not_report_not_running_or_recover_existing_failures() -> io::Result<()>
        {
            let fixture = Fixture::new()?;
            let (_, mut runner) = fixture.runner(true, false)?;
            let (saved, published, mut runtime) = observed(&fixture.node);
            let now = Instant::now();
            let mut state = State::new(fixture.node.clone());
            for elapsed in [0, 16, 60] {
                if elapsed == 60 {
                    runtime.phase = proxy::Phase::Drained;
                }
                state.apply(
                    collect(
                        &mut runner,
                        &saved,
                        Some(published),
                        false,
                        &runtime,
                        now + Duration::from_secs(elapsed),
                    ),
                    now,
                    Some(elapsed),
                )?;
                assert!(state.active.is_empty());
                assert!(state.recent.is_empty());
            }
            // A genuine same-policy failure predating the request remains recorded.
            // A planned pause is not a new successful policy observation.
            runner.policy_fact(&mut Frame::default(), 2, None, false, now);
            let mut failure = Frame::default();
            runner.policy_fact(&mut failure, 2, None, false, now + Duration::from_secs(16));
            state.apply(failure, now, Some(70))?;
            assert_eq!(state.active.len(), 1);
            state.apply(
                collect(&mut runner, &saved, Some(published), false, &runtime, now),
                now,
                Some(80),
            )?;
            let retained = state.active.values().next().unwrap();
            assert_eq!(retained.code, "proxy_not_running");
            assert!(!retained.fresh);
            assert!(state.recent.is_empty());
            Ok(())
        }

        #[test]
        fn invalidated_pause_owner_or_publication_cannot_borrow_old_maintenance_status()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let (_, mut runner) = fixture.runner(true, false)?;
            let now = Instant::now();
            for case in 0..9 {
                let (mut saved, mut published, mut runtime) = observed(&fixture.node);
                match case {
                    0 => saved.admission = None,
                    1 => saved.admission.as_mut().unwrap().accepting = true,
                    2 => saved.admission.as_mut().unwrap().ownership.epoch = 2,
                    3 => {
                        saved
                            .admission
                            .as_mut()
                            .unwrap()
                            .ownership
                            .controller_node_id = Some(URL_SAFE_NO_PAD.encode([15; 16]))
                    }
                    4 => {
                        saved.policy_revision = 3;
                        published.revision = 3;
                    }
                    5 => published.accepting = true,
                    6 => published.revision = 1,
                    7 => runtime.intent = None,
                    8 => {
                        runtime.intent.as_mut().unwrap().node_id = URL_SAFE_NO_PAD.encode([16; 16])
                    }
                    _ => unreachable!(),
                }
                runner.pending_policy = None;
                let _ = collect(&mut runner, &saved, Some(published), false, &runtime, now);
                let frame = collect(
                    &mut runner,
                    &saved,
                    Some(published),
                    false,
                    &runtime,
                    now + Duration::from_secs(16),
                );
                assert!(
                    frame
                        .facts
                        .iter()
                        .any(|fact| matches!(fact.outcome, Outcome::Failure("proxy_not_running"))),
                    "invalid maintenance case {case}"
                );
            }
            // A matching remote owner qualifies; a different current controller does
            // not inherit an earlier controller's process-local request.
            let (mut saved, published, mut runtime) = observed(&fixture.node);
            let controller = URL_SAFE_NO_PAD.encode([17; 16]);
            saved
                .admission
                .as_mut()
                .unwrap()
                .ownership
                .controller_node_id = Some(controller.clone());
            runtime.intent.as_mut().unwrap().actor = proxy::DrainActor::Remote {
                controller_node_id: controller,
                administrator_id: URL_SAFE_NO_PAD.encode([18; 16]),
            };
            let frame = collect(
                &mut runner,
                &saved,
                Some(published),
                false,
                &runtime,
                now + Duration::from_secs(60),
            );
            assert!(
                frame
                    .facts
                    .iter()
                    .all(|fact| matches!(fact.outcome, Outcome::Unknown))
            );
            Ok(())
        }

        #[test]
        fn terminal_runtime_failures_remain_distinct_and_unknown_never_clears_them()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let (_, mut runner) = fixture.runner(true, false)?;
            let now = Instant::now();
            for (phase, code) in [
                (proxy::Phase::Failed, "proxy_drain_failed"),
                (proxy::Phase::Interrupted, "proxy_drain_interrupted"),
            ] {
                let (saved, published, mut runtime) = observed(&fixture.node);
                runtime.phase = phase;
                let mut state = State::new(fixture.node.clone());
                state.apply(
                    collect(&mut runner, &saved, Some(published), false, &runtime, now),
                    now,
                    Some(1),
                )?;
                assert!(state.active.values().any(|incident| incident.code == code));
                let revision = state.revision;
                state.apply(
                    collect(&mut runner, &saved, Some(published), false, &runtime, now),
                    now,
                    Some(2),
                )?;
                assert_eq!(
                    state.revision, revision,
                    "identical terminal results do not refresh evidence"
                );
                state.apply(
                    Frame {
                        error: true,
                        ..Frame::default()
                    },
                    now,
                    Some(3),
                )?;
                assert!(
                    state
                        .active
                        .values()
                        .any(|incident| incident.code == code && !incident.fresh)
                );
                runtime.phase = proxy::Phase::Draining;
                state.apply(
                    collect(&mut runner, &saved, Some(published), false, &runtime, now),
                    now,
                    Some(4),
                )?;
                assert!(
                    state
                        .active
                        .values()
                        .any(|incident| incident.code == code && !incident.fresh)
                );
                assert!(state.recent.is_empty());
                runtime.runtime_id = URL_SAFE_NO_PAD.encode([19; 16]);
                state.apply(
                    collect(&mut runner, &saved, Some(published), false, &runtime, now),
                    now,
                    Some(5),
                )?;
                assert!(state.active.is_empty());
                assert_eq!(state.recent.back().unwrap().status, Status::Unmonitored);
            }
            Ok(())
        }

        #[test]
        fn actual_stop_and_acceptance_windows_never_report_policy_recovery() -> io::Result<()> {
            let fixture = Fixture::new()?;
            let (_, mut runner) = fixture.runner(true, false)?;
            let (saved, published, mut runtime) = observed(&fixture.node);
            let now = Instant::now();
            for (running, stopping) in [(true, false), (false, true), (true, true)] {
                runtime.stopping = stopping;
                let frame = collect(
                    &mut runner,
                    &saved,
                    Some(published),
                    running,
                    &runtime,
                    now + Duration::from_secs(30),
                );
                assert!(
                    frame
                        .facts
                        .iter()
                        .all(|fact| matches!(fact.outcome, Outcome::Unknown))
                );
            }
            Ok(())
        }

        #[tokio::test]
        async fn real_saved_pause_request_and_collector_keep_terminal_results_distinct()
        -> io::Result<()> {
            use crate::{manage::drain, server};

            // Exercise the real saved pause, Reader publication, request acceptance and
            // collector wiring, not a network/driver-completion claim. No wall-clock
            // delay is necessary to place the existing policy grace in the past.
            for terminal in [
                None,
                Some(io::ErrorKind::TimedOut),
                Some(io::ErrorKind::PermissionDenied),
            ] {
                let fixture = Fixture::new()?;
                let policy = fixture.policy.as_ref().unwrap();
                let connection = rusqlite::Connection::open_with_flags(
                    fixture.directory.join("management.sqlite3"),
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                )
                .map_err(io::Error::other)?;
                let administrator: String = connection
                    .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                    .map_err(io::Error::other)?;
                drop(connection);
                let runtime = proxy::Lifecycle::new(server::Handle::new())?;
                let runtime_id = runtime.snapshot()?.runtime_id;
                policy.configure_runtime(runtime.clone())?;
                policy.activate().await?;
                let changed = policy
                    .change_admission(
                        administrator.clone(),
                        1,
                        store::admission::Assertion {
                            node_id: fixture.node.clone(),
                            epoch: 1,
                        },
                        false,
                    )
                    .await?;
                assert_eq!(changed.revision, 2);
                policy
                    .request_drain(
                        administrator,
                        drain::Request {
                            expected_node_id: fixture.node.clone(),
                            expected_epoch: "1".into(),
                            expected_revision: "2".into(),
                            runtime_id,
                            request_id: URL_SAFE_NO_PAD.encode([20; 16]),
                        },
                    )
                    .await?;
                assert!(!policy.is_running());
                let (handle, mut runner) = fixture.runner(true, false)?;
                runner.pending_policy =
                    Some(("2:2:false".into(), Instant::now() - Duration::from_secs(30)));
                runner.collect_once().await?;
                assert!(
                    handle
                        .page(Filter::Active, None, 16)
                        .unwrap()
                        .items
                        .iter()
                        .all(|incident| incident.kind != Kind::Policy)
                );
                let result = terminal.map_or(Ok(()), |kind| {
                    Err(io::Error::new(kind, "fixture driver result"))
                });
                assert!(runtime.complete(&result)?);
                runner.collect_once().await?;
                let codes = handle
                    .page(Filter::Active, None, 16)
                    .unwrap()
                    .items
                    .into_iter()
                    .filter(|incident| incident.kind == Kind::Policy)
                    .map(|incident| incident.code)
                    .collect::<Vec<_>>();
                let expected = match terminal {
                    None => Vec::new(),
                    Some(io::ErrorKind::TimedOut) => vec!["proxy_drain_interrupted"],
                    Some(_) => vec!["proxy_drain_failed"],
                };
                assert_eq!(codes, expected);
                assert!(runner.pending_policy.is_none() || terminal.is_some());
            }
            Ok(())
        }
    }
    mod nodes {
        use super::*;

        const FOREIGN: &str = "AQAAAAAAAAAAAAAAAAAAAA";
        const LOCAL: [Kind; 8] = [
            Kind::EgressCheck,
            Kind::HealthCatalog,
            Kind::ManagementHttps,
            Kind::NodeTls,
            Kind::ProxyTls,
            Kind::Policy,
            Kind::TrafficCheckpoint,
            Kind::TrafficContinuity,
        ];

        fn observation(kind: Kind, slot: usize, sequence: u64, outcome: Outcome) -> Fact {
            Fact {
                key: Key {
                    kind,
                    origin: NODE.into(),
                    resource: matches!(kind, Kind::EgressCheck | Kind::ProxyTls)
                        .then(|| NODE.into()),
                    slot: slot.to_string(),
                },
                lineage: "node-self-generation".into(),
                stamp: sequence.to_string(),
                sequence: Some(sequence),
                check: (kind == Kind::EgressCheck).then_some(health::CheckKind::Bind),
                target: None,
                outcome,
            }
        }

        fn complete(facts: Vec<Fact>) -> Frame {
            Frame {
                facts,
                complete: LOCAL
                    .into_iter()
                    .chain([Kind::RemoteJob, Kind::RemoteTraffic])
                    .collect(),
                ..Frame::default()
            }
        }

        fn local_facts() -> Vec<Fact> {
            LOCAL
                .into_iter()
                .enumerate()
                .map(|(slot, kind)| {
                    observation(
                        kind,
                        slot,
                        1,
                        Outcome::Failure(match kind {
                            Kind::EgressCheck => "egress_failed",
                            Kind::HealthCatalog => "health_catalog_stale",
                            Kind::ManagementHttps => "https_identity_expiring",
                            Kind::NodeTls => "node_tls_identity_expiring",
                            Kind::ProxyTls => "proxy_tls_identity_expiring",
                            Kind::Policy => "proxy_not_running",
                            Kind::TrafficCheckpoint => "traffic_checkpoint_stale",
                            Kind::TrafficContinuity => "traffic_history_gap",
                            Kind::RemoteTraffic | Kind::RemoteJob | Kind::RemoteObservation => {
                                unreachable!("fixed local test inventory")
                            }
                        }),
                    )
                })
                .collect()
        }

        #[test]
        fn own_operations_filter_before_counts_and_pages_without_downstream_payload()
        -> io::Result<()> {
            let mut facts = local_facts();
            facts.push(observation(
                Kind::RemoteJob,
                9,
                1,
                Outcome::Failure("remote_job_blocked"),
            ));
            facts.push(observation(
                Kind::RemoteTraffic,
                10,
                1,
                Outcome::Failure("remote_traffic_stale"),
            ));
            let mut foreign =
                observation(Kind::EgressCheck, 11, 1, Outcome::Failure("foreign_canary"));
            foreign.key.origin = FOREIGN.into();
            facts.push(foreign);
            let mut state = State::new(NODE.into());
            state.apply(complete(facts), Instant::now(), Some(1))?;
            let handle = handle(state);
            let mut after = None;
            let mut ids = BTreeSet::new();
            let mut kinds = BTreeSet::new();
            let mut page_count = 0;
            loop {
                let page = handle
                    .node_page(Filter::Active, after.as_deref(), 3)
                    .expect("page");
                assert_eq!(page.node_id, NODE);
                assert_eq!(page.active_count, 8);
                assert_eq!(page.recent_count, 0);
                assert_eq!(page.dropped, "0");
                assert!(page.items.len() <= 3);
                for item in &page.items {
                    assert_eq!(item.origin_node_id, NODE);
                    assert!(ids.insert(item.id.clone()));
                    kinds.insert(item.kind);
                }
                let encoded = serde_json::to_string(&page)?;
                for excluded in [
                    FOREIGN,
                    "foreign_canary",
                    "remote_job",
                    "remote_traffic",
                    "remote_cached",
                    "remote_egress",
                ] {
                    assert!(!encoded.contains(excluded), "excluded {excluded}");
                }
                let mut json = serde_json::to_value(&page)?;
                assert!(serde_json::from_value::<NodePage>(json.clone()).is_ok());
                json["coverage"]["remote_cached"] = true.into();
                assert!(serde_json::from_value::<NodePage>(json).is_err());
                page_count += 1;
                after = page.next_cursor;
                if after.is_none() {
                    break;
                }
                assert!(page_count < 4);
            }
            assert_eq!(page_count, 3);
            assert_eq!(ids.len(), 8);
            assert_eq!(kinds, BTreeSet::from(LOCAL));
            Ok(())
        }

        #[test]
        fn node_cursors_are_separate_and_global_changes_only_invalidate_the_snapshot()
        -> io::Result<()> {
            let mut state = State::new(NODE.into());
            state.apply(complete(local_facts()), Instant::now(), Some(1))?;
            let handle = handle(state);
            let node = handle.node_page(Filter::Active, None, 1).expect("node");
            let cursor = node.next_cursor.as_deref().expect("cursor");
            let query = Query::parse(Some(&format!("after={cursor}&limit=1"))).expect("query");
            assert_eq!(
                query.node_offset(NODE, node.revision.parse().unwrap()),
                Ok(1)
            );
            assert!(matches!(
                handle.page(Filter::Active, Some(cursor), 1),
                Err(PageError::InvalidQuery)
            ));
            assert!(matches!(
                handle.egress_page(Filter::Active, Some(cursor), 1),
                Err(PageError::InvalidQuery)
            ));
            for namespace in ["active", "egress-active"] {
                let other = cursor.replace("node-active", namespace);
                assert!(matches!(
                    handle.node_page(Filter::Active, Some(&other), 1),
                    Err(PageError::InvalidQuery)
                ));
            }
            assert!(matches!(
                handle.node_page(Filter::Recent, Some(cursor), 1),
                Err(PageError::Changed)
            ));
            assert_eq!(
                query.node_offset(FOREIGN, node.revision.parse().unwrap()),
                Err(PageError::Changed)
            );
            for limit in [0, 17] {
                assert!(matches!(
                    handle.node_page(Filter::Active, None, limit),
                    Err(PageError::InvalidQuery)
                ));
            }
            let mut facts = local_facts();
            facts.push(observation(
                Kind::RemoteJob,
                9,
                1,
                Outcome::Failure("remote_job_blocked"),
            ));
            handle.0.apply(complete(facts), Instant::now(), Some(2))?;
            assert!(matches!(
                handle.node_page(Filter::Active, Some(cursor), 1),
                Err(PageError::Changed)
            ));
            let current = handle.node_page(Filter::Active, None, 16).expect("current");
            assert_eq!(current.active_count, 8);
            assert!(current.items.iter().all(|row| row.evidence_fresh));
            Ok(())
        }

        #[test]
        fn node_drop_counter_counts_only_its_capacity_loss_and_shared_ring_eviction()
        -> io::Result<()> {
            let now = Instant::now();
            let mut state = State::new(NODE.into());
            let excluded = (0..MAX_ACTIVE)
                .map(|slot| {
                    observation(
                        Kind::RemoteJob,
                        slot,
                        1,
                        Outcome::Failure("remote_job_blocked"),
                    )
                })
                .collect();
            state.apply(complete(excluded), now, None)?;
            state.apply(
                Frame {
                    facts: vec![observation(
                        Kind::RemoteJob,
                        MAX_ACTIVE,
                        1,
                        Outcome::Failure("remote_job_blocked"),
                    )],
                    ..Frame::default()
                },
                now,
                None,
            )?;
            assert_eq!(state.dropped, 1);
            assert_eq!(state.local_dropped, 0);
            let local = observation(Kind::Policy, 0, 1, Outcome::Failure("proxy_not_running"));
            state.apply(
                Frame {
                    facts: vec![local],
                    ..Frame::default()
                },
                now,
                None,
            )?;
            assert_eq!(state.local_dropped, 1);
            state.local_dropped = u64::MAX;
            let local = observation(Kind::Policy, 1, 1, Outcome::Failure("proxy_not_running"));
            assert!(
                state
                    .apply(
                        Frame {
                            facts: vec![local],
                            ..Frame::default()
                        },
                        now,
                        None
                    )
                    .is_err()
            );
            assert_eq!(state.local_dropped, u64::MAX);

            let mut state = State::new(NODE.into());
            state.apply(
                complete(vec![observation(
                    Kind::Policy,
                    0,
                    1,
                    Outcome::Failure("proxy_not_running"),
                )]),
                now,
                None,
            )?;
            state.apply(complete(Vec::new()), now, None)?;
            for slot in 0..MAX_RECENT {
                state.apply(
                    complete(vec![observation(
                        Kind::RemoteJob,
                        slot,
                        1,
                        Outcome::Failure("remote_job_blocked"),
                    )]),
                    now,
                    None,
                )?;
                state.apply(complete(Vec::new()), now, None)?;
            }
            assert_eq!(
                state.local_dropped, 1,
                "excluded traffic can evict a retained local episode"
            );
            state.apply(
                complete(vec![observation(
                    Kind::RemoteJob,
                    MAX_RECENT,
                    1,
                    Outcome::Failure("remote_job_blocked"),
                )]),
                now,
                None,
            )?;
            state.apply(complete(Vec::new()), now, None)?;
            assert_eq!(
                state.local_dropped, 1,
                "discarding another excluded episode is not a local gap"
            );
            let page = handle(state)
                .node_page(Filter::Recent, None, 16)
                .expect("recent");
            assert_eq!(page.dropped, "1");
            assert_eq!(page.recent_count, 0);
            assert!(page.items.is_empty());
            Ok(())
        }

        #[test]
        fn missing_collection_and_partial_failure_are_not_empty_healthy_results() -> io::Result<()>
        {
            let mut state = State::new(NODE.into());
            let empty = handle(state.clone())
                .node_page(Filter::Active, None, 1)
                .expect("empty");
            assert_eq!(empty.age_millis, None);
            assert_eq!(empty.observed_at_unix_ms, None);
            state.apply(complete(local_facts()), Instant::now(), Some(5))?;
            state.apply(
                Frame {
                    error: true,
                    ..Frame::default()
                },
                Instant::now(),
                Some(9),
            )?;
            let page = handle(state)
                .node_page(Filter::Active, None, 16)
                .expect("stale");
            assert!(page.collection_error);
            assert_eq!(page.observed_at_unix_ms.as_deref(), Some("5"));
            assert_eq!(page.active_count, 8);
            assert!(page.items.iter().all(|row| row.status == Status::Active
                && row.evidence_fresh
                    == matches!(row.kind, Kind::EgressCheck | Kind::HealthCatalog)));
            Ok(())
        }
    }

    const NODE: &str = "AAAAAAAAAAAAAAAAAAAAAA";

    fn fact(sequence: u64, outcome: Outcome) -> Fact {
        Fact {
            key: Key {
                kind: Kind::EgressCheck,
                origin: NODE.to_owned(),
                resource: Some(NODE.to_owned()),
                slot: "bind".into(),
            },
            lineage: "boot:1:127.0.0.1".into(),
            stamp: sequence.to_string(),
            sequence: Some(sequence),
            check: Some(health::CheckKind::Bind),
            target: None,
            outcome,
        }
    }

    fn frame(facts: Vec<Fact>) -> Frame {
        Frame {
            facts,
            complete: BTreeSet::from([Kind::EgressCheck]),
            error: false,
            failures: Vec::new(),
            egress: Some(EgressCollection {
                completed: Instant::now(),
                observed_at: None,
                error: false,
            }),
            ..Frame::default()
        }
    }

    fn active(state: &State) -> &Incident {
        state.active.values().next().expect("active incident")
    }

    #[test]
    fn only_newer_same_lineage_success_recovers_and_repeats_do_not_refresh() -> io::Result<()> {
        let mut state = State::new(NODE.into());
        let now = Instant::now();
        state.apply(
            frame(vec![fact(4, Outcome::Failure("egress_failed"))]),
            now,
            Some(10),
        )?;
        let revision = state.revision;
        state.apply(
            frame(vec![fact(4, Outcome::Failure("egress_failed"))]),
            now + Duration::from_secs(5),
            Some(20),
        )?;
        assert_eq!(state.revision, revision);
        assert_eq!(active(&state).last, Some(10));
        for outcome in [Outcome::Unknown, Outcome::Success] {
            state.apply(frame(vec![fact(4, outcome)]), now, Some(30))?;
            assert_eq!(state.active.len(), 1);
        }
        state.apply(frame(vec![fact(3, Outcome::Success)]), now, Some(40))?;
        assert_eq!(state.active.len(), 1);
        assert!(
            !active(&state).fresh,
            "regressed evidence cannot become fresh"
        );
        state.apply(
            frame(vec![fact(5, Outcome::Failure("egress_timed_out"))]),
            now,
            Some(50),
        )?;
        assert_eq!(state.active.len(), 1);
        assert_eq!(active(&state).last, Some(50));
        state.apply(frame(vec![fact(6, Outcome::Success)]), now, Some(60))?;
        assert!(state.active.is_empty());
        let ended = state.recent.front().expect("recovered incident");
        assert_eq!(ended.status, Status::Recovered);
        assert_eq!(ended.sequence, 6);
        assert_eq!(ended.first, Some(10));
        assert_eq!(ended.last, Some(60));
        Ok(())
    }

    #[test]
    fn unknown_stale_and_failed_rounds_preserve_incident_with_unfresh_evidence() -> io::Result<()> {
        let mut state = State::new(NODE.into());
        let now = Instant::now();
        state.apply(
            frame(vec![fact(1, Outcome::Failure("egress_failed"))]),
            now,
            Some(1),
        )?;
        state.apply(frame(vec![fact(2, Outcome::Unknown)]), now, Some(2))?;
        assert!(!active(&state).fresh);
        assert_eq!(active(&state).sequence, 1);
        assert_eq!(active(&state).last, Some(1));
        state.apply(
            Frame {
                error: true,
                ..Frame::default()
            },
            now,
            Some(3),
        )?;
        assert_eq!(state.active.len(), 1);
        assert!(state.collection_error);
        assert!(!active(&state).fresh);
        state.apply(Frame::default(), now, Some(4))?;
        assert_eq!(
            state.active.len(),
            1,
            "incomplete catalog cannot prove retirement"
        );
        Ok(())
    }

    #[test]
    fn all_lineage_fences_and_resource_exit_end_as_unmonitored() -> io::Result<()> {
        for lineage in [
            "new-boot:1:127.0.0.1",
            "boot:2:127.0.0.1",
            "boot:1:127.0.0.2",
        ] {
            let mut state = State::new(NODE.into());
            let now = Instant::now();
            state.apply(
                frame(vec![fact(8, Outcome::Failure("egress_failed"))]),
                now,
                Some(1),
            )?;
            let mut changed = fact(9, Outcome::Success);
            changed.lineage = lineage.into();
            state.apply(frame(vec![changed]), now, Some(2))?;
            assert!(state.active.is_empty());
            assert_eq!(state.recent[0].status, Status::Unmonitored);
            assert!(!state.recent[0].fresh);
        }
        let mut state = State::new(NODE.into());
        let now = Instant::now();
        state.apply(
            frame(vec![fact(1, Outcome::Failure("egress_failed"))]),
            now,
            None,
        )?;
        state.apply(frame(Vec::new()), now, None)?;
        assert_eq!(state.recent[0].status, Status::Unmonitored);
        assert!(state.recent[0].ended.is_none());
        assert!(
            state.known.is_empty(),
            "retirement frees the bounded evidence map"
        );
        Ok(())
    }

    #[test]
    fn active_and_healthy_evidence_are_bounded_and_drops_are_explicit() -> io::Result<()> {
        let mut state = State::new(NODE.into());
        let facts = (0..=MAX_ACTIVE)
            .map(|number| {
                let mut fact = fact(1, Outcome::Failure("egress_failed"));
                fact.key.slot = number.to_string();
                fact
            })
            .collect();
        state.apply(frame(facts), Instant::now(), None)?;
        assert_eq!(state.active.len(), MAX_ACTIVE);
        assert_eq!(state.known.len(), MAX_ACTIVE);
        assert_eq!(state.dropped, 1);
        assert_eq!(state.egress.dropped, 1);
        Ok(())
    }

    fn handle(state: State) -> Handle {
        Handle(Arc::new(Shared {
            boot_id: NODE.into(),
            coverage: Coverage {
                local_egress: true,
                local_traffic: false,
                local_proxy_expected: false,
                local_management_https: false,
                local_node_tls: false,
                local_proxy_tls: false,
                remote_cached: true,
                remote_egress: false,
                remote_observation: false,
            },
            state: Mutex::new(Arc::new(state)),
            available: AtomicBool::new(true),
            remote_observation: AtomicBool::new(false),
        }))
    }

    #[test]
    fn pagination_binds_boot_revision_filter_and_reports_history_drops() -> io::Result<()> {
        let mut state = State::new(NODE.into());
        let now = Instant::now();
        for number in 0..=MAX_RECENT {
            let mut failed = fact(1, Outcome::Failure("egress_failed"));
            failed.key.slot = number.to_string();
            state.apply(frame(vec![failed]), now, None)?;
            state.apply(frame(Vec::new()), now, None)?;
        }
        assert_eq!(state.recent.len(), MAX_RECENT);
        assert_eq!(state.dropped, 1);
        let handle = handle(state);
        let page = handle.page(Filter::Recent, None, 1).expect("first page");
        assert_eq!(page.dropped, "1");
        let cursor = page.next_cursor.as_deref().expect("next cursor");
        assert_eq!(
            handle
                .page(Filter::Recent, Some(cursor), 1)
                .expect("second page")
                .items
                .len(),
            1
        );
        assert!(matches!(
            handle.page(Filter::Active, Some(cursor), 1),
            Err(PageError::Changed)
        ));
        let other_boot = cursor.replacen(NODE, "AQAAAAAAAAAAAAAAAAAAAA", 1);
        assert!(matches!(
            handle.page(Filter::Recent, Some(&other_boot), 1),
            Err(PageError::Changed)
        ));
        {
            let mut state = handle.0.state()?;
            Arc::make_mut(&mut *state).revision += 1;
        }
        assert!(matches!(
            handle.page(Filter::Recent, Some(cursor), 1),
            Err(PageError::Changed)
        ));
        for limit in [0, 17] {
            assert!(matches!(
                handle.page(Filter::Active, None, limit),
                Err(PageError::InvalidQuery)
            ));
        }
        assert!(matches!(
            handle.page(Filter::Active, Some("not-a-cursor"), 1),
            Err(PageError::InvalidQuery)
        ));
        assert_eq!(millis(Duration::MAX), u64::MAX.to_string());
        Ok(())
    }

    pub(super) struct Fixture {
        directory: std::path::PathBuf,
        policy: Option<Arc<Coordinator>>,
        node: String,
    }

    impl Fixture {
        pub(super) fn new() -> io::Result<Self> {
            let mut random = [0; 16];
            getrandom::fill(&mut random).map_err(|_| unavailable())?;
            let directory = std::env::temp_dir()
                .join(format!("vproxy-alerts-{}", URL_SAFE_NO_PAD.encode(random)));
            let overview = store::initialize(&directory, "operations", "admin", "fixture PHC")?;
            let policy = Coordinator::new(
                directory.clone(),
                store::load_policy(&directory)?,
                Arc::new(store::lock(&directory)?),
            )?;
            Ok(Self {
                directory,
                policy: Some(policy),
                node: overview.node_id,
            })
        }

        pub(super) fn runner(&self, proxy: bool, collector: bool) -> io::Result<(Handle, Runner)> {
            new(
                self.policy.as_ref().expect("fixture policy").clone(),
                self.node.clone(),
                None,
                None,
                proxy,
                collector,
                None,
                None,
            )
        }

        pub(super) fn directory(&self) -> &std::path::Path {
            &self.directory
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.policy.take();
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[tokio::test]
    async fn api_only_collects_without_proxy_or_checkpoint_alarm_and_precancel_does_no_work()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (handle, mut runner) = fixture.runner(false, false)?;
        runner.collect_once().await?;
        let page = handle
            .page(Filter::Active, None, 16)
            .expect("observed page");
        assert_eq!(page.active_count, 0);
        assert!(!page.collection_error);
        assert!(!page.coverage.local_proxy_expected);
        assert!(!page.coverage.local_traffic);
        assert!(!page.coverage.local_management_https);
        assert!(page.coverage.remote_cached);
        let egress = handle
            .egress_page(Filter::Active, None, 16)
            .expect("unmonitored egress page");
        assert!(!egress.monitored);
        assert!(!egress.collection_error);
        assert_eq!(egress.active_count, 0);
        assert!(egress.observed_at_unix_ms.is_none() && egress.age_millis.is_none());
        let (handle, runner) = fixture.runner(false, false)?;
        let token = CancellationToken::new();
        token.cancel();
        runner.run(token).await?;
        assert!(
            handle
                .page(Filter::Active, None, 16)
                .expect("unused page")
                .age_millis
                .is_none()
        );
        Ok(())
    }

    fn target() -> store::alerts::Target {
        store::alerts::Target {
            id: NODE.into(),
            revision: 2,
            active: true,
            retired: false,
            rollback: false,
            peer_active: true,
            authorization_revision: 3,
            source_authorization_revision: Some(3),
            source_target_revision: Some(2),
            last_success_at: Some(100),
            meter_epoch: Some(NODE.into()),
            cursor: Some(1),
            source_error: None,
            quarantined: false,
            job_id: None,
            job_state: None,
            job_attempts: None,
        }
    }

    #[test]
    fn cached_remote_freshness_is_monotonic_and_collector_configuration_is_precise()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (_, mut runner) = fixture.runner(false, true)?;
        let now = Instant::now();
        let mut first = Frame::default();
        runner.remote_facts(&mut first, vec![target()], now, Some(100));
        assert!(matches!(first.facts[0].outcome, Outcome::Success));
        let mut later = Frame::default();
        runner.remote_facts(
            &mut later,
            vec![target()],
            now + Duration::from_secs(91),
            Some(1),
        );
        assert!(matches!(
            later.facts[0].outcome,
            Outcome::Failure("remote_traffic_stale")
        ));
        let (_, mut runner) = fixture.runner(false, false)?;
        let mut frame = Frame::default();
        runner.remote_facts(&mut frame, vec![target()], now, Some(100));
        assert!(matches!(
            frame.facts[0].outcome,
            Outcome::Failure("remote_collector_unavailable")
        ));
        let mut paused = target();
        paused.active = false;
        let mut frame = Frame::default();
        runner.remote_facts(&mut frame, vec![paused], now, Some(100));
        assert!(frame.facts.is_empty());
        Ok(())
    }

    #[test]
    fn policy_grace_fences_publication_and_remote_old_generation_errors_are_unknown()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (_, mut runner) = fixture.runner(true, true)?;
        let now = Instant::now();
        let mut frame = Frame::default();
        runner.policy_fact(&mut frame, 2, Some(1), true, now);
        assert!(matches!(frame.facts[0].outcome, Outcome::Unknown));
        let mut frame = Frame::default();
        runner.policy_fact(&mut frame, 2, Some(1), true, now + Duration::from_secs(15));
        assert!(matches!(
            frame.facts[0].outcome,
            Outcome::Failure("policy_not_applied")
        ));
        let mut frame = Frame::default();
        runner.policy_fact(&mut frame, 2, Some(3), true, now + Duration::from_secs(16));
        assert!(matches!(frame.facts[0].outcome, Outcome::Unknown));
        let mut frame = Frame::default();
        runner.policy_fact(&mut frame, 2, Some(2), true, now + Duration::from_secs(17));
        assert!(matches!(frame.facts[0].outcome, Outcome::Success));
        let mut old = target();
        old.last_success_at = None;
        old.source_target_revision = Some(1);
        old.source_error = Some("unavailable".into());
        let mut frame = Frame::default();
        runner.remote_facts(&mut frame, vec![old], now, Some(100));
        assert!(matches!(frame.facts[0].outcome, Outcome::Unknown));
        Ok(())
    }

    fn snapshot(outcome: health::FixedOutcome, age: u64) -> health::Snapshot {
        health::Snapshot {
            boot_id: "boot".into(),
            sequence: 2,
            catalog_revision: Some(1),
            catalog_loaded: true,
            catalog_error: None,
            catalog_observed_at_unix_ms: Some(1),
            catalog_age_millis: Some(age),
            in_flight: 0,
            entries: vec![health::Entry {
                address_id: NODE.into(),
                address_revision: 1,
                ip: "127.0.0.1".parse().unwrap(),
                checks: vec![health::CheckView {
                    kind: health::CheckKind::Bind,
                    target: None,
                    outcome,
                    sequence: Some(2),
                    observed_at_unix_ms: Some(2),
                    age_millis: Some(age),
                    latency_millis: Some(0),
                }],
            }],
        }
    }

    #[test]
    fn health_cancelled_unknown_and_expired_catalog_do_not_recover_or_retire() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (_, runner) = fixture.runner(false, false)?;
        let now = Instant::now();
        for outcome in [
            health::FixedOutcome::Unknown,
            health::FixedOutcome::Cancelled,
        ] {
            let mut state = State::new(NODE.into());
            let mut failed = fact(1, Outcome::Failure("egress_failed"));
            failed.key.origin = runner.node_id.clone();
            state.apply(frame(vec![failed]), now, Some(1))?;
            let mut observed = Frame::default();
            runner.health_snapshot_facts(&mut observed, snapshot(outcome, 1), 100);
            state.apply(observed, now, Some(2))?;
            assert_eq!(state.active.len(), 1);
            assert!(!active(&state).fresh);
            assert!(state.recent.is_empty());
        }
        let mut state = State::new(NODE.into());
        let mut failed = fact(1, Outcome::Failure("egress_failed"));
        failed.key.origin = runner.node_id.clone();
        state.apply(frame(vec![failed]), now, Some(1))?;
        let mut expired = snapshot(health::FixedOutcome::Success, 101);
        expired.entries.clear();
        let mut observed = Frame::default();
        runner.health_snapshot_facts(&mut observed, expired, 100);
        state.apply(observed, now, Some(2))?;
        assert!(state.active.keys().any(|key| key.kind == Kind::EgressCheck));
        assert!(state.recent.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn busy_read_budget_keeps_incidents_and_owned_blocking_work_is_joined() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        let (handle, mut runner) = fixture.runner(false, false)?;
        runner.shared.apply(
            frame(vec![fact(1, Outcome::Failure("egress_failed"))]),
            Instant::now(),
            Some(1),
        )?;
        let mut tasks = Vec::new();
        let mut releases = Vec::new();
        for _ in 0..2 {
            let policy = fixture.policy.as_ref().expect("fixture policy").clone();
            let (started, waiting) = tokio::sync::oneshot::channel();
            let (release, blocked) = std::sync::mpsc::channel();
            tasks.push(tokio::spawn(async move {
                policy
                    .read(move |_| {
                        let _ = started.send(());
                        blocked.recv().map_err(io::Error::other)?;
                        Ok(())
                    })
                    .await
            }));
            releases.push(release);
            waiting.await.map_err(io::Error::other)?;
        }
        let observed = runner.collect_once().await;
        for release in releases {
            let _ = release.send(());
        }
        for task in tasks {
            task.await.map_err(io::Error::other)??;
        }
        observed?;
        let page = handle
            .page(Filter::Active, None, 16)
            .expect("busy observation");
        assert!(page.collection_error);
        assert_eq!(page.active_count, 1);
        assert!(!page.items[0].evidence_fresh);
        assert_eq!(
            runner.collection_failures,
            [collect::Failure::Policy(
                crate::manage::policy::ReadStage::Admission,
                io::ErrorKind::WouldBlock,
            )],
        );
        runner.collect_once().await?;
        assert!(runner.collection_failures.is_empty());
        assert_eq!(
            handle.page(Filter::Active, None, 16).unwrap().active_count,
            1,
            "a complete collection cannot invent newer egress evidence",
        );
        let token = CancellationToken::new();
        token.cancel();
        runner.run(token).await?;
        Ok(())
    }

    fn https_observation() -> acme::Observation {
        acme::Observation {
            // Fixed seven-day warning policy: at second 200, exactly seven days remain.
            certificate: Some((100, 604_800 + 200)),
            activation_seq: 1,
            result_seq: 0,
            last_failure: None,
            stopped: false,
        }
    }

    fn https_frame(runner: &Runner, observed: acme::Observation, seconds: Option<u64>) -> Frame {
        let mut frame = Frame::default();
        runner.management_https_observation_facts(
            &mut frame,
            observed,
            seconds.and_then(|seconds| seconds.checked_mul(1000)),
        );
        frame
    }

    fn https_incident<'a>(state: &'a State, slot: &str) -> &'a Incident {
        state
            .active
            .values()
            .find(|incident| {
                incident.key.kind == Kind::ManagementHttps && incident.key.slot == slot
            })
            .expect("active HTTPS slot")
    }

    #[test]
    fn https_validity_boundaries_repeats_and_clock_rollback_require_new_activation()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (_, runner) = fixture.runner(false, false)?;
        let observed = https_observation();
        let after = observed.certificate.unwrap().1;
        for (seconds, expected) in [
            (99, Some("https_identity_unavailable")),
            (100, None),
            (200, Some("https_identity_expiring")),
            (after, Some("https_identity_expiring")),
            (after + 1, Some("https_identity_unavailable")),
        ] {
            let frame = https_frame(&runner, observed, Some(seconds));
            assert!(!frame.error);
            assert!(frame.complete.contains(&Kind::ManagementHttps));
            let certificate = frame
                .facts
                .iter()
                .find(|fact| fact.key.slot == "certificate")
                .unwrap();
            match expected {
                Some(expected) => {
                    assert!(
                        matches!(certificate.outcome, Outcome::Failure(code) if code == expected)
                    )
                }
                None => assert!(matches!(certificate.outcome, Outcome::Success)),
            }
        }
        let now = Instant::now();
        let mut state = State::new(runner.node_id.clone());
        state.apply(
            https_frame(&runner, observed, Some(100)),
            now,
            Some(100_000),
        )?;
        state.apply(
            https_frame(&runner, observed, Some(200)),
            now,
            Some(200_000),
        )?;
        let id = https_incident(&state, "certificate").id;
        let revision = state.revision;
        state.apply(
            https_frame(&runner, observed, Some(205)),
            now + Duration::from_secs(5),
            Some(205_000),
        )?;
        assert_eq!(state.revision, revision);
        assert_eq!(https_incident(&state, "certificate").last, Some(200_000));
        state.apply(
            https_frame(&runner, observed, Some(after + 1)),
            now,
            Some(300_000),
        )?;
        assert_eq!(https_incident(&state, "certificate").id, id);
        assert_eq!(
            https_incident(&state, "certificate").code,
            "https_identity_unavailable"
        );
        state.apply(
            https_frame(&runner, observed, Some(100)),
            now,
            Some(100_000),
        )?;
        assert_eq!(https_incident(&state, "certificate").id, id);
        assert!(!https_incident(&state, "certificate").fresh);
        assert!(state.recent.is_empty());
        let renewed = acme::Observation {
            activation_seq: 2,
            ..observed
        };
        state.apply(https_frame(&runner, renewed, Some(100)), now, Some(101_000))?;
        assert!(state.active.is_empty());
        assert_eq!(state.recent.len(), 1);
        assert_eq!(state.recent[0].status, Status::Recovered);
        Ok(())
    }

    #[test]
    fn https_recovery_is_not_issuance_success_and_stopped_cannot_be_revived() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (_, runner) = fixture.runner(false, false)?;
        let now = Instant::now();
        let mut state = State::new(runner.node_id.clone());
        let cold = acme::Observation {
            certificate: None,
            activation_seq: 0,
            ..https_observation()
        };
        state.apply(https_frame(&runner, cold, Some(100)), now, Some(1))?;
        assert_eq!(
            state.active.len(),
            1,
            "no completed outcome is not an attempt failure"
        );
        let failed = acme::Observation {
            result_seq: 1,
            last_failure: Some(acme::Failure::ReviewRequired),
            ..cold
        };
        state.apply(https_frame(&runner, failed, Some(100)), now, Some(2))?;
        let attempt = https_incident(&state, "attempt").id;
        let recovered = acme::Observation {
            certificate: https_observation().certificate,
            activation_seq: 1,
            ..failed
        };
        state.apply(https_frame(&runner, recovered, Some(100)), now, Some(3))?;
        assert_eq!(state.active.len(), 1);
        assert_eq!(https_incident(&state, "attempt").id, attempt);
        assert_eq!(
            https_incident(&state, "attempt").code,
            "acme_review_required"
        );
        let revision = state.revision;
        state.apply(https_frame(&runner, recovered, Some(105)), now, Some(4))?;
        assert_eq!(state.revision, revision);
        assert_eq!(https_incident(&state, "attempt").last, Some(2));
        let completed = acme::Observation {
            activation_seq: 2,
            result_seq: 2,
            last_failure: None,
            ..recovered
        };
        state.apply(https_frame(&runner, completed, Some(100)), now, Some(5))?;
        assert!(state.active.is_empty());
        assert_eq!(state.recent.len(), 2);
        let stopped = acme::Observation {
            result_seq: 3,
            last_failure: Some(acme::Failure::AttemptUnavailable),
            stopped: true,
            ..completed
        };
        state.apply(https_frame(&runner, stopped, Some(100)), now, Some(6))?;
        assert_eq!(
            https_incident(&state, "attempt").code,
            "acme_attempt_unavailable"
        );
        assert_eq!(https_incident(&state, "worker").code, "acme_worker_stopped");
        let worker = https_incident(&state, "worker").id;
        let fake_restart = acme::Observation {
            activation_seq: 3,
            result_seq: 4,
            last_failure: None,
            stopped: false,
            ..stopped
        };
        state.apply(https_frame(&runner, fake_restart, Some(100)), now, Some(7))?;
        assert_eq!(state.active.len(), 1);
        assert_eq!(https_incident(&state, "worker").id, worker);
        assert!(!https_incident(&state, "worker").fresh);
        Ok(())
    }

    #[test]
    fn https_unknown_clock_and_exhausted_rank_do_not_recover_or_retire() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (_, runner) = fixture.runner(false, false)?;
        let observed = https_observation();
        let now = Instant::now();
        let mut state = State::new(runner.node_id.clone());
        state.apply(https_frame(&runner, observed, Some(200)), now, Some(1))?;
        let id = https_incident(&state, "certificate").id;
        let missing_clock = https_frame(&runner, observed, None);
        assert!(missing_clock.error);
        assert_eq!(missing_clock.facts.len(), 3);
        assert!(missing_clock.complete.contains(&Kind::ManagementHttps));
        state.apply(missing_clock, now, None)?;
        assert_eq!(https_incident(&state, "certificate").id, id);
        assert!(!https_incident(&state, "certificate").fresh);
        assert!(state.recent.is_empty());
        for activation_seq in [u64::MAX, u64::MAX / 3] {
            let overflow = https_frame(
                &runner,
                acme::Observation {
                    activation_seq,
                    ..observed
                },
                Some(100),
            );
            assert!(overflow.error);
            assert!(overflow.facts.is_empty());
            assert!(!overflow.complete.contains(&Kind::ManagementHttps));
            state.apply(overflow, now, Some(2))?;
            assert_eq!(https_incident(&state, "certificate").id, id);
            assert!(state.recent.is_empty());
        }
        let mut manual = Frame::default();
        runner.management_https_facts(&mut manual, Some(100_000));
        assert!(manual.complete.contains(&Kind::ManagementHttps));
        assert!(manual.facts.is_empty() && !manual.error);
        state.apply(manual, now, Some(3))?;
        assert!(state.active.is_empty());
        assert_eq!(state.recent[0].status, Status::Unmonitored);
        Ok(())
    }

    #[tokio::test]
    async fn https_monitoring_on_api_only_node_does_not_depend_on_proxy_configuration()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (handle, mut runner) = new(
            fixture.policy.as_ref().expect("fixture policy").clone(),
            fixture.node.clone(),
            None,
            None,
            false,
            false,
            Some(acme::Handle::testing()),
            None,
        )?;
        runner.collect_once().await?;
        let page = handle
            .page(Filter::Active, None, 16)
            .expect("automatic HTTPS page");
        assert!(page.coverage.local_management_https);
        assert!(!page.coverage.local_proxy_expected);
        assert!(!page.collection_error);
        assert_eq!(page.active_count, 1);
        assert_eq!(page.items[0].kind, Kind::ManagementHttps);
        assert_eq!(page.items[0].code, "https_identity_unavailable");
        assert!(page.items[0].resource_id.is_none());
        assert!(page.items[0].check.is_none() && page.items[0].target.is_none());
        Ok(())
    }
}
