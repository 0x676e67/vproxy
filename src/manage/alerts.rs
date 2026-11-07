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
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Parameters {
            state: Option<String>,
            after: Option<String>,
            limit: Option<String>,
        }
        let input: Parameters =
            serde_urlencoded::from_str(raw).map_err(|_| PageError::InvalidQuery)?;
        let filter = match input.state.as_deref().unwrap_or("active") {
            "active" => Filter::Active,
            "recent" => Filter::Recent,
            _ => return Err(PageError::InvalidQuery),
        };
        if input
            .after
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 160 || !value.is_ascii())
        {
            return Err(PageError::InvalidQuery);
        }
        let limit = input
            .limit
            .map(|text| {
                text.parse::<u32>()
                    .ok()
                    .filter(|value| (1..=MAX_PAGE).contains(value) && value.to_string() == text)
                    .ok_or(PageError::InvalidQuery)
            })
            .transpose()?
            .unwrap_or(10);
        Ok(Self {
            filter,
            after: input.after,
            limit,
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
    super::views::number(value).ok_or(PageError::InvalidQuery)
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
}
