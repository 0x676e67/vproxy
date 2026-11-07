//! Bounded, node-local observations of explicitly registered egress addresses.
//!
//! Binding proves only that this process could bind that source at that time.
//! A TCP probe proves only a connection to its configured numeric target. Neither
//! observation authorizes an address, measures an entire prefix, or changes the
//! admission policy. No health lock or storage lookup enters proxy forwarding.

use std::{
    collections::HashSet,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, Serializer};
use tokio::{task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;

use super::{policy::Coordinator, store};
use crate::{
    access::routing::{AddressRecord, MAX_ADDRESSES, ResourceState, RoutingData},
    connect::Connector,
    ext::Extension,
};

/// Startup-only, trusted local probe policy. Targets are literal socket addresses;
/// no DNS, URL, redirect, HTTP credentials, or node TLS identity is involved.
#[derive(Clone)]
pub(super) struct Config {
    pub(super) interval_secs: u64,
    pub(super) timeout_secs: u64,
    pub(super) concurrency: usize,
    pub(super) probes_per_second: u32,
    pub(super) targets: Vec<SocketAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interval_secs: 60,
            timeout_secs: 3,
            concurrency: 2,
            probes_per_second: 8,
            targets: Vec::new(),
        }
    }
}

impl Config {
    /// Reject unbounded schedules and ambiguous/non-unicast destinations before
    /// starting. Private/loopback targets require the same explicit operator
    /// configuration as public targets; this engine never discovers targets.
    pub(super) fn validate(&self) -> io::Result<()> {
        let mut unique = HashSet::new();
        if !(10..=86_400).contains(&self.interval_secs)
            || !(1..=10).contains(&self.timeout_secs)
            || !(1..=4).contains(&self.concurrency)
            || !(1..=16).contains(&self.probes_per_second)
            || self.targets.len() > 4
            || self.targets.iter().any(|target| {
                target.port() == 0
                    || !crate::access::routing::valid_ip(target.ip())
                    || matches!(target, SocketAddr::V6(address)
                        if address.scope_id() != 0 || address.flowinfo() != 0)
                    || !unique.insert(*target)
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "health schedule or numeric targets are invalid",
            ));
        }
        Ok(())
    }
}

/// Every outcome belongs to one source/check/target only. There is deliberately
/// no global healthy/unhealthy flag or automatic failover decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FixedOutcome {
    Unknown,
    Success,
    AddressUnavailable,
    ConnectionRefused,
    TimedOut,
    PermissionDenied,
    NetworkUnreachable,
    Failed,
    FamilyMismatch,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CheckKind {
    Bind,
    Tcp,
}

/// A fresh observation or Unknown after monotonic expiry. Wall-clock timestamps
/// are presentation only; clock adjustments cannot extend observation validity.
#[derive(Serialize)]
pub(super) struct CheckView {
    pub(super) kind: CheckKind,
    pub(super) target: Option<SocketAddr>,
    pub(super) outcome: FixedOutcome,
    #[serde(serialize_with = "optional_decimal")]
    pub(super) sequence: Option<u64>,
    pub(super) observed_at_unix_ms: Option<u64>,
    pub(super) age_millis: Option<u64>,
    pub(super) latency_millis: Option<u64>,
}

/// Only Active concrete addresses appear. Missing entries and unobserved checks
/// remain unknown; no address is synthesized from an inventory prefix.
#[derive(Serialize)]
pub(super) struct Entry {
    pub(super) address_id: String,
    #[serde(serialize_with = "decimal")]
    pub(super) address_revision: u64,
    pub(super) ip: IpAddr,
    pub(super) checks: Vec<CheckView>,
}

/// Bounded read-side projection, independent of routing/admission. Sequences and
/// revisions serialize as decimal strings to preserve all integer bits in JS.
#[derive(Serialize)]
pub(super) struct Snapshot {
    pub(super) boot_id: String,
    #[serde(serialize_with = "decimal")]
    pub(super) sequence: u64,
    #[serde(serialize_with = "optional_decimal")]
    pub(super) catalog_revision: Option<u64>,
    pub(super) catalog_loaded: bool,
    pub(super) catalog_error: Option<&'static str>,
    pub(super) catalog_observed_at_unix_ms: Option<u64>,
    pub(super) catalog_age_millis: Option<u64>,
    pub(super) in_flight: usize,
    pub(super) entries: Vec<Entry>,
}

#[derive(Clone)]
pub(super) struct Handle(Arc<Shared>);

pub(super) struct Runner {
    policy: Arc<Coordinator>,
    connector: Connector,
    config: Config,
    shared: Arc<Shared>,
    active: HashSet<Key>,
}

struct Shared {
    boot_id: String,
    validity: Duration,
    state: Mutex<State>,
}

struct State {
    sequence: u64,
    catalog_revision: Option<u64>,
    catalog_error: Option<&'static str>,
    catalog_success: Option<Instant>,
    catalog_observed_at: Option<u64>,
    entries: Vec<Address>,
    cursor: usize,
    in_flight: usize,
}

struct Address {
    id: String,
    revision: u64,
    ip: IpAddr,
    checks: Vec<Observation>,
}

struct Observation {
    check: Check,
    started: Option<Instant>,
    sample: Option<Sample>,
}

struct Sample {
    outcome: FixedOutcome,
    sequence: u64,
    completed: Instant,
    observed_at: Option<u64>,
    latency: Duration,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Check {
    Bind,
    Tcp(SocketAddr),
}

/// Resource identity, not the unrelated global policy revision, fences late work.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Key {
    id: String,
    revision: u64,
    ip: IpAddr,
    check: Check,
}

struct Completion {
    key: Key,
    outcome: FixedOutcome,
    completed: Instant,
    observed_at: Option<u64>,
    latency: Duration,
}

/// Create an empty per-process monitor. This does not spawn, read storage, or
/// probe. The caller supervises Runner::run alongside its other managed tasks.
pub(super) fn new(
    policy: Arc<Coordinator>,
    connector: Connector,
    config: Config,
) -> io::Result<(Handle, Runner)> {
    config.validate()?;
    let mut identity = [0; 16];
    getrandom::fill(&mut identity).map_err(|_| unavailable())?;
    let shared = Arc::new(Shared {
        boot_id: URL_SAFE_NO_PAD.encode(identity),
        validity: Duration::from_secs(config.interval_secs * 3),
        state: Mutex::new(State {
            sequence: 0,
            catalog_revision: None,
            catalog_error: None,
            catalog_success: None,
            catalog_observed_at: None,
            entries: Vec::new(),
            cursor: 0,
            in_flight: 0,
        }),
    });
    Ok((
        Handle(shared.clone()),
        Runner {
            policy,
            connector,
            config,
            shared,
            active: HashSet::new(),
        },
    ))
}

impl Shared {
    fn state(&self) -> io::Result<MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| unavailable())
    }
}

impl Handle {
    /// Use the configured monotonic freshness window, not a guessed probe
    /// interval, when interpreting cached catalog observations.
    pub(super) fn validity_millis(&self) -> u64 {
        u64::try_from(self.0.validity.as_millis()).unwrap_or(u64::MAX)
    }

    /// Clone at most 1024 addresses × five checks under an observation-only
    /// mutex. Poison is an error, never a panic or a fabricated healthy result.
    pub(super) fn snapshot(&self) -> io::Result<Snapshot> {
        let now = Instant::now();
        let state = self.0.state()?;
        let catalog_fresh = state
            .catalog_success
            .is_some_and(|time| now.saturating_duration_since(time) < self.0.validity);
        let entries = state
            .entries
            .iter()
            .map(|address| Entry {
                address_id: address.id.clone(),
                address_revision: address.revision,
                ip: address.ip,
                checks: address
                    .checks
                    .iter()
                    .map(|observation| {
                        let sample = observation.sample.as_ref();
                        let age =
                            sample.map(|sample| now.saturating_duration_since(sample.completed));
                        let fresh = catalog_fresh && age.is_some_and(|age| age < self.0.validity);
                        CheckView {
                            kind: match observation.check {
                                Check::Bind => CheckKind::Bind,
                                Check::Tcp(_) => CheckKind::Tcp,
                            },
                            target: match observation.check {
                                Check::Bind => None,
                                Check::Tcp(target) => Some(target),
                            },
                            outcome: if fresh {
                                sample.map_or(FixedOutcome::Unknown, |sample| sample.outcome)
                            } else {
                                FixedOutcome::Unknown
                            },
                            sequence: sample.map(|sample| sample.sequence),
                            observed_at_unix_ms: sample.and_then(|sample| sample.observed_at),
                            age_millis: age.map(millis),
                            latency_millis: sample.map(|sample| millis(sample.latency)),
                        }
                    })
                    .collect(),
            })
            .collect();
        Ok(Snapshot {
            boot_id: self.0.boot_id.clone(),
            sequence: state.sequence,
            catalog_revision: state.catalog_revision,
            catalog_loaded: state.catalog_success.is_some(),
            catalog_error: state.catalog_error,
            catalog_observed_at_unix_ms: state.catalog_observed_at,
            catalog_age_millis: state
                .catalog_success
                .map(|time| millis(now.saturating_duration_since(time))),
            in_flight: state.in_flight,
            entries,
        })
    }
}

impl Runner {
    /// Read the finite catalog once per interval and schedule at most one check
    /// per rate tick. There are no per-address tasks/timers or unbounded queues.
    /// At capacity, checks remain due; coverage can expire to Unknown rather
    /// than interpreting scheduler pressure as an address failure.
    pub(super) async fn run(mut self, shutdown: CancellationToken) -> io::Result<()> {
        let mut tasks = JoinSet::new();
        let mut refresh = tokio::time::interval(Duration::from_secs(self.config.interval_secs));
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let rate = u64::from(self.config.probes_per_second);
        let spacing = Duration::from_nanos(1_000_000_000_u64.div_ceil(rate));
        let mut schedule = tokio::time::interval(spacing);
        schedule.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let result = loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break Ok(()),
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    match joined {
                        Some(Ok(completion)) => {
                            if let Err(error) = self.complete(completion) { break Err(error); }
                        }
                        _ => break Err(unavailable()),
                    }
                }
                _ = refresh.tick() => {
                    let catalog = tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => break Ok(()),
                        value = self.policy.read(store::routing_data) => value,
                    };
                    if let Err(error) = self.catalog(catalog) { break Err(error); }
                }
                _ = schedule.tick(), if tasks.len() < self.config.concurrency => {
                    let key = match self.next(Instant::now()) {
                        Ok(Some(key)) => key,
                        Ok(None) => continue,
                        Err(error) => break Err(error),
                    };
                    let connector = self.connector.clone();
                    let timeout = Duration::from_secs(self.config.timeout_secs);
                    let shutdown = shutdown.clone();
                    tasks.spawn(async move { probe(connector, key, timeout, shutdown).await });
                }
            }
        };
        // Dropping Runner must not leave its network probes detached. Cancellation
        // is checked inside each probe too; abort covers unexpected task failure.
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        self.active.clear();
        self.shared.state()?.in_flight = 0;
        result
    }

    fn catalog(&mut self, result: io::Result<(u64, RoutingData)>) -> io::Result<()> {
        let mut state = self.shared.state()?;
        state.sequence = state.sequence.checked_add(1).ok_or_else(unavailable)?;
        let (revision, catalog) = match result {
            Ok(value) => value,
            Err(_) => {
                // Stop launches immediately. Existing observations are not
                // rewritten as failures; monotonic expiry handles stale data.
                state.catalog_error = Some("catalog_unavailable");
                return Ok(());
            }
        };
        if catalog.addresses.len() > MAX_ADDRESSES {
            return Err(unavailable());
        }
        let mut old = std::mem::take(&mut state.entries);
        let mut entries = Vec::new();
        for record in catalog.addresses {
            if record.state != ResourceState::Active {
                continue;
            }
            let existing = old.iter().position(|entry| {
                entry.id == record.id && entry.revision == record.revision && entry.ip == record.ip
            });
            entries.push(match existing {
                Some(index) => old.swap_remove(index),
                None => self.address(record),
            });
        }
        entries.sort_unstable_by(|a, b| a.id.cmp(&b.id));
        state.entries = entries;
        state.catalog_revision = Some(revision);
        state.catalog_error = None;
        state.catalog_success = Some(Instant::now());
        state.catalog_observed_at = wall_time();
        Ok(())
    }

    fn address(&self, record: AddressRecord) -> Address {
        let mut checks = Vec::with_capacity(1 + self.config.targets.len());
        for check in
            std::iter::once(Check::Bind).chain(self.config.targets.iter().copied().map(Check::Tcp))
        {
            checks.push(Observation {
                check,
                started: None,
                sample: None,
            });
        }
        Address {
            id: record.id,
            revision: record.revision,
            ip: record.ip,
            checks,
        }
    }

    fn next(&mut self, now: Instant) -> io::Result<Option<Key>> {
        if self.active.len() >= self.config.concurrency {
            return Ok(None);
        }
        let mut state = self.shared.state()?;
        if state.catalog_error.is_some() || state.catalog_success.is_none() {
            return Ok(None);
        }
        let width = 1 + self.config.targets.len();
        let length = state
            .entries
            .len()
            .checked_mul(width)
            .ok_or_else(unavailable)?;
        for _ in 0..length {
            let position = state.cursor % length;
            state.cursor = (position + 1) % length;
            let address = &mut state.entries[position / width];
            let observation = &mut address.checks[position % width];
            if observation.started.is_some_and(|started| {
                now.saturating_duration_since(started)
                    < Duration::from_secs(self.config.interval_secs)
            }) {
                continue;
            }
            let key = Key {
                id: address.id.clone(),
                revision: address.revision,
                ip: address.ip,
                check: observation.check,
            };
            if self.active.contains(&key) {
                continue;
            }
            observation.started = Some(now);
            self.active.insert(key.clone());
            state.in_flight = self.active.len();
            return Ok(Some(key));
        }
        Ok(None)
    }

    fn complete(&mut self, completion: Completion) -> io::Result<()> {
        self.active.remove(&completion.key);
        let mut state = self.shared.state()?;
        state.in_flight = self.active.len();
        let Some(address_index) = state.entries.iter().position(|entry| {
            entry.id == completion.key.id
                && entry.revision == completion.key.revision
                && entry.ip == completion.key.ip
        }) else {
            return Ok(());
        };
        let Some(check_index) = state.entries[address_index]
            .checks
            .iter()
            .position(|entry| entry.check == completion.key.check)
        else {
            return Ok(());
        };
        state.sequence = state.sequence.checked_add(1).ok_or_else(unavailable)?;
        state.entries[address_index].checks[check_index].sample = Some(Sample {
            outcome: completion.outcome,
            sequence: state.sequence,
            completed: completion.completed,
            observed_at: completion.observed_at,
            latency: completion.latency,
        });
        Ok(())
    }
}

async fn probe(
    connector: Connector,
    key: Key,
    timeout: Duration,
    shutdown: CancellationToken,
) -> Completion {
    let started = Instant::now();
    let connector = connector.with_source(Some(key.ip));
    let tcp = connector.tcp(Extension::None);
    let outcome = match key.check {
        Check::Bind => bounded(async { tcp.bind_source().map(drop) }, timeout, &shutdown).await,
        Check::Tcp(target) if target.is_ipv4() != key.ip.is_ipv4() => FixedOutcome::FamilyMismatch,
        Check::Tcp(target) => bounded(tcp.connect(target), timeout, &shutdown).await,
    };
    let completed = Instant::now();
    Completion {
        key,
        outcome,
        completed,
        observed_at: wall_time(),
        latency: completed.saturating_duration_since(started),
    }
}

async fn bounded<T>(
    operation: impl Future<Output = io::Result<T>>,
    timeout: Duration,
    shutdown: &CancellationToken,
) -> FixedOutcome {
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => FixedOutcome::Cancelled,
        result = tokio::time::timeout(timeout, operation) => match result {
            Err(_) => FixedOutcome::TimedOut,
            Ok(Ok(_)) => FixedOutcome::Success,
            Ok(Err(error)) => match error.kind() {
                io::ErrorKind::AddrNotAvailable => FixedOutcome::AddressUnavailable,
                io::ErrorKind::ConnectionRefused => FixedOutcome::ConnectionRefused,
                io::ErrorKind::TimedOut => FixedOutcome::TimedOut,
                io::ErrorKind::PermissionDenied => FixedOutcome::PermissionDenied,
                io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
                    FixedOutcome::NetworkUnreachable
                }
                _ => FixedOutcome::Failed,
            },
        },
    }
}

fn wall_time() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(millis)
}

fn millis(duration: Duration) -> u64 {
    // Presentation only: even an extreme clock/uptime cannot lose JS precision.
    const MAX_SAFE: u128 = (1u128 << 53) - 1;
    duration.as_millis().min(MAX_SAFE) as u64
}

fn decimal<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}

fn optional_decimal<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_some(&value.to_string()),
        None => serializer.serialize_none(),
    }
}

fn unavailable() -> io::Error {
    io::Error::other("health observer unavailable")
}
