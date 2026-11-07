//! Single-flight traffic checkpoints, independent of forwarding runtimes.
//!
//! A timer is not a durability guarantee. Accepted bytes remain in direct
//! counters on failure; only confirmed absolute-value commits advance durable
//! watermarks. The final checkpoint must follow actual proxy runtime teardown.

use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use super::{
    policy::{Coordinator, TrafficWriteFailure, TrafficWriteStage},
    store,
};
use crate::access::traffic::{PoolSnapshot, Registry, SeriesSnapshot};
use crate::{
    access::traffic::{PROTOCOL_COUNT, Protocol},
    traffic::Snapshot,
};

const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(5);
const BATCH_LIMIT: usize = 256;
const ZERO: Snapshot = Snapshot {
    upload: 0,
    download: 0,
    saturated: false,
};

/// Context belongs only to the collector, never to shared API error mapping.
/// The original kind/source are retained; logs use only the fixed stage label.
#[derive(Debug, thiserror::Error)]
#[error("traffic checkpoint failed during {stage}")]
struct CheckpointFailure {
    stage: &'static str,
    #[source]
    error: io::Error,
}

fn checkpoint_failure(stage: &'static str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), CheckpointFailure { stage, error })
}

fn write_failure(failure: TrafficWriteFailure) -> io::Error {
    let stage = match failure.stage {
        TrafficWriteStage::Admission => "write_admission",
        TrafficWriteStage::UpdateGate => "update_gate",
        TrafficWriteStage::Store => "store",
        TrafficWriteStage::Worker => "worker",
    };
    checkpoint_failure(stage, failure.error)
}

/// Sampling includes read admission and the in-memory registry's blocking work.
/// Store errors deliberately remain unclassified: the same kind can represent
/// both SQLite contention and a stale run that must stay fenced.
fn failure_stage(error: &io::Error) -> &'static str {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<CheckpointFailure>())
        .map_or("observation", |failure| failure.stage)
}

/// Stage of this process's last failed checkpoint cycle. This does not identify
/// the underlying cause or prove whether a write committed. Only a confirmed
/// successful full cycle clears it; no error text crosses the API boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CheckpointStage {
    /// Read admission or blocking work while sampling the direct counters.
    Sample,
    /// Waiting for the bounded management writer budget.
    WriteAdmission,
    /// Waiting for exclusive access to the policy update gate.
    UpdateGate,
    /// Storage execution, including SQLite errors and stale-run fencing.
    Store,
    /// Completion of the blocking writer task.
    Worker,
    /// Local confirmation or an error without a recognized stage wrapper.
    Observation,
}

impl CheckpointStage {
    fn from_error(error: &io::Error) -> Self {
        match failure_stage(error) {
            "sample" => Self::Sample,
            "write_admission" => Self::WriteAdmission,
            "update_gate" => Self::UpdateGate,
            "store" => Self::Store,
            "worker" => Self::Worker,
            _ => Self::Observation,
        }
    }
}

/// Shared non-secret observation and direct counter owner. Its policy service
/// retains the process author and blocking-work budgets during cancelled waits.
#[derive(Clone)]
pub(super) struct Handle(Arc<Shared>);

pub(super) struct Runner {
    handle: Handle,
}

struct Shared {
    policy: Arc<Coordinator>,
    registry: Arc<Registry>,
    state: Mutex<State>,
}

struct State {
    durable: store::traffic::Status,
    // Unlike durable.run_id, this means this process opened a data-plane run.
    // An API-only process must not advertise a previous crashed run as active.
    active_run: Option<String>,
    checkpoint_failure: Option<CheckpointStage>,
    last_completed_at: Option<u64>,
    last_completed: Option<Instant>,
    completion_sequence: u64,
    // Absolute values confirmed by storage. Filtering unchanged series here
    // keeps an idle 8192-credential node from opening 96 write transactions per
    // tick. Only a confirmed commit advances these bounded cold-path maps.
    credentials: HashMap<Arc<str>, [Snapshot; PROTOCOL_COUNT]>,
    pools: HashMap<Arc<str>, [Snapshot; PROTOCOL_COUNT]>,
}

/// A cached checkpoint observation, not a promise of current wire throughput.
pub(super) struct Observation {
    pub(super) durable: store::traffic::Status,
    pub(super) active_run: Option<String>,
    pub(super) checkpoint_error: bool,
    pub(super) checkpoint_failure_stage: Option<CheckpointStage>,
    pub(super) last_completed_at: Option<u64>,
    pub(super) age_millis: Option<u64>,
    /// Process-local successful full cycles, including idle checkpoints. Unlike
    /// wall time or the durable byte cursor, this orders recovery evidence.
    pub(super) completion_sequence: u64,
}

/// Construct from existing durable metadata without opening a run or inventing
/// a new epoch. The Coordinator's reader must already use restored counters.
pub(super) async fn new(policy: Arc<Coordinator>) -> io::Result<(Handle, Runner)> {
    let durable = policy.read(store::traffic::status).await?;
    let restored = policy.traffic_restoration();
    if durable.meter_epoch != restored.meter_epoch || durable.cursor != restored.cursor {
        return Err(io::Error::other(
            "traffic restoration changed before startup",
        ));
    }
    let registry = policy.reader().traffic_registry();
    let restored_registry = registry.clone();
    let (series, pools) = policy
        .read(move |_| {
            Ok((
                restored_registry.snapshot()?,
                restored_registry.pool_snapshot()?,
            ))
        })
        .await?;
    // No proxy listener has started yet. These are the same absolute seeds
    // validated above, including zero for newly configured untouched identities.
    let mut credentials = HashMap::new();
    let mut pool_values = HashMap::new();
    for series in series {
        credentials
            .entry(series.credential_id)
            .or_insert([ZERO; PROTOCOL_COUNT])[index(series.protocol)] = series.value;
    }
    for pool in pools {
        pool_values
            .entry(pool.pool_id)
            .or_insert([ZERO; PROTOCOL_COUNT])[index(pool.protocol)] = pool.value;
    }
    let handle = Handle(Arc::new(Shared {
        policy,
        registry,
        state: Mutex::new(State {
            durable,
            active_run: None,
            checkpoint_failure: None,
            last_completed_at: None,
            last_completed: None,
            completion_sequence: 0,
            credentials,
            pools: pool_values,
        }),
    }));
    Ok((handle.clone(), Runner { handle }))
}

impl Handle {
    fn state(&self) -> io::Result<MutexGuard<'_, State>> {
        self.0
            .state
            .lock()
            .map_err(|_| io::Error::other("traffic observation unavailable"))
    }

    /// Persist an open marker before any managed listener can admit payload.
    /// A stale restored epoch/cursor fails, rather than resetting live counters.
    pub(super) async fn begin(&self) -> io::Result<()> {
        let (epoch, cursor) = {
            let state = self.state()?;
            if state.active_run.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "traffic run already active",
                ));
            }
            (state.durable.meter_epoch.clone(), state.durable.cursor)
        };
        let run = self
            .0
            .policy
            .store_write(move |dir, gate| {
                crate::manage::store::traffic::start_run(dir, gate, &epoch, cursor, now())
            })
            .await?;
        let run_id = run
            .status
            .run_id
            .clone()
            .ok_or_else(|| io::Error::other("traffic run identity is missing"))?;
        let mut state = self.state()?;
        state.durable = run.status;
        state.active_run = Some(run_id);
        Ok(())
    }

    /// Obtain bounded direct counter snapshots off the management executor.
    /// This never samples sockets, reads content, or accesses the network.
    pub(super) async fn sample(&self) -> io::Result<(Vec<SeriesSnapshot>, Vec<PoolSnapshot>)> {
        let registry = self.0.registry.clone();
        self.0
            .policy
            .read(move |_| Ok((registry.snapshot()?, registry.pool_snapshot()?)))
            .await
    }

    pub(super) fn observation(&self) -> io::Result<Observation> {
        let state = self.state()?;
        let mut durable = state.durable.clone();
        durable.loss_possible = observed_loss(&durable, state.active_run.as_deref());
        Ok(Observation {
            durable,
            active_run: state.active_run.clone(),
            checkpoint_error: state.checkpoint_failure.is_some(),
            checkpoint_failure_stage: state.checkpoint_failure,
            last_completed_at: state.last_completed_at,
            completion_sequence: state.completion_sequence,
            age_millis: state
                .last_completed
                .map(|instant| u64::try_from(instant.elapsed().as_millis()).unwrap_or(u64::MAX)),
        })
    }

    async fn checkpoint(&self) -> io::Result<()> {
        let run_id = {
            let state = self.state()?;
            let Some(run_id) = &state.active_run else {
                return Ok(());
            };
            run_id.clone()
        };
        let registry = self.0.registry.clone();
        let (mut series, mut pools) = self
            .0
            .policy
            .traffic_sample(move || Ok((registry.snapshot()?, registry.pool_snapshot()?)))
            .await
            .map_err(|error| checkpoint_failure("sample", error))?;
        {
            let state = self.state()?;
            series.retain(|row| {
                state
                    .credentials
                    .get(row.credential_id.as_ref())
                    .map_or(ZERO, |values| values[index(row.protocol)])
                    != row.value
            });
            pools.retain(|row| {
                state
                    .pools
                    .get(row.pool_id.as_ref())
                    .map_or(ZERO, |values| values[index(row.protocol)])
                    != row.value
            });
        }
        let observed_at = now();
        let mut series_iter = series.into_iter();
        let mut pools_iter = pools.into_iter();
        // Even an empty node needs a confirmed observation rather than unknown
        // being rendered as zero. One iteration records that bounded interval.
        loop {
            let series: Vec<_> = series_iter.by_ref().take(BATCH_LIMIT).collect();
            let pools: Vec<_> = pools_iter
                .by_ref()
                .take(BATCH_LIMIT - series.len())
                .collect();
            let drained = series_iter.len() == 0 && pools_iter.len() == 0;
            let confirmed_series: Vec<_> = series
                .iter()
                .map(|row| (row.credential_id.clone(), row.protocol, row.value))
                .collect();
            let confirmed_pools: Vec<_> = pools
                .iter()
                .map(|row| (row.pool_id.clone(), row.protocol, row.value))
                .collect();
            let expected = run_id.clone();
            let durable = self
                .0
                .policy
                .store_write_staged(move |dir, gate| {
                    crate::manage::store::traffic::checkpoint(
                        dir,
                        gate,
                        &expected,
                        observed_at,
                        &series,
                        &pools,
                    )
                })
                .await
                .map_err(write_failure)?;
            {
                let mut state = self.state()?;
                if durable.meter_epoch != state.durable.meter_epoch
                    || durable.cursor < state.durable.cursor
                {
                    return Err(io::Error::other("traffic checkpoint continuity changed"));
                }
                state.durable = durable;
                for (id, protocol, value) in confirmed_series {
                    state
                        .credentials
                        .entry(id)
                        .or_insert([ZERO; PROTOCOL_COUNT])[index(protocol)] = value;
                }
                for (id, protocol, value) in confirmed_pools {
                    state.pools.entry(id).or_insert([ZERO; PROTOCOL_COUNT])[index(protocol)] =
                        value;
                }
            }
            if drained {
                break;
            }
            // The writer permit and update gate have been released. A policy
            // mutation can run between batches; no mutex crosses this yield.
            tokio::task::yield_now().await;
        }
        let mut state = self.state()?;
        state.completion_sequence = state
            .completion_sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("traffic observation sequence exhausted"))?;
        state.checkpoint_failure = None;
        state.last_completed_at = observed_at;
        state.last_completed = Some(Instant::now());
        Ok(())
    }

    /// Called only after proxy::Running::finish outside the async supervisor.
    /// A failed/timed-out runtime cleanup may still have writers: sample what
    /// is known, but leave the durable open marker and possible-loss warning.
    pub(super) async fn finish(&self, proxy_cleanup_succeeded: bool) -> io::Result<()> {
        let run_id = self.state()?.active_run.clone();
        let Some(run_id) = run_id else {
            return Ok(());
        };
        loop {
            match self.checkpoint().await {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    // Cancelled API workers may still be finishing their owned
                    // transactions. The outer final-flush deadline bounds this.
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                result => {
                    result?;
                    break;
                }
            }
        }
        if !proxy_cleanup_succeeded {
            return Ok(());
        }
        let durable = loop {
            let run_id = run_id.clone();
            let result = self
                .0
                .policy
                .store_write(move |dir, gate| {
                    crate::manage::store::traffic::finish(dir, gate, &run_id, now())
                })
                .await;
            match result {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                result => break result?,
            }
        };
        let mut state = self.state()?;
        state.durable = durable;
        state.active_run = None;
        Ok(())
    }
}

impl Runner {
    /// Coalesce ticks; a blocked/failed checkpoint never queues an unbounded
    /// stream of blocking jobs and never resets accepted forwarding counters.
    pub(super) async fn run(self, shutdown: CancellationToken) -> io::Result<()> {
        let mut interval = tokio::time::interval(CHECKPOINT_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                _ = interval.tick() => {}
            }
            // Do not cancel an in-flight write on shutdown: its worker owns the
            // gate through commit. Final flush follows real runtime teardown.
            if let Err(error) = self.handle.checkpoint().await {
                self.handle.state()?.checkpoint_failure = Some(CheckpointStage::from_error(&error));
                tracing::warn!(stage = failure_stage(&error), kind = ?error.kind(), "traffic checkpoint delayed; live counters retained");
            }
        }
    }
}

/// Millisecond wall time is display/bucketing metadata, never a monotonic timer
/// or an authorization clock. Unknown/unsafe JS timestamps remain absent.
pub(super) fn now() -> Option<u64> {
    let value = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis(),
    )
    .ok()?;
    (value <= 9_007_199_254_740_991).then_some(value)
}

fn index(protocol: Protocol) -> usize {
    crate::access::traffic::protocol_index(protocol)
}

/// A stored open marker is normal only for this process's matching active run.
/// An API-only restart must expose the previous unconfirmed tail immediately,
/// without waiting for another proxy start or mutating history just to read it.
pub(super) fn observed_loss(status: &store::traffic::Status, active_run: Option<&str>) -> bool {
    status.loss_possible || (!status.clean && status.run_id.as_deref() != active_run)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::{Arc, mpsc},
        thread,
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use tokio::{sync::oneshot, task::JoinHandle, time::timeout};
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        manage::store::PolicyChange,
        traffic::{Direction, Meter},
    };

    struct Fixture {
        directory: PathBuf,
        administrator: String,
        policy: Option<Arc<Coordinator>>,
        author: Option<Arc<store::Guard>>,
    }

    impl Fixture {
        fn new() -> io::Result<Self> {
            let mut unique = [0; 16];
            getrandom::fill(&mut unique)
                .map_err(|_| io::Error::other("fixture entropy unavailable"))?;
            let mut fixture = Self {
                directory: std::env::temp_dir().join(format!(
                    "vproxy-traffic-collector-{}",
                    URL_SAFE_NO_PAD.encode(unique)
                )),
                administrator: String::new(),
                policy: None,
                author: None,
            };
            store::initialize(&fixture.directory, "collector node", "admin", "fixture PHC")?;
            fixture.administrator =
                rusqlite::Connection::open(fixture.directory.join("management.sqlite3"))
                    .map_err(io::Error::other)?
                    .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                    .map_err(io::Error::other)?;
            fixture.author = Some(Arc::new(store::lock(&fixture.directory)?));
            fixture.reload()?;
            Ok(fixture)
        }

        fn policy(&self) -> Arc<Coordinator> {
            self.policy.as_ref().expect("fixture coordinator").clone()
        }

        fn reload(&mut self) -> io::Result<()> {
            self.policy.take();
            self.policy = Some(Coordinator::new(
                self.directory.clone(),
                store::load_policy(&self.directory)?,
                self.author.as_ref().expect("fixture author").clone(),
            )?);
            Ok(())
        }

        async fn identity(&self) -> io::Result<Identity> {
            let policy = self.policy();
            let revision = policy.reader().revision()?;
            let created = policy
                .change(
                    self.administrator.clone(),
                    revision,
                    PolicyChange::CreateUser {
                        name: "counter owner".into(),
                        protocols: vec![crate::access::Protocol::Http],
                        concurrent_limit: 8,
                    },
                )
                .await?;
            let user = created.user.expect("created user").id;
            let created = policy
                .change(
                    self.administrator.clone(),
                    created.revision,
                    PolicyChange::CreateCredential {
                        user_id: user.clone(),
                    },
                )
                .await?;
            let credential = created.credential.expect("created credential");
            Ok(Identity {
                user,
                credential: credential.id,
                login: credential.login,
                secret: created.secret.expect("one-time secret"),
            })
        }

        fn total(&self, credential: &str) -> io::Result<Snapshot> {
            Ok(store::traffic::totals(
                &self.directory,
                store::traffic::Scope::Credential(credential.to_owned()),
            )?
            .items
            .into_iter()
            .find(|row| row.protocol == Protocol::Http)
            .expect("HTTP cumulative row")
            .value)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.policy.take();
            self.author.take();
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    struct Identity {
        user: String,
        credential: String,
        login: String,
        secret: Zeroizing<String>,
    }

    impl Identity {
        fn meters(&self, fixture: &Fixture) -> (Meter, Meter) {
            let admitted = fixture
                .policy()
                .reader()
                .authenticate(
                    &self.login,
                    self.secret.as_bytes(),
                    crate::access::Protocol::Http,
                )
                .expect("real managed admission");
            assert_eq!(admitted.lease.user_id.as_ref(), self.user);
            // A queued DATA/writer may outlive the authentication result itself.
            (
                admitted.lease.meter(Direction::Upload),
                admitted.lease.meter(Direction::Download),
            )
        }
    }

    struct Running {
        shutdown: CancellationToken,
        task: Option<JoinHandle<io::Result<()>>>,
    }

    impl Running {
        fn new(runner: Runner) -> Self {
            let shutdown = CancellationToken::new();
            let task = tokio::spawn(runner.run(shutdown.clone()));
            Self {
                shutdown,
                task: Some(task),
            }
        }

        async fn stop(mut self) -> io::Result<()> {
            self.shutdown.cancel();
            let mut task = self.task.take().expect("collector task");
            match timeout(Duration::from_secs(10), &mut task).await {
                Ok(result) => result.map_err(io::Error::other)?,
                Err(error) => {
                    task.abort();
                    let _ = task.await;
                    Err(io::Error::new(io::ErrorKind::TimedOut, error))
                }
            }
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            self.shutdown.cancel();
            if let Some(task) = self.task.take() {
                task.abort();
            }
        }
    }

    /// The external writer holds its file lock on an ordinary blocking thread, not
    /// on an async executor or in a mutex guard across an await. Drop always releases
    /// and joins it before the private fixture directory can be removed.
    struct HeldGate {
        release: Option<mpsc::Sender<()>>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl HeldGate {
        async fn new(directory: PathBuf) -> io::Result<Self> {
            let (ready, waiting) = oneshot::channel();
            let (release, blocked) = mpsc::channel();
            let worker = thread::Builder::new()
                .name("traffic-test-update-holder".into())
                .spawn(move || match store::update_lock(&directory) {
                    Ok(gate) => {
                        let _ = ready.send(Ok(()));
                        let _ = blocked.recv();
                        drop(gate);
                    }
                    Err(error) => {
                        let _ = ready.send(Err(error));
                    }
                })?;
            let holder = Self {
                release: Some(release),
                thread: Some(worker),
            };
            waiting.await.map_err(io::Error::other)??;
            Ok(holder)
        }
    }

    impl Drop for HeldGate {
        fn drop(&mut self) {
            self.release.take();
            if let Some(worker) = self.thread.take() {
                let _ = worker.join();
            }
        }
    }

    async fn observed(handle: &Handle, ready: impl Fn(&Observation) -> bool) {
        timeout(Duration::from_secs(10), async {
            loop {
                if ready(&handle.observation().expect("collector observation")) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("collector reached the requested state");
    }

    #[tokio::test]
    async fn failed_checkpoint_retains_live_bytes_and_only_commits_advance_the_cache()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let identity = fixture.identity().await?;
        let (handle, runner) = new(fixture.policy()).await?;
        handle.begin().await?;
        let open = store::traffic::status(&fixture.directory)?;
        let observation = handle.observation()?;
        assert!(!open.clean && !observation.durable.loss_possible);
        assert_eq!(open.run_id, observation.active_run);
        assert_eq!(
            handle.begin().await.unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let (upload, download) = identity.meters(&fixture);
        upload.add(100);
        download.add(40);
        handle.checkpoint().await?;
        let confirmed = fixture.total(&identity.credential)?;
        assert_eq!(
            confirmed,
            Snapshot {
                upload: 100,
                download: 40,
                saturated: false
            }
        );
        let cursor = handle.observation()?.durable.cursor;
        let completion = handle.observation()?.completion_sequence;
        upload.add(23);
        download.add(7);

        let gate = HeldGate::new(fixture.directory.clone()).await?;
        let error = handle.checkpoint().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(failure_stage(&error), "update_gate");
        let running = Running::new(runner);
        observed(&handle, |view| view.checkpoint_error).await;
        running.stop().await?;
        assert_eq!(
            handle.observation()?.checkpoint_failure_stage,
            Some(CheckpointStage::UpdateGate)
        );
        assert_eq!(handle.observation()?.durable.cursor, cursor);
        assert_eq!(handle.observation()?.completion_sequence, completion);
        assert_eq!(fixture.total(&identity.credential)?, confirmed);
        assert_eq!(
            handle
                .state()?
                .credentials
                .get(identity.credential.as_str())
                .unwrap()[index(Protocol::Http)],
            confirmed
        );
        assert_eq!(
            handle
                .sample()
                .await?
                .0
                .into_iter()
                .find(|row| row.protocol == Protocol::Http)
                .unwrap()
                .value,
            Snapshot {
                upload: 123,
                download: 47,
                saturated: false
            }
        );
        drop(gate);

        handle.checkpoint().await?;
        assert!(!handle.observation()?.checkpoint_error);
        assert_eq!(handle.observation()?.checkpoint_failure_stage, None);
        assert_eq!(handle.observation()?.completion_sequence, completion + 1);
        assert_eq!(
            fixture.total(&identity.credential)?,
            Snapshot {
                upload: 123,
                download: 47,
                saturated: false
            }
        );
        handle.checkpoint().await?;
        assert_eq!(handle.observation()?.completion_sequence, completion + 2);
        assert_eq!(
            fixture.total(&identity.credential)?,
            Snapshot {
                upload: 123,
                download: 47,
                saturated: false
            }
        );
        handle.finish(true).await?;
        Ok(())
    }

    #[tokio::test]
    async fn final_flush_after_collector_stop_keeps_drain_bytes_and_revoked_identity()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let identity = fixture.identity().await?;
        let (handle, runner) = new(fixture.policy()).await?;
        handle.begin().await?;
        let (upload, download) = identity.meters(&fixture);
        upload.add(11);
        let running = Running::new(runner);
        observed(&handle, |view| view.last_completed_at.is_some()).await;
        running.stop().await?;
        assert_eq!(fixture.total(&identity.credential)?.upload, 11);

        let policy = fixture.policy();
        policy.deactivate();
        policy
            .change(
                fixture.administrator.clone(),
                policy.reader().revision()?,
                PolicyChange::RevokeCredential {
                    id: identity.credential.clone(),
                },
            )
            .await?;
        assert!(
            policy
                .reader()
                .authenticate(
                    &identity.login,
                    identity.secret.as_bytes(),
                    crate::access::Protocol::Http
                )
                .is_err()
        );
        // Simulate the already admitted proxy draining after its supervisor stopped
        // the periodic task. Revocation must not erase a queued writer's identity.
        upload.add(29);
        download.add(17);
        assert!(!store::traffic::status(&fixture.directory)?.clean);
        handle.finish(true).await?;
        assert_eq!(
            fixture.total(&identity.credential)?,
            Snapshot {
                upload: 40,
                download: 17,
                saturated: false
            }
        );
        let closed = store::traffic::status(&fixture.directory)?;
        assert!(closed.clean);
        assert!(handle.observation()?.active_run.is_none());
        let closed_cursor = closed.cursor;
        handle.finish(true).await?;
        assert_eq!(
            store::traffic::status(&fixture.directory)?.cursor,
            closed_cursor
        );
        Ok(())
    }
}
