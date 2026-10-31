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
            .traffic_write(move |writer| writer.start_run(&epoch, cursor, now()))
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
                .traffic_write_staged(move |writer| {
                    writer.checkpoint(&expected, observed_at, &series, &pools)
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
                .traffic_write(move |writer| writer.finish(&run_id, now()))
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

    #[cfg(feature = "witness-journal")]
    mod source {
        //! Real collector and loopback mTLS witness tests. The synthetic witness also
        //! serves as the child target; this does not prove independent failure domains.

        use super::*;
        use crate::manage::{node, node::control, store::journal::SourceFixture};

        fn invalid() -> io::Error {
            io::Error::other("source traffic fixture failed")
        }

        async fn live(fault: node::tests::CutResponse) -> io::Result<SourceFixture> {
            SourceFixture::new_with(fault, |_| Ok(())).await
        }

        async fn counters(live: &SourceFixture) -> io::Result<(String, Meter, Meter)> {
            let user = live
                .source
                .change(
                    live.administrator.clone(),
                    1,
                    PolicyChange::CreateUser {
                        name: "source traffic owner".into(),
                        protocols: vec![crate::access::Protocol::Http],
                        concurrent_limit: 2,
                    },
                )
                .await?
                .user
                .ok_or_else(invalid)?
                .id;
            let saved = live
                .source
                .change(
                    live.administrator.clone(),
                    2,
                    PolicyChange::CreateCredential { user_id: user },
                )
                .await?;
            let credential = saved.credential.ok_or_else(invalid)?;
            let secret = saved.secret.ok_or_else(invalid)?;
            let admitted = live
                .source
                .reader()
                .authenticate(
                    &credential.login,
                    secret.as_bytes(),
                    crate::access::Protocol::Http,
                )
                .map_err(|_| invalid())?;
            Ok((
                credential.id,
                admitted.lease.meter(Direction::Upload),
                admitted.lease.meter(Direction::Download),
            ))
        }

        fn total(live: &SourceFixture, credential: &str) -> io::Result<Snapshot> {
            Ok(store::traffic::totals(
                &live.fixture.client_state,
                store::traffic::Scope::Credential(credential.into()),
            )?
            .items
            .into_iter()
            .find(|r| r.protocol == Protocol::Http)
            .map_or(ZERO, |r| r.value))
        }

        #[tokio::test]
        async fn source_collector_absolute_checkpoints_clean_restart_and_stale_run_preserve_totals()
        -> io::Result<()> {
            let mut live = live(Default::default()).await?;
            let result = async {
                let (id, upload, download) = counters(&live).await?;
                let (handle, runner) = new(live.source.clone()).await?;
                handle.begin().await?;
                let old_run = handle.observation()?.active_run.ok_or_else(invalid)?;
                upload.add(83);
                download.add(29);
                handle.checkpoint().await?;
                assert_eq!(
                    (total(&live, &id)?.upload, total(&live, &id)?.download),
                    (83, 29)
                );
                let (samples, pools) = handle.sample().await?;
                let first = samples.first().ok_or_else(invalid)?;
                let oversized: Vec<_> = (0..257)
                    .map(|_| SeriesSnapshot {
                        user_id: first.user_id.clone(),
                        credential_id: first.credential_id.clone(),
                        protocol: first.protocol,
                        value: first.value,
                    })
                    .collect();
                let run = old_run.clone();
                let floor = live.floor()?.sequence;
                assert_eq!(
                    live.source
                        .traffic_write(move |w| w.checkpoint(&run, now(), &oversized, &[]))
                        .await
                        .err()
                        .map(|e| e.kind()),
                    Some(io::ErrorKind::InvalidInput)
                );
                assert_eq!(live.floor()?.sequence, floor);
                let run = old_run.clone();
                live.source
                    .traffic_write(move |w| w.checkpoint(&run, now(), &samples, &pools))
                    .await?;
                assert_eq!(total(&live, &id)?.upload, 83);
                upload.add(9);
                handle.finish(true).await?;
                assert!(handle.observation()?.durable.clean);
                let floor = live.floor()?.sequence;
                let run = old_run.clone();
                live.source
                    .traffic_write(move |w| w.finish(&run, now()))
                    .await?;
                assert_eq!(live.floor()?.sequence, floor);
                drop((handle, runner, upload, download));
                live.restart_source().await?;
                let (handle, runner) = new(live.source.clone()).await?;
                assert_eq!(total(&live, &id)?.upload, 92);
                assert!(!handle.observation()?.durable.loss_possible);
                handle.begin().await?;
                let floor = live.floor()?.sequence;
                assert!(
                    live.source
                        .traffic_write(move |w| w.checkpoint(&old_run, now(), &[], &[]))
                        .await
                        .is_err()
                );
                assert_eq!(live.floor()?.sequence, floor);
                handle.finish(true).await?;
                drop((handle, runner));
                assert_eq!(live.source.reader().revision()?, 3);
                Ok(())
            }
            .await;
            let closed = live.close().await;
            result.and(closed)
        }

        #[tokio::test]
        async fn source_lost_checkpoint_reserve_or_confirm_never_advances_cached_watermarks_or_double_counts()
        -> io::Result<()> {
            for reserve in [true, false] {
                let live = live(node::tests::CutResponse {
                    witness_only: true,
                    witness_reserve: reserve,
                    witness_confirm: !reserve,
                    witness_sequence: Some(4),
                    ..Default::default()
                })
                .await?;
                let result = async {
                    let (id, upload, _) = counters(&live).await?;
                    let (handle, runner) = new(live.source.clone()).await?;
                    handle.begin().await?;
                    upload.add(83);
                    live.arm();
                    assert!(handle.checkpoint().await.is_err());
                    assert!(live.source.reader().revision().is_err());
                    assert_eq!(handle.observation()?.durable.cursor, 1);
                    assert_eq!(
                        handle
                            .state()?
                            .credentials
                            .get(id.as_str())
                            .ok_or_else(invalid)?[index(Protocol::Http)],
                        ZERO
                    );
                    // Existing admitted work retains its direct counter even while new
                    // Source admission is suspended. Only the original intent resolves.
                    upload.add(9);
                    live.source.reconcile_source().await?;
                    handle.checkpoint().await?;
                    assert_eq!(total(&live, &id)?.upload, 92);
                    assert_eq!(
                        handle
                            .state()?
                            .credentials
                            .get(id.as_str())
                            .ok_or_else(invalid)?[index(Protocol::Http)]
                        .upload,
                        92
                    );
                    handle.checkpoint().await?;
                    assert_eq!(total(&live, &id)?.upload, 92);
                    handle.finish(true).await?;
                    drop((handle, runner));
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)?;
            }
            Ok(())
        }

        #[tokio::test]
        async fn cancelled_source_begin_keeps_writer_and_reopened_run_reports_unconfirmed_tail()
        -> io::Result<()> {
            let pause = Arc::new(node::tests::ResponsePause::default());
            let mut live = live(node::tests::CutResponse {
                witness_only: true,
                witness_confirm: true,
                witness_sequence: Some(1),
                pause: Some(pause.clone()),
                ..Default::default()
            })
            .await?;
            let result = async {
                let (handle, runner) = new(live.source.clone()).await?;
                live.arm();
                let mut begin = Box::pin(handle.begin());
                assert!(futures_util::poll!(&mut begin).is_pending());
                timeout(Duration::from_secs(15), pause.entered.notified())
                    .await
                    .map_err(io::Error::other)?;
                drop(begin);
                assert!(handle.observation()?.active_run.is_none());
                assert_eq!(handle.observation()?.durable.cursor, 0);
                assert!(store::update_lock(&live.fixture.client_state).is_err());
                pause.release.notify_one();
                timeout(Duration::from_secs(15), async {
                    while live.source.write_work().available_permits() != 1 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .map_err(io::Error::other)?;
                assert_eq!(
                    store::traffic::status(&live.fixture.client_state)?.cursor,
                    1
                );
                // Do not invent a new run from the stale pre-begin RAM cursor.
                assert!(handle.begin().await.is_err());
                drop((handle, runner));
                live.restart_source().await?;
                let (handle, runner) = new(live.source.clone()).await?;
                assert!(handle.observation()?.durable.loss_possible);
                handle.begin().await?;
                assert!(handle.observation()?.durable.loss_possible);
                handle.finish(true).await?;
                drop((handle, runner));
                Ok(())
            }
            .await;
            pause.release.notify_one();
            let closed = live.close().await;
            result.and(closed)
        }

        #[tokio::test]
        async fn source_remote_import_rechecks_proof_and_confirms_quarantine_before_returning_rejection()
        -> io::Result<()> {
            let live = SourceFixture::new_with(
                node::tests::CutResponse {
                    witness_only: true,
                    witness_confirm: true,
                    witness_sequence: Some(3),
                    ..Default::default()
                },
                |f| {
                    let c = rusqlite::Connection::open(f.server_state.join("management.sqlite3"))
                        .map_err(io::Error::other)?;
                    let actor: String = c
                        .query_row("SELECT id FROM administrators", [], |r| r.get(0))
                        .map_err(io::Error::other)?;
                    store::set_owner(
                        &f.server_state,
                        &store::update_lock(&f.server_state)?,
                        &actor,
                        1,
                        Some(&f.client_id),
                    )?;
                    Ok(())
                },
            )
            .await?;
            let result = async {
                let (actor, peer, origin) = (
                    live.administrator.clone(),
                    live.fixture.server_id.clone(),
                    live.endpoint.clone(),
                );
                live.source
                    .targets_write(move |w| w.configure(&actor, &peer, None, &origin, true, None))
                    .await?;
                let fetch = || async {
                    let control::Reply::TrafficSnapshot(value) = control::request(
                        &live.source,
                        live.fixture.client_tls.clone(),
                        &live.endpoint,
                        &live.fixture.server_id,
                        control::Request::TrafficSnapshot,
                    )
                    .await?
                    else {
                        return Err(invalid());
                    };
                    Ok(value)
                };
                for _ in 0..2 {
                    let value = fetch().await?;
                    live.source
                        .traffic_write(move |w| {
                            w.import(&value.authorization, 1, value.value, Some(70_000))
                        })
                        .await??;
                }
                assert_eq!(live.floor()?.sequence, "2");
                let mut value = fetch().await?;
                value.authorization.authorization_revision = 2;
                assert!(
                    live.source
                        .traffic_write(move |w| w.import(
                            &value.authorization,
                            1,
                            value.value,
                            Some(70_000)
                        ))
                        .await
                        .is_err()
                );
                assert_eq!(live.floor()?.sequence, "2");
                let mut value = fetch().await?;
                value.value.status.meter_epoch =
                    if value.value.status.meter_epoch == "AAAAAAAAAAAAAAAAAAAAAA" {
                        "AQAAAAAAAAAAAAAAAAAAAA"
                    } else {
                        "AAAAAAAAAAAAAAAAAAAAAA"
                    }
                    .into();
                live.arm();
                // The continuity conflict has committed locally, but a missing witness
                // confirmation must surface uncertainty rather than a definite reject.
                assert!(
                    live.source
                        .traffic_write(move |w| w.import(
                            &value.authorization,
                            1,
                            value.value,
                            Some(70_000)
                        ))
                        .await
                        .is_err()
                );
                assert!(live.source.reader().revision().is_err());
                let cached = store::remote_traffic::get(
                    &live.fixture.client_state,
                    &live.fixture.server_id,
                )?;
                assert!(cached.source.quarantined && cached.snapshot.is_some());
                live.source.reconcile_source().await?;
                let value = fetch().await?;
                let rejected = live
                    .source
                    .traffic_write(move |w| {
                        w.import(&value.authorization, 1, value.value, Some(70_000))
                    })
                    .await?;
                assert_eq!(
                    rejected.err().map(|error| error.kind()),
                    Some(io::ErrorKind::InvalidData)
                );
                let floor = live.floor()?.sequence;
                assert_eq!(live.source.reader().revision()?, 1);
                for _ in 0..2 {
                    let peer = live.fixture.server_id.clone();
                    live.source
                        .traffic_write(move |w| {
                            w.failed(&peer, 1, store::remote_traffic::Failure::Unavailable)
                        })
                        .await?;
                }
                assert_eq!(live.floor()?.sequence, floor);
                assert!(
                    store::remote_traffic::get(
                        &live.fixture.client_state,
                        &live.fixture.server_id
                    )?
                    .source
                    .quarantined
                );
                assert_eq!(live.source.reader().revision()?, 1);
                Ok(())
            }
            .await;
            let closed = live.close().await;
            result.and(closed)
        }
    }

    use super::*;
    use crate::{
        manage::store::PolicyChange,
        traffic::{Direction, Meter},
    };

    #[test]
    fn public_checkpoint_stages_are_closed_and_preserve_private_error_sources() {
        for (label, expected) in [
            ("sample", CheckpointStage::Sample),
            ("write_admission", CheckpointStage::WriteAdmission),
            ("update_gate", CheckpointStage::UpdateGate),
            ("store", CheckpointStage::Store),
            ("worker", CheckpointStage::Worker),
            ("observation", CheckpointStage::Observation),
            (
                "private unexpected diagnostic",
                CheckpointStage::Observation,
            ),
        ] {
            let error = checkpoint_failure(label, io::Error::from_raw_os_error(13));
            assert_eq!(CheckpointStage::from_error(&error), expected);
            let failure = error
                .get_ref()
                .unwrap()
                .downcast_ref::<CheckpointFailure>()
                .unwrap();
            assert_eq!(failure.error.raw_os_error(), Some(13));
            assert_eq!(error.kind(), failure.error.kind());
            let encoded = serde_json::to_string(&expected).unwrap();
            assert_eq!(
                encoded,
                format!(
                    "\"{}\"",
                    if label == "private unexpected diagnostic" {
                        "observation"
                    } else {
                        label
                    }
                )
            );
        }
        assert_eq!(
            CheckpointStage::from_error(&io::Error::other("private failure")),
            CheckpointStage::Observation
        );
    }

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

    /// The joinable test thread waits for the real Coordinator read worker, so
    /// releasing a slot also confirms its permit/author are gone before fixture Drop.
    struct HeldRead {
        release: Option<mpsc::Sender<()>>,
        thread: Option<thread::JoinHandle<io::Result<()>>>,
    }

    impl HeldRead {
        async fn new(policy: Arc<Coordinator>) -> io::Result<Self> {
            let runtime = tokio::runtime::Handle::current();
            let (ready, waiting) = oneshot::channel();
            let (release, blocked) = mpsc::channel();
            let worker = thread::Builder::new()
                .name("traffic-test-read-holder".into())
                .spawn(move || {
                    runtime.block_on(policy.read(move |_| {
                        let _ = ready.send(());
                        let _ = blocked.recv();
                        Ok(())
                    }))
                })?;
            let holder = Self {
                release: Some(release),
                thread: Some(worker),
            };
            timeout(Duration::from_secs(10), waiting)
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)?;
            Ok(holder)
        }

        fn release(mut self) -> io::Result<()> {
            self.release.take();
            self.thread
                .take()
                .expect("held read worker")
                .join()
                .map_err(|_| io::Error::other("held read worker panicked"))?
        }
    }

    impl Drop for HeldRead {
        fn drop(&mut self) {
            self.release.take();
            if let Some(worker) = self.thread.take() {
                let _ = worker.join();
            }
        }
    }

    /// This writer deliberately bypasses UpdateGuard only in a fresh fixture, to
    /// distinguish SQLite's real busy result from update-gate/admission rejection.
    struct HeldSqlite {
        release: Option<mpsc::Sender<()>>,
        thread: Option<thread::JoinHandle<io::Result<()>>>,
    }

    impl HeldSqlite {
        async fn new(database: PathBuf) -> io::Result<Self> {
            let (ready, waiting) = oneshot::channel();
            let (release, blocked) = mpsc::channel();
            let worker = thread::Builder::new()
                .name("traffic-test-sqlite-holder".into())
                .spawn(move || {
                    let opened = (|| {
                        let connection = rusqlite::Connection::open_with_flags(
                            database,
                            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
                        )
                        .map_err(|_| io::Error::other("cannot open held SQLite fixture"))?;
                        connection.execute_batch("BEGIN IMMEDIATE").map_err(|_| {
                            io::Error::other("cannot hold SQLite fixture transaction")
                        })?;
                        Ok::<_, io::Error>(connection)
                    })();
                    match opened {
                        Ok(connection) => {
                            let _ = ready.send(Ok(()));
                            let _ = blocked.recv();
                            connection.execute_batch("ROLLBACK").map_err(|_| {
                                io::Error::other("cannot release SQLite fixture transaction")
                            })
                        }
                        Err(error) => {
                            let _ = ready.send(Err(error));
                            Ok(())
                        }
                    }
                })?;
            let holder = Self {
                release: Some(release),
                thread: Some(worker),
            };
            timeout(Duration::from_secs(10), waiting)
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)??;
            Ok(holder)
        }

        fn release(mut self) -> io::Result<()> {
            self.release.take();
            self.thread
                .take()
                .expect("held SQLite worker")
                .join()
                .map_err(|_| io::Error::other("held SQLite worker panicked"))?
        }
    }

    impl Drop for HeldSqlite {
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
    async fn api_only_construction_ticks_and_finish_do_not_open_a_run() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let initial = store::traffic::status(&fixture.directory)?;
        let (handle, runner) = new(fixture.policy()).await?;
        let running = Running::new(runner);
        tokio::task::yield_now().await;
        running.stop().await?;
        handle.finish(true).await?;
        let observation = handle.observation()?;
        assert!(observation.active_run.is_none());
        assert!(observation.durable.clean && !observation.durable.loss_possible);
        assert!(observation.last_completed_at.is_none());
        assert_eq!(observation.completion_sequence, 0);
        let after = store::traffic::status(&fixture.directory)?;
        assert_eq!(after.cursor, initial.cursor);
        assert_eq!(after.meter_epoch, initial.meter_epoch);
        assert!(after.run_id.is_none() && after.meter_started_at.is_none());
        Ok(())
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
    async fn checkpoint_sampling_waits_without_losing_api_backpressure_or_cancelled_bytes()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let identity = fixture.identity().await?;
        let (handle, _runner) = new(fixture.policy()).await?;
        handle.begin().await?;
        handle.checkpoint().await?;
        let before = handle.observation()?;
        let (upload, download) = identity.meters(&fixture);
        upload.add(17);
        download.add(9);

        let first = HeldRead::new(fixture.policy()).await?;
        let second = HeldRead::new(fixture.policy()).await?;
        let mut cancelled = Box::pin(handle.checkpoint());
        assert!(
            futures_util::poll!(&mut cancelled).is_pending(),
            "checkpoint sampling must wait for a short read overlap"
        );
        assert!(
            matches!(handle.sample().await, Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        drop(cancelled);
        first.release()?;

        // Cancelling a queued sample must return its queue position, not leave a
        // detached sample or a reserved permit. The ordinary API read stays fail-fast.
        let sampled = handle.sample().await?.0;
        let value = sampled
            .into_iter()
            .find(|row| {
                row.credential_id.as_ref() == identity.credential && row.protocol == Protocol::Http
            })
            .expect("live credential sample")
            .value;
        assert_eq!(value.upload, 17);
        assert_eq!(value.download, 9);
        let cancelled = handle.observation()?;
        assert_eq!(cancelled.durable.cursor, before.durable.cursor);
        assert_eq!(cancelled.completion_sequence, before.completion_sequence);
        assert_eq!(fixture.total(&identity.credential)?.upload, 0);

        let first = HeldRead::new(fixture.policy()).await?;
        let mut checkpoint = Box::pin(handle.checkpoint());
        assert!(futures_util::poll!(&mut checkpoint).is_pending());
        first.release()?;
        // The semaphore reserves the released slot for the already queued sample.
        // A newer API read cannot repeatedly steal it and starve the checkpoint.
        assert!(
            matches!(handle.sample().await, Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        timeout(Duration::from_secs(10), checkpoint)
            .await
            .map_err(io::Error::other)??;
        second.release()?;

        let completed = handle.observation()?;
        assert!(!completed.checkpoint_error);
        assert_eq!(
            completed.completion_sequence,
            before.completion_sequence + 1
        );
        assert!(completed.durable.cursor > before.durable.cursor);
        assert_eq!(fixture.total(&identity.credential)?, value);
        handle.finish(true).await?;
        assert!(store::traffic::status(&fixture.directory)?.clean);
        Ok(())
    }

    #[tokio::test]
    async fn exhausted_read_slots_report_sample_and_recover_retained_absolute_counts()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let identity = fixture.identity().await?;
        let (handle, runner) = new(fixture.policy()).await?;
        handle.begin().await?;
        let (upload, download) = identity.meters(&fixture);
        upload.add(13);
        download.add(7);
        handle.checkpoint().await?;
        let confirmed = fixture.total(&identity.credential)?;
        let before = handle.observation()?;
        upload.add(5);
        download.add(3);

        let first = HeldRead::new(fixture.policy()).await?;
        let second = HeldRead::new(fixture.policy()).await?;
        let error = handle.checkpoint().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(failure_stage(&error), "sample");
        let running = Running::new(runner);
        observed(&handle, |view| view.checkpoint_error).await;
        running.stop().await?;
        let delayed = handle.observation()?;
        assert!(delayed.checkpoint_error);
        assert_eq!(
            delayed.checkpoint_failure_stage,
            Some(CheckpointStage::Sample)
        );
        assert_eq!(delayed.durable.cursor, before.durable.cursor);
        assert_eq!(delayed.completion_sequence, before.completion_sequence);
        assert_eq!(fixture.total(&identity.credential)?, confirmed);
        assert_eq!(
            handle.state()?.credentials[identity.credential.as_str()][index(Protocol::Http)],
            confirmed
        );
        let retained = handle.0.registry.snapshot()?;
        assert_eq!(
            retained
                .into_iter()
                .find(|row| row.protocol == Protocol::Http)
                .unwrap()
                .value,
            Snapshot {
                upload: 18,
                download: 10,
                saturated: false
            }
        );
        first.release()?;
        second.release()?;

        handle.checkpoint().await?;
        let recovered = handle.observation()?;
        assert!(!recovered.checkpoint_error);
        assert_eq!(recovered.checkpoint_failure_stage, None);
        assert!(recovered.durable.cursor > before.durable.cursor);
        assert_eq!(
            recovered.completion_sequence,
            before.completion_sequence + 1
        );
        assert_eq!(fixture.total(&identity.credential)?.upload, 18);
        assert_eq!(fixture.total(&identity.credential)?.download, 10);
        handle.checkpoint().await?;
        assert_eq!(fixture.total(&identity.credential)?.upload, 18);
        assert_eq!(fixture.total(&identity.credential)?.download, 10);
        handle.finish(true).await?;
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_busy_reports_store_and_recovers_retained_absolute_counts() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let identity = fixture.identity().await?;
        let (handle, runner) = new(fixture.policy()).await?;
        handle.begin().await?;
        let (upload, download) = identity.meters(&fixture);
        upload.add(17);
        download.add(9);
        handle.checkpoint().await?;
        let confirmed = fixture.total(&identity.credential)?;
        let before = handle.observation()?;
        upload.add(31);
        download.add(11);

        let writer = HeldSqlite::new(fixture.directory.join("management.sqlite3")).await?;
        let error = handle.checkpoint().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(failure_stage(&error), "store");
        let running = Running::new(runner);
        observed(&handle, |view| view.checkpoint_error).await;
        running.stop().await?;
        let delayed = handle.observation()?;
        assert!(delayed.checkpoint_error);
        assert_eq!(
            delayed.checkpoint_failure_stage,
            Some(CheckpointStage::Store)
        );
        assert_eq!(delayed.durable.cursor, before.durable.cursor);
        assert_eq!(delayed.completion_sequence, before.completion_sequence);
        assert_eq!(fixture.total(&identity.credential)?, confirmed);
        assert_eq!(
            handle.state()?.credentials[identity.credential.as_str()][index(Protocol::Http)],
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
                upload: 48,
                download: 20,
                saturated: false
            }
        );
        writer.release()?;

        handle.checkpoint().await?;
        let recovered = handle.observation()?;
        assert!(!recovered.checkpoint_error);
        assert!(recovered.durable.cursor > before.durable.cursor);
        assert_eq!(
            recovered.completion_sequence,
            before.completion_sequence + 1
        );
        assert_eq!(fixture.total(&identity.credential)?.upload, 48);
        assert_eq!(recovered.checkpoint_failure_stage, None);
        assert_eq!(fixture.total(&identity.credential)?.download, 20);
        handle.checkpoint().await?;
        assert_eq!(fixture.total(&identity.credential)?.upload, 48);
        assert_eq!(fixture.total(&identity.credential)?.download, 20);
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

    #[tokio::test]
    async fn failed_proxy_cleanup_remains_open_and_restart_exposes_possible_tail_loss()
    -> io::Result<()> {
        let mut fixture = Fixture::new()?;
        let identity = fixture.identity().await?;
        let (handle, runner) = new(fixture.policy()).await?;
        handle.begin().await?;
        let (upload, download) = identity.meters(&fixture);
        upload.add(27);
        download.add(10);
        handle.finish(false).await?;
        let old = store::traffic::status(&fixture.directory)?;
        assert!(!old.clean && old.run_id.is_some());
        assert_eq!(handle.observation()?.active_run, old.run_id);
        assert_eq!(fixture.total(&identity.credential)?.upload, 27);
        // A timed-out proxy may still have a late writer. That uncheckpointed tail
        // is deliberately not manufactured from the durable lower bound on reboot.
        upload.add(11);
        drop((upload, download, handle, runner));
        fixture.reload()?;
        let (restarted, runner) = new(fixture.policy()).await?;
        let restored = restarted.observation()?;
        assert!(restored.active_run.is_none());
        assert!(!restored.durable.clean && restored.durable.loss_possible);
        assert_eq!(restored.durable.meter_epoch, old.meter_epoch);
        assert_eq!(restored.durable.cursor, old.cursor);
        // API-only recovery is read-only: the old marker is not silently closed.
        assert_eq!(
            store::traffic::status(&fixture.directory)?.cursor,
            old.cursor
        );
        assert_eq!(
            restarted
                .sample()
                .await?
                .0
                .into_iter()
                .find(|row| row.protocol == Protocol::Http)
                .unwrap()
                .value
                .upload,
            27
        );
        restarted.begin().await?;
        let next = restarted.observation()?;
        assert!(next.durable.loss_possible);
        assert_ne!(next.active_run, old.run_id);
        restarted.finish(true).await?;
        let final_status = store::traffic::status(&fixture.directory)?;
        assert!(final_status.clean && final_status.loss_possible);
        drop(runner);
        Ok(())
    }

    struct Release(Option<mpsc::Sender<()>>);

    impl Drop for Release {
        fn drop(&mut self) {
            self.0.take();
        }
    }

    #[tokio::test]
    async fn cancelled_committed_writer_keeps_single_flight_and_absolute_retry_is_idempotent()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let identity = fixture.identity().await?;
        let (handle, runner) = new(fixture.policy()).await?;
        handle.begin().await?;
        let (upload, _) = identity.meters(&fixture);
        upload.add(83);
        let (samples, pools) = handle.sample().await?;
        let run = handle.observation()?.active_run.expect("open run");
        let (committed, ready) = oneshot::channel();
        let (release, blocked) = mpsc::channel();
        let release = Release(Some(release));
        let policy = fixture.policy();
        let task = tokio::spawn(async move {
            policy
                .traffic_write(move |writer| {
                    let status = writer.checkpoint(&run, now(), &samples, &pools)?;
                    let _ = committed.send(());
                    let _ = blocked.recv();
                    Ok(status)
                })
                .await
        });
        timeout(Duration::from_secs(10), ready)
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        task.abort();
        match task.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => panic!("cancelled awaiting task unexpectedly returned a result"),
        }
        let error = handle.checkpoint().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(failure_stage(&error), "write_admission");
        assert_eq!(fixture.total(&identity.credential)?.upload, 83);
        // The awaiting collector never confirmed the result, so its filter must
        // still retry the same absolute value rather than throw the live sample away.
        assert_eq!(
            handle
                .state()?
                .credentials
                .get(identity.credential.as_str())
                .unwrap()[0],
            ZERO
        );
        drop(release);
        timeout(Duration::from_secs(10), async {
            loop {
                match fixture.policy().traffic_write(|_| Ok(())).await {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                    result => break result,
                }
            }
        })
        .await
        .map_err(io::Error::other)??;
        handle.checkpoint().await?;
        assert_eq!(fixture.total(&identity.credential)?.upload, 83);
        upload.add(9);
        handle.finish(true).await?;
        assert_eq!(fixture.total(&identity.credential)?.upload, 92);
        drop(runner);
        Ok(())
    }
}
