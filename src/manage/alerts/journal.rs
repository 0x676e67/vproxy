//! A single retained observation batch, not an independent queue or service.
//! Only confirmed transactions publish incident changes. Failure retains prior
//! evidence and never closes the management listener. Source uncertainty keeps
//! its separate admission fence until the original operation is resolved.

use super::*;
use crate::manage::store::alerts::history::{self, Batch};

const MAX_TRANSITIONS: usize = MAX_TOTAL * 2;

/// Immutable accepted evidence survives an ambiguous commit. Retries confirm
/// exactly this boot/sequence/digest; they never sample again or invent an ID.
pub(super) struct Prepared {
    base_generation: u64,
    base_revision: u64,
    base_egress_revision: u64,
    next: Arc<State>,
    batch: Batch,
    proofs: Vec<Arc<crate::manage::observations::Proof>>,
    bindings: Vec<history::Binding>,
    delayed: AtomicBool,
    published: AtomicBool,
}

/// A staged SQL decision, not confirmation or permission to publish RAM yet.
enum Persistence {
    Discard,
    Publish {
        commit: Option<history::Commit>,
        remote_current: bool,
    },
}

fn persist(
    writer: &mut history::Writer<'_>,
    prepared: &Prepared,
    confirm_first: bool,
) -> io::Result<Persistence> {
    if prepared.batch.transitions.is_empty() {
        return match writer.validate_current(&prepared.proofs, &prepared.bindings) {
            Ok(()) => Ok(Persistence::Publish {
                commit: None,
                remote_current: true,
            }),
            Err(error) if changed(&error) => Ok(Persistence::Discard),
            Err(error) => Err(error),
        };
    }
    let receipt = if confirm_first {
        writer.receipt(&prepared.batch)?
    } else {
        None
    };
    let (commit, remote_current) = match receipt {
        Some(commit) => {
            let current = if prepared.bindings.is_empty() {
                Ok(())
            } else {
                writer.validate_current(&prepared.proofs, &prepared.bindings)
            };
            match current {
                Ok(()) => (commit, true),
                Err(error) if changed(&error) => (commit, false),
                Err(error) => return Err(error),
            }
        }
        None => {
            let proofs = (!prepared.bindings.is_empty())
                .then_some((prepared.proofs.as_slice(), prepared.bindings.as_slice()));
            match writer.record(&prepared.batch, proofs) {
                Ok(commit) => (commit, true),
                // Guard denial precedes event writes. A committed receipt above
                // remains historical evidence even if its current proof expired.
                Err(error) if changed(&error) => return Ok(Persistence::Discard),
                Err(error) => return Err(error),
            }
        }
    };
    Ok(Persistence::Publish {
        commit: Some(commit),
        remote_current,
    })
}

pub(super) fn push(events: &mut Vec<Transition>, event: Transition) -> io::Result<()> {
    if events.len() == MAX_TRANSITIONS {
        return Err(unavailable());
    }
    events.push(event);
    Ok(())
}

/// Make no recovery claim while publication is delayed. This changes only
/// observation availability/freshness, never incident identity or evidence.
fn stale(state: &mut State, egress_covered: bool) -> (bool, bool) {
    let mut changed = !state.collection_error;
    let mut scoped = egress_covered && !state.egress.collection_error;
    state.collection_error = true;
    if egress_covered {
        state.egress.collection_error = true;
    }
    // Freshness for an active incident describes current evidence. A terminal
    // episode instead retains the evidence that proved recovery or retirement;
    // a later collection failure cannot invalidate that historical fact.
    for incident in state.active.values_mut() {
        if incident.fresh {
            incident.fresh = false;
            changed = true;
            scoped |= incident.key.local_egress(&state.node_id);
        }
    }
    (changed, scoped)
}

impl Prepared {
    fn publish(&self, shared: &Shared, remote_current: bool) -> io::Result<()> {
        if self.published.load(Ordering::Acquire) {
            return Ok(());
        }
        let current = shared.snapshot()?;
        if current.generation != self.base_generation {
            return Err(unavailable());
        }
        // Deep copying, stale marking and counter checks precede the short
        // compare-and-replace lock. Readers never wait on maps or SQLite.
        let mut next = (*self.next).clone();
        // An exact receipt proves the original authorized transaction committed.
        // Preserve that transition boundary even after subsequent revocation:
        // restoring an older active RAM episode would contradict its SQL terminal
        // state. Only current freshness is withdrawn, never historical recovery.
        if !remote_current
            || self.delayed.load(Ordering::Acquire)
            || current.revision != self.base_revision
            || current.egress.revision != self.base_egress_revision
        {
            let (_, scoped) = stale(&mut next, shared.coverage.local_egress);
            next.revision = current.revision.checked_add(1).ok_or_else(unavailable)?;
            next.egress.revision = if scoped
                || current.egress.revision != self.base_egress_revision
                || self.next.egress.revision != self.base_egress_revision
            {
                current
                    .egress
                    .revision
                    .checked_add(1)
                    .ok_or_else(unavailable)?
            } else {
                current.egress.revision
            };
            // Confirmation is not a new producer observation. Keep its older
            // sampling watermark until a subsequent real collect succeeds.
            next.completed = current.completed;
            next.observed_at = current.observed_at;
            next.egress.completed = current.egress.completed;
            next.egress.observed_at = current.egress.observed_at;
        }
        shared.publish(&current, next)?;
        self.published.store(true, Ordering::Release);
        Ok(())
    }
}

impl Runner {
    fn history_error(&mut self, error: &io::Error) {
        let kind = error.kind();
        if self.history_failure != Some(kind) {
            tracing::warn!(
                ?kind,
                "operations history persistence unavailable; prior evidence retained"
            );
            self.history_failure = Some(kind);
        }
        // A cancelled caller can race the original owned worker's publication.
        // A bounded second snapshot handles that one replacement; persistent
        // contention or counter exhaustion makes only this monitor unavailable.
        let degraded = (0..2).any(|_| {
            let result: io::Result<()> = (|| {
                let current = self.shared.snapshot()?;
                let mut next = (*current).clone();
                let (changed, scoped) = stale(&mut next, self.shared.coverage.local_egress);
                if !changed && !scoped {
                    return Ok(());
                }
                next.revision = current.revision.checked_add(1).ok_or_else(unavailable)?;
                if scoped {
                    next.egress.revision = current
                        .egress
                        .revision
                        .checked_add(1)
                        .ok_or_else(unavailable)?;
                }
                self.shared.publish(&current, next)
            })();
            result.is_ok()
        });
        if !degraded {
            self.shared.available.store(false, Ordering::Release);
        }
    }

    fn history_resumed(&mut self) {
        if self.history_failure.take().is_some() {
            tracing::info!("operations history persistence resumed; awaiting a new observation");
        }
    }

    /// Startup and ambiguous batches are resolved before touching producer
    /// clocks again. Shutdown never cancels an admitted commit/publication.
    pub(super) async fn history_before_collect(&mut self) -> bool {
        if !self.history_enabled {
            return false;
        }
        if self.history_blocked {
            return true;
        }
        if let Some(prepared) = &self.history_pending {
            prepared.delayed.store(true, Ordering::Release);
            self.persist_history(true).await;
            return true;
        }
        if !self.history_started {
            let boot = self.shared.boot_id.clone();
            let result = self
                .policy
                .history_write(move |writer| writer.start(&boot))
                .await;
            match result {
                Ok(commit)
                    if commit.boot_id == self.shared.boot_id && commit.batch_sequence == 0 =>
                {
                    self.history_started = true;
                    self.history_resumed();
                }
                Ok(_) => {
                    self.history_blocked = true;
                    self.history_error(&unavailable());
                    return true;
                }
                Err(error) => {
                    self.history_error(&error);
                    return true;
                }
            }
        }
        false
    }

    fn prepare_frame(&self, mut frame: Frame) -> io::Result<Option<Arc<Prepared>>> {
        let current = self.shared.snapshot()?;
        let mut next = (*current).clone();
        let proofs = std::mem::take(&mut frame.remote_proofs);
        let bindings = std::mem::take(&mut frame.remote_bindings);
        let transitions = next.apply_with_events(frame, Instant::now(), wall_time())?;
        if !self.history_enabled || transitions.is_empty() && bindings.is_empty() {
            if !bindings.is_empty() {
                return Err(unavailable());
            }
            self.shared.publish(&current, next)?;
            return Ok(None);
        }
        let sequence = self
            .history_sequence
            .checked_add(1)
            .ok_or_else(unavailable)?;
        Ok(Some(Arc::new(Prepared {
            base_generation: current.generation,
            base_revision: current.revision,
            base_egress_revision: current.egress.revision,
            next: Arc::new(next),
            batch: Batch {
                boot_id: self.shared.boot_id.clone(),
                sequence,
                transitions,
            },
            proofs,
            bindings,
            delayed: AtomicBool::new(false),
            published: AtomicBool::new(false),
        })))
    }

    pub(super) async fn accept_frame(&mut self, frame: Frame) -> io::Result<()> {
        self.report_collection(&frame);
        let prepared = self.prepare_frame(frame);
        match prepared {
            Ok(Some(prepared)) => {
                self.history_pending = Some(prepared);
                self.persist_history(false).await;
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(error) if self.history_enabled => {
                // No bounded/canonical batch could be formed. Do not collect
                // again with already-advanced clocks or wrap sequence numbers.
                self.history_blocked = true;
                self.history_error(&error);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    async fn persist_history(&mut self, confirm_first: bool) {
        let Some(prepared) = self.history_pending.clone() else {
            return;
        };
        let shared = self.shared.clone();
        let after = prepared.clone();
        let result = self
            .policy
            .history_write_then(
                move |writer| persist(writer, &prepared, confirm_first),
                move |outcome| match outcome {
                    Persistence::Discard => Ok((None, false)),
                    Persistence::Publish {
                        commit,
                        remote_current,
                    } => {
                        // This is a post-commit response/publication check. It
                        // cannot roll a confirmed Source transaction back.
                        if commit.as_ref().is_some_and(|commit| {
                            commit.boot_id != after.batch.boot_id
                                || commit.batch_sequence != after.batch.sequence
                        }) {
                            return Err(unavailable());
                        }
                        after.publish(&shared, remote_current)?;
                        Ok((commit, true))
                    }
                },
            )
            .await;
        match result {
            Ok((commit, published)) => {
                if let Some(commit) = commit {
                    self.history_sequence = commit.batch_sequence;
                }
                self.history_pending = None;
                if published {
                    self.history_resumed();
                } else {
                    self.history_error(&unavailable());
                }
            }
            Err(error) => {
                if let Some(prepared) = &self.history_pending {
                    prepared.delayed.store(true, Ordering::Release);
                }
                self.history_error(&error);
            }
        }
    }
}

fn changed(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|error| error.downcast_ref::<history::Error>())
        == Some(&history::Error::Denied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::alerts::tests::Fixture;
    use crate::manage::store;

    #[cfg(feature = "witness-journal")]
    mod source {
        //! The actual history runner publishes only after its loopback mTLS witness
        //! confirms. Frames are synthetic evidence, not real health/proxy probes.

        use super::*;
        use crate::manage::{node, store::journal::SourceFixture};
        use std::sync::atomic::AtomicUsize;
        use tokio::time::timeout;

        mod segments {
            //! Real history Writer batches and loopback mTLS, not arbitrary changeset blobs.
            //! Distinct historical subjects exercise store bounds, not live IPAM capacity.
            use super::*;
            use crate::manage::store::alerts::history::{
                Batch, EndReason, Observation, Transition,
            };
            use std::net::{Ipv6Addr, SocketAddr};

            const LOCAL: u64 = 6_144;

            fn batch(node: &str, boot: &str, sequence: u64, kinds: &[TransitionKind]) -> Batch {
                let target = SocketAddr::from((
                    Ipv6Addr::new(
                        0x2001, 0x4860, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                    ),
                    u16::MAX,
                ));
                Batch {
                    boot_id: boot.to_owned(),
                    sequence,
                    transitions: kinds
                        .iter()
                        .flat_map(|kind| {
                            (1..=LOCAL).map(move |id| Transition {
                                kind: *kind,
                                observation: Observation {
                                    incident_id: id,
                                    kind: Kind::EgressCheck,
                                    origin_node_id: node.to_owned(),
                                    resource_id: Some(
                                        URL_SAFE_NO_PAD.encode(u128::from(id).to_be_bytes()),
                                    ),
                                    slot: format!("tcp:{target}"),
                                    check: Some(health::CheckKind::Tcp),
                                    target: Some(target),
                                    code: if sequence == 1 {
                                        "egress_network_unreachable"
                                    } else {
                                        "egress_address_unavailable"
                                    }
                                    .into(),
                                    first_observed_at_unix_ms: Some(u64::MAX),
                                    last_observed_at_unix_ms: Some(u64::MAX),
                                    evidence_sequence: Some(u64::MAX),
                                },
                                observed_at_unix_ms: Some(u64::MAX),
                                ended_reason: (*kind == TransitionKind::Unmonitored)
                                    .then_some(EndReason::SourceUnmonitored),
                            })
                        })
                        .collect(),
                }
            }

            fn metadata(live: &SourceFixture, sequence: u64) -> io::Result<serde_json::Value> {
                let root = live.fixture.client_state.join("witness-intents");
                let locator: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(root.join(format!("{sequence}.json")))?)
                        .map_err(io::Error::other)?;
                let id = locator["intent_id"].as_str().ok_or_else(unavailable)?;
                serde_json::from_slice(&std::fs::read(root.join(id).join("intent.json"))?)
                    .map_err(io::Error::other)
            }

            async fn opened(live: &SourceFixture) -> io::Result<String> {
                let boot = URL_SAFE_NO_PAD.encode([61u8; 16]);
                let saved = boot.clone();
                live.source.history_write(move |w| w.start(&saved)).await?;
                let value = batch(&live.fixture.client_id, &boot, 1, &[TransitionKind::Opened]);
                live.source
                    .history_write(move |w| w.record(&value, None))
                    .await?;
                Ok(boot)
            }

            #[tokio::test]
            async fn large_segmented_history_lost_replies_replay_once_and_survive_same_identity_restart()
            -> io::Result<()> {
                for reserve in [true, false] {
                    let mut live = live(node::tests::CutResponse {
                        witness_only: true,
                        witness_reserve: reserve,
                        witness_confirm: !reserve,
                        witness_sequence: Some(3),
                        ..Default::default()
                    })
                    .await?;
                    let result = async {
                        let boot = opened(&live).await?;
                        let original = Arc::new(batch(
                            &live.fixture.client_id,
                            &boot,
                            2,
                            &[TransitionKind::ReasonChanged, TransitionKind::Unmonitored],
                        ));
                        let value = original.clone();
                        let calls = Arc::new(AtomicUsize::new(0));
                        let called = calls.clone();
                        live.arm();
                        let error = live
                            .source
                            .history_write(move |w| {
                                called.fetch_add(1, Ordering::AcqRel);
                                w.record(&value, None)
                            })
                            .await
                            .err()
                            .ok_or_else(unavailable)?;
                        assert!(store::journal::is_uncertain(&error));
                        assert_eq!(calls.load(Ordering::Acquire), 1);
                        assert!(live.source.reader().revision().is_err());
                        let saved = metadata(&live, 3)?;
                        assert_eq!(saved["format"], 3);
                        assert!(
                            saved["payload_bytes"].as_u64().ok_or_else(unavailable)?
                                > 16 * 1024 * 1024
                        );
                        assert!(
                            saved["segmented"]["segments"]
                                .as_u64()
                                .ok_or_else(unavailable)?
                                > 2
                        );
                        assert_eq!(counts(&db(&live)?)?.1, if reserve { 1 } else { 2 });
                        live.source.reconcile_source().await?;
                        assert_eq!(metadata(&live, 3)?, saved);
                        assert_eq!(calls.load(Ordering::Acquire), 1);
                        let summary =
                            history::summary(&live.fixture.client_state, &live.administrator)?;
                        assert_eq!(
                            (
                                summary.active_count,
                                summary.closed_count,
                                summary.event_count
                            ),
                            (0, 4096, 16384)
                        );
                        assert_eq!(
                            (summary.trimmed, summary.last_event_sequence),
                            (2048, 18432)
                        );
                        live.restart_source().await?;
                        let value = original.clone();
                        live.source
                            .history_write(move |w| w.receipt(&value))
                            .await?
                            .ok_or_else(unavailable)?;
                        assert_eq!(live.floor()?.sequence, "3");
                        assert_eq!(live.source.reader().revision()?, 1);
                        // A later raw intent shares the chain and may retire format-3
                        // history without allocating its entire large payload for cleanup.
                        for revision in 1..=3 {
                            live.source
                                .change(
                                    live.administrator.clone(),
                                    revision,
                                    store::PolicyChange::CreateUser {
                                        name: "history chain continuation".into(),
                                        protocols: vec![crate::access::Protocol::Http],
                                        concurrent_limit: 1,
                                    },
                                )
                                .await?;
                        }
                        assert_eq!(live.floor()?.sequence, "6");
                        assert_eq!(metadata(&live, 6)?["format"], 2);
                        assert!(
                            !live
                                .fixture
                                .client_state
                                .join("witness-intents/3.json")
                                .try_exists()?
                        );
                        history::validate_snapshot(&db(&live)?)?;
                        assert_eq!(
                            live.floor()?.phase,
                            crate::manage::witness::Phase::Confirmed
                        );
                        Ok(())
                    }
                    .await;
                    let closed = live.close().await;
                    result.and(closed)?;
                }
                Ok(())
            }

            #[tokio::test]
            async fn cancelled_segmented_history_keeps_permit_until_confirmed_publication()
            -> io::Result<()> {
                let pause = Arc::new(node::tests::ResponsePause::default());
                let live = live(node::tests::CutResponse {
                    witness_only: true,
                    witness_confirm: true,
                    witness_sequence: Some(2),
                    pause: Some(pause.clone()),
                    ..Default::default()
                })
                .await?;
                let result = async {
                    let boot = URL_SAFE_NO_PAD.encode([62u8; 16]);
                    let saved = boot.clone();
                    live.source.history_write(move |w| w.start(&saved)).await?;
                    let value = batch(&live.fixture.client_id, &boot, 1, &[TransitionKind::Opened]);
                    let published = Arc::new(AtomicUsize::new(0));
                    let count = published.clone();
                    live.arm();
                    let mut accepted = Box::pin(live.source.history_write_then(
                        move |w| w.record(&value, None),
                        move |_| {
                            count.fetch_add(1, Ordering::AcqRel);
                            Ok(())
                        },
                    ));
                    assert!(futures_util::poll!(&mut accepted).is_pending());
                    timeout(Duration::from_secs(30), pause.entered.notified())
                        .await
                        .map_err(io::Error::other)?;
                    assert!(
                        metadata(&live, 2)?["segmented"]["segments"]
                            .as_u64()
                            .ok_or_else(unavailable)?
                            > 1
                    );
                    drop(accepted);
                    assert_eq!(published.load(Ordering::Acquire), 0);
                    assert_eq!(live.source.write_work().available_permits(), 0);
                    assert!(store::update_lock(&live.fixture.client_state).is_err());
                    pause.release.notify_one();
                    timeout(Duration::from_secs(30), async {
                        while live.source.write_work().available_permits() != 1 {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .map_err(io::Error::other)?;
                    assert_eq!(published.load(Ordering::Acquire), 1);
                    assert_eq!(counts(&db(&live)?)?, (6144, 1, 6144));
                    // Closing a full active generation also checkpoints before applying
                    // retention, without resetting old event/incident sequence identities.
                    let next = URL_SAFE_NO_PAD.encode([63u8; 16]);
                    live.source.history_write(move |w| w.start(&next)).await?;
                    let summary =
                        history::summary(&live.fixture.client_state, &live.administrator)?;
                    assert_eq!(
                        (
                            summary.active_count,
                            summary.closed_count,
                            summary.event_count
                        ),
                        (0, 4096, 12288)
                    );
                    history::validate_snapshot(&db(&live)?)?;
                    Ok(())
                }
                .await;
                pause.release.notify_one();
                let closed = live.close().await;
                result.and(closed)
            }
        }

        async fn live(fault: node::tests::CutResponse) -> io::Result<SourceFixture> {
            SourceFixture::new_with(fault, |_| Ok(())).await
        }

        fn monitor(live: &SourceFixture) -> io::Result<(Handle, Runner)> {
            let (handle, mut runner) = super::super::super::new(
                live.source.clone(),
                live.fixture.client_id.clone(),
                None,
                None,
                false,
                false,
                None,
                None,
            )?;
            runner.enable_history();
            Ok((handle, runner))
        }

        fn db(live: &SourceFixture) -> io::Result<rusqlite::Connection> {
            rusqlite::Connection::open(live.fixture.client_state.join("management.sqlite3"))
                .map_err(io::Error::other)
        }

        #[tokio::test]
        async fn source_history_lifecycle_ack_cas_and_monitor_restart_preserve_original_events()
        -> io::Result<()> {
            let live = live(Default::default()).await?;
            let result = async {
                let (handle, mut runner) = monitor(&live)?;
                assert!(!runner.history_before_collect().await);
                let boot = runner.shared.boot_id.clone();
                let repeated = boot.clone();
                live.source
                    .history_write(move |w| w.start(&repeated))
                    .await?;
                assert_eq!(live.floor()?.sequence, "1");
                runner
                    .accept_frame(observed(
                        &runner.node_id,
                        1,
                        Outcome::Failure("egress_failed"),
                    ))
                    .await?;
                assert!(runner.history_pending.is_none());
                assert_eq!(counts(&db(&live)?)?, (1, 1, 1));
                assert_eq!(
                    handle
                        .page(Filter::Active, None, 16)
                        .map_err(|_| unavailable())?
                        .items
                        .len(),
                    1
                );
                let input = || history::Ack {
                    expected_node_id: live.fixture.client_id.clone(),
                    episode_id: 1,
                    expected_transition_sequence: 1,
                };
                let ack = input();
                let wrong = live.fixture.server_id.clone();
                assert_eq!(
                    live.source
                        .history_write(move |w| w.acknowledge(&wrong, &ack))
                        .await
                        .err()
                        .map(|e| e.kind()),
                    Some(io::ErrorKind::PermissionDenied)
                );
                assert_eq!(live.floor()?.sequence, "2");
                for _ in 0..2 {
                    let (ack, actor) = (input(), live.administrator.clone());
                    let episode = live
                        .source
                        .history_write(move |w| w.acknowledge(&actor, &ack))
                        .await?;
                    assert!(episode.is_acknowledged);
                }
                assert_eq!(live.floor()?.sequence, "3");
                assert_eq!(counts(&db(&live)?)?, (2, 1, 2));
                runner
                    .accept_frame(observed(
                        &runner.node_id,
                        2,
                        Outcome::Failure("egress_timed_out"),
                    ))
                    .await?;
                let (ack, actor) = (input(), live.administrator.clone());
                assert_eq!(
                    live.source
                        .history_write(move |w| w.acknowledge(&actor, &ack))
                        .await
                        .err()
                        .map(|e| e.kind()),
                    Some(io::ErrorKind::AlreadyExists)
                );
                assert_eq!(live.floor()?.sequence, "4");
                drop((handle, runner));
                let (_, mut next) = monitor(&live)?;
                assert!(!next.history_before_collect().await);
                assert_eq!(counts(&db(&live)?)?, (4, 0, 4));
                let episode = history::episode(&live.fixture.client_state, &live.administrator, 1)?
                    .ok_or_else(unavailable)?;
                assert_eq!(episode.status, Status::Unmonitored);
                assert_eq!(
                    episode.ended_reason,
                    Some(history::EndReason::MonitorRestarted)
                );
                assert!(
                    live.source
                        .history_write(move |w| w.start(&boot))
                        .await
                        .is_err()
                );
                assert_eq!(live.floor()?.sequence, "5");
                assert_eq!(live.source.reader().revision()?, 1);
                Ok(())
            }
            .await;
            let closed = live.close().await;
            result.and(closed)
        }

        #[tokio::test]
        async fn cancelled_source_history_wait_still_publishes_after_confirm_before_releasing_writer()
        -> io::Result<()> {
            let pause = Arc::new(node::tests::ResponsePause::default());
            let live = live(node::tests::CutResponse {
                witness_only: true,
                witness_confirm: true,
                witness_sequence: Some(2),
                pause: Some(pause.clone()),
                ..Default::default()
            })
            .await?;
            let result = async {
                let (handle, mut runner) = monitor(&live)?;
                assert!(!runner.history_before_collect().await);
                let frame = observed(&runner.node_id, 1, Outcome::Failure("egress_failed"));
                live.arm();
                let mut accepted = Box::pin(runner.accept_frame(frame));
                assert!(futures_util::poll!(&mut accepted).is_pending());
                timeout(Duration::from_secs(15), pause.entered.notified())
                    .await
                    .map_err(io::Error::other)?;
                drop(accepted);
                assert_eq!(counts(&db(&live)?)?, (1, 1, 1));
                assert!(
                    handle
                        .page(Filter::Active, None, 16)
                        .map_err(|_| unavailable())?
                        .items
                        .is_empty()
                );
                assert_eq!(live.source.write_work().available_permits(), 0);
                assert!(store::update_lock(&live.fixture.client_state).is_err());
                let original = runner
                    .history_pending
                    .as_ref()
                    .ok_or_else(unavailable)?
                    .batch
                    .clone();
                pause.release.notify_one();
                timeout(Duration::from_secs(15), async {
                    while live.source.write_work().available_permits() != 1 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .map_err(io::Error::other)?;
                assert_eq!(
                    handle
                        .page(Filter::Active, None, 16)
                        .map_err(|_| unavailable())?
                        .items
                        .len(),
                    1
                );
                assert!(
                    runner
                        .history_pending
                        .as_ref()
                        .ok_or_else(unavailable)?
                        .published
                        .load(Ordering::Acquire)
                );
                assert!(runner.history_before_collect().await);
                assert!(runner.history_pending.is_none());
                assert_eq!(
                    history::receipt(&live.fixture.client_state, &original)?
                        .ok_or_else(unavailable)?
                        .batch_sequence,
                    1
                );
                assert_eq!(live.floor()?.sequence, "2");
                assert_eq!(counts(&db(&live)?)?, (1, 1, 1));
                Ok(())
            }
            .await;
            pause.release.notify_one();
            let closed = live.close().await;
            result.and(closed)
        }

        #[tokio::test]
        async fn source_history_lost_reserve_or_confirm_keeps_original_pending_without_premature_ram()
        -> io::Result<()> {
            for reserve in [true, false] {
                let live = live(node::tests::CutResponse {
                    witness_only: true,
                    witness_reserve: reserve,
                    witness_confirm: !reserve,
                    witness_sequence: Some(2),
                    ..Default::default()
                })
                .await?;
                let result = async {
                    let (handle, mut runner) = monitor(&live)?;
                    assert!(!runner.history_before_collect().await);
                    live.arm();
                    runner
                        .accept_frame(observed(
                            &runner.node_id,
                            1,
                            Outcome::Failure("egress_failed"),
                        ))
                        .await?;
                    let original = runner
                        .history_pending
                        .as_ref()
                        .ok_or_else(unavailable)?
                        .batch
                        .clone();
                    assert!(live.source.reader().revision().is_err());
                    assert!(
                        handle
                            .page(Filter::Active, None, 16)
                            .map_err(|_| unavailable())?
                            .items
                            .is_empty()
                    );
                    assert!(runner.history_before_collect().await);
                    assert_eq!(
                        runner
                            .history_pending
                            .as_ref()
                            .ok_or_else(unavailable)?
                            .batch,
                        original
                    );
                    live.source.reconcile_source().await?;
                    assert!(runner.history_before_collect().await);
                    assert!(runner.history_pending.is_none());
                    let delayed = handle
                        .page(Filter::Active, None, 16)
                        .map_err(|_| unavailable())?;
                    assert_eq!(delayed.items.len(), 1);
                    assert!(delayed.collection_error && !delayed.items[0].evidence_fresh);
                    assert_eq!(counts(&db(&live)?)?, (1, 1, 1));
                    assert_eq!(live.floor()?.sequence, "2");
                    runner
                        .accept_frame(observed(
                            &runner.node_id,
                            2,
                            Outcome::Failure("egress_failed"),
                        ))
                        .await?;
                    let fresh = handle
                        .page(Filter::Active, None, 16)
                        .map_err(|_| unavailable())?;
                    assert!(!fresh.collection_error && fresh.items[0].evidence_fresh);
                    assert_eq!(counts(&db(&live)?)?, (1, 1, 1));
                    assert_eq!(live.floor()?.sequence, "2");
                    assert_eq!(live.source.reader().revision()?, 1);
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)?;
            }
            Ok(())
        }

        #[tokio::test]
        async fn source_history_publication_error_does_not_roll_back_confirmed_sql_or_repeat_business()
        -> io::Result<()> {
            let live = live(Default::default()).await?;
            let result = async {
                let boot = URL_SAFE_NO_PAD.encode([4u8; 16]);
                let saved = boot.clone();
                let completed = Arc::new(AtomicUsize::new(0));
                let count = completed.clone();
                assert!(
                    live.source
                        .history_write_then(
                            move |w| w.start(&saved),
                            move |_| {
                                count.fetch_add(1, Ordering::AcqRel);
                                Err::<(), _>(unavailable())
                            }
                        )
                        .await
                        .is_err()
                );
                assert_eq!(completed.load(Ordering::Acquire), 1);
                assert_eq!(live.floor()?.sequence, "1");
                assert_eq!(live.source.reader().revision()?, 1);
                let count = completed.clone();
                let proof = live
                    .source
                    .history_write_then(
                        move |w| w.start(&boot),
                        move |value| {
                            count.fetch_add(1, Ordering::AcqRel);
                            Ok(value)
                        },
                    )
                    .await?;
                assert_eq!(proof.batch_sequence, 0);
                assert_eq!(completed.load(Ordering::Acquire), 2);
                assert_eq!(live.floor()?.sequence, "1");
                assert_eq!(counts(&db(&live)?)?, (0, 0, 0));
                Ok(())
            }
            .await;
            let closed = live.close().await;
            result.and(closed)
        }
    }

    fn observed(node: &str, sequence: u64, outcome: Outcome) -> Frame {
        Frame {
            facts: vec![Fact {
                key: Key {
                    kind: Kind::EgressCheck,
                    origin: node.to_owned(),
                    resource: Some(node.to_owned()),
                    slot: "bind".into(),
                },
                lineage: "stable-source".into(),
                stamp: sequence.to_string(),
                sequence: Some(sequence),
                check: Some(health::CheckKind::Bind),
                target: None,
                outcome,
            }],
            complete: BTreeSet::from([Kind::EgressCheck]),
            egress: Some(EgressCollection {
                completed: Instant::now(),
                observed_at: Some(sequence),
                error: false,
            }),
            ..Frame::default()
        }
    }

    fn connection(fixture: &Fixture) -> io::Result<rusqlite::Connection> {
        rusqlite::Connection::open(fixture.directory().join("management.sqlite3"))
            .map_err(io::Error::other)
    }

    fn counts(connection: &rusqlite::Connection) -> io::Result<(i64, i64, i64)> {
        connection.query_row("SELECT last_sequence,batch_sequence,(SELECT count(*) FROM alert_events) FROM alert_history_state WHERE singleton=1", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).map_err(io::Error::other)
    }

    #[test]
    fn events_follow_accepted_episodes_not_ticks_or_unknown_evidence() -> io::Result<()> {
        let node = "AAAAAAAAAAAAAAAAAAAAAA";
        let now = Instant::now();
        let mut state = State::new(node.into());
        let opened = state.apply_with_events(
            observed(node, 1, Outcome::Failure("egress_failed")),
            now,
            Some(1),
        )?;
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].kind, TransitionKind::Opened);
        for (sequence, outcome) in [
            (1, Outcome::Failure("egress_failed")),
            (2, Outcome::Failure("egress_failed")),
            (3, Outcome::Unknown),
            (2, Outcome::Success),
        ] {
            assert!(
                state
                    .apply_with_events(observed(node, sequence, outcome), now, Some(2))?
                    .is_empty()
            );
        }
        let changed = state.apply_with_events(
            observed(node, 4, Outcome::Failure("egress_timed_out")),
            now,
            Some(4),
        )?;
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].kind, TransitionKind::ReasonChanged);
        let recovered =
            state.apply_with_events(observed(node, 5, Outcome::Success), now, Some(5))?;
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].kind, TransitionKind::Recovered);
        assert_eq!(recovered[0].observation.code, "egress_timed_out");
        assert_eq!(
            recovered[0].observation.incident_id,
            opened[0].observation.incident_id
        );
        state.apply_with_events(
            observed(node, 6, Outcome::Failure("egress_failed")),
            now,
            Some(6),
        )?;
        let mut replacement = observed(node, 7, Outcome::Success);
        replacement.facts[0].lineage = "replacement".into();
        let ended = state.apply_with_events(replacement, now, Some(9))?;
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].kind, TransitionKind::Unmonitored);
        assert_eq!(ended[0].ended_reason, Some(EndReason::SourceUnmonitored));
        assert_eq!(ended[0].observed_at_unix_ms, Some(9));
        assert_eq!(ended[0].observation.last_observed_at_unix_ms, Some(6));
        Ok(())
    }

    #[tokio::test]
    async fn unchanged_evidence_and_legacy_mode_do_not_write_history() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (handle, mut runner) = fixture.runner(false, false)?;
        let db = connection(&fixture)?;
        db.execute_batch("CREATE TRIGGER forbid_history BEFORE UPDATE ON alert_history_state BEGIN SELECT RAISE(ABORT,'fixture'); END;").map_err(io::Error::other)?;
        runner
            .accept_frame(observed(
                &runner.node_id,
                1,
                Outcome::Failure("egress_failed"),
            ))
            .await?;
        assert_eq!(
            handle
                .page(Filter::Active, None, 16)
                .expect("RAM monitor")
                .active_count,
            1
        );
        assert_eq!(counts(&db)?, (0, 0, 0));
        db.execute_batch("DROP TRIGGER forbid_history;")
            .map_err(io::Error::other)?;
        let (_, mut durable) = fixture.runner(false, false)?;
        durable.enable_history();
        assert!(!durable.history_before_collect().await);
        durable
            .accept_frame(observed(
                &durable.node_id,
                1,
                Outcome::Failure("egress_failed"),
            ))
            .await?;
        assert_eq!(counts(&db)?, (1, 1, 1));
        db.execute_batch("CREATE TRIGGER forbid_history BEFORE UPDATE ON alert_history_state BEGIN SELECT RAISE(ABORT,'fixture'); END;").map_err(io::Error::other)?;
        durable
            .accept_frame(observed(
                &durable.node_id,
                2,
                Outcome::Failure("egress_failed"),
            ))
            .await?;
        assert!(durable.history_pending.is_none());
        assert_eq!(counts(&db)?, (1, 1, 1));
        assert!(
            durable.policy.reader().revision().is_ok(),
            "journal never fail-closes proxy policy"
        );
        Ok(())
    }

    #[tokio::test]
    async fn failed_batch_is_retained_and_delayed_confirmation_rebases_stale_pages()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (handle, mut runner) = fixture.runner(false, false)?;
        runner.enable_history();
        assert!(!runner.history_before_collect().await);
        runner
            .accept_frame(observed(
                &runner.node_id,
                1,
                Outcome::Failure("egress_failed"),
            ))
            .await?;
        let db = connection(&fixture)?;
        db.execute_batch("CREATE TRIGGER reject_transition BEFORE INSERT ON alert_events BEGIN SELECT RAISE(ABORT,'fixture'); END;").map_err(io::Error::other)?;
        runner
            .accept_frame(observed(
                &runner.node_id,
                2,
                Outcome::Failure("egress_timed_out"),
            ))
            .await?;
        let original = runner
            .history_pending
            .as_ref()
            .expect("original batch")
            .batch
            .clone();
        let failed = handle
            .page(Filter::Active, None, 16)
            .expect("failed persistence");
        let failed_egress = handle
            .egress_page(Filter::Active, None, 16)
            .expect("egress stale");
        assert!(failed.collection_error && !failed.items[0].evidence_fresh);
        assert_eq!(
            failed.items[0].code, "egress_failed",
            "uncommitted code is not published"
        );
        assert_eq!(counts(&db)?, (1, 1, 1));
        assert!(runner.history_before_collect().await);
        assert_eq!(
            runner.history_pending.as_ref().expect("same batch").batch,
            original
        );
        db.execute_batch("DROP TRIGGER reject_transition;")
            .map_err(io::Error::other)?;
        assert!(runner.history_before_collect().await);
        assert!(runner.history_pending.is_none());
        assert_eq!(counts(&db)?, (2, 2, 2));
        let confirmed = handle
            .page(Filter::Active, None, 16)
            .expect("confirmed delayed event");
        assert!(confirmed.collection_error && !confirmed.items[0].evidence_fresh);
        assert_eq!(confirmed.items[0].code, "egress_timed_out");
        assert!(
            confirmed.revision.parse::<u64>().expect("revision")
                > failed.revision.parse::<u64>().expect("old revision")
        );
        let cursor = format!("{}:{}:active:0", failed.boot_id, failed.revision);
        assert!(matches!(
            handle.page(Filter::Active, Some(&cursor), 16),
            Err(PageError::Changed)
        ));
        let cursor = format!(
            "{}:{}:egress-active:0",
            failed_egress.boot_id, failed_egress.revision
        );
        assert!(matches!(
            handle.egress_page(Filter::Active, Some(&cursor), 16),
            Err(PageError::Changed)
        ));
        runner
            .accept_frame(observed(
                &runner.node_id,
                2,
                Outcome::Failure("egress_timed_out"),
            ))
            .await?;
        let current = handle
            .page(Filter::Active, None, 16)
            .expect("new observation");
        assert!(!current.collection_error && current.items[0].evidence_fresh);
        assert_eq!(counts(&db)?, (2, 2, 2));
        assert!(runner.policy.reader().revision().is_ok());
        Ok(())
    }

    fn recovered_recent_is_valid(
        handle: &Handle,
        node: &str,
        collection_error: bool,
    ) -> io::Result<()> {
        let local = handle
            .page(Filter::Recent, None, 16)
            .expect("local terminal episode");
        assert_eq!(local.collection_error, collection_error);
        assert_eq!(local.items.len(), 1);
        assert_eq!(local.items[0].status, Status::Recovered);
        assert!(local.items[0].evidence_fresh);
        let egress = handle
            .egress_page(Filter::Recent, None, 16)
            .expect("egress terminal episode");
        assert_eq!(egress.collection_error, collection_error);
        assert!(egress.monitored);
        assert_eq!(egress.items.len(), 1);
        assert_eq!(egress.items[0].status, Status::Recovered);
        assert!(egress.items[0].evidence_fresh);
        let wire = serde_json::to_vec(&serde_json::json!({
            "version": 1, "resource": "proxy_policy", "node_id": node, "data": egress,
        }))?;
        let query = Query::parse(Some("state=recent&limit=16")).expect("fixed query");
        assert!(matches!(
            crate::manage::node::control::decode_egress_alerts_for_test(&query, &wire, node),
            Ok(crate::manage::node::control::Reply::EgressAlerts(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn journal_failure_does_not_rewrite_recovered_egress_evidence() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (_, owner) = fixture.runner(false, false)?;
        // A configured real monitor makes the egress projection covered. Its runner
        // is never started: accepted frames below supply the fixture's observations.
        let (health, _health_runner) = health::new(
            owner.policy.clone(),
            crate::connect::Connector::new(
                None,
                None,
                Some(crate::connect::Fallback::Address(
                    std::net::Ipv4Addr::LOCALHOST.into(),
                )),
                10,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                None,
                None,
            ),
            health::Config::default(),
        )?;
        let (handle, mut runner) = new(
            owner.policy.clone(),
            owner.node_id.clone(),
            Some(health),
            None,
            false,
            false,
            None,
            None,
        )?;
        runner.enable_history();
        assert!(!runner.history_before_collect().await);
        for (sequence, outcome) in [
            (1, Outcome::Failure("egress_failed")),
            (2, Outcome::Success),
        ] {
            runner
                .accept_frame(observed(&runner.node_id, sequence, outcome))
                .await?;
        }
        recovered_recent_is_valid(&handle, &runner.node_id, false)?;
        let db = connection(&fixture)?;
        assert_eq!(counts(&db)?, (2, 2, 2));
        db.execute_batch("CREATE TRIGGER reject_transition BEFORE INSERT ON alert_events BEGIN SELECT RAISE(ABORT,'fixture'); END;").map_err(io::Error::other)?;
        runner
            .accept_frame(Frame {
                facts: vec![Fact {
                    key: Key {
                        kind: Kind::Policy,
                        origin: runner.node_id.clone(),
                        resource: None,
                        slot: "policy".into(),
                    },
                    lineage: "fixture-policy".into(),
                    stamp: "1".into(),
                    sequence: Some(1),
                    check: None,
                    target: None,
                    outcome: Outcome::Failure("policy_not_applied"),
                }],
                complete: BTreeSet::from([Kind::Policy]),
                ..Frame::default()
            })
            .await?;
        assert!(runner.history_pending.is_some());
        assert_eq!(counts(&db)?, (2, 2, 2), "failed transaction rolled back");
        recovered_recent_is_valid(&handle, &runner.node_id, true)?;
        db.execute_batch("DROP TRIGGER reject_transition;")
            .map_err(io::Error::other)?;
        assert!(runner.history_before_collect().await);
        assert!(runner.history_pending.is_none());
        assert_eq!(counts(&db)?, (3, 3, 3));
        recovered_recent_is_valid(&handle, &runner.node_id, true)?;
        runner
            .accept_frame(observed(&runner.node_id, 3, Outcome::Success))
            .await?;
        recovered_recent_is_valid(&handle, &runner.node_id, false)?;
        assert_eq!(counts(&db)?, (3, 3, 3));
        Ok(())
    }

    #[tokio::test]
    async fn a_committed_lost_answer_is_confirmed_once_and_restart_is_not_recovery()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (handle, mut runner) = fixture.runner(false, false)?;
        runner.enable_history();
        assert!(!runner.history_before_collect().await);
        let prepared = runner
            .prepare_frame(observed(
                &runner.node_id,
                1,
                Outcome::Failure("egress_failed"),
            ))?
            .expect("one event");
        let batch = prepared.batch.clone();
        runner
            .policy
            .observations_write(move |directory, gate| history::record(directory, gate, &batch))
            .await?;
        assert_eq!(
            handle
                .page(Filter::Active, None, 16)
                .expect("before publication")
                .active_count,
            0
        );
        runner.history_pending = Some(prepared);
        assert!(runner.history_before_collect().await);
        let db = connection(&fixture)?;
        assert_eq!(counts(&db)?, (1, 1, 1));
        let confirmed = handle
            .page(Filter::Active, None, 16)
            .expect("exact confirmation");
        assert_eq!(confirmed.active_count, 1);
        assert!(!confirmed.items[0].evidence_fresh);
        let (new_handle, mut restarted) = fixture.runner(false, false)?;
        restarted.enable_history();
        assert!(!restarted.history_before_collect().await);
        let current = new_handle.page(Filter::Active, None, 16).expect("new boot");
        assert_eq!(current.active_count, 0);
        assert!(current.observed_at_unix_ms.is_none());
        let payload: Vec<u8> = db
            .query_row(
                "SELECT payload FROM alert_events WHERE sequence=2",
                [],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        let event: history::Event = serde_json::from_slice(&payload).map_err(io::Error::other)?;
        assert_eq!(event.kind, history::EventKind::Unmonitored);
        assert_eq!(event.ended_reason, Some(EndReason::MonitorRestarted));
        assert_ne!(event.boot_id, restarted.shared.boot_id);
        Ok(())
    }

    struct Release(Option<std::sync::mpsc::Sender<()>>);
    impl Drop for Release {
        fn drop(&mut self) {
            if let Some(release) = self.0.take() {
                let _ = release.send(());
            }
        }
    }

    #[tokio::test]
    async fn cancelled_waiter_does_not_cancel_owned_commit_and_publication() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (handle, mut runner) = fixture.runner(false, false)?;
        runner.enable_history();
        assert!(!runner.history_before_collect().await);
        let prepared = runner
            .prepare_frame(observed(
                &runner.node_id,
                1,
                Outcome::Failure("egress_failed"),
            ))?
            .expect("one event");
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let release = Release(Some(release));
        let (finished, completion) = tokio::sync::oneshot::channel();
        let shared = runner.shared.clone();
        let policy = runner.policy.clone();
        let task = tokio::spawn(async move {
            policy
                .observations_write(move |directory, gate| {
                    history::record(directory, gate, &prepared.batch)?;
                    let _ = started.send(());
                    wait.recv_timeout(Duration::from_secs(5))
                        .map_err(io::Error::other)?;
                    let result = prepared.publish(&shared, true);
                    let _ = finished.send(result.is_ok());
                    result
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), ready)
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        assert_eq!(
            handle
                .page(Filter::Active, None, 16)
                .expect("commit before publish")
                .active_count,
            0
        );
        task.abort();
        assert!(task.await.expect_err("caller cancelled").is_cancelled());
        drop(release);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), completion)
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)?
        );
        assert_eq!(
            handle
                .page(Filter::Active, None, 16)
                .expect("owned publication")
                .active_count,
            1
        );
        assert_eq!(counts(&connection(&fixture)?)?, (1, 1, 1));
        Ok(())
    }

    #[test]
    fn bounded_batch_and_exhausted_overlay_never_wrap_or_reuse_cursors() -> io::Result<()> {
        let node = "AAAAAAAAAAAAAAAAAAAAAA";
        let mut state = State::new(node.into());
        let event = state
            .apply_with_events(
                observed(node, 1, Outcome::Failure("egress_failed")),
                Instant::now(),
                None,
            )?
            .remove(0);
        let mut events = vec![event.clone(); MAX_TRANSITIONS];
        assert!(push(&mut events, event).is_err());
        assert_eq!(events.len(), MAX_TRANSITIONS);
        let fixture = Fixture::new()?;
        let (handle, mut runner) = fixture.runner(false, false)?;
        let current = runner.shared.snapshot()?;
        let mut exhausted = (*current).clone();
        exhausted.revision = u64::MAX;
        runner.shared.publish(&current, exhausted)?;
        runner.history_error(&unavailable());
        assert!(matches!(
            handle.page(Filter::Active, None, 16),
            Err(PageError::Unavailable)
        ));
        assert!(runner.policy.reader().revision().is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn exact_committed_foreign_transitions_remain_aligned_after_revoked_confirmation()
    -> io::Result<()> {
        use crate::manage::observations::Proof;
        fn id() -> io::Result<String> {
            let mut bytes = [0; 16];
            getrandom::fill(&mut bytes).map_err(|_| unavailable())?;
            Ok(URL_SAFE_NO_PAD.encode(bytes))
        }
        for recovered in [false, true] {
            let fixture = Fixture::new()?;
            let (handle, mut runner) = fixture.runner(false, false)?;
            runner.enable_history();
            assert!(!runner.history_before_collect().await);
            let db = connection(&fixture)?;
            let administrator: String = db
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)?;
            let peer = id()?;
            let boot = id()?;
            let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .map_err(io::Error::other)?;
            let leaf: Arc<[u8]> = Arc::from(certificate.cert.der().as_ref());
            store::register_peer(
                fixture.directory(),
                &peer,
                "source",
                &leaf,
                "localhost",
                None,
            )?;
            store::targets::configure(
                fixture.directory(),
                &administrator,
                &peer,
                None,
                "https://localhost:9443",
                true,
                None,
            )?;
            let proof = Arc::new(Proof {
                target_revision: 1,
                authorization: store::RemoteAuthorization {
                    node_id: peer.clone(),
                    authorization_revision: 1,
                    leaf,
                },
            });
            let binding = history::Binding {
                peer_id: peer.clone(),
                target_revision: 1,
                authorization_revision: 1,
                active: true,
                retired: false,
                rollback: false,
                peer_active: true,
            };
            let observed = |sequence: u64, outcome| Frame {
                facts: vec![Fact {
                    key: Key {
                        kind: Kind::Policy,
                        origin: peer.clone(),
                        resource: None,
                        slot: format!("source:{boot}:1"),
                    },
                    lineage: format!("1:1:{boot}:1"),
                    stamp: sequence.to_string(),
                    sequence: Some(sequence),
                    check: None,
                    target: None,
                    outcome,
                }],
                remote_complete: BTreeSet::from([peer.clone()]),
                remote_proofs: vec![proof.clone()],
                remote_bindings: vec![binding.clone()],
                ..Frame::default()
            };
            if recovered {
                runner
                    .accept_frame(observed(1, Outcome::Failure("proxy_not_running")))
                    .await?;
                assert!(runner.history_pending.is_none());
            }
            let sequence = if recovered { 2 } else { 1 };
            let outcome = if recovered {
                Outcome::Success
            } else {
                Outcome::Failure("proxy_not_running")
            };
            let prepared = runner
                .prepare_frame(observed(sequence, outcome))?
                .expect("one foreign transition");
            {
                let gate = store::update_lock(fixture.directory())?;
                history::record_guarded(
                    fixture.directory(),
                    &gate,
                    &prepared.batch,
                    &prepared.proofs,
                    &prepared.bindings,
                )?;
            }
            // The SQL commit was authorized, but its answer/publication was lost.
            // Revocation cannot turn that historical recovery back into Active RAM.
            store::set_peer_active(fixture.directory(), &peer, 1, false)?;
            runner.history_pending = Some(prepared);
            assert!(runner.history_before_collect().await);
            assert!(runner.history_pending.is_none());
            let state = runner.shared.snapshot()?;
            assert!(state.collection_error);
            assert!(state.active.values().all(|incident| !incident.fresh));
            if recovered {
                assert!(state.active.is_empty());
                assert_eq!(state.recent.back().unwrap().status, Status::Recovered);
            } else {
                assert_eq!(state.active.len(), 1);
            }
            let retired = history::Binding {
                authorization_revision: 2,
                peer_active: false,
                ..binding
            };
            runner
                .accept_frame(Frame {
                    remote_complete: BTreeSet::from([peer.clone()]),
                    remote_bindings: vec![retired],
                    ..Frame::default()
                })
                .await?;
            assert!(
                runner.history_pending.is_none(),
                "no conflict with the confirmed SQL terminal"
            );
            assert_eq!(
                handle.page(Filter::Active, None, 16).unwrap().active_count,
                0
            );
            let status: String = db
                .query_row("SELECT status FROM alert_episodes WHERE id=1", [], |row| {
                    row.get(0)
                })
                .map_err(io::Error::other)?;
            assert_eq!(
                status,
                if recovered {
                    "recovered"
                } else {
                    "unmonitored"
                }
            );
            history::validate_snapshot(&db)?;
        }
        Ok(())
    }
}
