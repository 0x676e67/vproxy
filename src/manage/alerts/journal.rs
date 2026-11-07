//! A single retained observation batch, not an independent queue or service.
//! Only confirmed transactions publish incident changes. Failure retains prior
//! evidence and never closes the management listener.

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
    directory: &std::path::Path,
    gate: &crate::manage::store::UpdateGuard,
    prepared: &Prepared,
    confirm_first: bool,
) -> io::Result<Persistence> {
    if prepared.batch.transitions.is_empty() {
        return match history::publish_guarded(
            directory,
            gate,
            &prepared.proofs,
            &prepared.bindings,
            || Ok(()),
        ) {
            Ok(()) => Ok(Persistence::Publish {
                commit: None,
                remote_current: true,
            }),
            Err(error) if changed(&error) => Ok(Persistence::Discard),
            Err(error) => Err(error),
        };
    }
    let receipt = if confirm_first {
        history::receipt(directory, &prepared.batch)?
    } else {
        None
    };
    let (commit, remote_current) = match receipt {
        Some(commit) => {
            let current = if prepared.bindings.is_empty() {
                Ok(())
            } else {
                history::publish_guarded(
                    directory,
                    gate,
                    &prepared.proofs,
                    &prepared.bindings,
                    || Ok(()),
                )
            };
            match current {
                Ok(()) => (commit, true),
                Err(error) if changed(&error) => (commit, false),
                Err(error) => return Err(error),
            }
        }
        None => {
            let result = if prepared.bindings.is_empty() {
                history::record(directory, gate, &prepared.batch)
            } else {
                history::record_guarded(
                    directory,
                    gate,
                    &prepared.batch,
                    &prepared.proofs,
                    &prepared.bindings,
                )
            };
            match result {
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
                .store_write(move |dir, gate| history::start(dir, gate, &boot))
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
                move |dir, gate| persist(dir, gate, &prepared, confirm_first),
                move |outcome| match outcome {
                    Persistence::Discard => Ok((None, false)),
                    Persistence::Publish {
                        commit,
                        remote_current,
                    } => {
                        // This is a post-commit response/publication check. It
                        // cannot roll the committed transaction back.
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
            .store_write(move |directory, gate| history::record(directory, gate, &batch))
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
}
