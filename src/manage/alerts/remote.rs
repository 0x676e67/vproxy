//! Cold projection of authenticated bounded snapshots into this observer's
//! existing state machine. It never performs network or SQLite work.

use super::*;
use crate::manage::{
    observations,
    store::alerts::{Target, history::Binding},
};

const SELF_CODES: &[&str] = &[
    "egress_address_unavailable",
    "egress_connection_refused",
    "egress_timed_out",
    "egress_permission_denied",
    "egress_network_unreachable",
    "egress_failed",
    "egress_family_mismatch",
    "health_catalog_unavailable",
    "health_catalog_stale",
    "https_identity_unavailable",
    "https_identity_expiring",
    "https_identity_expired",
    "https_identity_not_yet_valid",
    "https_identity_metadata_unavailable",
    "acme_attempt_unavailable",
    "acme_review_required",
    "acme_worker_stopped",
    "node_tls_identity_unavailable",
    "node_tls_identity_expiring",
    "node_tls_identity_expired",
    "node_tls_identity_not_yet_valid",
    "node_tls_identity_metadata_unavailable",
    "proxy_tls_identity_unavailable",
    "proxy_tls_identity_expiring",
    "proxy_tls_identity_expired",
    "proxy_tls_identity_not_yet_valid",
    "proxy_tls_identity_metadata_unavailable",
    "proxy_not_running",
    "policy_publication_unavailable",
    "policy_not_applied",
    "proxy_drain_failed",
    "proxy_drain_interrupted",
    "traffic_checkpoint_failed",
    "traffic_checkpoint_stale",
    "traffic_loss_possible",
    "traffic_history_gap",
    "traffic_time_uncertain",
];

impl Runner {
    /// Enable only after startup has required schema22 and the configured node
    /// controller. Existing/legacy monitors keep their original behavior.
    pub(in crate::manage) fn enable_remote_observation(&mut self, handle: observations::Handle) {
        self.observations = Some(handle);
        self.shared
            .remote_observation
            .store(true, Ordering::Release);
    }

    pub(super) fn remote_observation_facts(
        &self,
        frame: &mut Frame,
        targets: &[Target],
        now: Instant,
    ) {
        let Some(handle) = &self.observations else {
            return;
        };
        let snapshot = match handle.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                frame.fail(collect::Failure::RemoteObservation(error.kind()));
                return;
            }
        };
        let sources = snapshot
            .sources
            .iter()
            .map(|source| (source.peer_id.as_str(), source))
            .collect::<BTreeMap<_, _>>();
        frame.complete.insert(Kind::RemoteObservation);
        for target in targets {
            if target.id == self.node_id {
                frame.fail(collect::Failure::RemoteInvalid);
                continue;
            }
            frame.remote_bindings.push(Binding {
                peer_id: target.id.clone(),
                target_revision: target.revision,
                authorization_revision: target.authorization_revision,
                active: target.active,
                retired: target.retired,
                rollback: target.rollback,
                peer_active: target.peer_active,
            });
            if !target.active || target.retired || !target.peer_active {
                frame.remote_complete.insert(target.id.clone());
                continue;
            }
            let source = sources.get(target.id.as_str()).copied();
            let mut failure = source.and_then(|source| source.failure);
            let observation = source.and_then(|source| source.observation.as_deref());
            if target.rollback
                || source.is_some_and(|source| source.target_revision != target.revision)
                || observation.is_some_and(|observation| {
                    observation.proof.target_revision != target.revision
                        || observation.proof.authorization.authorization_revision
                            != target.authorization_revision
                        || observation.proof.authorization.node_id != target.id
                })
            {
                failure = Some(observations::Failure::Changed);
            }
            if failure.is_none() {
                failure = match observation {
                    None => Some(observations::Failure::Pending),
                    Some(observation) if observation.collection_error => {
                        Some(observations::Failure::Incomplete)
                    }
                    Some(observation) if !observation.complete(now.into_std()) => {
                        Some(if observation.dropped != 0 {
                            observations::Failure::Incomplete
                        } else {
                            observations::Failure::Stale
                        })
                    }
                    Some(_) => None,
                };
                if failure.is_none() && observation.is_some_and(|value| value.dropped != 0) {
                    failure = Some(observations::Failure::Incomplete);
                }
            }
            // A new source has no failure episode yet. Its missing first
            // observation still makes aggregate zero counts unconfirmed.
            if failure == Some(observations::Failure::Pending) {
                frame.error = true;
            }
            frame.facts.push(Fact {
                key: collect::key(Kind::RemoteObservation, &target.id, None, "operations"),
                lineage: format!("{}:{}", target.revision, target.authorization_revision),
                stamp: format!(
                    "{}:{}",
                    source.map_or(0, |source| source.sequence),
                    failure.map_or("ready", observations::Failure::code)
                ),
                sequence: None,
                check: None,
                target: None,
                outcome: match failure {
                    Some(observations::Failure::Pending) => Outcome::Unknown,
                    Some(failure) => Outcome::Failure(failure.code()),
                    None => Outcome::Success,
                },
            });
            let import_allowed = failure.is_none()
                || failure == Some(observations::Failure::Incomplete)
                    && observation.is_some_and(|value| value.complete(now.into_std()));
            if !import_allowed {
                continue;
            }
            let Some(observation) = observation else {
                continue;
            };
            let mut facts = Vec::with_capacity(observation.active.len() + observation.recent.len());
            let valid = observation
                .active
                .iter()
                .chain(&observation.recent)
                .all(|item| {
                    let Some(code) = SELF_CODES.iter().copied().find(|code| *code == item.code)
                    else {
                        return false;
                    };
                    let id = item
                        .id
                        .parse::<u64>()
                        .ok()
                        .filter(|id| *id > 0 && id.to_string() == item.id);
                    if id.is_none()
                        || item.origin_node_id != target.id
                        || matches!(
                            item.kind,
                            Kind::RemoteTraffic | Kind::RemoteJob | Kind::RemoteObservation
                        )
                    {
                        return false;
                    }
                    // Explicit Unmonitored is represented by absence from this
                    // complete set, never translated to a healthy observation.
                    if item.status == Status::Unmonitored {
                        return true;
                    }
                    let sequence = item
                        .evidence_sequence
                        .as_deref()
                        .and_then(|value| value.parse::<u64>().ok())
                        .filter(|sequence| *sequence > 0);
                    // Item age measures the last distinct evidence, not the
                    // source monitor's latest confirmation. A still-loaded
                    // expiring certificate can keep the same sequence for
                    // days. The complete snapshot's monotonic age already
                    // bounds transport/collection freshness; retain the
                    // producer's per-item freshness and sequence separately.
                    let fresh = sequence.is_some() && item.evidence_fresh;
                    facts.push(Fact {
                        key: collect::key(
                            item.kind,
                            &target.id,
                            item.resource_id.as_deref(),
                            &format!("source:{}:{}", observation.boot_id, item.id),
                        ),
                        lineage: format!(
                            "{}:{}:{}:{}",
                            target.revision,
                            target.authorization_revision,
                            observation.boot_id,
                            item.id
                        ),
                        stamp: format!(
                            "{}:{}:{}",
                            item.evidence_sequence.as_deref().unwrap_or("none"),
                            item.code,
                            if item.status == Status::Active {
                                "active"
                            } else {
                                "recovered"
                            }
                        ),
                        sequence,
                        check: item.check,
                        target: item.target,
                        outcome: if !fresh {
                            Outcome::Unknown
                        } else if item.status == Status::Active {
                            Outcome::Failure(code)
                        } else {
                            Outcome::Success
                        },
                    });
                    true
                });
            if valid {
                frame.remote_complete.insert(target.id.clone());
                frame.remote_proofs.push(observation.proof.clone());
                frame.facts.extend(facts);
            } else {
                if let Some(diagnostic) = frame.facts.last_mut() {
                    diagnostic.outcome = Outcome::Unknown;
                }
                frame.fail(collect::Failure::RemoteInvalid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::{alerts::tests::Fixture, store};

    const LOCAL: &str = "AAAAAAAAAAAAAAAAAAAAAA";
    const PEER: &str = "AQEBAQEBAQEBAQEBAQEBAQ";
    const OTHER: &str = "AgICAgICAgICAgICAgICAg";
    const BOOT: &str = "AwMDAwMDAwMDAwMDAwMDAw";

    fn fact(origin: &str, id: u64, sequence: u64, outcome: Outcome) -> Fact {
        Fact {
            key: Key {
                kind: Kind::Policy,
                origin: origin.into(),
                resource: None,
                slot: format!("source:{BOOT}:{id}"),
            },
            lineage: format!("1:1:{BOOT}:{id}"),
            stamp: sequence.to_string(),
            sequence: Some(sequence),
            check: None,
            target: None,
            outcome,
        }
    }

    fn frame(facts: Vec<Fact>, peers: &[&str]) -> Frame {
        Frame {
            facts,
            remote_complete: peers.iter().map(|peer| (*peer).to_owned()).collect(),
            ..Frame::default()
        }
    }

    #[test]
    fn peer_completeness_and_explicit_source_evidence_do_not_retire_unread_origins()
    -> io::Result<()> {
        let now = Instant::now();
        let mut state = State::new(LOCAL.into());
        state.apply(
            frame(
                vec![
                    fact(PEER, 1, 1, Outcome::Failure("proxy_not_running")),
                    fact(OTHER, 1, 1, Outcome::Failure("proxy_not_running")),
                ],
                &[PEER, OTHER],
            ),
            now,
            Some(1),
        )?;
        state.apply(
            frame(vec![fact(PEER, 1, 2, Outcome::Success)], &[PEER]),
            now,
            Some(2),
        )?;
        assert_eq!(state.active.len(), 1);
        assert_eq!(state.active.values().next().unwrap().key.origin, OTHER);
        assert!(!state.active.values().next().unwrap().fresh);
        assert_eq!(state.recent.back().unwrap().status, Status::Recovered);
        state.apply(frame(vec![], &[OTHER]), now, Some(3))?;
        assert!(state.active.is_empty());
        assert_eq!(state.recent.back().unwrap().status, Status::Unmonitored);
        Ok(())
    }

    #[test]
    fn source_replacement_and_unknown_sequence_cannot_prove_recovery() -> io::Result<()> {
        let now = Instant::now();
        let mut state = State::new(LOCAL.into());
        state.apply(
            frame(
                vec![fact(PEER, 1, 4, Outcome::Failure("proxy_not_running"))],
                &[PEER],
            ),
            now,
            None,
        )?;
        let mut unknown = fact(PEER, 1, 5, Outcome::Unknown);
        unknown.sequence = None;
        state.apply(frame(vec![unknown], &[PEER]), now, None)?;
        assert_eq!(state.active.len(), 1);
        assert!(state.recent.is_empty());
        let mut replaced = fact(PEER, 1, 6, Outcome::Success);
        replaced.lineage = "new-authorized-source".into();
        state.apply(frame(vec![replaced], &[PEER]), now, None)?;
        assert!(state.active.is_empty());
        assert_eq!(state.recent.back().unwrap().status, Status::Unmonitored);
        Ok(())
    }

    #[test]
    fn mirrored_capacity_preserves_local_budget_and_old_foreign_evidence() -> io::Result<()> {
        let now = Instant::now();
        let mut state = State::new(LOCAL.into());
        let remote = (1..=MAX_REMOTE as u64)
            .map(|id| fact(PEER, id, 1, Outcome::Failure("proxy_not_running")))
            .collect();
        state.apply(frame(remote, &[PEER]), now, None)?;
        let mut local = Vec::with_capacity(MAX_ACTIVE);
        for id in 0..MAX_ACTIVE {
            let mut item = fact(LOCAL, id as u64 + 1, 1, Outcome::Failure("egress_failed"));
            item.key.kind = Kind::EgressCheck;
            item.key.slot = format!("local:{id}");
            local.push(item);
        }
        state.apply(
            Frame {
                facts: local,
                complete: BTreeSet::from([Kind::EgressCheck]),
                ..Frame::default()
            },
            now,
            None,
        )?;
        assert_eq!(state.active.len(), MAX_ACTIVE + MAX_REMOTE);
        let over = (1..=MAX_REMOTE as u64 + 1)
            .map(|id| fact(PEER, id, 2, Outcome::Failure("proxy_not_running")))
            .collect();
        state.apply(frame(over, &[PEER]), now, None)?;
        assert_eq!(state.active.len(), MAX_ACTIVE + MAX_REMOTE);
        assert!(state.collection_error);
        assert!(
            state
                .active
                .values()
                .filter(|incident| incident.key.origin == PEER)
                .all(|incident| !incident.fresh)
        );
        assert!(state.recent.is_empty());
        Ok(())
    }

    #[test]
    fn atomic_self_snapshot_excludes_mirrors_and_refuses_truncation() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (handle, runner) = fixture.runner(false, false)?;
        let mut facts = vec![fact(PEER, 1, 1, Outcome::Failure("proxy_not_running"))];
        for id in 0..256 {
            let mut item = fact(
                &runner.node_id,
                id + 1,
                1,
                Outcome::Failure("egress_failed"),
            );
            item.key.kind = Kind::EgressCheck;
            item.key.slot = format!("bind:{id}");
            facts.push(item);
        }
        runner.shared.apply(
            Frame {
                facts,
                ..Frame::default()
            },
            Instant::now(),
            Some(1),
        )?;
        let snapshot = handle.node_snapshot().map_err(|_| unavailable())?;
        assert_eq!(snapshot.active_count, 256);
        assert_eq!(snapshot.active.len(), 256);
        assert!(
            snapshot
                .active
                .iter()
                .all(|item| item.origin_node_id == runner.node_id)
        );
        let mut extra = fact(&runner.node_id, 257, 1, Outcome::Failure("egress_failed"));
        extra.key.kind = Kind::EgressCheck;
        extra.key.slot = "bind:256".into();
        runner.shared.apply(
            Frame {
                facts: vec![extra],
                ..Frame::default()
            },
            Instant::now(),
            Some(2),
        )?;
        assert!(matches!(
            handle.node_snapshot(),
            Err(SnapshotError::Capacity)
        ));
        assert!(handle.node_page(Filter::Active, None, 16).is_ok());
        Ok(())
    }

    #[test]
    fn fresh_snapshot_confirms_old_distinct_evidence_but_not_pending_or_unknown_items()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (_, mut runner) = fixture.runner(false, false)?;
        let cache = observations::Handle::default();
        let directory = store::targets::Target {
            peer_id: PEER.into(),
            name: "projection source".into(),
            origin: "https://localhost:9443".into(),
            server_ip: None,
            active: true,
            retired: false,
            revision: 1,
            observed_epoch: None,
            observed_command: None,
            observed_policy_revision: None,
            rollback_detected: false,
        };
        let targets = [Target {
            id: PEER.into(),
            revision: 1,
            active: true,
            retired: false,
            rollback: false,
            peer_active: true,
            authorization_revision: 1,
            source_authorization_revision: None,
            source_target_revision: None,
            last_success_at: None,
            meter_epoch: None,
            cursor: None,
            source_error: None,
            quarantined: false,
            job_id: None,
            job_state: None,
            job_attempts: None,
        }];
        cache.reconcile(&[directory])?;
        runner.enable_remote_observation(cache.clone());
        // Cache input is already decoded/verified by its caller. This fixture
        // exercises projection freshness, not TLS or SQL commit authorization.
        let proof = || observations::Proof {
            target_revision: 1,
            authorization: store::RemoteAuthorization {
                node_id: PEER.into(),
                authorization_revision: 1,
                leaf: Arc::from([1_u8]),
            },
        };
        let item = |id: u64, status, sequence: Option<u64>, fresh| Alert {
            id: id.to_string(),
            kind: Kind::Policy,
            origin_node_id: PEER.into(),
            resource_id: None,
            check: None,
            target: None,
            status,
            code: "proxy_not_running".into(),
            first_observed_at_unix_ms: Some("1".into()),
            last_observed_at_unix_ms: Some("2".into()),
            ended_at_unix_ms: (status != Status::Active).then(|| "3".into()),
            age_millis: 86_400_000_u64.to_string(),
            evidence_sequence: sequence.map(|value| value.to_string()),
            evidence_fresh: fresh,
        };
        let snapshot = |revision: u64, active: Vec<Alert>, recent: Vec<Alert>| NodeSnapshot {
            node_id: PEER.into(),
            boot_id: BOOT.into(),
            revision: revision.to_string(),
            observed_at_unix_ms: Some("4".into()),
            age_millis: Some("0".into()),
            collection_error: false,
            coverage: LocalCoverage {
                local_egress: false,
                local_traffic: false,
                local_proxy_expected: true,
                local_management_https: false,
                local_node_tls: false,
                local_proxy_tls: false,
            },
            active_count: active.len() as u32,
            recent_count: recent.len() as u32,
            dropped: "0".into(),
            active,
            recent,
        };
        let now = Instant::now();
        let project = || {
            let mut frame = Frame::default();
            runner.remote_observation_facts(&mut frame, &targets, now);
            frame
        };
        let mut state = State::new(runner.node_id.clone());
        let pending = project();
        assert!(
            pending.error,
            "a target without its first sample is incomplete"
        );
        assert!(
            pending
                .facts
                .iter()
                .all(|fact| matches!(fact.outcome, Outcome::Unknown))
        );
        state.apply(pending, now, None)?;
        assert!(state.collection_error);
        assert!(state.active.is_empty() && state.recent.is_empty());

        cache.accept(
            proof(),
            snapshot(1, vec![item(1, Status::Active, Some(1), true)], vec![]),
            now.into_std(),
        )?;
        let ready = project();
        assert!(!ready.error);
        assert!(ready.facts.iter().any(|fact| fact.key.kind == Kind::Policy
            && matches!(fact.outcome, Outcome::Failure("proxy_not_running"))));
        state.apply(ready, now, None)?;
        assert!(!state.collection_error);
        assert_eq!(state.active.len(), 1);
        assert!(state.active.values().all(|incident| incident.fresh));

        for (revision, sequence, fresh) in [(2, Some(2), false), (3, None, true)] {
            cache.accept(
                proof(),
                snapshot(
                    revision,
                    vec![item(2, Status::Active, sequence, fresh)],
                    vec![item(1, Status::Recovered, sequence, fresh)],
                ),
                now.into_std(),
            )?;
            let unknown = project();
            assert!(
                unknown
                    .facts
                    .iter()
                    .filter(|fact| fact.key.kind == Kind::Policy)
                    .all(|fact| matches!(fact.outcome, Outcome::Unknown))
            );
            state.apply(unknown, now, None)?;
            assert_eq!(
                state.active.len(),
                1,
                "unknown cannot open item2 or recover item1"
            );
            assert!(state.active.values().all(|incident| !incident.fresh));
            assert!(state.recent.is_empty());
        }

        let old = now
            .into_std()
            .checked_sub(Duration::from_secs(180))
            .ok_or_else(unavailable)?;
        cache.accept(
            proof(),
            snapshot(
                4,
                vec![item(3, Status::Active, Some(3), true)],
                vec![item(1, Status::Recovered, Some(3), true)],
            ),
            old,
        )?;
        let stale = project();
        assert!(!stale.facts.iter().any(|fact| fact.key.kind == Kind::Policy));
        assert!(stale.remote_complete.is_empty());
        state.apply(stale, now, None)?;
        assert_eq!(
            state
                .active
                .values()
                .filter(|incident| incident.key.kind == Kind::Policy)
                .count(),
            1
        );
        assert!(
            state
                .active
                .values()
                .filter(|incident| incident.key.kind == Kind::Policy)
                .all(|incident| !incident.fresh)
        );
        assert!(
            state.recent.is_empty(),
            "transport-stale recovery is not evidence"
        );
        Ok(())
    }
}
