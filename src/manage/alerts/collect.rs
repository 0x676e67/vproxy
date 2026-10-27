//! Concrete projections of existing observations. Each source keeps its own
//! freshness and identity rules; no projection starts probes or remote work.

use super::*;
use crate::manage::{
    policy::{ReadAdmission, ReadStage},
    store,
};

const CHECKPOINT_STALE: u64 = 30_000;
const REMOTE_STALE: u64 = 90_000;
const POLICY_GRACE: Duration = Duration::from_secs(15);
// Local warning policy, not an ACME/RFC lifetime requirement or retry timer.
const HTTPS_EXPIRY_WARNING: u64 = 7 * 24 * 60 * 60;

/// Allowlisted causes for local logs, independent of incidents and wire data.
/// Only an error's kind is retained: messages can contain paths or identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Failure {
    Policy(ReadStage, io::ErrorKind),
    Runtime(io::ErrorKind),
    Health(io::ErrorKind),
    Traffic(io::ErrorKind),
    TrafficUnavailable,
    ManagementHttps(io::ErrorKind),
    HttpsSequenceExhausted,
    WallClockUnavailable,
    Certificates(io::ErrorKind),
    CertificateMetadataUnavailable,
    CertificateSequenceExhausted,
    CertificateInventoryInvalid,
    RemoteObservation(io::ErrorKind),
    RemoteCapacity,
    RemoteInvalid,
}

impl Frame {
    pub(super) fn fail(&mut self, failure: Failure) {
        self.error = true;
        self.failures.push(failure);
    }
}

pub(super) struct RemoteClock {
    last_success: Option<u64>,
    captured: Instant,
    initial_age: Option<u64>,
}

/// One bounded, process-local clock per configured certificate identity. A
/// missing descriptor never becomes a replacement fingerprint. Metadata has a
/// separate transition counter so its recovery cannot clear an expiry episode.
#[derive(Default)]
pub(super) struct CertificateClock {
    fingerprint: Option<String>,
    generation: u64,
    metadata_unavailable: Option<bool>,
    metadata_sequence: u64,
}

struct CertificateEvidence {
    stamp: String,
    sequence: Option<u64>,
    outcome: Outcome,
    metadata_sequence: u64,
    metadata_unavailable: bool,
}

impl CertificateClock {
    #[cfg(test)]
    pub(super) fn exhausted() -> Self {
        Self {
            generation: u64::MAX,
            ..Self::default()
        }
    }

    /// Advance only an actual fingerprint change or metadata transition. A
    /// certificate's time phases advance from not-yet-valid through valid and
    /// expiring to expired. State::apply rejects rollback to an earlier phase.
    fn observe(
        &mut self,
        state: &certificates::State,
        wall: Option<i64>,
    ) -> Option<CertificateEvidence> {
        let unavailable = matches!(state, certificates::State::Unavailable);
        let metadata_sequence = if self.metadata_unavailable == Some(unavailable) {
            self.metadata_sequence
        } else {
            self.metadata_sequence.checked_add(1)?
        };
        let changed = match state {
            certificates::State::Loaded(leaf) => {
                self.fingerprint.as_deref() != Some(leaf.sha256.as_str())
            }
            _ => false,
        };
        let generation = if changed {
            self.generation.checked_add(1)?
        } else {
            self.generation
        };
        let (bucket, outcome) = match state {
            certificates::State::Loaded(leaf) => match wall {
                Some(now) if now < leaf.not_before_unix_s => {
                    (Some(0), Outcome::Failure("not_yet_valid"))
                }
                Some(now) if now > leaf.not_after_unix_s => (Some(3), Outcome::Failure("expired")),
                Some(now)
                    if i128::from(leaf.not_after_unix_s) - i128::from(now)
                        <= i128::from(HTTPS_EXPIRY_WARNING) =>
                {
                    (Some(2), Outcome::Failure("expiring"))
                }
                Some(_) => (Some(1), Outcome::Success),
                None => (None, Outcome::Unknown),
            },
            certificates::State::Pending => (Some(4), Outcome::Failure("unavailable")),
            certificates::State::Unavailable | certificates::State::Disabled => {
                (None, Outcome::Unknown)
            }
        };
        // Reserve the entire bucket range before changing any clock field.
        // Even an unknown wall clock cannot authorize a wrapped generation.
        let base = generation.checked_mul(5)?;
        base.checked_add(4)?;
        let sequence = bucket.and_then(|bucket| base.checked_add(bucket));
        let stamp = bucket.map_or_else(String::new, |bucket| format!("{generation}:{bucket}"));
        self.metadata_sequence = metadata_sequence;
        self.metadata_unavailable = Some(unavailable);
        self.generation = generation;
        if changed && let certificates::State::Loaded(leaf) = state {
            self.fingerprint = Some(leaf.sha256.clone());
        }
        Some(CertificateEvidence {
            stamp,
            sequence,
            outcome,
            metadata_sequence,
            metadata_unavailable: unavailable,
        })
    }
}

fn certificate_key(node: &str, entry: &certificates::Entry, slot: &str) -> Key {
    let kind = match entry.role {
        certificates::Role::Management => Kind::ManagementHttps,
        certificates::Role::Node => Kind::NodeTls,
        certificates::Role::Proxy => Kind::ProxyTls,
    };
    key(kind, node, entry.id.as_deref(), slot)
}

/// Translate only local reason labels; no descriptor bytes, names, paths or
/// arbitrary producer text enter the public incident or collection log.
fn certificate_code(role: certificates::Role, reason: &'static str) -> &'static str {
    match (role, reason) {
        (certificates::Role::Management, "metadata") => "https_identity_metadata_unavailable",
        (certificates::Role::Management, "expiring") => "https_identity_expiring",
        (certificates::Role::Management, "expired") => "https_identity_expired",
        (certificates::Role::Management, "not_yet_valid") => "https_identity_not_yet_valid",
        (certificates::Role::Management, _) => "https_identity_unavailable",
        (certificates::Role::Node, "metadata") => "node_tls_identity_metadata_unavailable",
        (certificates::Role::Node, "expiring") => "node_tls_identity_expiring",
        (certificates::Role::Node, "expired") => "node_tls_identity_expired",
        (certificates::Role::Node, "not_yet_valid") => "node_tls_identity_not_yet_valid",
        (certificates::Role::Node, _) => "node_tls_identity_unavailable",
        (certificates::Role::Proxy, "metadata") => "proxy_tls_identity_metadata_unavailable",
        (certificates::Role::Proxy, "expiring") => "proxy_tls_identity_expiring",
        (certificates::Role::Proxy, "expired") => "proxy_tls_identity_expired",
        (certificates::Role::Proxy, "not_yet_valid") => "proxy_tls_identity_not_yet_valid",
        (certificates::Role::Proxy, _) => "proxy_tls_identity_unavailable",
    }
}

impl Runner {
    fn certificate_facts(&mut self, frame: &mut Frame, acme_complete: bool) {
        let Some(handle) = &self.certificates else {
            return;
        };
        match handle.snapshot() {
            Ok(snapshot) => self.certificate_snapshot_facts(frame, snapshot, acme_complete),
            Err(error) => frame.fail(Failure::Certificates(error.kind())),
        }
    }

    /// Validate the complete bounded inventory before touching clocks. Failed
    /// snapshots keep every previous TLS key stale only in freshness,
    /// never retire or recover it. Disabled entries alone explicitly leave scope.
    pub(super) fn certificate_snapshot_facts(
        &mut self,
        frame: &mut Frame,
        snapshot: certificates::Snapshot,
        acme_complete: bool,
    ) {
        let mut management = 0;
        let mut node = 0;
        let mut all = BTreeSet::new();
        let mut live = BTreeSet::new();
        if snapshot.node_id != self.node_id || snapshot.entries.len() > certificates::MAX_PROXY + 2
        {
            frame.fail(Failure::CertificateInventoryInvalid);
            return;
        }
        for entry in &snapshot.entries {
            let valid = match entry.role {
                certificates::Role::Management => {
                    management += 1;
                    entry.id.is_none() && entry.protocol.is_none()
                }
                certificates::Role::Node => {
                    node += 1;
                    entry.id.is_none() && entry.protocol.is_none()
                }
                certificates::Role::Proxy => {
                    entry.id.as_deref().is_some_and(store::valid_id) && entry.protocol.is_some()
                }
            };
            let key = certificate_key(&self.node_id, entry, "certificate");
            if !valid || !all.insert(key.clone()) {
                frame.fail(Failure::CertificateInventoryInvalid);
                return;
            }
            if !matches!(entry.state, certificates::State::Disabled) {
                live.insert(key);
            }
        }
        if management != 1 || node != 1 {
            frame.fail(Failure::CertificateInventoryInvalid);
            return;
        }
        self.certificate_clocks.retain(|key, _| live.contains(key));
        if acme_complete {
            frame.complete.insert(Kind::ManagementHttps);
        }
        frame.complete.extend([Kind::NodeTls, Kind::ProxyTls]);
        if snapshot.observed_at_unix_s.is_none()
            && snapshot
                .entries
                .iter()
                .any(|entry| matches!(entry.state, certificates::State::Loaded(_)))
        {
            frame.fail(Failure::WallClockUnavailable);
        }
        for entry in snapshot.entries {
            if matches!(entry.state, certificates::State::Disabled) {
                continue;
            }
            let key = certificate_key(&self.node_id, &entry, "certificate");
            let observed = self
                .certificate_clocks
                .entry(key.clone())
                .or_default()
                .observe(&entry.state, snapshot.observed_at_unix_s);
            let Some(observed) = observed else {
                frame.fail(Failure::CertificateSequenceExhausted);
                for slot in ["certificate", "metadata"] {
                    frame.facts.push(Fact {
                        key: certificate_key(&self.node_id, &entry, slot),
                        lineage: self.shared.boot_id.clone(),
                        stamp: String::new(),
                        sequence: None,
                        check: None,
                        target: None,
                        outcome: Outcome::Unknown,
                    });
                }
                continue;
            };
            if observed.metadata_unavailable
                && !frame
                    .failures
                    .contains(&Failure::CertificateMetadataUnavailable)
            {
                frame.fail(Failure::CertificateMetadataUnavailable);
            }
            frame.facts.push(Fact {
                key,
                lineage: self.shared.boot_id.clone(),
                stamp: observed.stamp,
                sequence: observed.sequence,
                check: None,
                target: None,
                outcome: match observed.outcome {
                    Outcome::Failure(reason) => {
                        Outcome::Failure(certificate_code(entry.role, reason))
                    }
                    other => other,
                },
            });
            frame.facts.push(Fact {
                key: certificate_key(&self.node_id, &entry, "metadata"),
                lineage: self.shared.boot_id.clone(),
                stamp: observed.metadata_sequence.to_string(),
                sequence: Some(observed.metadata_sequence),
                check: None,
                target: None,
                outcome: if observed.metadata_unavailable {
                    Outcome::Failure(certificate_code(entry.role, "metadata"))
                } else {
                    Outcome::Success
                },
            });
        }
    }

    pub(super) async fn collect(&mut self) -> Frame {
        let mut frame = Frame::default();
        self.health_facts(&mut frame);
        self.traffic_facts(&mut frame);
        // RAM on both sides fences publication races without taking the writer
        // every five seconds. A changing publication is unknown, not failure.
        let running = self.policy.is_running();
        let publication = self.policy.reader().admission_state().ok();
        let runtime = self.policy.runtime_observation();
        let service = self.policy.service().map(|control| control.snapshot());
        // Periodic readers can wake together. This single-flight collector
        // waits within the shared internal budget, without admitting another
        // worker or treating a missed deadline as a complete observation.
        match self
            .policy
            .read_with_admission_staged(ReadAdmission::Internal, store::alerts::read)
            .await
        {
            Ok(snapshot) => {
                let now = Instant::now();
                let service_after = self.policy.service().map(|control| control.snapshot());
                let service_ready = match (service, service_after) {
                    (Some(Ok(before)), Some(Ok(after)))
                        if service_identity(&before) == service_identity(&after) =>
                    {
                        Some(self.service_policy_fact(
                            &mut frame,
                            &before,
                            snapshot.policy_revision,
                        ))
                    }
                    (None, None) => Some(true),
                    (Some(Err(error)), _) | (_, Some(Err(error))) => {
                        frame.fail(Failure::Runtime(error.kind()));
                        None
                    }
                    _ => None,
                };
                match (runtime, self.policy.runtime_observation()) {
                    (Err(error), _) | (_, Err(error)) => frame.fail(Failure::Runtime(error.kind())),
                    (Ok(before), Ok(after))
                        if service_ready == Some(true)
                            && before == after
                            && running == self.policy.is_running()
                            && publication == self.policy.reader().admission_state().ok() =>
                    {
                        self.runtime_policy_facts(
                            &mut frame,
                            &snapshot,
                            publication,
                            running,
                            before.as_ref(),
                            now,
                        );
                    }
                    _ => {
                        // An acceptance, completion, publication or process-stop
                        // transition across storage is unknown. Keep old facts
                        // stale; it cannot retire or recover an incident.
                    }
                }
                self.remote_observation_facts(&mut frame, &snapshot.targets, now);
                self.remote_facts(&mut frame, snapshot.targets, now, wall_time());
            }
            Err(failure) => frame.fail(Failure::Policy(failure.stage, failure.error.kind())),
        }
        // Copy producer evidence after the only storage await. No status lock
        // overlaps that wait, the alert-state lock, or any TLS/cache operation.
        self.management_https_facts(&mut frame, wall_time());
        // Completion is per kind, so certificate and ACME evidence must both
        // be complete before absent management slots may leave scope.
        let acme_complete = frame.complete.remove(&Kind::ManagementHttps);
        if self.certificates.is_some() {
            self.certificate_facts(&mut frame, acme_complete);
        } else if acme_complete {
            frame.complete.insert(Kind::ManagementHttps);
        }
        frame
    }

    /// Report transitions, including a change of source while collection remains
    /// incomplete. Repeated failures do not emit a warning every five seconds.
    /// A successful round says nothing about recovery of individual incidents.
    pub(super) fn report_collection(&mut self, frame: &Frame) {
        if self.collection_failures == frame.failures {
            return;
        }
        if frame.failures.is_empty() {
            tracing::info!("operations observation collection resumed");
        } else {
            tracing::warn!(failures = ?frame.failures, "operations observation collection incomplete");
        }
        self.collection_failures.clone_from(&frame.failures);
    }

    pub(super) fn management_https_facts(&self, frame: &mut Frame, wall: Option<u64>) {
        let Some(handle) = &self.acme else {
            // No ACME attempt/worker source is configured. Actual manual TLS
            // metadata, when present, is collected separately below.
            frame.complete.insert(Kind::ManagementHttps);
            return;
        };
        match handle.observation() {
            Ok(observed) => self.management_https_observation_facts(frame, observed, wall),
            Err(error) => frame.fail(Failure::ManagementHttps(error.kind())),
        }
    }

    /// Keep legacy certificate/attempt/worker slots without a loaded-identity
    /// handle; otherwise only ACME attempt/worker facts are authoritative here.
    /// An unreadable producer never retires an episode.
    pub(super) fn management_https_observation_facts(
        &self,
        frame: &mut Frame,
        observed: acme::Observation,
        wall: Option<u64>,
    ) {
        if self.certificates.is_none() {
            let Some(certificate_base) = observed.activation_seq.checked_mul(3) else {
                frame.fail(Failure::HttpsSequenceExhausted);
                return;
            };
            if certificate_base.checked_add(2).is_none() {
                frame.fail(Failure::HttpsSequenceExhausted);
                return;
            }
            let (stamp, sequence, outcome) = if let Some(now) = wall.map(|value| value / 1000) {
                // Healthy=0, Expiring=1, Unavailable=2. Within one activation only
                // deterioration advances evidence. Clock rollback cannot recover a
                // failure; a real activation advances past all three old buckets.
                let (bucket, outcome) = match observed.certificate {
                    Some((before, after)) if before <= now => match after.checked_sub(now) {
                        Some(remaining) if remaining > HTTPS_EXPIRY_WARNING => {
                            (0, Outcome::Success)
                        }
                        Some(_) => (1, Outcome::Failure("https_identity_expiring")),
                        None => (2, Outcome::Failure("https_identity_unavailable")),
                    },
                    _ => (2, Outcome::Failure("https_identity_unavailable")),
                };
                (
                    format!("{}:{bucket}", observed.activation_seq),
                    certificate_base.checked_add(bucket),
                    outcome,
                )
            } else {
                frame.fail(Failure::WallClockUnavailable);
                // Still include this key so an unknown clock does not retire it.
                (String::new(), None, Outcome::Unknown)
            };
            frame.facts.push(Fact {
                key: key(Kind::ManagementHttps, &self.node_id, None, "certificate"),
                lineage: self.shared.boot_id.clone(),
                stamp,
                sequence,
                check: None,
                target: None,
                outcome,
            });
        }
        frame.complete.insert(Kind::ManagementHttps);
        let lineage = &self.shared.boot_id;
        frame.facts.push(Fact {
            key: key(Kind::ManagementHttps, &self.node_id, None, "attempt"),
            lineage: lineage.clone(),
            stamp: observed.result_seq.to_string(),
            sequence: Some(observed.result_seq),
            check: None,
            target: None,
            outcome: match observed.last_failure {
                Some(acme::Failure::AttemptUnavailable) => {
                    Outcome::Failure("acme_attempt_unavailable")
                }
                Some(acme::Failure::ReviewRequired) => Outcome::Failure("acme_review_required"),
                None if observed.result_seq > 0 => Outcome::Success,
                None => Outcome::Unknown,
            },
        });
        let worker_sequence = u64::from(observed.stopped);
        frame.facts.push(Fact {
            key: key(Kind::ManagementHttps, &self.node_id, None, "worker"),
            lineage: lineage.clone(),
            stamp: worker_sequence.to_string(),
            sequence: Some(worker_sequence),
            check: None,
            target: None,
            // The handle is not a restart controller. A stale/fabricated
            // non-stopped snapshot regresses to zero and cannot clear stopped.
            outcome: if observed.stopped {
                Outcome::Failure("acme_worker_stopped")
            } else {
                Outcome::Success
            },
        });
    }

    #[cfg(test)]
    pub(in crate::manage) async fn collect_once(&mut self) -> io::Result<()> {
        if self.history_before_collect().await {
            return Ok(());
        }
        let frame = self.collect().await;
        self.accept_frame(frame).await
    }

    fn health_facts(&self, frame: &mut Frame) {
        let Some(handle) = &self.health else {
            return;
        };
        let snapshot = match handle.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                frame.fail(Failure::Health(error.kind()));
                frame.egress = Some(EgressCollection {
                    completed: Instant::now(),
                    observed_at: wall_time(),
                    error: true,
                });
                return;
            }
        };
        self.health_snapshot_facts(frame, snapshot, handle.validity_millis());
    }

    pub(super) fn health_snapshot_facts(
        &self,
        frame: &mut Frame,
        snapshot: health::Snapshot,
        validity_millis: u64,
    ) {
        frame.egress = Some(EgressCollection {
            completed: Instant::now(),
            observed_at: wall_time(),
            error: false,
        });
        let fresh = snapshot.catalog_loaded
            && snapshot.catalog_error.is_none()
            && snapshot
                .catalog_age_millis
                .is_some_and(|age| age < validity_millis);
        frame.complete.insert(Kind::HealthCatalog);
        let outcome = if snapshot.catalog_error.is_some() {
            Outcome::Failure("health_catalog_unavailable")
        } else if snapshot.catalog_loaded && !fresh {
            Outcome::Failure("health_catalog_stale")
        } else if fresh {
            Outcome::Success
        } else {
            Outcome::Unknown
        };
        frame.facts.push(Fact {
            key: key(Kind::HealthCatalog, &self.node_id, None, "catalog"),
            lineage: format!(
                "{}:{}",
                snapshot.boot_id,
                snapshot.catalog_revision.unwrap_or(0)
            ),
            stamp: format!(
                "{}:{}:{}",
                snapshot.catalog_revision.unwrap_or(0),
                snapshot.catalog_error.unwrap_or(""),
                fresh
            ),
            sequence: None,
            check: None,
            target: None,
            outcome,
        });
        if !fresh {
            return;
        }
        frame.complete.insert(Kind::EgressCheck);
        for entry in snapshot.entries {
            let lineage = format!(
                "{}:{}:{}",
                snapshot.boot_id, entry.address_revision, entry.ip
            );
            for check in entry.checks {
                let slot = match check.kind {
                    health::CheckKind::Bind => "bind".to_owned(),
                    health::CheckKind::Tcp => format!(
                        "tcp:{}",
                        check
                            .target
                            .map_or_else(String::new, |target| target.to_string())
                    ),
                };
                let outcome = match check.outcome {
                    health::FixedOutcome::Success if fresh => Outcome::Success,
                    health::FixedOutcome::Unknown | health::FixedOutcome::Cancelled => {
                        Outcome::Unknown
                    }
                    _ if !fresh => Outcome::Unknown,
                    health::FixedOutcome::Success => Outcome::Unknown,
                    health::FixedOutcome::AddressUnavailable => {
                        Outcome::Failure("egress_address_unavailable")
                    }
                    health::FixedOutcome::ConnectionRefused => {
                        Outcome::Failure("egress_connection_refused")
                    }
                    health::FixedOutcome::TimedOut => Outcome::Failure("egress_timed_out"),
                    health::FixedOutcome::PermissionDenied => {
                        Outcome::Failure("egress_permission_denied")
                    }
                    health::FixedOutcome::NetworkUnreachable => {
                        Outcome::Failure("egress_network_unreachable")
                    }
                    health::FixedOutcome::Failed => Outcome::Failure("egress_failed"),
                    health::FixedOutcome::FamilyMismatch => {
                        Outcome::Failure("egress_family_mismatch")
                    }
                };
                frame.facts.push(Fact {
                    key: key(
                        Kind::EgressCheck,
                        &self.node_id,
                        Some(&entry.address_id),
                        &slot,
                    ),
                    lineage: lineage.clone(),
                    stamp: check
                        .sequence
                        .map_or_else(String::new, |sequence| sequence.to_string()),
                    sequence: check.sequence,
                    check: Some(check.kind),
                    target: check.target,
                    outcome,
                });
            }
        }
    }

    fn traffic_facts(&self, frame: &mut Frame) {
        if !self.proxy_expected {
            return;
        }
        let Some(handle) = &self.traffic else {
            frame.fail(Failure::TrafficUnavailable);
            return;
        };
        let observed = match handle.observation() {
            Ok(observed) => observed,
            Err(error) => {
                frame.fail(Failure::Traffic(error.kind()));
                return;
            }
        };
        frame
            .complete
            .extend([Kind::TrafficCheckpoint, Kind::TrafficContinuity]);
        let Some(run) = observed.active_run.as_deref() else {
            return;
        };
        let lineage = format!("{}:{}", observed.durable.meter_epoch, run);
        let stale = observed.age_millis.map_or_else(
            || {
                Instant::now()
                    .saturating_duration_since(self.started)
                    .as_millis()
                    > u128::from(CHECKPOINT_STALE)
            },
            |age| age > CHECKPOINT_STALE,
        );
        let outcome = if observed.checkpoint_error {
            Outcome::Failure("traffic_checkpoint_failed")
        } else if stale {
            Outcome::Failure("traffic_checkpoint_stale")
        } else if observed.completion_sequence > 0 {
            Outcome::Success
        } else {
            Outcome::Unknown
        };
        frame.facts.push(Fact {
            key: key(Kind::TrafficCheckpoint, &self.node_id, None, "checkpoint"),
            lineage: lineage.clone(),
            stamp: format!(
                "{}:{}:{}",
                observed.completion_sequence, observed.checkpoint_error, stale
            ),
            sequence: None,
            check: None,
            target: None,
            outcome,
        });
        for (slot, failed, code) in [
            (
                "loss",
                observed.durable.loss_possible,
                "traffic_loss_possible",
            ),
            (
                "history",
                observed.durable.history_gap,
                "traffic_history_gap",
            ),
            (
                "clock",
                observed.durable.time_uncertain,
                "traffic_time_uncertain",
            ),
        ] {
            frame.facts.push(Fact {
                key: key(Kind::TrafficContinuity, &self.node_id, None, slot),
                lineage: lineage.clone(),
                stamp: failed.to_string(),
                sequence: None,
                check: None,
                target: None,
                outcome: if failed {
                    Outcome::Failure(code)
                } else {
                    Outcome::Success
                },
            });
        }
    }

    pub(super) fn policy_fact(
        &mut self,
        frame: &mut Frame,
        saved: u64,
        applied: Option<u64>,
        running: bool,
        now: Instant,
    ) {
        frame.complete.insert(Kind::Policy);
        if !self.proxy_expected {
            self.pending_policy = None;
            return;
        }
        let stamp = format!("{}:{}:{}", saved, applied.unwrap_or(0), running);
        let outcome = if applied.is_some_and(|revision| revision > saved) {
            self.pending_policy = None;
            Outcome::Unknown
        } else if running && applied == Some(saved) {
            self.pending_policy = None;
            Outcome::Success
        } else {
            let pending = self
                .pending_policy
                .get_or_insert_with(|| (stamp.clone(), now));
            if pending.0 != stamp {
                *pending = (stamp.clone(), now);
            }
            if now.saturating_duration_since(pending.1) < POLICY_GRACE {
                Outcome::Unknown
            } else if !running {
                Outcome::Failure("proxy_not_running")
            } else if applied.is_none() {
                Outcome::Failure("policy_publication_unavailable")
            } else {
                Outcome::Failure("policy_not_applied")
            }
        };
        frame.facts.push(Fact {
            key: key(Kind::Policy, &self.node_id, None, "policy"),
            lineage: saved.to_string(),
            stamp,
            sequence: None,
            check: None,
            target: None,
            outcome,
        });
    }

    pub(super) fn remote_facts(
        &mut self,
        frame: &mut Frame,
        targets: Vec<store::alerts::Target>,
        now: Instant,
        wall: Option<u64>,
    ) {
        frame
            .complete
            .extend([Kind::RemoteTraffic, Kind::RemoteJob]);
        let current = targets
            .iter()
            .map(|target| target.id.clone())
            .collect::<BTreeSet<_>>();
        self.remote_clocks.retain(|id, _| current.contains(id));
        for target in targets {
            if !target.active || target.retired {
                continue;
            }
            let lineage = format!(
                "{}:{}:{}",
                target.revision,
                target.authorization_revision,
                target.meter_epoch.as_deref().unwrap_or("pending")
            );
            let clock = self
                .remote_clocks
                .entry(target.id.clone())
                .or_insert_with(|| RemoteClock {
                    last_success: target.last_success_at,
                    captured: now,
                    initial_age: wall
                        .zip(target.last_success_at)
                        .and_then(|(now, then)| now.checked_sub(then)),
                });
            if clock.last_success != target.last_success_at {
                let moved_back = clock
                    .last_success
                    .zip(target.last_success_at)
                    .is_some_and(|(old, new)| new < old);
                *clock = RemoteClock {
                    last_success: target.last_success_at,
                    captured: now,
                    initial_age: if moved_back {
                        None
                    } else {
                        wall.zip(target.last_success_at)
                            .and_then(|(now, then)| now.checked_sub(then))
                    },
                };
            }
            // Anchor wall-time age once. Repeated reads or clock adjustment
            // cannot extend the freshness of the very same cached sample.
            let fresh = clock.initial_age.is_some_and(|age| {
                u128::from(age)
                    .saturating_add(now.saturating_duration_since(clock.captured).as_millis())
                    <= u128::from(REMOTE_STALE)
            });
            let current_source = target.source_target_revision == Some(target.revision)
                && target.source_authorization_revision == Some(target.authorization_revision);
            let outcome = if target.rollback || target.quarantined {
                Outcome::Failure("remote_traffic_continuity_error")
            } else if !target.peer_active {
                Outcome::Failure("remote_traffic_not_authorized")
            } else if !self.remote_collector_available {
                Outcome::Failure("remote_collector_unavailable")
            } else if target
                .source_target_revision
                .is_some_and(|revision| revision != target.revision)
                || target
                    .source_authorization_revision
                    .is_some_and(|revision| revision != target.authorization_revision)
            {
                if target.last_success_at.is_some() {
                    Outcome::Failure("remote_traffic_stale")
                } else {
                    Outcome::Unknown
                }
            } else if let Some(error) = target.source_error.as_deref() {
                match error {
                    "unsupported" => Outcome::Failure("remote_traffic_unsupported"),
                    "not_authorized" => Outcome::Failure("remote_traffic_not_authorized"),
                    "continuity_error" => Outcome::Failure("remote_traffic_continuity_error"),
                    _ => Outcome::Failure("remote_traffic_unavailable"),
                }
            } else if target.last_success_at.is_none() {
                Outcome::Unknown
            } else if !fresh || !current_source {
                Outcome::Failure("remote_traffic_stale")
            } else {
                Outcome::Success
            };
            let code = match outcome {
                Outcome::Failure(code) => code,
                Outcome::Success => "ready",
                Outcome::Unknown => "unknown",
            };
            frame.facts.push(Fact {
                key: key(Kind::RemoteTraffic, &target.id, None, "traffic"),
                lineage,
                stamp: format!(
                    "{}:{}:{}",
                    target.last_success_at.unwrap_or(0),
                    target.cursor.unwrap_or(0),
                    code
                ),
                sequence: None,
                check: None,
                target: None,
                outcome,
            });
            if let (Some(job), Some(state)) = (target.job_id, target.job_state) {
                if state == "superseded" {
                    continue;
                }
                let outcome = match state.as_str() {
                    "blocked" => Outcome::Failure("remote_job_blocked"),
                    "rejected" => Outcome::Failure("remote_job_rejected"),
                    "saved" | "applied" => Outcome::Success,
                    _ => Outcome::Unknown,
                };
                frame.facts.push(Fact {
                    key: key(Kind::RemoteJob, &target.id, Some(&job), "job"),
                    lineage: format!(
                        "{}:{}:{}",
                        target.revision, target.authorization_revision, job
                    ),
                    stamp: format!("{}:{}", state, target.job_attempts.unwrap_or(0)),
                    sequence: None,
                    check: None,
                    target: None,
                    outcome,
                });
            }
        }
    }
}

/// A before/after RAM fence includes configuration and cleanup certainty, not
/// just the process-local counter. A changing service cannot retire incidents.
fn service_identity(
    value: &crate::manage::proxy::service::View,
) -> (u64, Option<u64>, crate::manage::proxy::service::Phase, bool) {
    (
        value.generation,
        value.configuration_revision,
        value.phase,
        value.cleanup_confirmed,
    )
}

pub(super) fn key(kind: Kind, origin: &str, resource: Option<&str>, slot: &str) -> Key {
    Key {
        kind,
        origin: origin.to_owned(),
        resource: resource.map(str::to_owned),
        slot: slot.to_owned(),
    }
}
