//! Non-secret observations from the single issuance worker, not a control API.
//! No status lock is used by TLS handshakes, cache workers or proxy traffic.

use std::{
    io,
    sync::{Arc, Mutex},
};

use rustls_pki_types::UnixTime;
use serde::Serialize;

use super::config::Challenge;

/// A bounded process-local snapshot. It deliberately contains no Config, key,
/// account, order, contact, path, CA response or error message.
#[derive(Clone, Copy)]
struct Snapshot {
    production: bool,
    challenge: Challenge,
    certificate: Option<(u64, u64)>,
    activity: Activity,
    due: Option<u64>,
    last_failure: Option<Failure>,
    /// Successful normal-identity publication, including cache recovery. None
    /// permanently marks exhausted evidence without changing issuance results.
    activation_seq: Option<u64>,
    /// Actual failed/completed operations only; scheduling is not an outcome.
    /// Zero means this process has not observed either result yet.
    result_seq: Option<u64>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Activity {
    Waiting,
    Working,
    Stopped,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum Failure {
    AttemptUnavailable,
    ReviewRequired,
}

impl Failure {
    fn from_kind(kind: io::ErrorKind) -> Self {
        match kind {
            io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidData => Self::ReviewRequired,
            _ => Self::AttemptUnavailable,
        }
    }
}

/// Shared by the worker, authenticated status adapter and local alert reader.
/// Writes are best-effort: monitoring failure must not change issuance or
/// shutdown results.
#[derive(Clone)]
pub(in crate::manage) struct Handle(Arc<Mutex<Snapshot>>);

/// Small typed input for local alerts, copied under the existing short lock.
/// Neither due nor observation time is evidence of a new operation. These
/// process-local counters deliberately do not enter the browser status wire.
#[derive(Clone, Copy)]
pub(in crate::manage) struct Observation {
    pub(in crate::manage) certificate: Option<(u64, u64)>,
    pub(in crate::manage) activation_seq: u64,
    pub(in crate::manage) result_seq: u64,
    pub(in crate::manage) last_failure: Option<Failure>,
    pub(in crate::manage) stopped: bool,
}

/// The wire view is explicit rather than serializing any operational owner.
/// Unix seconds are decimal strings, independent of JavaScript's numeric range.
#[derive(Serialize)]
#[serde(transparent)]
pub(in crate::manage) struct View(Mode);

#[derive(Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum Mode {
    Manual,
    Acme {
        environment: &'static str,
        challenge: Challenge,
        certificate: Option<Certificate>,
        activity: Activity,
        next_attempt_at_unix_s: Option<String>,
        last_failure: Option<Failure>,
        observed_at_unix_s: String,
    },
}

/// Only the most recently activated normal identity is observed. Expiration
/// does not erase its interval; validity is recomputed at each observation.
#[derive(Serialize)]
struct Certificate {
    not_before_unix_s: String,
    not_after_unix_s: String,
    available: bool,
}

impl View {
    pub(in crate::manage) const fn manual() -> Self {
        Self(Mode::Manual)
    }
}

impl Handle {
    pub(super) fn new(
        production: bool,
        challenge: Challenge,
        certificate: Option<(u64, u64)>,
        due: u64,
    ) -> Self {
        Self(Arc::new(Mutex::new(Snapshot {
            production,
            challenge,
            certificate,
            activity: Activity::Waiting,
            due: Some(due),
            last_failure: None,
            activation_seq: Some(u64::from(certificate.is_some())),
            result_seq: Some(0),
        })))
    }

    /// Copy the last worker observation without disk, network or TLS locks.
    /// Poisoned status is unavailable, never a manual-mode fallback.
    pub(in crate::manage) fn view(&self) -> io::Result<View> {
        self.view_at(UnixTime::now().as_secs())
    }

    fn view_at(&self, now: u64) -> io::Result<View> {
        let snapshot = self.snapshot()?;
        Ok(View(Mode::Acme {
            environment: if snapshot.production {
                "production"
            } else {
                "staging"
            },
            challenge: snapshot.challenge,
            certificate: snapshot.certificate.map(|(before, after)| Certificate {
                not_before_unix_s: before.to_string(),
                not_after_unix_s: after.to_string(),
                // Match the normal TLS identity's inclusive validity gate.
                available: before <= now && now <= after,
            }),
            activity: snapshot.activity,
            next_attempt_at_unix_s: snapshot.due.map(|due| due.to_string()),
            last_failure: snapshot.last_failure,
            observed_at_unix_s: now.to_string(),
        }))
    }

    /// Read only producer evidence. Poison or counter exhaustion is unavailable,
    /// never a successful operation, manual mode or a reason to retry issuance.
    pub(in crate::manage) fn observation(&self) -> io::Result<Observation> {
        let snapshot = self.snapshot()?;
        Ok(Observation {
            certificate: snapshot.certificate,
            activation_seq: snapshot.activation_seq.ok_or_else(unavailable)?,
            result_seq: snapshot.result_seq.ok_or_else(unavailable)?,
            last_failure: snapshot.last_failure,
            stopped: matches!(snapshot.activity, Activity::Stopped),
        })
    }

    fn snapshot(&self) -> io::Result<Snapshot> {
        self.0
            .lock()
            .map(|snapshot| *snapshot)
            .map_err(|_| unavailable())
    }

    fn update(&self, operation: impl FnOnce(&mut Snapshot)) {
        if let Ok(mut snapshot) = self.0.lock() {
            operation(&mut snapshot);
        }
    }

    pub(super) fn begin(&self) {
        self.update(|snapshot| {
            snapshot.activity = Activity::Working;
            snapshot.due = None;
        });
    }

    pub(super) fn failed(&self, kind: io::ErrorKind) {
        self.update(|snapshot| {
            snapshot.last_failure = Some(Failure::from_kind(kind));
            snapshot.result_seq = snapshot
                .result_seq
                .and_then(|sequence| sequence.checked_add(1));
        });
    }

    pub(super) fn recovery_failed(&self, kind: io::ErrorKind) {
        if matches!(Failure::from_kind(kind), Failure::ReviewRequired) {
            self.failed(kind);
        }
    }

    /// A successfully reloaded identity is not proof that issuance succeeded.
    /// Keep the attempt's failure and activity until the worker finalizes due.
    pub(super) fn activated(&self, validity: (u64, u64)) {
        self.update(|snapshot| {
            snapshot.certificate = Some(validity);
            snapshot.activation_seq = snapshot
                .activation_seq
                .and_then(|sequence| sequence.checked_add(1));
        });
    }

    pub(super) fn waiting(&self, due: u64) {
        self.update(|snapshot| {
            snapshot.activity = Activity::Waiting;
            snapshot.due = Some(due);
        });
    }

    pub(super) fn completed(&self, validity: (u64, u64), due: u64) {
        self.update(|snapshot| {
            snapshot.certificate = Some(validity);
            snapshot.activity = Activity::Waiting;
            snapshot.due = Some(due);
            snapshot.last_failure = None;
            snapshot.activation_seq = snapshot
                .activation_seq
                .and_then(|sequence| sequence.checked_add(1));
            snapshot.result_seq = snapshot
                .result_seq
                .and_then(|sequence| sequence.checked_add(1));
        });
    }

    pub(super) fn stopped(&self) {
        self.update(|snapshot| {
            snapshot.activity = Activity::Stopped;
            snapshot.due = None;
        });
    }

    #[cfg(test)]
    pub(in crate::manage) fn testing() -> Self {
        Self::new(false, Challenge::TlsAlpn01, None, 0)
    }
}

fn unavailable() -> io::Error {
    io::Error::other("ACME status is unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn view(handle: &Handle, now: u64) -> Value {
        serde_json::to_value(handle.view_at(now).unwrap()).unwrap()
    }

    #[test]
    fn wire_distinguishes_manual_cold_and_dynamic_activated_validity() {
        assert_eq!(
            serde_json::to_value(View::manual()).unwrap(),
            json!({"mode":"manual"})
        );
        let handle = Handle::testing();
        assert_eq!(
            view(&handle, 99),
            json!({
                "mode":"acme", "environment":"staging", "challenge":"tls-alpn-01",
                "certificate":null, "activity":"waiting", "next_attempt_at_unix_s":"0",
                "last_failure":null, "observed_at_unix_s":"99",
            })
        );
        handle.activated((100, 200));
        for (now, available) in [(99, false), (100, true), (200, true), (201, false)] {
            assert_eq!(view(&handle, now)["certificate"]["available"], available);
        }
        handle.completed((u64::MAX - 2, u64::MAX), u64::MAX);
        let state = view(&handle, u64::MAX);
        assert_eq!(
            state["certificate"]["not_after_unix_s"],
            u64::MAX.to_string()
        );
        assert_eq!(state["next_attempt_at_unix_s"], u64::MAX.to_string());
    }

    #[test]
    fn recovery_preserves_failure_and_exact_schedule_until_real_success() {
        let handle = Handle::testing();
        handle.begin();
        handle.failed(io::ErrorKind::TimedOut);
        handle.activated((1, 100));
        assert_eq!(view(&handle, 50)["activity"], "working");
        assert!(view(&handle, 50)["next_attempt_at_unix_s"].is_null());
        handle.recovery_failed(io::ErrorKind::InvalidData);
        handle.waiting(u64::MAX);
        assert_eq!(view(&handle, 50)["last_failure"], "review_required");
        assert_eq!(
            view(&handle, 50)["next_attempt_at_unix_s"],
            u64::MAX.to_string()
        );
        handle.begin();
        assert_eq!(view(&handle, 50)["last_failure"], "review_required");
        handle.failed(io::ErrorKind::ConnectionRefused);
        handle.recovery_failed(io::ErrorKind::TimedOut);
        handle.waiting(75);
        assert_eq!(view(&handle, 50)["last_failure"], "attempt_unavailable");
        handle.completed((2, 101), 90);
        assert!(view(&handle, 50)["last_failure"].is_null());
        handle.failed(io::ErrorKind::PermissionDenied);
        handle.stopped();
        let state = view(&handle, 50);
        assert_eq!(state["activity"], "stopped");
        assert_eq!(state["last_failure"], "review_required");
        assert!(state["next_attempt_at_unix_s"].is_null());
        assert_eq!(state["certificate"]["available"], true);
    }

    #[test]
    fn evidence_advances_only_for_activation_or_actual_results() -> io::Result<()> {
        let handle = Handle::testing();
        let cold = handle.observation()?;
        assert_eq!((cold.activation_seq, cold.result_seq), (0, 0));
        assert!(cold.certificate.is_none() && cold.last_failure.is_none());
        handle.begin();
        handle.failed(io::ErrorKind::TimedOut);
        let failed = handle.observation()?;
        assert_eq!((failed.activation_seq, failed.result_seq), (0, 1));
        assert!(matches!(
            failed.last_failure,
            Some(Failure::AttemptUnavailable)
        ));
        handle.activated((10, 100));
        handle.recovery_failed(io::ErrorKind::TimedOut);
        handle.waiting(u64::MAX);
        handle.begin();
        let recovered = handle.observation()?;
        assert_eq!((recovered.activation_seq, recovered.result_seq), (1, 1));
        assert_eq!(recovered.certificate, Some((10, 100)));
        assert!(matches!(
            recovered.last_failure,
            Some(Failure::AttemptUnavailable)
        ));
        handle.recovery_failed(io::ErrorKind::PermissionDenied);
        assert_eq!(handle.observation()?.result_seq, 2);
        handle.completed((10, 100), 90);
        let completed = handle.observation()?;
        assert_eq!((completed.activation_seq, completed.result_seq), (2, 3));
        assert!(completed.last_failure.is_none());
        handle.stopped();
        let stopped = handle.observation()?;
        assert!(stopped.stopped);
        assert_eq!((stopped.activation_seq, stopped.result_seq), (2, 3));
        Ok(())
    }

    #[test]
    fn exhausted_evidence_is_unavailable_without_changing_status_or_results() {
        let handle = Handle::testing();
        handle.0.lock().unwrap().activation_seq = Some(u64::MAX);
        handle.activated((1, 100));
        assert!(handle.observation().is_err());
        assert_eq!(view(&handle, 50)["certificate"]["available"], true);
        handle.completed((2, 101), 90);
        assert!(
            handle.observation().is_err(),
            "exhaustion cannot wrap or reset"
        );
        assert!(view(&handle, 50)["last_failure"].is_null());
        let handle = Handle::testing();
        handle.0.lock().unwrap().result_seq = Some(u64::MAX);
        handle.failed(io::ErrorKind::TimedOut);
        assert!(handle.observation().is_err());
        assert_eq!(view(&handle, 50)["last_failure"], "attempt_unavailable");
        handle.completed((1, 100), 90);
        assert!(handle.observation().is_err());
        assert!(view(&handle, 50)["last_failure"].is_null());
    }

    #[test]
    fn unavailable_monitoring_does_not_panic_or_become_manual_mode() {
        let handle = Handle::testing();
        let worker = handle.clone();
        assert!(
            std::thread::spawn(move || {
                let _lock = worker.0.lock().unwrap();
                panic!("fixture status writer stopped");
            })
            .join()
            .is_err()
        );
        handle.begin();
        handle.failed(io::ErrorKind::PermissionDenied);
        handle.activated((1, 2));
        handle.waiting(3);
        handle.completed((1, 2), 3);
        handle.stopped();
        assert_eq!(
            handle.view().err().unwrap().to_string(),
            "ACME status is unavailable"
        );
        assert!(handle.observation().is_err());
    }
}
