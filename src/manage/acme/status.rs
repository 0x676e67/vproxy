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
}

fn unavailable() -> io::Error {
    io::Error::other("ACME status is unavailable")
}
