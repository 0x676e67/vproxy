//! Process-local maintenance facts. A new process/runtime has a new namespace;
//! old requests remain unknown rather than being replayed on replacement work.

use std::{fmt, io};

use serde::{Deserialize, Serialize};

use super::{maintenance::Ownership, proxy, store};

/// A drain is separate from a saved pause. These assertions bind the explicit
/// action to one runtime and its current paused policy, never a replacement.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub(super) expected_node_id: String,
    pub(super) expected_epoch: String,
    pub(super) expected_revision: String,
    pub(super) runtime_id: String,
    pub(super) request_id: String,
}

impl Request {
    pub(super) fn numbers(&self) -> io::Result<(u64, u64)> {
        if !store::valid_id(&self.expected_node_id)
            || !store::valid_id(&self.runtime_id)
            || !store::valid_id(&self.request_id)
        {
            return Err(invalid_input());
        }
        Ok((
            positive(&self.expected_epoch)?,
            positive(&self.expected_revision)?,
        ))
    }
}

/// These states describe forwarding drivers, not worker destruction or receipt
/// by a remote application. Long-lived tunnels can keep Draining indefinitely.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Serving,
    Draining,
    Drained,
    Interrupted,
    Failed,
}

/// One runtime observation. A count is approximate admission ownership only;
/// even zero cannot establish that HTTP/TLS/QUIC buffers have reached a peer.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Runtime {
    pub(super) runtime_id: String,
    pub(super) phase: Phase,
    #[serde(deserialize_with = "required_nullable")]
    pub(super) request: Option<Request>,
    #[serde(deserialize_with = "required_nullable")]
    pub(super) active_operations: Option<String>,
}

/// Current ownership and saved pause, independent of the optional actual
/// runtime. A management-only node has no forwarding runtime to quiesce.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Status {
    pub(super) node_id: String,
    pub(super) ownership: Ownership,
    pub(super) saved_revision: String,
    pub(super) saved_accepting: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub(super) runtime: Option<Runtime>,
}

impl Status {
    pub(super) fn new(
        saved: store::admission::Snapshot,
        view: Option<proxy::View>,
        active: Option<u64>,
    ) -> Self {
        let runtime = view.map(|view| Runtime {
            runtime_id: view.runtime_id.clone(),
            phase: match view.phase {
                proxy::Phase::Serving => Phase::Serving,
                proxy::Phase::Draining => Phase::Draining,
                proxy::Phase::Drained => Phase::Drained,
                proxy::Phase::Interrupted => Phase::Interrupted,
                proxy::Phase::Failed => Phase::Failed,
            },
            request: view.intent.map(|intent| Request {
                expected_node_id: intent.node_id,
                expected_epoch: intent.epoch.to_string(),
                expected_revision: intent.revision.to_string(),
                runtime_id: view.runtime_id,
                request_id: intent.request_id,
            }),
            active_operations: active.map(|value| value.to_string()),
        });
        Self {
            node_id: saved.node_id,
            ownership: saved.ownership.into(),
            saved_revision: saved.saved_revision.to_string(),
            saved_accepting: saved.accepting,
            runtime,
        }
    }

    /// Validate node and namespace binding before a verified remote response is
    /// used. This is structural validation, never transport authentication.
    pub(super) fn validate(&self, expected: &str) -> io::Result<()> {
        let saved = positive(&self.saved_revision).map_err(|_| invalid_status())?;
        let epoch = positive(&self.ownership.epoch).map_err(|_| invalid_status())?;
        if !store::valid_id(expected)
            || self.node_id != expected
            || self
                .ownership
                .controller_node_id
                .as_deref()
                .is_some_and(|id| !store::valid_id(id) || id == expected)
            || number(&self.ownership.last_terminal_command).is_none_or(|v| v > i64::MAX as u64)
        {
            return Err(invalid_status());
        }
        if let Some(runtime) = &self.runtime {
            if !store::valid_id(&runtime.runtime_id)
                || runtime.phase != Phase::Serving && self.saved_accepting
                || runtime
                    .active_operations
                    .as_deref()
                    .is_some_and(|value| number(value).is_none())
            {
                return Err(invalid_status());
            }
            match (&runtime.phase, &runtime.request) {
                (Phase::Serving, None) => {}
                (Phase::Serving, Some(_)) | (_, None) => return Err(invalid_status()),
                (_, Some(request)) => {
                    let (original_epoch, revision) =
                        request.numbers().map_err(|_| invalid_status())?;
                    if request.expected_node_id != expected
                        || request.runtime_id != runtime.runtime_id
                        || original_epoch > epoch
                        || revision > saved
                    {
                        return Err(invalid_status());
                    }
                }
            }
        }
        Ok(())
    }
}

/// Known refusals occur before any runtime transition or durable policy write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Unavailable,
    AdmissionNotPaused,
    PolicyUnavailable,
    RestartRequired,
}

impl Error {
    pub(super) const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "proxy_runtime_unavailable",
            Self::AdmissionNotPaused => "proxy_admission_not_paused",
            Self::PolicyUnavailable => "proxy_policy_unavailable",
            Self::RestartRequired => "proxy_restart_required",
        }
    }

    pub(super) fn error(self) -> io::Error {
        io::Error::new(io::ErrorKind::AlreadyExists, self)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}
impl std::error::Error for Error {}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn positive(value: &str) -> io::Result<u64> {
    number(value)
        .filter(|value| *value != 0 && *value <= i64::MAX as u64)
        .ok_or_else(invalid_input)
}

fn number(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.len() > 20
        || value.len() > 1 && value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

fn invalid_input() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid proxy runtime assertion",
    )
}
fn invalid_status() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid proxy runtime observation",
    )
}
