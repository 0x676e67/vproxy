//! Public maintenance facts shared by browser and verified node transports.
//! Pausing admission never establishes transport flush, peer delivery or a safe
//! forced-stop boundary. Runtime facts belong to one explicit observation.

use std::io;

use serde::{Deserialize, Serialize};

/// A retained non-secret command intent, not a claim that it was applied.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub(super) accepting: bool,
}

/// Existing control authority; rendering this value does not grant ownership.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ownership {
    #[serde(deserialize_with = "required_nullable")]
    pub(super) controller_node_id: Option<String>,
    pub(super) epoch: String,
    pub(super) last_terminal_command: String,
}

impl From<super::store::Ownership> for Ownership {
    fn from(value: super::store::Ownership) -> Self {
        Self {
            controller_node_id: value.controller_node_id,
            epoch: value.epoch.to_string(),
            last_terminal_command: value.last_terminal_command.to_string(),
        }
    }
}

/// Saved policy and this process's bounded admission observation. Runtime fields
/// are jointly absent when stopped, unavailable, or inconsistent with saved
/// policy. A zero operation count is not evidence that H2/TLS queues are empty.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Status {
    pub(super) node_id: String,
    pub(super) ownership: Ownership,
    pub(super) saved_revision: String,
    #[serde(deserialize_with = "required_nullable")]
    pub(super) durable_applied_revision: Option<String>,
    pub(super) running: bool,
    pub(super) saved_accepting: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub(super) applied_revision: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub(super) runtime_accepting: Option<bool>,
    #[serde(deserialize_with = "required_nullable")]
    pub(super) active_operations: Option<String>,
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl Status {
    /// Check the entire response against the already-selected node. This does
    /// not authenticate that node; transport registration and current owner
    /// authorization are separate mandatory checks around the request.
    pub(super) fn validate(&self, expected: &str) -> io::Result<()> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid maintenance status");
        let positive = |value: &str| number(value, false).filter(|value| *value <= i64::MAX as u64);
        let saved = positive(&self.saved_revision).ok_or_else(invalid)?;
        if self.node_id != expected
            || !super::store::valid_id(expected)
            || self
                .ownership
                .controller_node_id
                .as_deref()
                .is_some_and(|id| !super::store::valid_id(id) || id == expected)
            || positive(&self.ownership.epoch).is_none()
            || number(&self.ownership.last_terminal_command, true)
                .is_none_or(|value| value > i64::MAX as u64)
            || self
                .durable_applied_revision
                .as_deref()
                .is_some_and(|value| positive(value).is_none_or(|value| value > saved))
        {
            return Err(invalid());
        }
        match (
            self.applied_revision.as_deref(),
            self.runtime_accepting,
            self.active_operations.as_deref(),
        ) {
            (None, None, None) => Ok(()),
            (Some(revision), Some(accepting), Some(active))
                if self.running
                    && positive(revision) == Some(saved)
                    && accepting == self.saved_accepting
                    && number(active, true).is_some() =>
            {
                Ok(())
            }
            _ => Err(invalid()),
        }
    }
}

fn number(value: &str, zero: bool) -> Option<u64> {
    if value.is_empty()
        || value.len() > 20
        || value.len() > 1 && value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok().filter(|value| zero || *value != 0)
}
