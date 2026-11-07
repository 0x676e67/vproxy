//! Optional node-local alert delivery. The durable journal owns one immutable
//! batch; HTTP never runs under the policy writer or a SQLite transaction.
//!
//! POST is not inherently idempotent (RFC 9110 §9.2.2). An ambiguous attempt
//! therefore pauses for review unless the administrator explicitly selects the
//! receiver-deduplicated retry contract. Every retry retains the ID/exact body.
//! https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2

pub(super) mod transport;

use std::{io, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

use super::{policy::Coordinator, store::notifications as storage};

const POLL: Duration = Duration::from_secs(5);
pub(super) const MAX_EVENTS: usize = 16;
pub(super) const MAX_BODY: usize = 32 * 1024;

/// Write-only destination authority. Even the URL path/query can contain a
/// capability; neither Debug nor the read model exposes any part of it.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Destination {
    pub(super) url: String,
    pub(super) bearer: String,
}

impl Drop for Destination {
    fn drop(&mut self) {
        self.url.zeroize();
        self.bearer.zeroize();
    }
}

/// Input is bound to this node and a CAS revision. A repeated operation is
/// recognized only by its actor and the digest of this exact request. Empty
/// replacement fields retain stored secrets; clearing a token is explicit.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Change {
    pub(super) expected_node_id: String,
    pub(super) expected_revision: String,
    pub(super) operation_id: String,
    pub(super) enabled: bool,
    pub(super) automatic_retry: bool,
    pub(super) url: Option<String>,
    pub(super) bearer: Option<String>,
    pub(super) clear_bearer: bool,
    pub(super) clear_destination: bool,
    pub(super) discard_pending: bool,
}

impl Drop for Change {
    fn drop(&mut self) {
        if let Some(value) = self.url.as_mut() {
            value.zeroize();
        }
        if let Some(value) = self.bearer.as_mut() {
            value.zeroize();
        }
    }
}

/// A retry grants one more attempt for this exact retained batch, never creates
/// another batch or silently resets an attempt counter after a lost response.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retry {
    pub(super) expected_node_id: String,
    pub(super) expected_revision: String,
    pub(super) delivery_id: String,
    pub(super) expected_attempts: u32,
}

/// Receiver wire contract v1. Decimal sequences avoid JavaScript rounding.
/// A retention gap is explicit even when no incident records remain to send.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    pub(super) version: u8,
    pub(super) delivery_id: String,
    pub(super) observer_node_id: String,
    pub(super) after_sequence: String,
    pub(super) through_sequence: String,
    pub(super) history_trimmed_through: String,
    pub(super) events: Vec<Event>,
}

/// Fixed, non-secret incident projection. Administrator identities, raw error
/// messages, peer certificates and executable command payloads are excluded.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Event {
    pub(super) sequence: String,
    pub(super) episode_id: String,
    pub(super) origin_node_id: String,
    pub(super) kind: super::alerts::Kind,
    pub(super) transition: super::store::alerts::history::EventKind,
    pub(super) code: String,
    pub(super) resource_id: Option<String>,
    pub(super) target: Option<std::net::SocketAddr>,
    pub(super) observed_at_unix_ms: Option<String>,
}

/// Durable transport fact, not a claim that a person saw a notification.
/// Sending after a crash is indeterminate and becomes Unknown before retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Outcome {
    Ready,
    Sending,
    Accepted,
    Rejected,
    Deferred,
    Unknown,
    DestinationBlocked,
}

/// One bounded request survives retention trimming and normal restart. Its
/// body and ID never change during retry, including after an ambiguous commit.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub(super) envelope: Envelope,
    pub(super) attempts: u32,
    pub(super) outcome: Outcome,
    pub(super) http_status: Option<u16>,
}

/// Public metadata only. Reconfiguration starts at the current event watermark;
/// skipped history and an explicitly discarded pending batch remain visible.
#[derive(Serialize)]
pub(super) struct View {
    pub(super) node_id: String,
    pub(super) revision: String,
    pub(super) enabled: bool,
    pub(super) automatic_retry: bool,
    pub(super) configured: bool,
    pub(super) has_bearer: bool,
    pub(super) operation_id: Option<String>,
    pub(super) cursor: String,
    pub(super) skipped_through: String,
    pub(super) last_accepted_delivery_id: Option<String>,
    pub(super) discarded_delivery_id: Option<String>,
    pub(super) pending: Option<DeliveryView>,
}

#[derive(Serialize)]
pub(super) struct DeliveryView {
    pub(super) id: String,
    pub(super) attempts: u32,
    pub(super) outcome: Outcome,
    pub(super) http_status: Option<u16>,
    pub(super) after_sequence: String,
    pub(super) through_sequence: String,
    pub(super) history_trimmed_through: String,
    pub(super) event_count: usize,
    pub(super) automatic_retry_eligible: bool,
}

/// Author-owned worker, started only after listeners are ready. It sends no
/// traffic for a disabled setting or old schema and has no proxy data-plane role.
pub(super) async fn run(policy: Arc<Coordinator>, shutdown: CancellationToken) -> io::Result<()> {
    // Retry delays use monotonic process time. Restart retains the durable
    // counter and starts a full delay; wall-clock rollback cannot accelerate it.
    let mut retry: Option<(storage::RetryFence, tokio::time::Instant)> = None;
    loop {
        let permission = retry
            .as_ref()
            .filter(|(_, due)| *due <= tokio::time::Instant::now())
            .map(|(fence, _)| fence.clone());
        let attempt = tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Ok(()),
            value = policy.store_write(move |dir, gate| storage::prepare(dir, gate, permission.as_ref())) => value,
        };
        match attempt {
            Ok(Some(storage::Work::Send(attempt))) => {
                retry = None;
                let result = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => return Ok(()),
                    value = transport::send(&attempt.destination, &attempt.body, &attempt.id) => value,
                };
                // Revision + ID + attempt fence rejects a late answer after
                // disable/reconfigure or an explicit retry. No lock spans HTTP.
                if policy
                    .store_write(move |dir, gate| storage::finish(dir, gate, &attempt, result))
                    .await
                    .is_err()
                {
                    tracing::warn!("webhook result could not be recorded; inspect delivery status");
                }
            }
            Ok(Some(storage::Work::Wait(fence))) => {
                if retry.as_ref().is_none_or(|(old, _)| *old != fence) {
                    let due = tokio::time::Instant::now() + fence.delay();
                    retry = Some((fence, due));
                }
            }
            Ok(None) => {
                retry = None;
            }
            Err(_) => tracing::warn!("webhook journal is unavailable; no request submitted"),
        }
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            _ = tokio::time::sleep(POLL) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::*;

    #[test]
    fn destination_rejects_authority_confusion_and_non_public_addresses() {
        for value in [
            "http://example.org/",
            "https://127.1/",
            "https://2130706433/",
            "https://10.0.0.1/",
            "https://100.64.0.1/",
            "https://169.254.169.254/",
            "https://192.0.2.1/",
            "https://198.18.0.1/",
            "https://224.0.0.1/",
            "https://[::1]/",
            "https://[::ffff:8.8.8.8]/",
            "https://[2002:808:808::1]/",
            "https://[2001:db8::1]/",
            "https://[fd00::1]/",
            "https://localhost/",
            "https://x.localhost/",
            "https://user:pass@example.org/",
            "https://@example.org/",
            "https://example.org/#secret",
            "https://example.org:0/",
        ] {
            assert!(
                !validate(&Destination {
                    url: value.into(),
                    bearer: String::new()
                }),
                "{value}"
            );
        }
        for value in [
            "https://example.org/path?token=x",
            "https://8.8.8.8/",
            "https://[2606:4700:4700::1111]/",
        ] {
            assert!(validate(&Destination {
                url: value.into(),
                bearer: "test-token".into()
            }));
        }
        assert!(!validate(&Destination {
            url: "https://example.org".into(),
            bearer: "token\r\nx: injected".into()
        }));
    }
}
