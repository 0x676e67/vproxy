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
            value = policy.notifications_write(move |writer| writer.prepare(permission.as_ref())) => value,
        };
        match attempt {
            Ok(Some(storage::Work::Send(attempt))) if policy.ensure_source_confirmed().is_ok() => {
                retry = None;
                let result = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => return Ok(()),
                    value = transport::send(&attempt.destination, &attempt.body, &attempt.id) => value,
                };
                // Revision + ID + attempt fence rejects a late answer after
                // disable/reconfigure or an explicit retry. No lock spans HTTP.
                if policy
                    .notifications_write(move |writer| writer.finish(&attempt, result))
                    .await
                    .is_err()
                {
                    tracing::warn!("webhook result could not be recorded; inspect delivery status");
                }
            }
            Ok(Some(storage::Work::Send(_))) => {
                // A different Source operation may become uncertain after
                // prepare returned. Do not start another request from that
                // state. The retained Sending marker remains indeterminate.
                tracing::warn!("webhook source confirmation is pending; no request submitted");
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

    fn tls_fixture() -> io::Result<(
        tokio_rustls::TlsAcceptor,
        rustls_pki_types::CertificateDer<'static>,
    )> {
        use rustls::{ServerConfig, crypto::aws_lc_rs};
        use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio_rustls::TlsAcceptor;
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(io::Error::other)?;
        let mut tls = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    certified.signing_key.serialize_der(),
                )),
            )
            .map_err(io::Error::other)?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok((
            TlsAcceptor::from(Arc::new(tls)),
            certified.cert.der().clone(),
        ))
    }

    /// Real loopback TLS receiver: no public network, system trust or existing CA.
    /// The production admission path remains intact; only the test client is pinned
    /// to this listener and explicitly trusts this fresh certificate.
    #[tokio::test]
    async fn strict_tls_post_acceptance_redirect_and_unknown_are_distinct() -> io::Result<()> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let (acceptor, certificate) = tls_fixture()?;
        for (response, expected) in [
            (
                "HTTP/1.1 204 No Content\r\n\r\n",
                (Outcome::Accepted, Some(204)),
            ),
            (
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/stolen\r\nContent-Length: 0\r\n\r\n",
                (Outcome::Rejected, Some(302)),
            ),
            (
                "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n",
                (Outcome::Rejected, Some(503)),
            ),
            ("", (Outcome::Unknown, None)),
            (
                "HTTP/1.1 503 Unavailable\r\nRetry-After: 3600\r\nContent-Length: 0\r\n\r\n",
                (Outcome::Deferred, Some(503)),
            ),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let acceptor = acceptor.clone();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await?;
                let mut stream = acceptor.accept(tcp).await?;
                let mut bytes = Vec::new();
                let mut one = [0; 1024];
                while !bytes.windows(4).any(|v| v == b"\r\n\r\n") {
                    let n = stream.read(&mut one).await?;
                    if n == 0 || bytes.len() > 8192 {
                        return Err(io::Error::other("test request incomplete"));
                    }
                    bytes.extend_from_slice(&one[..n]);
                }
                let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
                assert!(text.starts_with("post /event?private=value http/1.1\r\n"));
                assert!(text.contains("vproxy-delivery-id: test-delivery\r\n"));
                assert!(text.contains("authorization: bearer test-token\r\n"));
                assert!(text.contains("content-length: 2\r\n"));
                let start = bytes
                    .windows(4)
                    .position(|v| v == b"\r\n\r\n")
                    .ok_or_else(|| io::Error::other("test headers incomplete"))?
                    + 4;
                while bytes.len() < start + 2 {
                    let n = stream.read(&mut one).await?;
                    if n == 0 {
                        return Err(io::Error::other("test body incomplete"));
                    }
                    bytes.extend_from_slice(&one[..n]);
                }
                assert_eq!(&bytes[start..start + 2], b"{}");
                if !response.is_empty() {
                    stream.write_all(response.as_bytes()).await?;
                    stream.flush().await?;
                }
                Ok::<_, io::Error>(())
            });
            let mut roots = rustls::RootCertStore::empty();
            roots.add(certificate.clone()).map_err(io::Error::other)?;
            let client = test_builder(roots)
                .ok_or_else(|| io::Error::other("test TLS setup failed"))?
                .resolve("localhost", address)
                .build()
                .map_err(io::Error::other)?;
            let destination = Destination {
                url: format!("https://localhost:{}/event?private=value", address.port()),
                bearer: "test-token".into(),
            };
            assert_eq!(
                send_test(client, &destination, b"{}", "test-delivery").await,
                expected
            );
            tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)??;
        }
        Ok(())
    }

    #[tokio::test]
    async fn receiver_requires_a_trusted_certificate_and_the_original_url_name() -> io::Result<()> {
        let (acceptor, certificate) = tls_fixture()?;
        for (trusted, name) in [(false, "localhost"), (true, "wrong.test")] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let acceptor = acceptor.clone();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await?;
                assert!(acceptor.accept(tcp).await.is_err());
                Ok::<_, io::Error>(())
            });
            let mut roots = rustls::RootCertStore::empty();
            if trusted {
                roots.add(certificate.clone()).map_err(io::Error::other)?;
            }
            let client = test_builder(roots)
                .ok_or_else(|| io::Error::other("test TLS setup failed"))?
                .resolve(name, address)
                .build()
                .map_err(io::Error::other)?;
            let destination = Destination {
                url: format!("https://{name}:{}/", address.port()),
                bearer: "fixture-token".into(),
            };
            assert_eq!(
                send_test(client, &destination, b"{}", "test-delivery").await,
                (Outcome::Unknown, None)
            );
            tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)??;
        }
        Ok(())
    }
}
