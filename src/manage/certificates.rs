//! Public facts from actual loaded TLS identities, never a certificate-file
//! inventory or a TLS probe. Leaf parsing happens only when an identity loads
//! or publishes; reads copy bounded descriptors and use one observation time.
//!
//! A time-valid loaded certificate is not proof of trust, name coverage,
//! revocation status, listener readiness or reachability. No private key,
//! filesystem path, certificate name or issuer text enters this projection.

use std::{
    io,
    sync::{Arc, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::{acme, proxy};

pub(super) const MAX_PROXY: usize = 16;
const MAX_LEAF_BYTES: usize = 16 * 1024;

/// A fixed local use, not a remote permission or a certificate trust domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum Role {
    Management,
    Node,
    Proxy,
}

/// How the current local identity is supplied; manual does not mean untrusted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum Source {
    Manual,
    Acme,
}

/// Non-secret leaf metadata. Signed Unix seconds preserve pre-epoch X.509
/// validity without narrowing through JavaScript numbers or milliseconds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Descriptor {
    pub(super) sha256: String,
    pub(super) not_before_unix_s: i64,
    pub(super) not_after_unix_s: i64,
}

/// Disabled is an absent listener; Pending is ACME without a normal publication.
/// Unavailable means metadata cannot be read, not that TLS or a CA failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum State {
    Disabled,
    Pending,
    Unavailable,
    Loaded(Descriptor),
}

impl State {
    /// Parse only the bounded actual loaded leaf. A metadata failure must not
    /// tighten the existing loader's date/name/trust policy or replace its TLS.
    pub(super) fn from_leaf(leaf: &[u8]) -> Self {
        Descriptor::from_leaf(leaf).map_or(Self::Unavailable, Self::Loaded)
    }
}

impl Descriptor {
    fn from_leaf(leaf: &[u8]) -> Option<Self> {
        if leaf.is_empty() || leaf.len() > MAX_LEAF_BYTES {
            return None;
        }
        let (remaining, certificate) = x509_parser::parse_x509_certificate(leaf).ok()?;
        if !remaining.is_empty() {
            return None;
        }
        let not_before_unix_s = certificate.validity().not_before.timestamp();
        let not_after_unix_s = certificate.validity().not_after.timestamp();
        if not_before_unix_s > not_after_unix_s {
            return None;
        }
        let mut sha256 = String::with_capacity(64);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in Sha256::digest(leaf) {
            sha256.push(char::from(HEX[usize::from(byte >> 4)]));
            sha256.push(char::from(HEX[usize::from(byte & 15)]));
        }
        Some(Self {
            sha256,
            not_before_unix_s,
            not_after_unix_s,
        })
    }
}

/// A successful managed bind supplies its stable endpoint identity and actual
/// TLS observation together. Plaintext listeners carry Disabled, not Pending.
#[derive(Clone, Debug)]
pub(super) struct ProxyIdentity {
    pub(super) id: String,
    pub(super) protocol: proxy::Protocol,
    pub(super) state: State,
    pub(super) source: Source,
}

/// Static manual state or the actual renewable normal-identity resolver. The
/// ACME status observer and cache are deliberately not sources for this handle.
pub(super) enum ManagementSource {
    Manual(State),
    Acme(acme::Tls),
}

/// One local entry. Only proxies have an endpoint ID/protocol; these identifiers
/// are not interchangeable with node IDs or positions in a displayed list.
#[derive(Clone, Debug)]
pub(super) struct Entry {
    pub(super) role: Role,
    pub(super) source: Source,
    pub(super) id: Option<String>,
    pub(super) protocol: Option<proxy::Protocol>,
    pub(super) state: State,
    pub(super) valid_now: Option<bool>,
}

/// All entries use this one fallible wall-clock sample. No monotonic age or
/// successful TLS handshake is inferred from a certificate's validity interval.
#[derive(Clone, Debug)]
pub(super) struct Snapshot {
    pub(super) node_id: String,
    pub(super) observed_at_unix_s: Option<i64>,
    pub(super) entries: Vec<Entry>,
}

/// Configuration coverage, independent of metadata readiness or health. A
/// failed snapshot cannot turn an enabled source into an empty inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Coverage {
    pub(super) management: bool,
    pub(super) node: bool,
    pub(super) proxy: bool,
}

struct Inventory {
    node_id: String,
    management: ManagementSource,
    node: State,
    proxies: proxy::Certificates,
    service: OnceLock<proxy::service::Control>,
}

/// Shared read-only composition of existing owners; no second worker, queue,
/// filesystem watcher or mutable certificate registry is created.
#[derive(Clone)]
pub(super) struct Handle(Arc<Inventory>);

impl Handle {
    pub(super) fn new(
        node_id: String,
        management: ManagementSource,
        node: State,
        proxies: proxy::Certificates,
    ) -> io::Result<Self> {
        if !super::store::valid_id(&node_id)
            || matches!(
                &management,
                ManagementSource::Manual(State::Disabled | State::Pending)
            )
            || matches!(&node, State::Pending)
        {
            return Err(unavailable());
        }
        Ok(Self(Arc::new(Inventory {
            node_id,
            management,
            node,
            proxies,
            service: OnceLock::new(),
        })))
    }

    /// Install only the same process owner before collectors/API start. Later
    /// observations follow that owner's actual listener/identity publication;
    /// this is not another mutable key registry.
    pub(super) fn configure_service(&self, service: proxy::service::Control) -> io::Result<()> {
        self.0.service.set(service).map_err(|_| unavailable())
    }

    fn proxies(&self) -> io::Result<proxy::Certificates> {
        if let Some(service) = self.0.service.get() {
            let view = service.snapshot()?;
            if !view.cleanup_confirmed {
                return Err(unavailable());
            }
            Ok(view.certificates)
        } else {
            Ok(self.0.proxies.clone())
        }
    }

    pub(super) fn coverage(&self) -> Coverage {
        Coverage {
            management: true,
            node: !matches!(self.0.node, State::Disabled),
            proxy: self.proxies().map_or(true, |proxies| proxies.has_tls()),
        }
    }

    /// Copy the actual published metadata without disk/network work. Proxy
    /// publication not ready or invalid refuses the whole snapshot instead of
    /// reporting a healthy empty inventory. ACME poison remains Unavailable.
    pub(super) fn snapshot(&self) -> io::Result<Snapshot> {
        self.snapshot_at(system_time(SystemTime::now()))
    }

    fn snapshot_at(&self, now: Option<i64>) -> io::Result<Snapshot> {
        let proxies = self.proxies()?.snapshot(&self.0.node_id)?;
        if proxies.len() > MAX_PROXY {
            return Err(unavailable());
        }
        let (source, management) = match &self.0.management {
            ManagementSource::Manual(state) => (Source::Manual, state.clone()),
            ManagementSource::Acme(tls) => (Source::Acme, tls.certificate()),
        };
        let mut entries = Vec::with_capacity(proxies.len() + 2);
        entries.push(entry(Role::Management, source, None, None, management, now));
        entries.push(entry(
            Role::Node,
            Source::Manual,
            None,
            None,
            self.0.node.clone(),
            now,
        ));
        for proxy in proxies {
            if !super::store::valid_id(&proxy.id) || matches!(proxy.state, State::Pending) {
                return Err(unavailable());
            }
            entries.push(entry(
                Role::Proxy,
                proxy.source,
                Some(proxy.id),
                Some(proxy.protocol),
                proxy.state,
                now,
            ));
        }
        Ok(Snapshot {
            node_id: self.0.node_id.clone(),
            observed_at_unix_s: now,
            entries,
        })
    }
}

fn entry(
    role: Role,
    source: Source,
    id: Option<String>,
    protocol: Option<proxy::Protocol>,
    state: State,
    now: Option<i64>,
) -> Entry {
    let valid_now = match (&state, now) {
        (State::Loaded(leaf), Some(now)) => {
            Some(leaf.not_before_unix_s <= now && now <= leaf.not_after_unix_s)
        }
        _ => None,
    };
    Entry {
        role,
        source,
        id,
        protocol,
        state,
        valid_now,
    }
}

/// Floor signed seconds before the epoch, using checked conversion rather than
/// saturating an unsupported clock into a plausible certificate observation.
fn system_time(now: SystemTime) -> Option<i64> {
    match now.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).ok(),
        Err(error) => {
            let duration = error.duration();
            let seconds = i64::try_from(duration.as_secs()).ok()?;
            seconds
                .checked_neg()?
                .checked_sub(i64::from(duration.subsec_nanos() != 0))
        }
    }
}

fn unavailable() -> io::Error {
    io::Error::other("loaded certificate metadata is unavailable")
}
