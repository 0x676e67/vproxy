//! Non-secret Web-managed listener settings. These are desired configuration,
//! not a reachability result, TLS identity or permission to start forwarding.
//! Node-default egress leaves source selection to the existing connector and
//! per-user policy; no IPAM object is required and no route grant is widened.

use std::{collections::HashSet, io};

use serde::{Deserialize, Serialize};

use super::{ListenerView, MAX_LISTENERS, MAX_WORKERS, Protocol, invalid, public_address};

pub(in crate::manage) const MAX_BYTES: usize = 8192;

/// The same validated normal identity as management, with each proxy protocol
/// retaining its own ALPN and TLS policy. There are no PEM/path values in Web
/// settings. ACME selection follows renewal without rebinding live listeners.
#[derive(Clone)]
pub(in crate::manage) enum Tls {
    Manual(crate::server::tls::Identity),
    Acme(crate::manage::acme::Tls),
}

impl Tls {
    pub(in crate::manage) fn identity(&self) -> io::Result<crate::server::tls::Identity> {
        match self {
            Self::Manual(identity) => Ok(identity.clone()),
            Self::Acme(tls) => tls.proxy_identity(),
        }
    }

    pub(in crate::manage) fn certificate(&self) -> crate::manage::certificates::State {
        use crate::manage::certificates::State;
        match self {
            Self::Manual(identity) => identity
                .leaf()
                .map_or(State::Unavailable, |leaf| State::from_leaf(leaf.as_ref())),
            Self::Acme(tls) => tls.certificate(),
        }
    }

    pub(in crate::manage) fn source(&self) -> crate::manage::certificates::Source {
        match self {
            Self::Manual(_) => crate::manage::certificates::Source::Manual,
            Self::Acme(_) => crate::manage::certificates::Source::Acme,
        }
    }
}

/// Cold configuration persisted independently of runtime observations. TLS
/// listeners use the node's managed normal identity, never client-supplied
/// filesystem paths or the ACME challenge identity. Advanced file-based startup
/// remains a separate, mutually exclusive configuration authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Configuration {
    pub(in crate::manage) listeners: Vec<ListenerView>,
    pub(in crate::manage) workers: u16,
    pub(in crate::manage) concurrent: u32,
    /// Seconds, matching the existing outbound connection deadline.
    pub(in crate::manage) connect_timeout: u64,
}

impl Configuration {
    /// Construct through the same checked protocol/connector path as startup
    /// JSON, but with node-default egress and the retained managed TLS owner.
    /// This is inert: it neither binds a socket nor grants a user access.
    pub(in crate::manage) fn prepare(
        &self,
        tls: &Tls,
        profile: crate::ebpf::Config,
    ) -> io::Result<super::Prepared> {
        self.validate()?;
        let configuration = super::Configuration {
            listeners: self
                .listeners
                .iter()
                .map(|listener| super::Listener {
                    protocol: listener.protocol,
                    bind: listener.bind,
                    public_address: listener.public_address.clone(),
                    tls_cert: None,
                    tls_key: None,
                })
                .collect(),
            workers: Some(usize::from(self.workers)),
            concurrent: self.concurrent,
            connect_timeout: self.connect_timeout,
            cidr: None,
            cidr_range: None,
            fallback: None,
            reuseaddr: super::default_reuseaddr(),
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            tcp_user_timeout: super::default_tcp_user_timeout(),
        };
        let mut prepared = super::prepare_resolved(&configuration, |_, _| tls.identity())?
            .with_profile_config(profile);
        prepared.certificates = super::Certificates::managed(&prepared.endpoints, tls.clone());
        Ok(prepared)
    }

    /// Check bounded protocol/bind/address inputs without DNS, files or socket
    /// probes. Real bind remains authoritative; a successful precheck cannot
    /// reserve a port or prove that a client can reach the advertised address.
    pub(in crate::manage) fn validate(&self) -> io::Result<()> {
        if self.listeners.is_empty()
            || self.listeners.len() > MAX_LISTENERS
            || self.workers == 0
            || usize::from(self.workers) > MAX_WORKERS
            || !(1..=300).contains(&self.connect_timeout)
        {
            return Err(invalid("invalid managed service limits"));
        }
        crate::server::validate_concurrent(self.concurrent)?;
        let mut binds = HashSet::with_capacity(self.listeners.len());
        for listener in &self.listeners {
            if listener.bind.port() == 0
                || listener.bind.ip().is_multicast()
                || !binds.insert((listener.protocol == Protocol::Masque, listener.bind))
                || listener.public_address.as_deref().is_some_and(|address| {
                    !public_address(address).is_ok_and(|canonical| canonical == address)
                })
            {
                return Err(invalid("invalid managed service listener"));
            }
        }
        Ok(())
    }

    /// Stable, bounded bytes are used for persistence and exact-operation
    /// comparison. Field/listener order is intentional; never include secrets.
    pub(in crate::manage) fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid("managed service configuration is too large"));
        }
        Ok(bytes)
    }

    /// Reject changed/noncanonical storage instead of silently repairing it.
    /// API JSON need not be canonical; it is decoded then encoded before save.
    pub(in crate::manage) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(invalid("invalid managed service configuration size"));
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid("invalid managed service configuration"))?;
        if value.encode()? != bytes {
            return Err(invalid("managed service configuration is not canonical"));
        }
        Ok(value)
    }
}
