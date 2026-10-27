//! Non-secret startup endpoint descriptions shared by browser and node APIs.
//!
//! An explicit public address is configuration, not proof of reachability, DNS
//! resolution, certificate coverage or an observed proxy egress address. No
//! management origin, server IP or wildcard bind is substituted for it.

use std::net::{IpAddr, SocketAddr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{MAX_LISTENERS, Protocol, invalid};

/// One configured listener. `Auto` retains its native protocol name; clients
/// may offer HTTP, HTTPS and SOCKS5 separately, never an `auto://` URL.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct ListenerView {
    pub(in crate::manage) protocol: Protocol,
    pub(in crate::manage) bind: SocketAddr,
    /// Canonical host:port without credentials. None means not advertised, even
    /// when bind is a concrete address that looks publicly routable.
    pub(in crate::manage) public_address: Option<String>,
}

/// Process-local configuration and current managed runtime availability. A
/// stopped proxy can retain configured endpoints; neither state claims that a
/// remote client can reach them through NAT, routing or firewall rules.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct EndpointCatalog {
    pub(in crate::manage) node_id: String,
    pub(in crate::manage) proxy_running: bool,
    pub(in crate::manage) listeners: Vec<ListenerView>,
}

impl EndpointCatalog {
    /// Check a remote response against the TLS-selected node, finite startup
    /// limit and canonical address contract before exposing it to a browser.
    pub(in crate::manage) fn validate(&self, node_id: &str) -> std::io::Result<()> {
        if self.node_id != node_id
            || self.listeners.len() > MAX_LISTENERS
            || self.proxy_running && self.listeners.is_empty()
        {
            return Err(invalid("invalid managed proxy endpoint catalog"));
        }
        for listener in &self.listeners {
            if listener.bind.port() == 0
                || listener.public_address.as_deref().is_some_and(|address| {
                    !public_address(address).is_ok_and(|canonical| canonical == address)
                })
            {
                return Err(invalid("invalid managed proxy endpoint metadata"));
            }
        }
        Ok(())
    }
}

/// Validate a bounded, credential-free host:port without resolving its host.
/// Explicit non-zero decimal ports and brackets around IPv6 remove ambiguity.
/// Private and loopback addresses remain valid for internal deployments; only
/// unspecified, multicast and limited-broadcast destinations are excluded.
pub(in crate::manage) fn public_address(value: &str) -> std::io::Result<String> {
    let fail = || {
        invalid(
            "proxy public_address must be a numeric IP or DNS host with explicit non-zero port and no credentials or URI components",
        )
    };
    if value.is_empty()
        || value.len() > 259
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || value
            .bytes()
            .any(|byte| matches!(byte, b'@' | b'/' | b'\\' | b'?' | b'#' | b'%'))
    {
        return Err(fail());
    }
    let authority = value.parse::<http::uri::Authority>().map_err(|_| fail())?;
    let port = authority.port().ok_or_else(fail)?;
    let spelling = port.as_str();
    if spelling.starts_with('0') || !spelling.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(fail());
    }
    let port = port.as_u16();
    if port == 0 {
        return Err(fail());
    }
    let host = authority.host();
    let numeric = if host.starts_with('[') && host.ends_with(']') {
        Some(
            host[1..host.len() - 1]
                .parse::<std::net::Ipv6Addr>()
                .map(IpAddr::V6)
                .map_err(|_| fail())?,
        )
    } else {
        host.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
    };
    let host = if let Some(address) = numeric {
        let classified = address.to_canonical();
        if classified.is_unspecified()
            || classified.is_multicast()
            || matches!(classified, IpAddr::V4(address) if address.is_broadcast())
        {
            return Err(fail());
        }
        match address {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => format!("[{address}]"),
        }
    } else {
        // WHATWG-style consumers must not reinterpret a DNS-looking spelling
        // as legacy decimal/octal/hex IPv4. ASCII-only labels keep copy/export
        // behavior consistent without silently accepting IDNA transformations.
        if host.len() > 253
            || !host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
            || !matches!(url::Host::parse(host), Ok(url::Host::Domain(_)))
        {
            return Err(fail());
        }
        host.to_ascii_lowercase()
    };
    Ok(format!("{host}:{port}"))
}

use crate::manage::store::endpoints::{AddressSelection, Inventory, ListenerKey, State};

/// Persistent identity for a node's exact startup protocol/bind tuple, never its
/// array position or advertised destination. A changed bind is a new listener.
pub(in crate::manage) fn endpoint_id(
    node_id: &str,
    protocol: Protocol,
    bind: SocketAddr,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"vproxy.endpoint-identity.v1\0");
    hash_text(&mut hash, node_id);
    hash.update([protocol_tag(protocol)]);
    hash_text(&mut hash, &bind.to_string());
    URL_SAFE_NO_PAD.encode(&hash.finalize()[..16])
}

fn protocol_tag(protocol: Protocol) -> u8 {
    match protocol {
        Protocol::Http => 1,
        Protocol::Https => 2,
        Protocol::Socks5 => 3,
        Protocol::Masque => 4,
        Protocol::Auto => 5,
    }
}

fn hash_text(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value.as_bytes());
}

fn inventory_digest(listeners: &[ListenerKey]) -> String {
    let mut ordered: Vec<_> = listeners.iter().collect();
    ordered.sort_by(|a, b| a.id.cmp(&b.id));
    let mut hash = Sha256::new();
    hash.update(b"vproxy.endpoint-inventory.v1\0");
    for listener in ordered {
        hash_text(&mut hash, &listener.id);
        hash.update([protocol_tag(listener.protocol)]);
        hash_text(&mut hash, &listener.bind.to_string());
        match &listener.configured_public_address {
            None => hash.update([0]),
            Some(address) => {
                hash.update([1]);
                hash_text(&mut hash, address);
            }
        }
    }
    let bytes = hash.finalize();
    let mut output = String::with_capacity(64);
    for byte in bytes {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    output
}

impl Inventory {
    /// Construct and validate the bounded immutable catalog. Config reordering
    /// is irrelevant; defaults change the digest but not listener identities.
    pub(in crate::manage) fn new(
        node_id: &str,
        listeners: Vec<ListenerKey>,
    ) -> std::io::Result<Self> {
        let value = Self {
            digest: inventory_digest(&listeners),
            listeners,
        };
        value.validate(node_id)?;
        Ok(value)
    }

    pub(in crate::manage) fn from_views(
        node_id: &str,
        listeners: &[ListenerView],
    ) -> std::io::Result<Self> {
        Self::new(
            node_id,
            listeners
                .iter()
                .map(|listener| ListenerKey {
                    id: endpoint_id(node_id, listener.protocol, listener.bind),
                    protocol: listener.protocol,
                    bind: listener.bind,
                    configured_public_address: listener.public_address.clone(),
                })
                .collect(),
        )
    }

    /// Reject malformed identity or observed hash collisions instead of applying
    /// one listener's durable address declaration to a different socket tuple.
    pub(in crate::manage) fn validate(&self, node_id: &str) -> std::io::Result<()> {
        let mut decoded = [0_u8; 16];
        if node_id.len() != 22
            || !URL_SAFE_NO_PAD
                .decode_slice(node_id, &mut decoded)
                .is_ok_and(|len| len == 16)
            || self.listeners.len() > MAX_LISTENERS
        {
            return Err(invalid("invalid endpoint inventory identity or capacity"));
        }
        let mut ids = std::collections::HashSet::new();
        let mut tuples = std::collections::HashSet::new();
        for listener in &self.listeners {
            if listener.bind.port() == 0
                || listener.id != endpoint_id(node_id, listener.protocol, listener.bind)
                || !ids.insert(listener.id.as_str())
                || !tuples.insert((protocol_tag(listener.protocol), listener.bind))
                || listener
                    .configured_public_address
                    .as_deref()
                    .is_some_and(|address| {
                        !public_address(address).is_ok_and(|canonical| canonical == address)
                    })
            {
                return Err(invalid("invalid or duplicate endpoint inventory listener"));
            }
        }
        if self.digest != inventory_digest(&self.listeners) {
            return Err(invalid(
                "endpoint inventory digest does not match startup configuration",
            ));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct SettingListener {
    pub(in crate::manage) id: String,
    pub(in crate::manage) protocol: Protocol,
    pub(in crate::manage) bind: SocketAddr,
    pub(in crate::manage) configured_public_address: Option<String>,
    pub(in crate::manage) selection: AddressSelection,
    pub(in crate::manage) public_address: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct DetachedSetting {
    pub(in crate::manage) id: String,
    pub(in crate::manage) protocol: Protocol,
    pub(in crate::manage) bind: SocketAddr,
    pub(in crate::manage) selection: AddressSelection,
}
/// Versioned management-only projection. Bind remains descriptive and immutable;
/// neither this DTO nor its public address can create a listener or route.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct SettingsCatalog {
    pub(in crate::manage) node_id: String,
    pub(in crate::manage) proxy_running: bool,
    pub(in crate::manage) revision: String,
    pub(in crate::manage) generation: String,
    pub(in crate::manage) listeners: Vec<SettingListener>,
    pub(in crate::manage) detached: Vec<DetachedSetting>,
}
impl SettingsCatalog {
    /// Validate an untrusted management reply against the TLS-selected node and
    /// exact effective-address rules before the browser may copy its URLs.
    pub(in crate::manage) fn validate(&self, node_id: &str) -> std::io::Result<()> {
        if self.node_id != node_id
            || self
                .revision
                .parse::<i64>()
                .ok()
                .filter(|n| *n > 0)
                .is_none_or(|n| n.to_string() != self.revision)
            || self.listeners.len() > MAX_LISTENERS
            || self.detached.len() > crate::manage::store::endpoints::MAX_OVERRIDES
            || self.proxy_running && self.listeners.is_empty()
        {
            return Err(invalid("invalid endpoint settings catalog"));
        }
        let inventory = Inventory::new(
            node_id,
            self.listeners
                .iter()
                .map(|item| ListenerKey {
                    id: item.id.clone(),
                    protocol: item.protocol,
                    bind: item.bind,
                    configured_public_address: item.configured_public_address.clone(),
                })
                .collect(),
        )?;
        if inventory.digest != self.generation {
            return Err(invalid(
                "endpoint settings generation differs from startup catalog",
            ));
        }
        let mut ids = std::collections::HashSet::new();
        let mut overrides = 0usize;
        for item in &self.listeners {
            ids.insert(item.id.as_str());
            let effective = match &item.selection {
                AddressSelection::Inherit => item.configured_public_address.as_deref(),
                AddressSelection::Hidden => {
                    overrides += 1;
                    None
                }
                AddressSelection::Custom {
                    public_address: address,
                } => {
                    overrides += 1;
                    if !public_address(address).is_ok_and(|canonical| canonical == *address) {
                        return Err(invalid("invalid endpoint custom address"));
                    }
                    Some(address.as_str())
                }
            };
            if item.public_address.as_deref() != effective {
                return Err(invalid(
                    "endpoint effective address differs from its declared source",
                ));
            }
        }
        for item in &self.detached {
            if item.bind.port() == 0
                || item.id != endpoint_id(node_id, item.protocol, item.bind)
                || !ids.insert(item.id.as_str())
            {
                return Err(invalid("invalid detached endpoint identity"));
            }
            match &item.selection {
                AddressSelection::Inherit => {
                    return Err(invalid("detached endpoint has no override"));
                }
                AddressSelection::Custom {
                    public_address: address,
                } => {
                    if !public_address(address).is_ok_and(|canonical| canonical == *address) {
                        return Err(invalid("invalid detached endpoint address"));
                    }
                }
                AddressSelection::Hidden => {}
            }
            overrides += 1;
        }
        if overrides > crate::manage::store::endpoints::MAX_OVERRIDES {
            return Err(invalid("endpoint override catalog exceeds capacity"));
        }
        Ok(())
    }

    pub(in crate::manage) fn new(
        node_id: &str,
        running: bool,
        inventory: &Inventory,
        state: State,
    ) -> std::io::Result<Self> {
        inventory.validate(node_id)?;
        if state.digest != inventory.digest {
            return Err(invalid(
                "endpoint metadata is not synchronized with startup inventory",
            ));
        }
        let mut detached = Vec::new();
        for item in &state.overrides {
            if !inventory
                .listeners
                .iter()
                .any(|listener| listener.id == item.listener_id)
            {
                detached.push(DetachedSetting {
                    id: item.listener_id.clone(),
                    protocol: item.protocol,
                    bind: item.bind,
                    selection: item.selection.clone(),
                });
            }
        }
        let listeners = inventory
            .listeners
            .iter()
            .map(|listener| {
                let selection = state
                    .overrides
                    .iter()
                    .find(|item| item.listener_id == listener.id)
                    .map(|item| item.selection.clone())
                    .unwrap_or(AddressSelection::Inherit);
                let public_address = match &selection {
                    AddressSelection::Inherit => listener.configured_public_address.clone(),
                    AddressSelection::Custom { public_address } => Some(public_address.clone()),
                    AddressSelection::Hidden => None,
                };
                SettingListener {
                    id: listener.id.clone(),
                    protocol: listener.protocol,
                    bind: listener.bind,
                    configured_public_address: listener.configured_public_address.clone(),
                    selection,
                    public_address,
                }
            })
            .collect();
        Ok(Self {
            node_id: node_id.to_owned(),
            proxy_running: running,
            revision: state.revision.to_string(),
            generation: inventory.digest.clone(),
            listeners,
            detached,
        })
    }

    pub(in crate::manage) fn legacy(&self) -> EndpointCatalog {
        EndpointCatalog {
            node_id: self.node_id.clone(),
            proxy_running: self.proxy_running,
            listeners: self
                .listeners
                .iter()
                .map(|listener| ListenerView {
                    protocol: listener.protocol,
                    bind: listener.bind,
                    public_address: listener.public_address.clone(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod inventory_tests {
    use super::*;
    const NODE: &str = "AAAAAAAAAAAAAAAAAAAAAA";
    const OTHER: &str = "AQEBAQEBAQEBAQEBAQEBAQ";

    fn listener(protocol: Protocol, port: u16) -> ListenerKey {
        let bind = SocketAddr::from(([127, 0, 0, 1], port));
        ListenerKey {
            id: endpoint_id(NODE, protocol, bind),
            protocol,
            bind,
            configured_public_address: Some("proxy.example:1080".into()),
        }
    }

    #[test]
    fn identities_are_node_tuple_bound_and_generation_ignores_array_order() {
        let first = listener(Protocol::Http, 8080);
        let second = listener(Protocol::Socks5, 1080);
        let original = Inventory::new(NODE, vec![first.clone(), second.clone()]).unwrap();
        let reordered = Inventory::new(NODE, vec![second, first.clone()]).unwrap();
        assert_eq!(original.digest, reordered.digest);
        assert_ne!(first.id, endpoint_id(OTHER, first.protocol, first.bind));
        assert_ne!(first.id, endpoint_id(NODE, Protocol::Https, first.bind));
        let mut changed = first.clone();
        changed.configured_public_address = None;
        assert_eq!(changed.id, first.id);
        assert_ne!(
            Inventory::new(NODE, vec![first]).unwrap().digest,
            Inventory::new(NODE, vec![changed]).unwrap().digest
        );
    }

    #[test]
    fn inventory_rejects_fabricated_duplicate_or_unadvertisable_metadata() {
        let first = listener(Protocol::Http, 8080);
        assert!(Inventory::new(NODE, vec![first.clone(), first.clone()]).is_err());
        let mut invalid = first.clone();
        invalid.id = OTHER.into();
        assert!(Inventory::new(NODE, vec![invalid]).is_err());
        let mut invalid = first;
        invalid.configured_public_address = Some("user:secret@proxy.example:443".into());
        assert!(Inventory::new(NODE, vec![invalid]).is_err());
    }

    #[test]
    fn settings_validate_sources_and_legacy_projection_without_retargeting() {
        let configured = listener(Protocol::Http, 8080);
        let removed = listener(Protocol::Socks5, 1080);
        let inventory = Inventory::new(NODE, vec![configured.clone()]).unwrap();
        for (selection, effective) in [
            (AddressSelection::Inherit, Some("proxy.example:1080")),
            (AddressSelection::Hidden, None),
            (
                AddressSelection::Custom {
                    public_address: "new.example:443".into(),
                },
                Some("new.example:443"),
            ),
        ] {
            let overrides = if selection == AddressSelection::Inherit {
                Vec::new()
            } else {
                vec![crate::manage::store::endpoints::Override {
                    listener_id: configured.id.clone(),
                    protocol: configured.protocol,
                    bind: configured.bind,
                    selection,
                }]
            };
            let mut state = State {
                revision: 3,
                digest: inventory.digest.clone(),
                overrides,
            };
            state
                .overrides
                .push(crate::manage::store::endpoints::Override {
                    listener_id: removed.id.clone(),
                    protocol: removed.protocol,
                    bind: removed.bind,
                    selection: AddressSelection::Hidden,
                });
            let mut catalog = SettingsCatalog::new(NODE, true, &inventory, state).unwrap();
            catalog.validate(NODE).unwrap();
            assert_eq!(
                catalog.legacy().listeners[0].public_address.as_deref(),
                effective
            );
            assert_eq!(catalog.detached.len(), 1);
            assert!(catalog.validate(OTHER).is_err());
            catalog.listeners[0].public_address = Some("unselected.example:443".into());
            assert!(catalog.validate(NODE).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_addresses_are_explicit_destinations_not_urls_or_ambiguous_hosts() {
        for (input, expected) in [
            ("PROXY.Example:443", "proxy.example:443"),
            ("localhost:1080", "localhost:1080"),
            ("192.0.2.7:65535", "192.0.2.7:65535"),
            ("127.0.0.1:1", "127.0.0.1:1"),
            ("10.0.0.1:1080", "10.0.0.1:1080"),
            ("[2001:0DB8::7]:443", "[2001:db8::7]:443"),
            ("[::1]:1080", "[::1]:1080"),
        ] {
            assert_eq!(public_address(input).unwrap(), expected);
        }
        for input in [
            "",
            "proxy.example",
            "proxy.example:0",
            "proxy.example:00080",
            "proxy.example:65536",
            "proxy.example:abc",
            "https://proxy.example:443",
            "user:password@proxy.example:443",
            "proxy.example:443/",
            "proxy.example:443?x=1",
            "proxy.example:443#fragment",
            "proxy.example:443\\path",
            " proxy.example:443",
            "proxy.example:443\r\n",
            "0.0.0.0:1080",
            "[::]:1080",
            "255.255.255.255:1080",
            "224.0.0.1:1080",
            "[ff02::1]:1080",
            "[::ffff:0.0.0.0]:1080",
            "[::ffff:224.0.0.1]:1080",
            "127.1:1080",
            "2130706433:1080",
            "0177.0.0.1:1080",
            "0x7f000001:1080",
            "2001:db8::1:1080",
            "[fe80::1%1]:1080",
            "a..example:1080",
            "-proxy.example:1080",
            "proxy_.example:1080",
            "代理.example:1080",
        ] {
            assert!(public_address(input).is_err(), "accepted {input:?}");
        }
        assert!(public_address(&format!("{}:1080", "a".repeat(254))).is_err());
    }
}
