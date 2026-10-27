//! Finite node-local shared egress assets and immutable admission indexes.
//!
//! Prefixes describe inventory only. No routing, interface or health claim is
//! inferred from registration; concrete addresses must already be usable by
//! this node. Selection never accesses storage or a parent and never falls back.

use super::{Error, valid_id, valid_name, valid_revision};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cidr::IpCidr;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
};

pub(crate) const MAX_PREFIXES: usize = 256;
pub(crate) const MAX_ADDRESSES: usize = 1024;
pub(crate) const MAX_POOLS: usize = 128;
pub(crate) const MAX_MEMBERS: usize = 8192;
pub(crate) const MAX_GRANTS: usize = 32;

/// A reversible drain stops new selections; retirement permanently preserves ID/IP.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResourceState {
    Active,
    Draining,
    Retired,
}
impl ResourceState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }
    pub(crate) fn parse(value: &str) -> io::Result<Self> {
        match value {
            "active" => Ok(Self::Active),
            "draining" => Ok(Self::Draining),
            "retired" => Ok(Self::Retired),
            _ => Err(invalid()),
        }
    }
}
/// Pool membership cannot silently introduce a different address family.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AddressFamily {
    V4,
    V6,
}
impl AddressFamily {
    pub(crate) const fn of(ip: IpAddr) -> Self {
        if ip.is_ipv4() { Self::V4 } else { Self::V6 }
    }
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
        }
    }
    pub(crate) fn parse(value: &str) -> io::Result<Self> {
        match value {
            "v4" => Ok(Self::V4),
            "v6" => Ok(Self::V6),
            _ => Err(invalid()),
        }
    }
}
/// Canonical owned prefix asset, not proof that its entire address space is healthy.
#[derive(Clone)]
pub(crate) struct PrefixRecord {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) cidr: IpCidr,
    pub(crate) retired: bool,
    pub(crate) revision: u64,
}
/// Immutable concrete IP identity; retirement never frees its uniqueness key.
#[derive(Clone)]
pub(crate) struct AddressRecord {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) ip: IpAddr,
    pub(crate) prefix_id: Option<String>,
    pub(crate) state: ResourceState,
    pub(crate) revision: u64,
}
/// One shared, single-family finite set. Membership is explicit, never a CIDR expansion.
#[derive(Clone)]
pub(crate) struct PoolRecord {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) family: AddressFamily,
    pub(crate) members: Vec<String>,
    pub(crate) state: ResourceState,
    pub(crate) revision: u64,
}
/// User-scoped permissions. Empty grants deny explicit selectors, not all users' assets.
#[derive(Clone)]
pub(crate) struct RoutePermission {
    pub(crate) user_id: String,
    pub(crate) legacy_allowed: bool,
    pub(crate) exits: Vec<String>,
    pub(crate) pools: Vec<String>,
}
impl RoutePermission {
    /// Explicit compatibility grant for a migrated/new legacy-routing user.
    pub(crate) fn legacy(user_id: String) -> Self {
        Self {
            user_id,
            legacy_allowed: true,
            exits: Vec::new(),
            pools: Vec::new(),
        }
    }
}
/// Complete bounded route catalog, published with the same user/credential revision.
#[derive(Clone, Default)]
pub(crate) struct RoutingData {
    pub(crate) prefixes: Vec<PrefixRecord>,
    pub(crate) addresses: Vec<AddressRecord>,
    pub(crate) pools: Vec<PoolRecord>,
    pub(crate) permissions: Vec<RoutePermission>,
}
/// Non-secret mutation projection; no credential verifier is exported with it.
#[derive(Clone)]
pub(crate) enum RoutingEntity {
    Prefix(PrefixRecord),
    Address(AddressRecord),
    Pool(PoolRecord),
    Permission(RoutePermission),
}

struct Permission {
    legacy_allowed: bool,
    exits: HashSet<String>,
    pools: HashSet<String>,
}
/// Ready-to-use indexes; active pool members are prefiltered off the hot path.
pub(super) struct Compiled {
    addresses: HashMap<String, IpAddr>,
    pools: HashMap<String, Vec<IpAddr>>,
    permissions: HashMap<String, Permission>,
}

/// One admitted route, including the explicitly selected pool. An address
/// cannot identify the pool when finite pool membership overlaps.
pub(super) struct Selection<'a> {
    pub(super) source: Option<IpAddr>,
    pub(super) pool_id: Option<&'a str>,
}

/// Validate relationships/capacities and compile a complete policy without I/O.
pub(super) fn compile(
    data: RoutingData,
    users: &HashSet<&str>,
    revision: u64,
) -> io::Result<Compiled> {
    if data.prefixes.len() > MAX_PREFIXES
        || data.addresses.len() > MAX_ADDRESSES
        || data.pools.len() > MAX_POOLS
        || data.permissions.len() != users.len()
    {
        return Err(invalid());
    }
    let mut prefixes = HashMap::new();
    let mut networks = HashSet::new();
    for prefix in &data.prefixes {
        if !valid_id(&prefix.id)
            || !valid_name(&prefix.name)
            || !valid_revision(prefix.revision)
            || prefix.revision > revision
            || !networks.insert(prefix.cidr.to_string())
            || prefixes.insert(prefix.id.as_str(), prefix).is_some()
        {
            return Err(invalid());
        }
    }
    let mut all_addresses = HashMap::new();
    let mut addresses = HashMap::new();
    let mut ips = HashSet::new();
    for address in &data.addresses {
        if !valid_id(&address.id)
            || !valid_name(&address.name)
            || !valid_revision(address.revision)
            || address.revision > revision
            || !valid_ip(address.ip)
            || !ips.insert(address.ip)
            || all_addresses.insert(address.id.as_str(), address).is_some()
        {
            return Err(invalid());
        }
        if let Some(id) = &address.prefix_id {
            let prefix = prefixes.get(id.as_str()).ok_or_else(invalid)?;
            if !prefix.cidr.contains(&address.ip)
                || (prefix.retired && address.state != ResourceState::Retired)
            {
                return Err(invalid());
            }
        }
        if address.state == ResourceState::Active {
            addresses.insert(address.id.clone(), address.ip);
        }
    }
    let mut pools = HashMap::new();
    let mut pool_ids = HashSet::new();
    let mut total = 0usize;
    for pool in &data.pools {
        total = total.checked_add(pool.members.len()).ok_or_else(invalid)?;
        if total > MAX_MEMBERS
            || !valid_id(&pool.id)
            || !valid_name(&pool.name)
            || !valid_revision(pool.revision)
            || pool.revision > revision
            || !pool_ids.insert(pool.id.as_str())
        {
            return Err(invalid());
        }
        let mut members = HashSet::new();
        let mut eligible = Vec::new();
        for id in &pool.members {
            let address = all_addresses.get(id.as_str()).ok_or_else(invalid)?;
            if !members.insert(id) || pool.family != AddressFamily::of(address.ip) {
                return Err(invalid());
            }
            if address.state == ResourceState::Active {
                eligible.push(address.ip);
            }
        }
        if pool.state == ResourceState::Active {
            pools.insert(pool.id.clone(), eligible);
        }
    }
    let mut permissions = HashMap::new();
    for permission in data.permissions {
        if !users.contains(permission.user_id.as_str())
            || permission.exits.len() > MAX_GRANTS
            || permission.pools.len() > MAX_GRANTS
        {
            return Err(invalid());
        }
        let exit_count = permission.exits.len();
        let pool_count = permission.pools.len();
        let exits: HashSet<_> = permission.exits.into_iter().collect();
        let granted_pools: HashSet<_> = permission.pools.into_iter().collect();
        if exits.len() != exit_count
            || granted_pools.len() != pool_count
            || exits
                .iter()
                .any(|id| !all_addresses.contains_key(id.as_str()))
            || granted_pools
                .iter()
                .any(|id| !pool_ids.contains(id.as_str()))
            || permissions
                .insert(
                    permission.user_id,
                    Permission {
                        legacy_allowed: permission.legacy_allowed,
                        exits,
                        pools: granted_pools,
                    },
                )
                .is_some()
        {
            return Err(invalid());
        }
    }
    Ok(Compiled {
        addresses,
        pools,
        permissions,
    })
}
impl Compiled {
    /// Select exactly once after secret verification, before reserving a user slot.
    /// Disabled, empty and ungranted selectors fail closed; health never changes this set.
    pub(super) fn source(&self, user: &str, suffix: &str) -> Result<Selection<'_>, Error> {
        let permission = self.permissions.get(user).ok_or(Error::Unavailable)?;
        if let Some((kind, value)) = suffix
            .split_once('-')
            .filter(|(kind, _)| matches!(*kind, "exit" | "pool"))
        {
            let id = selector_id(value).ok_or(Error::Denied)?;
            let selected = match kind {
                "exit" if permission.exits.contains(&id) => {
                    self.addresses.get(&id).copied().map(|source| Selection {
                        source: Some(source),
                        pool_id: None,
                    })
                }
                "pool" if permission.pools.contains(&id) => self
                    .pools
                    .get_key_value(&id)
                    .filter(|(_, values)| !values.is_empty())
                    .map(|(id, values)| Selection {
                        source: Some(
                            values[(crate::rand::random_u64() % (values.len() as u64)) as usize],
                        ),
                        pool_id: Some(id),
                    }),
                _ => None,
            };
            return selected.ok_or(Error::Denied);
        }
        if permission.legacy_allowed {
            Ok(Selection {
                source: None,
                pool_id: None,
            })
        } else {
            Err(Error::Denied)
        }
    }
}
/// Validate a cold routing projection without constructing any credential verifier.
pub(crate) fn validate(data: &RoutingData, users: &HashSet<&str>, revision: u64) -> io::Result<()> {
    compile(data.clone(), users, revision).map(|_| ())
}
/// A compact username selector uses hex because canonical IDs may contain '-'.
pub(crate) fn selector_id(value: &str) -> Option<String> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        bytes[index] = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Some(URL_SAFE_NO_PAD.encode(bytes))
}
/// Reject aliases and non-source addresses; private/loopback unicast remain valid for owned networks/tests.
pub(crate) fn valid_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified() && !ip.is_multicast() && ip != std::net::Ipv4Addr::BROADCAST
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && ip.to_ipv4_mapped().is_none()
                && !ip.is_unicast_link_local()
        }
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "finite egress policy is malformed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{
        Protocol, Reader,
        tests::{LOGIN, policy, secret},
    };

    fn fixture() -> crate::access::PolicyData {
        let mut data = policy(1, 16);
        let address = URL_SAFE_NO_PAD.encode([20; 16]);
        let pool = URL_SAFE_NO_PAD.encode([21; 16]);
        data.routing.addresses.push(AddressRecord {
            id: address.clone(),
            name: "Owned loopback".into(),
            ip: "127.0.0.2".parse().unwrap(),
            prefix_id: None,
            state: ResourceState::Active,
            revision: 1,
        });
        data.routing.pools.push(PoolRecord {
            id: pool.clone(),
            name: "Finite shared pool".into(),
            family: AddressFamily::V4,
            members: vec![address.clone()],
            state: ResourceState::Active,
            revision: 1,
        });
        data.presets
            .pools
            .push(crate::access::presets::PoolPreset::native(pool.clone()));
        data.routing.permissions[0].legacy_allowed = false;
        data.routing.permissions[0].exits = vec![address];
        data.routing.permissions[0].pools = vec![pool];
        data
    }
    fn auth(reader: &Reader, suffix: &str) -> Result<crate::access::Authorization, Error> {
        reader.authenticate(&format!("{LOGIN}{suffix}"), &secret(), Protocol::Http)
    }

    #[test]
    fn exact_selectors_are_authorized_and_do_not_fall_back_to_legacy() {
        let reader = Reader::new(fixture()).unwrap();
        for suffix in [
            "-exit-14141414141414141414141414141414",
            "-pool-15151515151515151515151515151515",
        ] {
            let admitted = auth(&reader, suffix).unwrap();
            assert_eq!(admitted.source, Some("127.0.0.2".parse().unwrap()));
            assert!(matches!(admitted.extension, super::super::Extension::None));
        }
        for suffix in [
            "",
            "-session-a",
            "-range-a",
            "-ttl-60",
            "-exit-16161616161616161616161616161616",
            "-pool-15151515151515151515151515151515-session-a",
            "-exit-1414141414141414141414141414141A",
            "-exit-127.0.0.2",
        ] {
            assert!(matches!(auth(&reader, suffix), Err(Error::Denied)));
        }
        let wrong = URL_SAFE_NO_PAD.encode([99; 32]);
        assert!(matches!(
            reader.authenticate(LOGIN, wrong.as_bytes(), Protocol::Http),
            Err(Error::InvalidCredentials)
        ));
    }

    #[test]
    fn draining_and_empty_pools_only_change_new_selections() {
        let reader = Reader::new(fixture()).unwrap();
        let live = auth(&reader, "-pool-15151515151515151515151515151515").unwrap();
        let mut next = fixture();
        next.revision = 2;
        next.routing.addresses[0].state = ResourceState::Draining;
        next.routing.addresses[0].revision = 2;
        reader.publish(next).unwrap();
        assert!(matches!(
            auth(&reader, "-pool-15151515151515151515151515151515"),
            Err(Error::Denied)
        ));
        assert!(matches!(
            auth(&reader, "-exit-14141414141414141414141414141414"),
            Err(Error::Denied)
        ));
        assert_eq!(live.source, Some("127.0.0.2".parse().unwrap()));
        let mut next = fixture();
        next.revision = 3;
        next.routing.pools[0].members.clear();
        reader.publish(next).unwrap();
        assert!(matches!(
            auth(&reader, "-pool-15151515151515151515151515151515"),
            Err(Error::Denied)
        ));
        assert!(auth(&reader, "-exit-14141414141414141414141414141414").is_ok());
    }

    #[test]
    fn malformed_catalog_never_silently_deduplicates_or_grants_missing_permissions() {
        let mut cases = Vec::new();
        let mut data = fixture();
        data.routing.permissions.clear();
        cases.push(data);
        let mut data = fixture();
        let duplicate = data.routing.permissions[0].exits[0].clone();
        data.routing.permissions[0].exits.push(duplicate);
        cases.push(data);
        let mut data = fixture();
        let mut duplicate = data.routing.addresses[0].clone();
        duplicate.id = URL_SAFE_NO_PAD.encode([30; 16]);
        data.routing.addresses.push(duplicate);
        cases.push(data);
        let mut data = fixture();
        data.routing.addresses[0].ip = "::ffff:127.0.0.2".parse().unwrap();
        cases.push(data);
        let mut data = fixture();
        data.routing.pools[0].family = AddressFamily::V6;
        cases.push(data);
        let mut data = fixture();
        data.routing.addresses[0].prefix_id = Some(URL_SAFE_NO_PAD.encode([40; 16]));
        cases.push(data);
        for data in cases {
            assert!(Reader::new(data).is_err());
        }
        assert!("127.0.0.1/8".parse::<cidr::IpCidr>().is_err());
    }
}
