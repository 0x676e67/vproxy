//! Bounded, strongly held credential/protocol accounting identities.
//!
//! Only policy compilation and background sampling use the registry mutex.
//! Admitted flows already own their direct counter: forwarding never looks up
//! an identity, locks this map or resets values after a checkpoint.

use std::{
    collections::{HashMap, HashSet},
    io,
    sync::{Arc, Mutex},
};

use crate::traffic::{Counter, Snapshot};

use super::{MAX_CREDENTIALS, MAX_USERS, Policy, routing::MAX_POOLS, valid_id};

/// Accounting identity, separate from the backwards-compatible user permission.
/// Slots 0..2 retain their durable meaning. Slot 0 is never used for new flows:
/// old HTTP-family bytes cannot retrospectively identify proxy TLS transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Protocol {
    HttpLegacy,
    Socks5,
    Masque,
    Http,
    Https,
}

pub(crate) const PROTOCOL_COUNT: usize = 5;
pub(crate) const PROTOCOLS: [Protocol; PROTOCOL_COUNT] = [
    Protocol::HttpLegacy,
    Protocol::Socks5,
    Protocol::Masque,
    Protocol::Http,
    Protocol::Https,
];

impl From<super::Protocol> for Protocol {
    fn from(value: super::Protocol) -> Self {
        match value {
            super::Protocol::Http => Self::Http,
            super::Protocol::Socks5 => Self::Socks5,
            super::Protocol::Masque => Self::Masque,
        }
    }
}

/// Compatibility projection only: older read protocols have one HTTP-family
/// position. Never write this combined value back into the historical slot.
pub(crate) fn legacy_values(values: [Snapshot; PROTOCOL_COUNT]) -> [Snapshot; 3] {
    [
        values[0].sum(values[3]).sum(values[4]),
        values[1],
        values[2],
    ]
}

pub(crate) fn legacy_window(values: [Option<Snapshot>; PROTOCOL_COUNT]) -> [Option<Snapshot>; 3] {
    let http = [values[0], values[3], values[4]]
        .into_iter()
        .flatten()
        .reduce(Snapshot::sum);
    [http, values[1], values[2]]
}
const MAX_SERIES: usize = MAX_CREDENTIALS * PROTOCOLS.len();
const ZERO: Snapshot = Snapshot {
    upload: 0,
    download: 0,
    saturated: false,
};

/// Restored absolute values, not a delta or a claim that old traffic was zero.
/// Storage validates durable provenance; this boundary additionally rejects
/// duplicate series, invalid identities, reassignment and excessive capacity.
pub(crate) struct Seed {
    pub(crate) user_id: String,
    pub(crate) credential_id: String,
    pub(crate) protocol: Protocol,
    pub(crate) value: Snapshot,
}

/// One sampled cumulative lower bound. It contains stable identity only, never
/// login text, secret/verifier material, session labels or a policy snapshot.
pub(crate) struct SeriesSnapshot {
    pub(crate) user_id: Arc<str>,
    pub(crate) credential_id: Arc<str>,
    pub(crate) protocol: Protocol,
    pub(crate) value: Snapshot,
}

/// Restored selected-pool totals, separate from primary credential totals.
pub(crate) struct PoolSeed {
    pub(crate) pool_id: String,
    pub(crate) protocol: Protocol,
    pub(crate) value: Snapshot,
}

/// Stable actual pool selection, not inferred from a potentially shared IP.
pub(crate) struct PoolSnapshot {
    pub(crate) pool_id: Arc<str>,
    pub(crate) protocol: Protocol,
    pub(crate) value: Snapshot,
}

struct CredentialMeters {
    user_id: Arc<str>,
    credential_id: Arc<str>,
    values: [Arc<Counter>; PROTOCOL_COUNT],
}

struct PoolMeters {
    id: Arc<str>,
    values: [Arc<Counter>; PROTOCOL_COUNT],
}

/// Permanent identity capacity bounds retained meters, including deleted or
/// revoked credentials and writes whose last flow has already disappeared.
/// This owner must outlive the final durable checkpoint, not just active flows.
pub(crate) struct Registry {
    credentials: Mutex<HashMap<String, CredentialMeters>>,
    pools: Mutex<HashMap<String, PoolMeters>>,
}

impl Registry {
    /// Restore at most 8192 credentials / 40960 protocol series. Missing protocol
    /// rows start at zero; duplicate rows and changing a credential's user fail.
    /// Construction performs no I/O and returns no partially initialized owner.
    pub(crate) fn new(seed: Vec<Seed>) -> io::Result<Arc<Self>> {
        if seed.len() > MAX_SERIES {
            return Err(invalid("traffic seed exceeds its series capacity"));
        }
        struct Pending {
            user_id: String,
            values: [Option<Snapshot>; PROTOCOL_COUNT],
        }
        let mut pending: HashMap<String, Pending> = HashMap::new();
        let mut users = HashSet::new();
        for value in seed {
            if !valid_id(&value.user_id) || !valid_id(&value.credential_id) {
                return Err(invalid("invalid traffic seed identity"));
            }
            users.insert(value.user_id.clone());
            let entry = pending
                .entry(value.credential_id)
                .or_insert_with(|| Pending {
                    user_id: value.user_id.clone(),
                    values: [None; PROTOCOL_COUNT],
                });
            if entry.user_id != value.user_id {
                return Err(invalid("traffic credential cannot change its user"));
            }
            let target = &mut entry.values[protocol_index(value.protocol)];
            if target.replace(value.value).is_some() {
                return Err(invalid("duplicate traffic seed series"));
            }
            if pending.len() > MAX_CREDENTIALS || users.len() > MAX_USERS {
                return Err(invalid("traffic seed exceeds its identity capacity"));
            }
        }
        let credentials = pending
            .into_iter()
            .map(|(id, pending)| {
                let meters = CredentialMeters {
                    user_id: Arc::from(pending.user_id),
                    credential_id: Arc::from(id.as_str()),
                    values: pending
                        .values
                        .map(|value| Arc::new(Counter::new(value.unwrap_or(ZERO)))),
                };
                (id, meters)
            })
            .collect();
        Ok(Arc::new(Self {
            credentials: Mutex::new(credentials),
            pools: Mutex::new(HashMap::new()),
        }))
    }

    /// Restore both bounded sets without exposing a partial registry. Missing
    /// protocols start at zero; invalid IDs, duplicates or >128 pools fail.
    pub(crate) fn with_pools(seed: Vec<Seed>, pools: Vec<PoolSeed>) -> io::Result<Arc<Self>> {
        if pools.len() > MAX_POOLS * PROTOCOLS.len() {
            return Err(invalid("traffic pool seed exceeds capacity"));
        }
        let mut pending: HashMap<String, [Option<Snapshot>; PROTOCOL_COUNT]> = HashMap::new();
        for pool in pools {
            if !valid_id(&pool.pool_id) {
                return Err(invalid("invalid traffic pool identity"));
            }
            let values = pending
                .entry(pool.pool_id)
                .or_insert([None; PROTOCOL_COUNT]);
            if values[protocol_index(pool.protocol)]
                .replace(pool.value)
                .is_some()
            {
                return Err(invalid("duplicate traffic pool series"));
            }
            if pending.len() > MAX_POOLS {
                return Err(invalid("traffic pool seed exceeds capacity"));
            }
        }
        let registry = Self::new(seed)?;
        let values = pending
            .into_iter()
            .map(|(id, values)| {
                let entry = PoolMeters {
                    id: Arc::from(id.as_str()),
                    values: values.map(|value| Arc::new(Counter::new(value.unwrap_or(ZERO)))),
                };
                (id, entry)
            })
            .collect();
        *registry.pools.lock().map_err(|_| unavailable())? = values;
        Ok(registry)
    }

    /// Sample pool groupings separately: adding these rows to credential rows
    /// when calculating a node total would count the same payload twice.
    pub(crate) fn pool_snapshot(&self) -> io::Result<Vec<PoolSnapshot>> {
        let handles = {
            let pools = self.pools.lock().map_err(|_| unavailable())?;
            let mut handles = Vec::with_capacity(pools.len() * PROTOCOLS.len());
            for entry in pools.values() {
                for (index, protocol) in PROTOCOLS.into_iter().enumerate() {
                    handles.push((entry.id.clone(), protocol, entry.values[index].clone()));
                }
            }
            handles
        };
        let mut values: Vec<_> = handles
            .into_iter()
            .map(|(pool_id, protocol, value)| PoolSnapshot {
                pool_id,
                protocol,
                value: value.snapshot(),
            })
            .collect();
        values.sort_unstable_by(|left, right| {
            left.pool_id
                .cmp(&right.pool_id)
                .then_with(|| protocol_index(left.protocol).cmp(&protocol_index(right.protocol)))
        });
        Ok(values)
    }

    /// Sample all bounded series in stable identity/protocol order. A short
    /// mutex copies small handles only; atomics are loaded after unlocking.
    /// Poison is an error, never zero traffic. This does not advance a durable
    /// watermark or reset values that race with persistence.
    pub(crate) fn snapshot(&self) -> io::Result<Vec<SeriesSnapshot>> {
        let handles = {
            let credentials = self.credentials.lock().map_err(|_| unavailable())?;
            let mut handles = Vec::with_capacity(credentials.len() * PROTOCOLS.len());
            for entry in credentials.values() {
                for (index, protocol) in PROTOCOLS.into_iter().enumerate() {
                    handles.push((
                        entry.user_id.clone(),
                        entry.credential_id.clone(),
                        protocol,
                        entry.values[index].clone(),
                    ));
                }
            }
            handles
        };
        let mut values: Vec<_> = handles
            .into_iter()
            .map(|(user_id, credential_id, protocol, value)| SeriesSnapshot {
                user_id,
                credential_id,
                protocol,
                value: value.snapshot(),
            })
            .collect();
        values.sort_unstable_by(|left, right| {
            left.credential_id
                .cmp(&right.credential_id)
                .then_with(|| protocol_index(left.protocol).cmp(&protocol_index(right.protocol)))
        });
        Ok(values)
    }

    /// Called only for a fully validated candidate, before it is published.
    /// All fallible checks/reservation precede insertion so a rejected candidate
    /// cannot consume historical capacity or reassign an existing counter.
    pub(super) fn bind(&self, policy: &mut Policy) -> io::Result<()> {
        let mut credentials = self.credentials.lock().map_err(|_| unavailable())?;
        // Only cold paths take these locks, always in credential→pool order.
        // Both complete preflights precede mutation of either identity set.
        let mut pools = self.pools.lock().map_err(|_| unavailable())?;
        let mut additional = 0usize;
        let mut users: HashSet<&str> = credentials
            .values()
            .map(|value| value.user_id.as_ref())
            .collect();
        for candidate in policy.credentials.values() {
            users.insert(&candidate.record.user_id);
            if let Some(previous) = credentials.get(&candidate.record.id) {
                if previous.user_id.as_ref() != candidate.record.user_id {
                    return Err(invalid("traffic credential cannot change its user"));
                }
            } else {
                additional = additional
                    .checked_add(1)
                    .ok_or_else(|| invalid("traffic capacity overflow"))?;
            }
        }
        let total = credentials
            .len()
            .checked_add(additional)
            .ok_or_else(|| invalid("traffic capacity overflow"))?;
        if total > MAX_CREDENTIALS || users.len() > MAX_USERS {
            return Err(invalid("traffic registry exceeds its identity capacity"));
        }
        let additional_pools = policy
            .pool_ids
            .iter()
            .filter(|id| !pools.contains_key(id.as_ref()))
            .count();
        let total_pools = pools
            .len()
            .checked_add(additional_pools)
            .ok_or_else(|| invalid("traffic pool capacity overflow"))?;
        if total_pools > MAX_POOLS {
            return Err(invalid("traffic pool registry exceeds capacity"));
        }
        drop(users);
        credentials.try_reserve(additional).map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "traffic registry allocation failed",
            )
        })?;
        pools.try_reserve(additional_pools).map_err(|_| {
            io::Error::new(io::ErrorKind::OutOfMemory, "traffic pool allocation failed")
        })?;
        policy
            .pool_traffic
            .try_reserve(policy.pool_ids.len())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "traffic pool binding allocation failed",
                )
            })?;
        for candidate in policy.credentials.values_mut() {
            let entry = credentials
                .entry(candidate.record.id.clone())
                .or_insert_with(|| CredentialMeters {
                    user_id: Arc::from(candidate.record.user_id.as_str()),
                    credential_id: candidate.id.clone(),
                    values: std::array::from_fn(|_| Arc::new(Counter::new(ZERO))),
                });
            candidate.traffic = Some(entry.values.clone());
        }
        for id in &policy.pool_ids {
            let entry = pools.entry(id.to_string()).or_insert_with(|| PoolMeters {
                id: id.clone(),
                values: std::array::from_fn(|_| Arc::new(Counter::new(ZERO))),
            });
            policy
                .pool_traffic
                .insert(id.to_string(), entry.values.clone());
        }
        Ok(())
    }
}

pub(crate) const fn protocol_index(protocol: Protocol) -> usize {
    match protocol {
        Protocol::HttpLegacy => 0,
        Protocol::Socks5 => 1,
        Protocol::Masque => 2,
        Protocol::Http => 3,
        Protocol::Https => 4,
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn unavailable() -> io::Error {
    io::Error::other("traffic registry unavailable")
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::*;
    use crate::{
        access::{
            Protocol as AccessProtocol, Reader,
            tests::{LOGIN, policy, secret},
        },
        traffic::Direction,
    };

    fn value(registry: &Registry, credential: &str, protocol: Protocol) -> Snapshot {
        registry
            .snapshot()
            .unwrap()
            .into_iter()
            .find(|row| row.credential_id.as_ref() == credential && row.protocol == protocol)
            .unwrap()
            .value
    }

    #[test]
    fn restored_meters_keep_protocol_identity_across_rotation_deletion_and_final_drop() {
        let initial = policy(1, 8);
        let credential = initial.credentials[0].id.clone();
        let user = initial.users[0].id.clone();
        let registry = Registry::new(vec![Seed {
            user_id: user,
            credential_id: credential.clone(),
            protocol: Protocol::Http,
            value: Snapshot {
                upload: 7,
                download: 11,
                saturated: false,
            },
        }])
        .unwrap();
        let reader = Reader::with_traffic(initial, registry.clone()).unwrap();
        let old = reader
            .authenticate(LOGIN, &secret(), AccessProtocol::Http)
            .unwrap();
        old.lease.meter(Direction::Upload).add(3);
        let other = reader
            .authenticate(LOGIN, &secret(), AccessProtocol::Socks5)
            .unwrap();
        other.lease.meter(Direction::Download).add(5);
        let mut rotated = policy(2, 8);
        let new_secret = URL_SAFE_NO_PAD.encode([9; 32]);
        rotated.credentials[0].verifier_revision = 2;
        rotated.credentials[0].secret_digest =
            crate::access::digest_secret(&credential, new_secret.as_bytes());
        reader.publish(rotated).unwrap();
        let current = reader
            .authenticate(LOGIN, new_secret.as_bytes(), AccessProtocol::Http)
            .unwrap();
        current.lease.meter(Direction::Download).add(13);
        let mut deleted = policy(3, 8);
        deleted.users[0].deleted = true;
        deleted.users[0].active = false;
        deleted.credentials[0].revoked = true;
        reader.publish(deleted).unwrap();
        old.lease.meter(Direction::Upload).add(17);
        drop((old, other, current, reader));
        assert_eq!(
            value(&registry, &credential, Protocol::Http),
            Snapshot {
                upload: 27,
                download: 24,
                saturated: false
            }
        );
        assert_eq!(
            value(&registry, &credential, Protocol::Socks5),
            Snapshot {
                upload: 0,
                download: 5,
                saturated: false
            }
        );
        assert_eq!(registry.snapshot().unwrap().len(), PROTOCOL_COUNT);
    }

    #[test]
    fn explicit_overlapping_pool_selection_keeps_old_flow_group_without_double_counting() {
        use crate::access::{
            routing::{AddressFamily, PoolRecord, ResourceState},
            tests::routed_policy,
        };
        let mut initial = routed_policy(1, 8);
        let credential = initial.credentials[0].id.clone();
        let address = initial.routing.addresses[0].id.clone();
        let pool_a = URL_SAFE_NO_PAD.encode([30; 16]);
        let pool_b = URL_SAFE_NO_PAD.encode([31; 16]);
        for id in [&pool_a, &pool_b] {
            initial.routing.pools.push(PoolRecord {
                id: id.clone(),
                name: "Overlapping source".into(),
                family: AddressFamily::V4,
                members: vec![address.clone()],
                state: ResourceState::Active,
                revision: 1,
            });
            initial.routing.permissions[0].pools.push(id.clone());
            initial
                .presets
                .pools
                .push(crate::access::presets::PoolPreset::native(id.clone()));
        }
        let registry = Registry::with_pools(
            Vec::new(),
            vec![PoolSeed {
                pool_id: pool_a.clone(),
                protocol: Protocol::Http,
                value: Snapshot {
                    upload: 7,
                    download: 0,
                    saturated: false,
                },
            }],
        )
        .unwrap();
        let reader = Reader::with_traffic(initial.clone(), registry.clone()).unwrap();
        let a = reader
            .authenticate(
                &format!("{LOGIN}-pool-{}", "1e".repeat(16)),
                &secret(),
                AccessProtocol::Http,
            )
            .unwrap();
        let b = reader
            .authenticate(
                &format!("{LOGIN}-pool-{}", "1f".repeat(16)),
                &secret(),
                AccessProtocol::Http,
            )
            .unwrap();
        let exit = reader
            .authenticate(
                &format!("{LOGIN}-exit-{}", "14".repeat(16)),
                &secret(),
                AccessProtocol::Http,
            )
            .unwrap();
        assert_eq!(a.source, b.source);
        assert_eq!(a.source, exit.source);
        let secure = reader
            .authenticate_http(
                &format!("{LOGIN}-pool-{}", "1e".repeat(16)),
                &secret(),
                true,
            )
            .unwrap();
        assert_eq!(secure.source, a.source);
        secure.lease.meter(Direction::Upload).add(17);
        a.lease.meter(Direction::Upload).add(3);
        b.lease.meter(Direction::Upload).add(11);
        exit.lease.meter(Direction::Upload).add(13);
        initial.revision = 2;
        initial.routing.pools[0].state = ResourceState::Draining;
        initial.routing.pools[0].revision = 2;
        reader.publish(initial).unwrap();
        assert!(
            reader
                .authenticate(
                    &format!("{LOGIN}-pool-{}", "1e".repeat(16)),
                    &secret(),
                    AccessProtocol::Http
                )
                .is_err()
        );
        a.lease.meter(Direction::Upload).add(5);
        drop((a, b, exit, secure, reader));
        assert_eq!(value(&registry, &credential, Protocol::Http).upload, 32);
        assert_eq!(value(&registry, &credential, Protocol::Https).upload, 17);
        let values = registry.pool_snapshot().unwrap();
        assert_eq!(
            values
                .iter()
                .find(|v| v.pool_id.as_ref() == pool_a && v.protocol == Protocol::Https)
                .unwrap()
                .value
                .upload,
            17
        );
        assert_eq!(
            values
                .iter()
                .find(|v| v.pool_id.as_ref() == pool_a && v.protocol == Protocol::Http)
                .unwrap()
                .value
                .upload,
            15
        );
        assert_eq!(
            values
                .iter()
                .find(|v| v.pool_id.as_ref() == pool_b && v.protocol == Protocol::Http)
                .unwrap()
                .value
                .upload,
            11
        );
    }
}
