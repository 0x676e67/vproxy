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

use super::{MAX_CREDENTIALS, MAX_USERS, Policy, Protocol, routing::MAX_POOLS, valid_id};

const PROTOCOLS: [Protocol; 3] = [Protocol::Http, Protocol::Socks5, Protocol::Masque];
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
    values: [Arc<Counter>; 3],
}

struct PoolMeters {
    id: Arc<str>,
    values: [Arc<Counter>; 3],
}

/// Permanent identity capacity bounds retained meters, including deleted or
/// revoked credentials and writes whose last flow has already disappeared.
/// This owner must outlive the final durable checkpoint, not just active flows.
pub(crate) struct Registry {
    credentials: Mutex<HashMap<String, CredentialMeters>>,
    pools: Mutex<HashMap<String, PoolMeters>>,
}

impl Registry {
    /// Restore at most 8192 credentials / 24576 protocol series. Missing protocol
    /// rows start at zero; duplicate rows and changing a credential's user fail.
    /// Construction performs no I/O and returns no partially initialized owner.
    pub(crate) fn new(seed: Vec<Seed>) -> io::Result<Arc<Self>> {
        if seed.len() > MAX_SERIES {
            return Err(invalid("traffic seed exceeds its series capacity"));
        }
        struct Pending {
            user_id: String,
            values: [Option<Snapshot>; 3],
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
                    values: [None; 3],
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
        let mut pending: HashMap<String, [Option<Snapshot>; 3]> = HashMap::new();
        for pool in pools {
            if !valid_id(&pool.pool_id) {
                return Err(invalid("invalid traffic pool identity"));
            }
            let values = pending.entry(pool.pool_id).or_insert([None; 3]);
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

pub(super) const fn protocol_index(protocol: Protocol) -> usize {
    match protocol {
        Protocol::Http => 0,
        Protocol::Socks5 => 1,
        Protocol::Masque => 2,
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
            Reader,
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
            .authenticate(LOGIN, &secret(), Protocol::Http)
            .unwrap();
        old.lease.meter(Direction::Upload).add(3);
        let other = reader
            .authenticate(LOGIN, &secret(), Protocol::Socks5)
            .unwrap();
        other.lease.meter(Direction::Download).add(5);
        let mut rotated = policy(2, 8);
        let new_secret = URL_SAFE_NO_PAD.encode([9; 32]);
        rotated.credentials[0].verifier_revision = 2;
        rotated.credentials[0].secret_digest =
            crate::access::digest_secret(&credential, new_secret.as_bytes());
        reader.publish(rotated).unwrap();
        let current = reader
            .authenticate(LOGIN, new_secret.as_bytes(), Protocol::Http)
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
        assert_eq!(registry.snapshot().unwrap().len(), 3);
    }

    #[test]
    fn invalid_seed_and_failed_publication_do_not_pollute_the_registry() {
        let initial = policy(1, 2);
        let credential = initial.credentials[0].id.clone();
        let user = initial.users[0].id.clone();
        let seed = || Seed {
            user_id: user.clone(),
            credential_id: credential.clone(),
            protocol: Protocol::Http,
            value: ZERO,
        };
        assert!(Registry::new(vec![seed(), seed()]).is_err());
        let mut wrong_owner = seed();
        wrong_owner.user_id = URL_SAFE_NO_PAD.encode([99; 16]);
        assert!(Registry::new(vec![seed(), wrong_owner]).is_err());
        let mut invalid_id = seed();
        invalid_id.credential_id = "not-canonical".into();
        assert!(Registry::new(vec![invalid_id]).is_err());
        let reader = Reader::new(initial).unwrap();
        let registry = reader.traffic_registry();
        let mut stale = policy(1, 2);
        stale.credentials[0].id = URL_SAFE_NO_PAD.encode([90; 16]);
        assert!(reader.publish(stale).is_err());
        assert_eq!(registry.snapshot().unwrap().len(), 3);
        let mut reassigned = policy(2, 2);
        let mut other_user = reassigned.users[0].clone();
        other_user.id = URL_SAFE_NO_PAD.encode([91; 16]);
        reassigned
            .routing
            .permissions
            .push(crate::access::routing::RoutePermission::legacy(
                other_user.id.clone(),
            ));
        reassigned.credentials[0].user_id = other_user.id.clone();
        let mut extra = reassigned.credentials[0].clone();
        extra.id = URL_SAFE_NO_PAD.encode([92; 16]);
        extra.login = "vp2_92929292929292929292929292929292".into();
        reassigned.credentials.push(extra);
        reassigned
            .presets
            .users
            .push(crate::access::presets::UserPreset::native(
                other_user.id.clone(),
            ));
        reassigned.users.push(other_user);
        assert!(reader.publish(reassigned).is_err());
        assert_eq!(reader.revision().unwrap(), 1);
        let rows = registry.snapshot().unwrap();
        assert_eq!(rows.len(), 3);
        assert!(
            rows.iter()
                .all(|row| row.user_id.as_ref() == user && row.credential_id.as_ref() == credential)
        );
    }

    #[test]
    fn full_historical_capacity_rejects_new_identity_without_partial_binding() {
        let initial = policy(1, 2);
        let user = initial.users[0].id.clone();
        let seed: Vec<_> = (0..MAX_CREDENTIALS)
            .map(|index| Seed {
                user_id: user.clone(),
                credential_id: URL_SAFE_NO_PAD.encode((index as u128).to_be_bytes()),
                protocol: Protocol::Http,
                value: ZERO,
            })
            .collect();
        let registry = Registry::new(seed).unwrap();
        assert_eq!(registry.snapshot().unwrap().len(), MAX_SERIES);
        assert!(Reader::with_traffic(initial, registry.clone()).is_err());
        assert_eq!(registry.snapshot().unwrap().len(), MAX_SERIES);
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
                Protocol::Http,
            )
            .unwrap();
        let b = reader
            .authenticate(
                &format!("{LOGIN}-pool-{}", "1f".repeat(16)),
                &secret(),
                Protocol::Http,
            )
            .unwrap();
        let exit = reader
            .authenticate(
                &format!("{LOGIN}-exit-{}", "14".repeat(16)),
                &secret(),
                Protocol::Http,
            )
            .unwrap();
        assert_eq!(a.source, b.source);
        assert_eq!(a.source, exit.source);
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
                    Protocol::Http
                )
                .is_err()
        );
        a.lease.meter(Direction::Upload).add(5);
        drop((a, b, exit, reader));
        assert_eq!(value(&registry, &credential, Protocol::Http).upload, 32);
        let values = registry.pool_snapshot().unwrap();
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

    #[test]
    fn full_pool_history_cannot_partially_insert_new_credential_meters() {
        use crate::access::{
            routing::{AddressFamily, PoolRecord, ResourceState},
            tests::routed_policy,
        };
        let pools = (0..MAX_POOLS)
            .map(|id| PoolSeed {
                pool_id: URL_SAFE_NO_PAD.encode((id as u128).to_be_bytes()),
                protocol: Protocol::Http,
                value: ZERO,
            })
            .collect();
        let registry = Registry::with_pools(Vec::new(), pools).unwrap();
        let mut candidate = routed_policy(1, 2);
        candidate.routing.pools.push(PoolRecord {
            id: URL_SAFE_NO_PAD.encode([90; 16]),
            name: "New pool".into(),
            family: AddressFamily::V4,
            members: Vec::new(),
            state: ResourceState::Active,
            revision: 1,
        });
        candidate
            .presets
            .pools
            .push(crate::access::presets::PoolPreset::native(
                URL_SAFE_NO_PAD.encode([90; 16]),
            ));
        assert!(Reader::with_traffic(candidate, registry.clone()).is_err());
        assert!(registry.snapshot().unwrap().is_empty());
        assert_eq!(registry.pool_snapshot().unwrap().len(), MAX_POOLS * 3);
    }
}
