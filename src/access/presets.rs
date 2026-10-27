//! Built-in TCP preset permissions, separate from source-address routing.
//!
//! A user or selected pool can suggest a default, but only the actual active
//! TCP operation checks and applies that suggestion. SOCKS authentication does
//! not yet know whether the command will be CONNECT, BIND or UDP ASSOCIATE.

use std::{
    collections::{HashMap, HashSet},
    io,
};

use serde::{Deserialize, Serialize};

use super::{Error, valid_id};
use crate::ebpf::Profile;

/// One user's complete preset grant. An empty grant preserves native sockets;
/// it never authorizes every built-in preset. IDs remain stable after deletion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserPreset {
    pub(crate) user_id: String,
    pub(crate) default_preset: Option<Profile>,
    /// At most the five distinct built-in presets. A default must be included.
    pub(crate) allowed_presets: Vec<Profile>,
}

impl UserPreset {
    /// Explicit compatibility record for a new or migrated native-only user.
    pub(crate) fn native(user_id: String) -> Self {
        Self {
            user_id,
            default_preset: None,
            allowed_presets: Vec::new(),
        }
    }
}

/// A shared pool's suggested TCP preset. It does not grant users permission to
/// apply it, and it has no effect on UDP or passive listening sockets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PoolPreset {
    pub(crate) pool_id: String,
    pub(crate) default_preset: Option<Profile>,
}

impl PoolPreset {
    /// Explicit native pool configuration, not an inferred missing-row fallback.
    pub(crate) fn native(pool_id: String) -> Self {
        Self {
            pool_id,
            default_preset: None,
        }
    }
}

/// The complete finite configuration is published with the access policy CAS.
/// Every durable user and pool, including tombstones, has exactly one record.
#[derive(Clone, Default)]
pub(crate) struct PresetData {
    pub(crate) users: Vec<UserPreset>,
    pub(crate) pools: Vec<PoolPreset>,
}

#[cfg(test)]
impl PresetData {
    /// Test fixtures still declare their exact user/pool set; this helper must
    /// not become a production missing-row compatibility fallback.
    pub(crate) fn native(
        users: impl IntoIterator<Item = String>,
        pools: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            users: users.into_iter().map(UserPreset::native).collect(),
            pools: pools.into_iter().map(PoolPreset::native).collect(),
        }
    }
}

/// Non-secret cold-path mutation result. Replay returns only the stable receipt
/// reference, never a configuration guessed from a newer policy revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum PresetEntity {
    User(UserPreset),
    Pool(PoolPreset),
}

/// An admitted flow keeps only these copied choices, not the policy or maps.
/// A default is intentionally unresolved until the protocol knows its command.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Selection {
    requested: Option<Profile>,
    default: Option<Profile>,
    allowed: u8,
}

impl Selection {
    /// Resolves one active TCP operation. Explicit device beats pool default,
    /// then user default; native requires no grant. A denied choice never falls
    /// back to another preset or silently becomes native.
    pub(crate) fn tcp(self) -> Result<Option<Profile>, Error> {
        let selected = self.requested.or(self.default);
        if selected.is_some_and(|value| self.allowed & bit(value) == 0) {
            return Err(Error::Denied);
        }
        Ok(selected)
    }

    /// Non-TCP operations reject an explicit device instead of ignoring it.
    /// Defaults alone must not reject UDP or passive BIND at authentication.
    pub(crate) const fn explicit(self) -> bool {
        self.requested.is_some()
    }
}

struct User {
    default: Option<Profile>,
    allowed: u8,
}

/// Immutable indexes built off the data plane; admission performs no I/O.
pub(super) struct Compiled {
    users: HashMap<String, User>,
    pools: HashMap<String, Option<Profile>>,
}

impl Compiled {
    /// A route has already authorized and selected the optional pool. A pool
    /// default is only a suggestion and cannot enlarge this user's grant.
    pub(super) fn select(
        &self,
        user_id: &str,
        pool_id: Option<&str>,
        requested: Option<Profile>,
    ) -> Result<Selection, Error> {
        let user = self.users.get(user_id).ok_or(Error::Unavailable)?;
        if requested.is_some_and(|value| user.allowed & bit(value) == 0) {
            return Err(Error::Denied);
        }
        let pool = pool_id
            .map(|id| self.pools.get(id).copied().ok_or(Error::Unavailable))
            .transpose()?
            .flatten();
        Ok(Selection {
            requested,
            default: pool.or(user.default),
            allowed: user.allowed,
        })
    }
}

/// Validates exact relationships, uniqueness and the fixed five-preset bound.
/// Missing rows fail closed rather than inventing a permissive default.
pub(super) fn compile(
    data: PresetData,
    users: &HashSet<&str>,
    pools: &HashSet<&str>,
) -> io::Result<Compiled> {
    if data.users.len() != users.len() || data.pools.len() != pools.len() {
        return Err(invalid());
    }
    let mut compiled_users = HashMap::with_capacity(users.len());
    for value in data.users {
        if !valid_id(&value.user_id) || !users.contains(value.user_id.as_str()) {
            return Err(invalid());
        }
        let allowed = allowed_mask(&value)?;
        if compiled_users
            .insert(
                value.user_id,
                User {
                    default: value.default_preset,
                    allowed,
                },
            )
            .is_some()
        {
            return Err(invalid());
        }
    }
    let mut compiled_pools = HashMap::with_capacity(pools.len());
    for value in data.pools {
        if !valid_id(&value.pool_id)
            || !pools.contains(value.pool_id.as_str())
            || compiled_pools
                .insert(value.pool_id, value.default_preset)
                .is_some()
        {
            return Err(invalid());
        }
    }
    Ok(Compiled {
        users: compiled_users,
        pools: compiled_pools,
    })
}

/// Applies the same complete relationship checks without publishing a policy.
/// Management read/write snapshots use this before exposing or committing data.
pub(crate) fn validate(
    data: &PresetData,
    users: &HashSet<&str>,
    pools: &HashSet<&str>,
) -> io::Result<()> {
    compile(data.clone(), users, pools).map(|_| ())
}

/// Shared cold-path validation for SQLite mutations and candidate compilation.
pub(crate) fn allowed_mask(value: &UserPreset) -> io::Result<u8> {
    if value.allowed_presets.len() > 5 {
        return Err(invalid());
    }
    let mut allowed = 0;
    for &profile in &value.allowed_presets {
        let flag = bit(profile);
        if allowed & flag != 0 {
            return Err(invalid());
        }
        allowed |= flag;
    }
    if value
        .default_preset
        .is_some_and(|profile| allowed & bit(profile) == 0)
    {
        return Err(invalid());
    }
    Ok(allowed)
}

/// Strict v2 device prefix only. Removing it leaves the old route bytes intact,
/// so session/range hashes and exact exit/pool selectors do not change.
pub(super) fn split(suffix: &str) -> Result<(Option<Profile>, &str), Error> {
    let Some(value) = suffix.strip_prefix("device-") else {
        return Ok((None, suffix));
    };
    let (name, route) = value.split_once('-').unwrap_or((value, ""));
    let profile = name.parse::<Profile>().map_err(|_| Error::Denied)?;
    if name.len() != value.len() && route.is_empty() {
        return Err(Error::Denied);
    }
    Ok((Some(profile), route))
}

pub(crate) const fn bit(profile: Profile) -> u8 {
    match profile {
        Profile::Windows => 1,
        Profile::Linux => 2,
        Profile::Android => 4,
        Profile::MacOs => 8,
        Profile::Ios => 16,
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "managed TCP preset configuration is malformed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD.encode([byte; 16])
    }

    #[test]
    fn selection_defers_defaults_but_never_downgrades_a_tcp_denial() {
        let user = id(1);
        let pool = id(2);
        let compiled = compile(
            PresetData {
                users: vec![UserPreset {
                    user_id: user.clone(),
                    default_preset: Some(Profile::Linux),
                    allowed_presets: vec![Profile::Linux, Profile::Windows],
                }],
                pools: vec![PoolPreset {
                    pool_id: pool.clone(),
                    default_preset: Some(Profile::Ios),
                }],
            },
            &HashSet::from([user.as_str()]),
            &HashSet::from([pool.as_str()]),
        )
        .unwrap();
        let selected = compiled.select(&user, Some(&pool), None).unwrap();
        assert!(
            !selected.explicit(),
            "a default must not reject UDP authentication"
        );
        assert_eq!(selected.tcp(), Err(Error::Denied));
        let explicit = compiled
            .select(&user, Some(&pool), Some(Profile::Windows))
            .unwrap();
        assert!(explicit.explicit());
        assert_eq!(explicit.tcp(), Ok(Some(Profile::Windows)));
        assert_eq!(
            compiled.select(&user, None, None).unwrap().tcp(),
            Ok(Some(Profile::Linux))
        );
        assert!(matches!(
            compiled.select(&user, None, Some(Profile::Android)),
            Err(Error::Denied)
        ));
    }

    #[test]
    fn missing_duplicate_and_ungranted_configuration_fails_closed() {
        let user = id(1);
        let users = HashSet::from([user.as_str()]);
        assert!(compile(PresetData::default(), &users, &HashSet::new()).is_err());
        for value in [
            UserPreset {
                user_id: user.clone(),
                default_preset: Some(Profile::Linux),
                allowed_presets: vec![],
            },
            UserPreset {
                user_id: user.clone(),
                default_preset: None,
                allowed_presets: vec![Profile::Linux, Profile::Linux],
            },
        ] {
            assert!(
                compile(
                    PresetData {
                        users: vec![value],
                        pools: vec![]
                    },
                    &users,
                    &HashSet::new()
                )
                .is_err()
            );
        }
        let native = compile(
            PresetData {
                users: vec![UserPreset::native(user.clone())],
                pools: vec![],
            },
            &users,
            &HashSet::new(),
        )
        .unwrap();
        assert_eq!(native.select(&user, None, None).unwrap().tcp(), Ok(None));
        assert!(matches!(
            native.select(&user, None, Some(Profile::Linux)),
            Err(Error::Denied)
        ));
    }

    #[test]
    fn device_prefix_preserves_the_exact_remaining_v2_route() {
        for route in [
            "",
            "session-client_a",
            "range-client_a",
            "ttl-10",
            "exit-0123456789abcdef0123456789abcdef",
            "pool-0123456789abcdef0123456789abcdef",
        ] {
            let suffix = if route.is_empty() {
                "device-windows".to_owned()
            } else {
                format!("device-windows-{route}")
            };
            assert_eq!(split(&suffix), Ok((Some(Profile::Windows), route)));
            assert_eq!(split(route), Ok((None, route)));
        }
        for value in [
            "device-",
            "device-native",
            "device-Windows",
            "device-windows-",
        ] {
            assert_eq!(split(value), Err(Error::Denied));
        }
    }
}
