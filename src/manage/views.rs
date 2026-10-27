//! Non-secret, bounded management projections shared by browser and node APIs.
//!
//! These types do not grant authority. Clients validate numeric and relationship
//! invariants within their own authenticated transport; node mTLS authorization
//! is separate from the read-only Bearer API. Each transport bounds its replies.

use std::{
    io,
    net::{IpAddr, SocketAddr},
};

use serde::{Deserialize, Serialize};

use super::{health, store};
use crate::access::{
    Protocol,
    routing::{self, AddressFamily, ResourceState},
};

/// Public user metadata only, shared without browser sessions, node transport
/// identities or proxy credential verifiers. Deleted IDs remain historical.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct User {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) active: bool,
    pub(super) deleted: bool,
    pub(super) protocols: Vec<Protocol>,
    pub(super) concurrent_limit: u32,
    pub(super) revision: String,
}

impl From<store::UserView> for User {
    fn from(value: store::UserView) -> Self {
        Self {
            id: value.id,
            name: value.name,
            active: value.active,
            deleted: value.deleted,
            protocols: value.protocols,
            concurrent_limit: value.concurrent_limit,
            revision: value.revision.to_string(),
        }
    }
}

/// Parse a canonical positive SQLite revision, not a signed number or an
/// arbitrary JSON integer. Invalid remote values return fixed, non-secret errors.
pub(super) fn revision(value: &str) -> io::Result<u64> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid management revision");
    if value.is_empty()
        || value.len() > 19
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(invalid)
}

/// Validate one bounded user projection. A page decoder must additionally
/// check its page revision, requested filters, ordering and continuation.
pub(super) fn validate_user(user: &User) -> io::Result<()> {
    revision(&user.revision)?;
    let mut mask = 0u8;
    for protocol in &user.protocols {
        let bit = match protocol {
            Protocol::Http => 1,
            Protocol::Socks5 => 2,
            Protocol::Masque => 4,
        };
        if mask & bit != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate management user protocol",
            ));
        }
        mask |= bit;
    }
    if !store::valid_id(&user.id)
        || user.name.is_empty()
        || user.name.len() > 128
        || user.name.trim() != user.name
        || user.name.chars().any(char::is_control)
        || !(1..=1_000_000).contains(&user.concurrent_limit)
        || (user.deleted && user.active)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid management user metadata",
        ));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Prefix {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) cidr: String,
    pub(super) retired: bool,
    pub(super) revision: String,
}
impl From<routing::PrefixRecord> for Prefix {
    fn from(value: routing::PrefixRecord) -> Self {
        Self {
            id: value.id,
            name: value.name,
            cidr: value.cidr.to_string(),
            retired: value.retired,
            revision: value.revision.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Address {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) ip: IpAddr,
    pub(super) prefix_id: Option<String>,
    pub(super) state: ResourceState,
    pub(super) revision: String,
}
impl From<routing::AddressRecord> for Address {
    fn from(value: routing::AddressRecord) -> Self {
        Self {
            id: value.id,
            name: value.name,
            ip: value.ip,
            prefix_id: value.prefix_id,
            state: value.state,
            revision: value.revision.to_string(),
        }
    }
}

/// One exact address and its catalog revision from the same read snapshot.
/// Retired addresses retain their identity and remain readable.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AddressView {
    pub(super) revision: String,
    pub(super) address: Address,
}

/// Pool pages never inline an arbitrarily large membership list.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pool {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) family: AddressFamily,
    pub(super) state: ResourceState,
    pub(super) member_count: usize,
    pub(super) revision: String,
}
impl From<routing::PoolRecord> for Pool {
    fn from(value: routing::PoolRecord) -> Self {
        Self {
            id: value.id,
            name: value.name,
            family: value.family,
            state: value.state,
            member_count: value.members.len(),
            revision: value.revision.to_string(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Permission {
    pub(super) user_id: String,
    pub(super) legacy_allowed: bool,
    pub(super) exits: Vec<String>,
    pub(super) pools: Vec<String>,
}
impl From<routing::RoutePermission> for Permission {
    fn from(value: routing::RoutePermission) -> Self {
        Self {
            user_id: value.user_id,
            legacy_allowed: value.legacy_allowed,
            exits: value.exits,
            pools: value.pools,
        }
    }
}

/// One bounded page; a revision is not a coherent multi-request snapshot over
/// legacy pagination. Search continuations carry their separate bindings.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Page<T> {
    pub(super) revision: String,
    pub(super) items: Vec<T>,
    pub(super) next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PermissionView {
    pub(super) revision: String,
    pub(super) permission: Permission,
}

/// First-acceptance projection only. Replay uses the durable reference, not a
/// reconstruction from the resource's potentially newer current contents.
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum Entity {
    Prefix(Prefix),
    Address(Address),
    Pool(Pool),
    Permission(Permission),
}
impl From<routing::RoutingEntity> for Entity {
    fn from(value: routing::RoutingEntity) -> Self {
        match value {
            routing::RoutingEntity::Prefix(value) => Self::Prefix(value.into()),
            routing::RoutingEntity::Address(value) => Self::Address(value.into()),
            routing::RoutingEntity::Pool(value) => Self::Pool(value.into()),
            routing::RoutingEntity::Permission(value) => Self::Permission(value.into()),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HealthCheck {
    pub(super) kind: health::CheckKind,
    pub(super) target: Option<SocketAddr>,
    pub(super) outcome: health::FixedOutcome,
    pub(super) sequence: Option<String>,
    pub(super) observed_at_unix_ms: Option<u64>,
    pub(super) age_millis: Option<u64>,
    pub(super) latency_millis: Option<u64>,
}
impl From<health::CheckView> for HealthCheck {
    fn from(value: health::CheckView) -> Self {
        Self {
            kind: value.kind,
            target: value.target,
            outcome: value.outcome,
            sequence: value.sequence.map(|v| v.to_string()),
            observed_at_unix_ms: value.observed_at_unix_ms,
            age_millis: value.age_millis,
            latency_millis: value.latency_millis,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HealthEntry {
    pub(super) address_id: String,
    pub(super) address_revision: String,
    pub(super) ip: IpAddr,
    pub(super) checks: Vec<HealthCheck>,
}
impl From<health::Entry> for HealthEntry {
    fn from(value: health::Entry) -> Self {
        Self {
            address_id: value.address_id,
            address_revision: value.address_revision.to_string(),
            ip: value.ip,
            checks: value.checks.into_iter().map(Into::into).collect(),
        }
    }
}

/// Health is a timed observation, not a routing policy or global IP verdict.
/// String integers preserve the runtime's full counter precision on the wire.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HealthPage {
    pub(super) boot_id: String,
    pub(super) sequence: String,
    pub(super) catalog_revision: Option<String>,
    pub(super) catalog_loaded: bool,
    pub(super) catalog_error: Option<String>,
    pub(super) catalog_observed_at_unix_ms: Option<u64>,
    pub(super) catalog_age_millis: Option<u64>,
    pub(super) in_flight: usize,
    pub(super) entries: Vec<HealthEntry>,
    pub(super) next_cursor: Option<String>,
}
impl HealthPage {
    /// Inputs are already paginated by the authenticated transport. Keep the
    /// existing local field order and representation, including null fields.
    pub(super) fn new(snapshot: health::Snapshot, next_cursor: Option<String>) -> Self {
        Self {
            boot_id: snapshot.boot_id,
            sequence: snapshot.sequence.to_string(),
            catalog_revision: snapshot.catalog_revision.map(|v| v.to_string()),
            catalog_loaded: snapshot.catalog_loaded,
            catalog_error: snapshot.catalog_error.map(str::to_owned),
            catalog_observed_at_unix_ms: snapshot.catalog_observed_at_unix_ms,
            catalog_age_millis: snapshot.catalog_age_millis,
            in_flight: snapshot.in_flight,
            entries: snapshot.entries.into_iter().map(Into::into).collect(),
            next_cursor,
        }
    }
}

/// Historical non-secret result. `saved` refers to a past database commit, not
/// the current runtime, user state or delivery of any credential.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Operation {
    pub(in crate::manage) id: String,
    pub(in crate::manage) node_id: String,
    pub(in crate::manage) sequence: String,
    pub(in crate::manage) expected_revision: String,
    pub(in crate::manage) expected_epoch: String,
    pub(in crate::manage) action: String,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::manage) user_id: Option<String>,
    pub(in crate::manage) state: String,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::manage) saved_revision: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::manage) rejection: Option<String>,
}

// The contract requires nullable fields to be present. Serde's default Option
// handling accepts missing fields; an explicit deserializer retains that check.
pub(in crate::manage) fn required_nullable<'de, D, T>(
    deserializer: D,
) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

impl Operation {
    /// Check public state relationships without coupling to the store's opaque
    /// ID layout or comparing history to a newer context snapshot.
    pub(in crate::manage) fn validate(&self, node_id: &str) -> io::Result<u64> {
        if !store::valid_id(&self.id) || self.node_id != node_id {
            return Err(operation_response_error());
        }
        let sequence = self::revision(&self.sequence).map_err(|_| operation_response_error())?;
        let revision =
            self::revision(&self.expected_revision).map_err(|_| operation_response_error())?;
        self::revision(&self.expected_epoch).map_err(|_| operation_response_error())?;
        let create = match self.action.as_str() {
            "create_user" => true,
            "update_user" | "set_user_active" | "delete_user" => false,
            _ => return Err(operation_response_error()),
        };
        if self
            .user_id
            .as_deref()
            .is_some_and(|id| !store::valid_id(id))
        {
            return Err(operation_response_error());
        }
        let valid = match self.state.as_str() {
            "saved" => {
                let saved = self
                    .saved_revision
                    .as_deref()
                    .map(self::revision)
                    .transpose()
                    .map_err(|_| operation_response_error())?;
                self.user_id.is_some()
                    && self.rejection.is_none()
                    && saved.is_some()
                    && saved == revision.checked_add(1)
            }
            "reserved" | "rejected" => {
                self.saved_revision.is_none()
                    && (self.user_id.is_none() == create)
                    && match self.state.as_str() {
                        "reserved" => self.rejection.is_none(),
                        _ => self.rejection.as_deref().is_some_and(|code| {
                            matches!(
                                code,
                                "invalid_policy"
                                    | "policy_conflict"
                                    | "resource_not_found"
                                    | "policy_capacity"
                                    | "resource_managed"
                                    | "owner_conflict"
                            )
                        }),
                    }
            }
            _ => false,
        };
        if !valid {
            return Err(operation_response_error());
        }
        Ok(sequence)
    }
}

fn operation_response_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "inconsistent management operation response",
    )
}
