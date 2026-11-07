//! Schema-5 finite egress inventory, permissions and actor-preserving audit.
//!
//! All writes run inside the existing policy CAS/owner transaction. IPs and IDs
//! remain tombstones, and no table or API attempts to configure the host network.

use super::{
    PolicyChange, random_id, read_overview, sqlite_error,
    users::{self, Actor},
    valid_id,
};
use crate::access::{
    PolicyData,
    routing::{
        self as model, AddressFamily, AddressRecord, PoolRecord, PrefixRecord, ResourceState,
        RoutePermission, RoutingData, RoutingEntity,
    },
};
use rusqlite::{Connection, params};
use std::{
    collections::{HashMap, HashSet},
    io,
    path::Path,
};

/// Add routing objects after v4, preserving existing policies and explicit legacy grants.
pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection.execute_batch("CREATE TABLE routing_prefixes(id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=22),name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),cidr TEXT NOT NULL UNIQUE,retired INTEGER NOT NULL CHECK(retired IN(0,1)),revision INTEGER NOT NULL CHECK(revision>=1)) STRICT;
    CREATE TABLE routing_addresses(id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=22),name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),address TEXT NOT NULL UNIQUE,prefix_id TEXT REFERENCES routing_prefixes(id) ON DELETE RESTRICT,state TEXT NOT NULL CHECK(state IN('active','draining','retired')),revision INTEGER NOT NULL CHECK(revision>=1)) STRICT;
    CREATE TABLE routing_pools(id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=22),name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),family TEXT NOT NULL CHECK(family IN('v4','v6')),state TEXT NOT NULL CHECK(state IN('active','draining','retired')),revision INTEGER NOT NULL CHECK(revision>=1)) STRICT;
    CREATE TABLE routing_pool_members(pool_id TEXT NOT NULL REFERENCES routing_pools(id) ON DELETE RESTRICT,address_id TEXT NOT NULL REFERENCES routing_addresses(id) ON DELETE RESTRICT,PRIMARY KEY(pool_id,address_id)) STRICT;
    CREATE TABLE routing_permissions(user_id TEXT PRIMARY KEY NOT NULL REFERENCES proxy_users(id) ON DELETE RESTRICT,legacy_allowed INTEGER NOT NULL CHECK(legacy_allowed IN(0,1))) STRICT;
    INSERT INTO routing_permissions SELECT id,1 FROM proxy_users;
    CREATE TABLE routing_exit_grants(user_id TEXT NOT NULL REFERENCES routing_permissions(user_id) ON DELETE RESTRICT,address_id TEXT NOT NULL REFERENCES routing_addresses(id) ON DELETE RESTRICT,PRIMARY KEY(user_id,address_id)) STRICT;
    CREATE TABLE routing_pool_grants(user_id TEXT NOT NULL REFERENCES routing_permissions(user_id) ON DELETE RESTRICT,pool_id TEXT NOT NULL REFERENCES routing_pools(id) ON DELETE RESTRICT,PRIMARY KEY(user_id,pool_id)) STRICT;
    CREATE TABLE routing_audit(sequence INTEGER PRIMARY KEY,entry TEXT NOT NULL CHECK(entry IN('local_management','node_management')),administrator_id TEXT REFERENCES administrators(id) ON DELETE RESTRICT,controller_node_id TEXT REFERENCES peers(node_id) ON DELETE RESTRICT,controller_epoch INTEGER CHECK(controller_epoch>=1),command_id INTEGER CHECK(command_id>=1),source_administrator_id TEXT,action TEXT NOT NULL CHECK(action IN('create_prefix','retire_prefix','create_address','set_address_state','create_pool','set_pool_state','add_pool_member','remove_pool_member','set_route_permission')),resource_id TEXT NOT NULL CHECK(length(resource_id)=22),policy_revision INTEGER NOT NULL CHECK(policy_revision>=1),CHECK((entry='local_management' AND administrator_id IS NOT NULL AND controller_node_id IS NULL AND controller_epoch IS NULL AND command_id IS NULL AND source_administrator_id IS NULL) OR (entry='node_management' AND administrator_id IS NULL AND controller_node_id IS NOT NULL AND controller_epoch IS NOT NULL AND command_id IS NOT NULL AND source_administrator_id IS NOT NULL AND length(source_administrator_id)=22))) STRICT;")
    .map_err(|error|sqlite_error("cannot create finite routing schema",error))
}

/// Read non-secret routing in one bounded snapshot. Schema<5 requires explicit migration.
/// This blocks on SQLite and belongs on the existing management blocking executor.
pub(in crate::manage) fn routing_data(directory: &Path) -> io::Result<(u64, RoutingData)> {
    let mut connection = super::peers::open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot inspect finite routing", error))?;
    let result = data_in(&transaction)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot finish finite routing inspection", error))?;
    Ok(result)
}

/// Validate bounded routing and its actual user set in the caller's snapshot.
pub(super) fn data_in(connection: &Connection) -> io::Result<(u64, RoutingData)> {
    if read_overview(connection)?.schema_version < 5 {
        return Err(corrupt());
    }
    let revision = users::read_state(connection)?.0;
    let data = read(connection)?;
    let users = {
        let mut statement = connection
            .prepare("SELECT id FROM proxy_users LIMIT 1025")
            .map_err(|error| sqlite_error("cannot inspect route owners", error))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| sqlite_error("cannot query route owners", error))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| sqlite_error("cannot read route owners", error))?
    };
    if users.len() > crate::access::MAX_USERS {
        return Err(corrupt());
    }
    model::validate(&data, &users.iter().map(String::as_str).collect(), revision)?;
    Ok((revision, data))
}

/// Caller supplies a read/write transaction; all relationship joins stay in this snapshot.
pub(super) fn read(connection: &Connection) -> io::Result<RoutingData> {
    let prefixes = collect(
        connection,
        "SELECT id,name,cidr,retired,revision FROM routing_prefixes ORDER BY id LIMIT 257",
        serde_rusqlite::from_row_with_columns::<PrefixRecord>,
    )?;
    let addresses = collect(
        connection,
        "SELECT id,name,address,prefix_id,state,revision FROM routing_addresses ORDER BY id LIMIT 1025",
        serde_rusqlite::from_row_with_columns::<AddressRecord>,
    )?;
    let mut pools = collect(
        connection,
        "SELECT id,name,family,state,revision FROM routing_pools ORDER BY id LIMIT 129",
        serde_rusqlite::from_row_with_columns::<PoolRecord>,
    )?;
    if prefixes.len() > model::MAX_PREFIXES
        || addresses.len() > model::MAX_ADDRESSES
        || pools.len() > model::MAX_POOLS
    {
        return Err(corrupt());
    }
    // One bounded cold-path index avoids scanning every pool for every member.
    // Duplicate parent identities are errors, never silently overwritten keys.
    let mut pool_indices = HashMap::with_capacity(pools.len());
    for (index, pool) in pools.iter().enumerate() {
        if pool_indices.insert(pool.id.clone(), index).is_some() {
            return Err(corrupt());
        }
    }
    let members = collect(
        connection,
        "SELECT pool_id,address_id FROM routing_pool_members ORDER BY pool_id,address_id LIMIT 8193",
        |row, _| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )?;
    if members.len() > model::MAX_MEMBERS {
        return Err(corrupt());
    }
    for (pool, address) in members {
        let index = *pool_indices.get(&pool).ok_or_else(corrupt)?;
        pools
            .get_mut(index)
            .ok_or_else(corrupt)?
            .members
            .push(address);
    }
    let mut permissions = collect(
        connection,
        "SELECT user_id,legacy_allowed FROM routing_permissions ORDER BY user_id LIMIT 1025",
        |row, _| {
            Ok(RoutePermission {
                user_id: row.get(0)?,
                legacy_allowed: users::read_bool(row, 1)?,
                exits: Vec::new(),
                pools: Vec::new(),
            })
        },
    )?;
    if permissions.len() > crate::access::MAX_USERS {
        return Err(corrupt());
    }
    let mut permission_indices = HashMap::with_capacity(permissions.len());
    for (index, permission) in permissions.iter().enumerate() {
        if permission_indices
            .insert(permission.user_id.clone(), index)
            .is_some()
        {
            return Err(corrupt());
        }
    }
    for (sql, is_exit) in [
        (
            "SELECT user_id,address_id FROM routing_exit_grants ORDER BY user_id,address_id LIMIT 32769",
            true,
        ),
        (
            "SELECT user_id,pool_id FROM routing_pool_grants ORDER BY user_id,pool_id LIMIT 32769",
            false,
        ),
    ] {
        let grants = collect(connection, sql, |row, _| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        if grants.len() > crate::access::MAX_USERS * model::MAX_GRANTS {
            return Err(corrupt());
        }
        for (user, id) in grants {
            let index = *permission_indices.get(&user).ok_or_else(corrupt)?;
            let permission = permissions.get_mut(index).ok_or_else(corrupt)?;
            if is_exit {
                permission.exits.push(id);
            } else {
                permission.pools.push(id);
            }
        }
    }
    Ok(RoutingData {
        prefixes,
        addresses,
        pools,
        permissions,
    })
}
fn collect<T>(
    connection: &Connection,
    sql: &str,
    mut read: impl FnMut(&rusqlite::Row<'_>, &[String]) -> Result<T, serde_rusqlite::Error>,
) -> io::Result<Vec<T>> {
    let mut statement = connection
        .prepare(sql)
        .map_err(|error| sqlite_error("cannot prepare finite routing inspection", error))?;
    let columns = serde_rusqlite::columns_from_statement(&statement);
    let rows = statement
        .query_and_then([], |row| read(row, &columns))
        .map_err(|error| sqlite_error("cannot query finite routing", error))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| sqlite_error("cannot read finite routing", error))
}

/// Change only a typed catalog object; the caller validates and commits the whole policy.
pub(super) fn mutate(
    policy: &mut PolicyData,
    change: PolicyChange,
) -> io::Result<(RoutingEntity, &'static str)> {
    let next = policy
        .revision
        .checked_add(1)
        .filter(|next| *next <= i64::MAX as u64)
        .ok_or_else(corrupt)?;
    let data = &mut policy.routing;
    match change {
        PolicyChange::CreatePrefix { name, cidr } => {
            name_valid(&name)?;
            if data.prefixes.len() >= model::MAX_PREFIXES {
                return Err(capacity());
            }
            if data.prefixes.iter().any(|entry| entry.cidr == cidr) {
                return Err(conflict());
            }
            let entry = PrefixRecord {
                id: random_id()?,
                name,
                cidr,
                retired: false,
                revision: next,
            };
            data.prefixes.push(entry.clone());
            Ok((RoutingEntity::Prefix(entry), "create_prefix"))
        }
        PolicyChange::RetirePrefix { id } => {
            id_valid(&id)?;
            if data.addresses.iter().any(|entry| {
                entry.prefix_id.as_deref() == Some(&id) && entry.state != ResourceState::Retired
            }) {
                return Err(conflict());
            }
            let entry = data
                .prefixes
                .iter_mut()
                .find(|entry| entry.id == id)
                .ok_or_else(missing)?;
            if entry.retired {
                return Err(conflict());
            }
            entry.retired = true;
            entry.revision = next;
            Ok((RoutingEntity::Prefix(entry.clone()), "retire_prefix"))
        }
        PolicyChange::CreateAddress {
            name,
            ip,
            prefix_id,
        } => {
            name_valid(&name)?;
            if !model::valid_ip(ip) {
                return Err(input());
            }
            if data.addresses.len() >= model::MAX_ADDRESSES {
                return Err(capacity());
            }
            if data.addresses.iter().any(|entry| entry.ip == ip) {
                return Err(conflict());
            }
            if let Some(id) = &prefix_id {
                id_valid(id)?;
                let prefix = data
                    .prefixes
                    .iter()
                    .find(|entry| &entry.id == id)
                    .ok_or_else(missing)?;
                if prefix.retired || !prefix.cidr.contains(&ip) {
                    return Err(input());
                }
            }
            let entry = AddressRecord {
                id: random_id()?,
                name,
                ip,
                prefix_id,
                state: ResourceState::Active,
                revision: next,
            };
            data.addresses.push(entry.clone());
            Ok((RoutingEntity::Address(entry), "create_address"))
        }
        PolicyChange::SetAddressState { id, state } => {
            id_valid(&id)?;
            let entry = data
                .addresses
                .iter_mut()
                .find(|entry| entry.id == id)
                .ok_or_else(missing)?;
            if entry.state == ResourceState::Retired {
                return Err(conflict());
            }
            entry.state = state;
            entry.revision = next;
            Ok((RoutingEntity::Address(entry.clone()), "set_address_state"))
        }
        PolicyChange::CreatePool { name, family } => {
            name_valid(&name)?;
            if data.pools.len() >= model::MAX_POOLS {
                return Err(capacity());
            }
            let entry = PoolRecord {
                id: random_id()?,
                name,
                family,
                members: Vec::new(),
                state: ResourceState::Active,
                revision: next,
            };
            data.pools.push(entry.clone());
            Ok((RoutingEntity::Pool(entry), "create_pool"))
        }
        PolicyChange::SetPoolState { id, state } => {
            id_valid(&id)?;
            let entry = data
                .pools
                .iter_mut()
                .find(|entry| entry.id == id)
                .ok_or_else(missing)?;
            if entry.state == ResourceState::Retired {
                return Err(conflict());
            }
            entry.state = state;
            entry.revision = next;
            Ok((RoutingEntity::Pool(entry.clone()), "set_pool_state"))
        }
        PolicyChange::AddPoolMember {
            pool_id,
            address_id,
        } => {
            id_valid(&pool_id)?;
            id_valid(&address_id)?;
            if data
                .pools
                .iter()
                .map(|entry| entry.members.len())
                .sum::<usize>()
                >= model::MAX_MEMBERS
            {
                return Err(capacity());
            }
            let address = data
                .addresses
                .iter()
                .find(|entry| entry.id == address_id)
                .ok_or_else(missing)?;
            let pool = data
                .pools
                .iter_mut()
                .find(|entry| entry.id == pool_id)
                .ok_or_else(missing)?;
            if pool.state == ResourceState::Retired
                || address.state == ResourceState::Retired
                || pool.family != AddressFamily::of(address.ip)
            {
                return Err(input());
            }
            if pool.members.contains(&address_id) {
                return Err(conflict());
            }
            pool.members.push(address_id);
            pool.revision = next;
            Ok((RoutingEntity::Pool(pool.clone()), "add_pool_member"))
        }
        PolicyChange::RemovePoolMember {
            pool_id,
            address_id,
        } => {
            id_valid(&pool_id)?;
            id_valid(&address_id)?;
            let pool = data
                .pools
                .iter_mut()
                .find(|entry| entry.id == pool_id)
                .ok_or_else(missing)?;
            if pool.state == ResourceState::Retired {
                return Err(conflict());
            }
            let index = pool
                .members
                .iter()
                .position(|id| id == &address_id)
                .ok_or_else(missing)?;
            pool.members.remove(index);
            pool.revision = next;
            Ok((RoutingEntity::Pool(pool.clone()), "remove_pool_member"))
        }
        PolicyChange::SetRoutePermission(permission) => {
            id_valid(&permission.user_id)?;
            if !policy
                .users
                .iter()
                .any(|user| user.id == permission.user_id && !user.deleted)
            {
                return Err(missing());
            }
            if permission.exits.len() > model::MAX_GRANTS
                || permission.pools.len() > model::MAX_GRANTS
                || permission.exits.iter().collect::<HashSet<_>>().len() != permission.exits.len()
                || permission.pools.iter().collect::<HashSet<_>>().len() != permission.pools.len()
            {
                return Err(input());
            }
            if permission.exits.iter().any(|id| {
                !data
                    .addresses
                    .iter()
                    .any(|entry| &entry.id == id && entry.state != ResourceState::Retired)
            }) || permission.pools.iter().any(|id| {
                !data
                    .pools
                    .iter()
                    .any(|entry| &entry.id == id && entry.state != ResourceState::Retired)
            }) {
                return Err(input());
            }
            let entry = data
                .permissions
                .iter_mut()
                .find(|entry| entry.user_id == permission.user_id)
                .ok_or_else(corrupt)?;
            *entry = permission.clone();
            Ok((
                RoutingEntity::Permission(permission),
                "set_route_permission",
            ))
        }
        _ => Err(input()),
    }
}

/// Persist only the changed metadata, never deleting resource tombstones.
pub(super) fn write_entity(connection: &Connection, entity: &RoutingEntity) -> io::Result<()> {
    match entity {
        RoutingEntity::Prefix(entry) => {
            connection.execute("INSERT INTO routing_prefixes VALUES(?1,?2,?3,?4,?5) ON CONFLICT(id) DO UPDATE SET retired=excluded.retired,revision=excluded.revision",params![entry.id,entry.name,entry.cidr.to_string(),entry.retired,number(entry.revision)?]).map_err(|error|sqlite_error("cannot save prefix asset",error))?;
        }
        RoutingEntity::Address(entry) => {
            connection.execute("INSERT INTO routing_addresses VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(id) DO UPDATE SET state=excluded.state,revision=excluded.revision",params![entry.id,entry.name,entry.ip.to_string(),entry.prefix_id,entry.state.as_str(),number(entry.revision)?]).map_err(|error|sqlite_error("cannot save concrete address asset",error))?;
        }
        RoutingEntity::Pool(entry) => {
            connection.execute("INSERT INTO routing_pools VALUES(?1,?2,?3,?4,?5) ON CONFLICT(id) DO UPDATE SET state=excluded.state,revision=excluded.revision",params![entry.id,entry.name,entry.family.as_str(),entry.state.as_str(),number(entry.revision)?]).map_err(|error|sqlite_error("cannot save finite pool",error))?;
            connection
                .execute(
                    "DELETE FROM routing_pool_members WHERE pool_id=?1",
                    [&entry.id],
                )
                .map_err(|error| sqlite_error("cannot replace finite pool members", error))?;
            for id in &entry.members {
                connection
                    .execute(
                        "INSERT INTO routing_pool_members VALUES(?1,?2)",
                        params![entry.id, id],
                    )
                    .map_err(|error| sqlite_error("cannot save finite pool member", error))?;
            }
        }
        RoutingEntity::Permission(entry) => write_permission(connection, entry)?,
    }
    Ok(())
}
/// Every user, including deleted history, retains an explicit permission record.
pub(super) fn write_permission(
    connection: &Connection,
    permission: &RoutePermission,
) -> io::Result<()> {
    connection.execute("INSERT INTO routing_permissions VALUES(?1,?2) ON CONFLICT(user_id) DO UPDATE SET legacy_allowed=excluded.legacy_allowed",params![permission.user_id,permission.legacy_allowed]).map_err(|error|sqlite_error("cannot save route permission",error))?;
    for table in ["routing_exit_grants", "routing_pool_grants"] {
        connection
            .execute(
                &format!("DELETE FROM {table} WHERE user_id=?1"),
                [&permission.user_id],
            )
            .map_err(|error| sqlite_error("cannot replace finite route grants", error))?;
    }
    for (table, ids) in [
        ("routing_exit_grants", &permission.exits),
        ("routing_pool_grants", &permission.pools),
    ] {
        for id in ids {
            connection
                .execute(
                    &format!("INSERT INTO {table} VALUES(?1,?2)"),
                    params![permission.user_id, id],
                )
                .map_err(|error| sqlite_error("cannot save finite route grant", error))?;
        }
    }
    Ok(())
}
/// Real local/remote actor identity; resource changes never invent a proxy user.
pub(super) fn audit(
    connection: &Connection,
    actor: Actor<'_>,
    action: &str,
    entity: &RoutingEntity,
    revision: u64,
) -> io::Result<()> {
    let id = match entity {
        RoutingEntity::Prefix(entry) => &entry.id,
        RoutingEntity::Address(entry) => &entry.id,
        RoutingEntity::Pool(entry) => &entry.id,
        RoutingEntity::Permission(entry) => &entry.user_id,
    };
    match actor {
        Actor::Automation { .. } => return Err(io::Error::new(io::ErrorKind::PermissionDenied, "automation routing changes are not authorized")),
        Actor::Local(administrator)=>connection.execute("INSERT INTO routing_audit(entry,administrator_id,action,resource_id,policy_revision) VALUES('local_management',?1,?2,?3,?4)",params![administrator,action,id,number(revision)?]),
        Actor::Remote{node_id,epoch,command_id,source_administrator_id}=>connection.execute("INSERT INTO routing_audit(entry,controller_node_id,controller_epoch,command_id,source_administrator_id,action,resource_id,policy_revision) VALUES('node_management',?1,?2,?3,?4,?5,?6,?7)",params![node_id,number(epoch)?,number(command_id)?,source_administrator_id,action,id,number(revision)?]),
    }.map_err(|error|sqlite_error("cannot audit finite routing change",error))?;
    connection.execute("DELETE FROM routing_audit WHERE sequence IN(SELECT sequence FROM routing_audit ORDER BY sequence DESC LIMIT -1 OFFSET 16384)",[]).map_err(|error|sqlite_error("cannot retain bounded routing audit",error))?;
    Ok(())
}
fn name_valid(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 128
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        Err(input())
    } else {
        Ok(())
    }
}
fn id_valid(id: &str) -> io::Result<()> {
    if valid_id(id) { Ok(()) } else { Err(input()) }
}
fn number(value: u64) -> io::Result<i64> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(corrupt)
}
fn input() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid finite routing change")
}
fn corrupt() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "finite routing storage is malformed",
    )
}
fn conflict() -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        "finite routing asset exists or is retired",
    )
}
fn missing() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "finite routing identity is not registered",
    )
}
fn capacity() -> io::Error {
    super::ControlError::PolicyCapacity.error()
}
