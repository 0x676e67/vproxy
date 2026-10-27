//! Schema-nine built-in TCP preset grants and actor-preserving policy writes.
//!
//! These records configure admission only. They never load a program, alter an
//! existing socket or claim that a preset backend is available on this host.

use std::{collections::HashSet, io, path::Path};

use rusqlite::{Connection, params};

use super::{
    PolicyChange, read_overview, sqlite_error,
    users::{self, Actor},
    valid_id,
};
use crate::{
    access::{
        self, PolicyData,
        presets::{self as model, PoolPreset, PresetData, PresetEntity, UserPreset},
    },
    ebpf::Profile,
};

const PRESETS: &str = "'windows','linux','android','macos','ios'";

/// Adds explicit native rows for every old durable identity. Missing records
/// after migration are corruption, not an implicit wildcard permission.
pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection.execute_batch(&format!(
        "CREATE TABLE user_presets(user_id TEXT PRIMARY KEY NOT NULL REFERENCES proxy_users(id) ON DELETE RESTRICT,
          default_preset TEXT CHECK(default_preset IN({PRESETS})),allowed_mask INTEGER NOT NULL CHECK(allowed_mask BETWEEN 0 AND 31),
          CHECK(default_preset IS NULL OR (allowed_mask & CASE default_preset WHEN 'windows' THEN 1 WHEN 'linux' THEN 2 WHEN 'android' THEN 4 WHEN 'macos' THEN 8 WHEN 'ios' THEN 16 END) != 0)) STRICT;
         INSERT INTO user_presets SELECT id,NULL,0 FROM proxy_users;
         CREATE TABLE pool_presets(pool_id TEXT PRIMARY KEY NOT NULL REFERENCES routing_pools(id) ON DELETE RESTRICT,
          default_preset TEXT CHECK(default_preset IN({PRESETS}))) STRICT;
         INSERT INTO pool_presets SELECT id,NULL FROM routing_pools;
         CREATE TABLE preset_audit(sequence INTEGER PRIMARY KEY CHECK(sequence>=1),
          entry TEXT NOT NULL CHECK(entry IN('local_management','node_management')),
          administrator_id TEXT REFERENCES administrators(id) ON DELETE RESTRICT,
          controller_node_id TEXT REFERENCES peers(node_id) ON DELETE RESTRICT,
          controller_epoch INTEGER CHECK(controller_epoch>=1),command_id INTEGER CHECK(command_id>=1),
          source_administrator_id TEXT CHECK(length(source_administrator_id)=22),
          action TEXT NOT NULL CHECK(action IN('set_user_presets','set_pool_preset')),
          user_id TEXT REFERENCES proxy_users(id) ON DELETE RESTRICT,
          pool_id TEXT REFERENCES routing_pools(id) ON DELETE RESTRICT,
          policy_revision INTEGER NOT NULL CHECK(policy_revision>=1),
          CHECK((action='set_user_presets' AND user_id IS NOT NULL AND pool_id IS NULL)
             OR (action='set_pool_preset' AND user_id IS NULL AND pool_id IS NOT NULL)),
          CHECK((entry='local_management' AND administrator_id IS NOT NULL AND controller_node_id IS NULL AND controller_epoch IS NULL AND command_id IS NULL AND source_administrator_id IS NULL)
             OR (entry='node_management' AND administrator_id IS NULL AND controller_node_id IS NOT NULL AND controller_epoch IS NOT NULL AND command_id IS NOT NULL AND source_administrator_id IS NOT NULL))) STRICT;"
    )).map_err(|error| sqlite_error("cannot create built-in preset policy schema", error))
}

/// Reads one complete non-secret configuration in a bounded read transaction.
/// Schema<9 requires explicit migration. This is blocking SQLite work.
pub(in crate::manage) fn presets_data(directory: &Path) -> io::Result<(u64, PresetData)> {
    super::control::read_snapshot(directory, data_in)
}

/// Reads a user grant and policy CAS together; IDs must be canonical and present.
pub(in crate::manage) fn user_presets(directory: &Path, id: &str) -> io::Result<(u64, UserPreset)> {
    if !valid_id(id) {
        return Err(invalid_input());
    }
    let (revision, data) = presets_data(directory)?;
    let value = data
        .users
        .into_iter()
        .find(|value| value.user_id == id)
        .ok_or_else(missing)?;
    Ok((revision, value))
}

/// Reads a pool suggestion and policy CAS without inferring user authorization.
pub(in crate::manage) fn pool_preset(directory: &Path, id: &str) -> io::Result<(u64, PoolPreset)> {
    if !valid_id(id) {
        return Err(invalid_input());
    }
    let (revision, data) = presets_data(directory)?;
    let value = data
        .pools
        .into_iter()
        .find(|value| value.pool_id == id)
        .ok_or_else(missing)?;
    Ok((revision, value))
}

/// Reads and validates actual relationships in the caller's authorized snapshot.
pub(super) fn data_in(connection: &Connection) -> io::Result<(u64, PresetData)> {
    if read_overview(connection)?.schema_version < 9 {
        return Err(corrupt());
    }
    let revision = users::read_state(connection)?.0;
    let data = read(connection)?;
    let users = ids(
        connection,
        "SELECT id FROM proxy_users ORDER BY id LIMIT 1025",
        access::MAX_USERS,
    )?;
    let pools = ids(
        connection,
        "SELECT id FROM routing_pools ORDER BY id LIMIT 129",
        access::routing::MAX_POOLS,
    )?;
    model::validate(
        &data,
        &users.iter().map(String::as_str).collect(),
        &pools.iter().map(String::as_str).collect(),
    )?;
    Ok((revision, data))
}

/// Load only finite rows. The enclosing policy validates the exact owner set.
pub(super) fn read(connection: &Connection) -> io::Result<PresetData> {
    let mut statement = connection.prepare("SELECT user_id,default_preset,allowed_mask FROM user_presets ORDER BY user_id LIMIT 1025")
        .map_err(|error| sqlite_error("cannot inspect user presets", error))?;
    let rows = statement
        .query_map([], |row| {
            let default_preset = profile(row.get::<_, Option<String>>(1)?)?;
            let mask: i64 = row.get(2)?;
            if !(0..=31).contains(&mask) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let allowed_presets = [
                Profile::Windows,
                Profile::Linux,
                Profile::Android,
                Profile::MacOs,
                Profile::Ios,
            ]
            .into_iter()
            .filter(|value| mask & i64::from(model::bit(*value)) != 0)
            .collect();
            Ok(UserPreset {
                user_id: row.get(0)?,
                default_preset,
                allowed_presets,
            })
        })
        .map_err(|error| sqlite_error("cannot query user presets", error))?;
    let users = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| sqlite_error("cannot read user presets", error))?;
    let mut statement = connection
        .prepare("SELECT pool_id,default_preset FROM pool_presets ORDER BY pool_id LIMIT 129")
        .map_err(|error| sqlite_error("cannot inspect pool presets", error))?;
    let rows = statement
        .query_map([], |row| {
            Ok(PoolPreset {
                pool_id: row.get(0)?,
                default_preset: profile(row.get::<_, Option<String>>(1)?)?,
            })
        })
        .map_err(|error| sqlite_error("cannot query pool presets", error))?;
    let pools = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| sqlite_error("cannot read pool presets", error))?;
    if users.len() > access::MAX_USERS || pools.len() > access::routing::MAX_POOLS {
        return Err(corrupt());
    }
    Ok(PresetData { users, pools })
}

/// Apply exactly the two preset mutations under the existing global CAS/owner
/// transaction. Deleted users and retired pools retain immutable history.
pub(super) fn mutate(
    connection: &Connection,
    policy: &mut PolicyData,
    change: PolicyChange,
) -> io::Result<PresetEntity> {
    match change {
        PolicyChange::SetUserPresets { presets } => {
            if !valid_id(&presets.user_id) {
                return Err(invalid_input());
            }
            let user = policy
                .users
                .iter()
                .find(|user| user.id == presets.user_id)
                .ok_or_else(missing)?;
            if user.deleted {
                return Err(conflict());
            }
            model::allowed_mask(&presets).map_err(|_| invalid_input())?;
            let value = policy
                .presets
                .users
                .iter_mut()
                .find(|value| value.user_id == presets.user_id)
                .ok_or_else(corrupt)?;
            write_user(connection, &presets)?;
            *value = presets.clone();
            Ok(PresetEntity::User(presets))
        }
        PolicyChange::SetPoolPreset { preset } => {
            if !valid_id(&preset.pool_id) {
                return Err(invalid_input());
            }
            let pool = policy
                .routing
                .pools
                .iter()
                .find(|pool| pool.id == preset.pool_id)
                .ok_or_else(missing)?;
            if pool.state == access::routing::ResourceState::Retired {
                return Err(conflict());
            }
            let value = policy
                .presets
                .pools
                .iter_mut()
                .find(|value| value.pool_id == preset.pool_id)
                .ok_or_else(corrupt)?;
            write_pool(connection, &preset)?;
            *value = preset.clone();
            Ok(PresetEntity::Pool(preset))
        }
        _ => Err(invalid_input()),
    }
}

/// Creation helpers are called in the same transaction as the actual identity.
pub(super) fn write_user(connection: &Connection, value: &UserPreset) -> io::Result<()> {
    let mask = model::allowed_mask(value).map_err(|_| invalid_input())?;
    connection.execute("INSERT INTO user_presets(user_id,default_preset,allowed_mask) VALUES(?1,?2,?3) ON CONFLICT(user_id) DO UPDATE SET default_preset=excluded.default_preset,allowed_mask=excluded.allowed_mask",
        params![value.user_id,value.default_preset.map(|value|value.to_string()),mask])
        .map_err(|error| sqlite_error("cannot save user presets",error))?;
    Ok(())
}
/// Save one validated pool's suggestion inside its creation or CAS transaction.
/// The policy caller rejects tombstones and validates the actual pool identity.
pub(super) fn write_pool(connection: &Connection, value: &PoolPreset) -> io::Result<()> {
    connection.execute("INSERT INTO pool_presets(pool_id,default_preset) VALUES(?1,?2) ON CONFLICT(pool_id) DO UPDATE SET default_preset=excluded.default_preset",
        params![value.pool_id,value.default_preset.map(|value|value.to_string())])
        .map_err(|error| sqlite_error("cannot save pool preset",error))?;
    Ok(())
}

/// Preserve the actual local administrator or TLS controller actor, not a fake
/// proxy user. Audit is bounded and contains no credentials, names or payload.
pub(super) fn audit(
    connection: &Connection,
    actor: Actor<'_>,
    entity: &PresetEntity,
    revision: u64,
) -> io::Result<()> {
    // SQLite otherwise chooses a random rowid after i64::MAX. That could sort
    // below the retention floor and silently lose the event being committed.
    let previous: i64 = connection
        .query_row(
            "SELECT COALESCE(MAX(sequence),0) FROM preset_audit",
            [],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot inspect preset audit sequence", error))?;
    let next = previous
        .checked_add(1)
        .filter(|value| previous >= 0 && *value > 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "preset audit sequence is exhausted",
            )
        })?;
    let (action, user, pool) = match entity {
        PresetEntity::User(value) => ("set_user_presets", Some(value.user_id.as_str()), None),
        PresetEntity::Pool(value) => ("set_pool_preset", None, Some(value.pool_id.as_str())),
    };
    let (entry, admin, controller, epoch, command, source) = match actor {
        Actor::Automation { .. } => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "automation preset changes are not authorized",
            ));
        }
        Actor::Local(id) => ("local_management", Some(id), None, None, None, None),
        Actor::Remote {
            node_id,
            epoch,
            command_id,
            source_administrator_id,
        } => (
            "node_management",
            None,
            Some(node_id),
            Some(users::sql_revision(epoch)?),
            Some(users::sql_revision(command_id)?),
            Some(source_administrator_id),
        ),
    };
    connection.execute("INSERT INTO preset_audit(sequence,entry,administrator_id,controller_node_id,controller_epoch,command_id,source_administrator_id,action,user_id,pool_id,policy_revision) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![next,entry,admin,controller,epoch,command,source,action,user,pool,users::sql_revision(revision)?])
        .map_err(|error| sqlite_error("cannot record preset policy actor",error))?;
    connection.execute("DELETE FROM preset_audit WHERE sequence NOT IN(SELECT sequence FROM preset_audit ORDER BY sequence DESC LIMIT 16384)",[])
        .map_err(|error| sqlite_error("cannot retain bounded preset audit",error))?;
    Ok(())
}

fn ids(connection: &Connection, sql: &str, limit: usize) -> io::Result<HashSet<String>> {
    let mut statement = connection
        .prepare(sql)
        .map_err(|error| sqlite_error("cannot inspect preset identities", error))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| sqlite_error("cannot query preset identities", error))?;
    let values = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| sqlite_error("cannot read preset identities", error))?;
    let size = values.len();
    let set = values.into_iter().collect::<HashSet<_>>();
    if size > limit || set.len() != size || set.iter().any(|id| !valid_id(id)) {
        return Err(corrupt());
    }
    Ok(set)
}
fn profile(value: Option<String>) -> rusqlite::Result<Option<Profile>> {
    value
        .map(|value| value.parse().map_err(|_| rusqlite::Error::InvalidQuery))
        .transpose()
}
fn corrupt() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "stored preset policy is malformed or requires migration",
    )
}
fn invalid_input() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "preset policy input is invalid",
    )
}
fn missing() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "preset policy identity is not registered",
    )
}
fn conflict() -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        "preset policy identity is permanently retired",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::store::{self, ChangeResult, apply_policy, initialize, update_lock};

    struct Fixture {
        directory: std::path::PathBuf,
        administrator: String,
    }
    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory =
                std::env::temp_dir().join(format!("vproxy-preset-store-{}", store::random_id()?));
            initialize(&directory, "preset node", "admin", "fixture PHC")?;
            let connection = super::super::peers::open_existing(&directory, false)?;
            let administrator = connection
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)?;
            Ok(Self {
                directory,
                administrator,
            })
        }
        fn change(&self, revision: u64, change: PolicyChange) -> io::Result<ChangeResult> {
            apply_policy(
                &self.directory,
                &self.administrator,
                revision,
                change,
                &update_lock(&self.directory)?,
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn complete_preset_policy_uses_global_cas_and_real_actor_without_fake_user() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let user = fixture
            .change(
                1,
                PolicyChange::CreateUser {
                    name: "preset user".into(),
                    protocols: vec![access::Protocol::Http],
                    concurrent_limit: 2,
                },
            )?
            .user
            .unwrap()
            .id;
        let pool = match fixture
            .change(
                2,
                PolicyChange::CreatePool {
                    name: "preset pool".into(),
                    family: access::routing::AddressFamily::V4,
                },
            )?
            .routing
            .unwrap()
        {
            access::routing::RoutingEntity::Pool(value) => value.id,
            _ => panic!("pool creation returned another entity"),
        };
        assert_eq!(
            user_presets(&fixture.directory, &user)?.1,
            UserPreset::native(user.clone())
        );
        assert_eq!(
            pool_preset(&fixture.directory, &pool)?.1,
            PoolPreset::native(pool.clone())
        );
        let presets = UserPreset {
            user_id: user.clone(),
            default_preset: Some(Profile::Linux),
            allowed_presets: vec![Profile::Windows, Profile::Linux],
        };
        let changed = fixture.change(
            3,
            PolicyChange::SetUserPresets {
                presets: presets.clone(),
            },
        )?;
        assert!(
            changed.user.is_none()
                && changed.credential.is_none()
                && changed.routing.is_none()
                && changed.secret.is_none()
        );
        assert!(matches!(changed.presets,Some(PresetEntity::User(ref value)) if value==&presets));
        assert_eq!(
            user_presets(&fixture.directory, &user)?,
            (4, presets.clone())
        );
        assert_eq!(
            fixture
                .change(
                    3,
                    PolicyChange::SetUserPresets {
                        presets: presets.clone()
                    }
                )
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        let invalid = UserPreset {
            allowed_presets: vec![],
            ..presets
        };
        assert_eq!(
            fixture
                .change(4, PolicyChange::SetUserPresets { presets: invalid })
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(presets_data(&fixture.directory)?.0, 4);
        fixture.change(
            4,
            PolicyChange::SetPoolPreset {
                preset: PoolPreset {
                    pool_id: pool.clone(),
                    default_preset: Some(Profile::Ios),
                },
            },
        )?;
        let connection = super::super::peers::open_existing(&fixture.directory, true)?;
        let actors:i64=connection.query_row("SELECT count(*) FROM preset_audit WHERE entry='local_management' AND administrator_id=?1 AND controller_node_id IS NULL",[&fixture.administrator],|row|row.get(0)).map_err(io::Error::other)?;
        assert_eq!(actors, 2);
        assert!(
            connection
                .execute(
                    "UPDATE preset_audit SET pool_id=?1 WHERE action='set_user_presets'",
                    [&pool]
                )
                .is_err()
        );
        connection
            .execute("DELETE FROM user_presets WHERE user_id=?1", [&user])
            .map_err(io::Error::other)?;
        assert!(presets_data(&fixture.directory).is_err());
        assert!(store::load_policy(&fixture.directory).is_err());
        Ok(())
    }

    #[test]
    fn failed_schema_nine_upgrade_rolls_back_all_new_objects_and_keeps_backup() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.change(
            1,
            PolicyChange::CreateUser {
                name: "preserved user".into(),
                protocols: vec![access::Protocol::Http],
                concurrent_limit: 1,
            },
        )?;
        let node = store::inspect(&fixture.directory)?.node_id;
        let connection = super::super::peers::open_existing(&fixture.directory, true)?;
        super::super::control::reconstruct_v8(&connection)?;
        connection
            .execute_batch("CREATE TABLE controller_audit_v9(operator_fixture TEXT);")
            .map_err(io::Error::other)?;
        let backup = fixture
            .directory
            .join("schema8-before-failed-upgrade.sqlite3");
        assert!(store::migrate(&fixture.directory, &backup).is_err());
        assert_eq!(store::inspect(&fixture.directory)?.schema_version, 8);
        assert_eq!(store::inspect(&fixture.directory)?.node_id, node);
        assert_eq!(store::load_policy(&fixture.directory)?.revision, 2);
        assert!(connection.prepare("SELECT * FROM user_presets").is_err());
        assert!(
            connection
                .prepare("SELECT preset_kind FROM control_outbox")
                .is_err()
        );
        assert!(
            connection
                .prepare("SELECT operator_fixture FROM controller_audit_v9")
                .is_ok()
        );
        let copied = Connection::open(backup).map_err(io::Error::other)?;
        assert_eq!(store::read_overview(&copied)?.schema_version, 8);
        assert!(
            copied
                .prepare("SELECT operator_fixture FROM controller_audit_v9")
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn exhausted_preset_audit_cannot_commit_an_unrecorded_policy_change() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let user = fixture
            .change(
                1,
                PolicyChange::CreateUser {
                    name: "audit owner".into(),
                    protocols: vec![access::Protocol::Http],
                    concurrent_limit: 1,
                },
            )?
            .user
            .unwrap()
            .id;
        let initial = UserPreset {
            user_id: user,
            default_preset: Some(Profile::Linux),
            allowed_presets: vec![Profile::Linux],
        };
        fixture.change(
            2,
            PolicyChange::SetUserPresets {
                presets: initial.clone(),
            },
        )?;
        let connection = super::super::peers::open_existing(&fixture.directory, true)?;
        connection
            .execute("UPDATE preset_audit SET sequence=?1", [i64::MAX])
            .map_err(io::Error::other)?;
        let error = fixture
            .change(
                3,
                PolicyChange::SetUserPresets {
                    presets: UserPreset {
                        default_preset: Some(Profile::Windows),
                        allowed_presets: vec![Profile::Windows],
                        ..initial.clone()
                    },
                },
            )
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            user_presets(&fixture.directory, &initial.user_id)?,
            (3, initial)
        );
        let sequence: i64 = connection
            .query_row("SELECT sequence FROM preset_audit", [], |row| row.get(0))
            .map_err(io::Error::other)?;
        assert_eq!(sequence, i64::MAX);
        Ok(())
    }
}
