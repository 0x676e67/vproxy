//! Minimal read-only facts for the in-process operations monitor.
//!
//! Each round uses one SQLite read transaction and one bounded JOIN for all
//! targets. It never opens a connection per node, reads command/snapshot blobs,
//! starts a write transaction, or changes schema, ownership or authorization.

pub(in crate::manage) mod history;

use std::{io, path::Path};

use rusqlite::Connection;

use super::{invalid_data, peers::open_existing, read_overview, sqlite_error, valid_id};

pub(in crate::manage) struct Snapshot {
    pub(in crate::manage) policy_revision: u64,
    pub(in crate::manage) admission: Option<Admission>,
    pub(in crate::manage) targets: Vec<Target>,
}

/// Current durable maintenance binding from the same read transaction as the
/// policy revision. Legacy schemas have no such evidence, not an open gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct Admission {
    pub(in crate::manage) node_id: String,
    pub(in crate::manage) ownership: super::Ownership,
    pub(in crate::manage) accepting: bool,
}

pub(in crate::manage) struct Target {
    pub(in crate::manage) id: String,
    pub(in crate::manage) revision: u64,
    pub(in crate::manage) active: bool,
    pub(in crate::manage) retired: bool,
    pub(in crate::manage) rollback: bool,
    pub(in crate::manage) peer_active: bool,
    pub(in crate::manage) authorization_revision: u64,
    pub(in crate::manage) source_authorization_revision: Option<u64>,
    pub(in crate::manage) source_target_revision: Option<u64>,
    pub(in crate::manage) last_success_at: Option<u64>,
    pub(in crate::manage) meter_epoch: Option<String>,
    pub(in crate::manage) cursor: Option<u64>,
    pub(in crate::manage) source_error: Option<String>,
    pub(in crate::manage) quarantined: bool,
    pub(in crate::manage) job_id: Option<String>,
    pub(in crate::manage) job_state: Option<String>,
    pub(in crate::manage) job_attempts: Option<u64>,
}

/// Read at most 128 target rows without loading credentials or traffic series.
/// Unsupported old schemas and malformed facts fail the round; they cannot be
/// interpreted as an empty, healthy installation. The caller supplies the
/// existing coordinator blocking-work budget and owns cancellation.
pub(in crate::manage) fn read(directory: &Path) -> io::Result<Snapshot> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection.transaction().map_err(sql_error)?;
    let overview = read_overview(&transaction)?;
    if overview.schema_version < 17 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "operations observations require management schema 17 or later",
        ));
    }
    let admission = if overview.schema_version >= 19 {
        Some(Admission {
            node_id: overview.node_id,
            ownership: super::control::read_ownership(&transaction)?,
            accepting: super::admission::read_in(&transaction, overview.schema_version)?,
        })
    } else {
        None
    };
    let result = read_in(&transaction, admission)?;
    transaction.commit().map_err(sql_error)?;
    Ok(result)
}

fn read_in(connection: &Connection, admission: Option<Admission>) -> io::Result<Snapshot> {
    let revision: i64 = connection
        .query_row(
            "SELECT revision FROM proxy_policy_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    let mut statement = connection
        .prepare(
            "SELECT t.peer_id,t.revision,t.active,t.retired,t.rollback_detected,
         p.active,p.authorization_revision,s.authorization_revision,s.target_revision,
         s.last_success_at,s.error,s.quarantined,j.job_id,j.state,j.attempts,s.meter_epoch,s.cursor
         FROM managed_targets t LEFT JOIN peers p ON p.node_id=t.peer_id
         LEFT JOIN remote_traffic_sources s ON s.peer_id=t.peer_id
         LEFT JOIN control_outbox j ON j.peer_id=t.peer_id
         ORDER BY t.peer_id LIMIT 129",
        )
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<i64>>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, Option<i64>>(14)?,
                row.get::<_, Option<String>>(15)?,
                row.get::<_, Option<i64>>(16)?,
            ))
        })
        .map_err(sql_error)?;
    let mut targets = Vec::new();
    for row in rows {
        let (
            id,
            revision,
            active,
            retired,
            rollback,
            peer_active,
            authorization,
            source_authorization,
            source_target,
            last_success,
            error,
            quarantined,
            job_id,
            job_state,
            attempts,
            meter_epoch,
            cursor,
        ) = row.map_err(sql_error)?;
        if targets.len() == 128
            || !valid_id(&id)
            || error.as_deref().is_some_and(|value| {
                !matches!(
                    value,
                    "unavailable" | "unsupported" | "not_authorized" | "continuity_error"
                )
            })
            || job_id.as_ref().is_some_and(|value| !valid_id(value))
            || job_id.is_some() != job_state.is_some()
            || job_id.is_some() != attempts.is_some()
            || meter_epoch.as_ref().is_some_and(|value| !valid_id(value))
            || meter_epoch.is_some() != cursor.is_some()
            || meter_epoch.is_some() != source_authorization.is_some()
            || last_success.is_some() && meter_epoch.is_none()
            || attempts.is_some_and(|attempts| !(0..=i64::from(u32::MAX)).contains(&attempts))
            || active == 1 && retired == 1
            || job_state.as_deref().is_some_and(|value| {
                !matches!(
                    value,
                    "pending" | "blocked" | "saved" | "applied" | "rejected" | "superseded"
                )
            })
        {
            return Err(corrupt());
        }
        targets.push(Target {
            id,
            revision: positive(revision)?,
            active: boolean(active)?,
            retired: boolean(retired)?,
            rollback: boolean(rollback)?,
            peer_active: boolean(peer_active)?,
            authorization_revision: positive(authorization)?,
            source_authorization_revision: source_authorization.map(positive).transpose()?,
            source_target_revision: source_target.map(positive).transpose()?,
            last_success_at: last_success.map(nonnegative).transpose()?,
            meter_epoch,
            cursor: cursor.map(nonnegative).transpose()?,
            source_error: error,
            quarantined: quarantined.map(boolean).transpose()?.unwrap_or(false),
            job_id,
            job_state,
            job_attempts: attempts.map(nonnegative).transpose()?,
        });
    }
    Ok(Snapshot {
        policy_revision: positive(revision)?,
        admission,
        targets,
    })
}

fn boolean(value: i64) -> io::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(corrupt()),
    }
}

fn nonnegative(value: i64) -> io::Result<u64> {
    u64::try_from(value).map_err(|_| corrupt())
}

fn positive(value: i64) -> io::Result<u64> {
    nonnegative(value).and_then(|value| {
        if value == 0 {
            Err(corrupt())
        } else {
            Ok(value)
        }
    })
}

fn corrupt() -> io::Error {
    invalid_data("operations observation metadata is malformed")
}

fn sql_error(error: rusqlite::Error) -> io::Error {
    sqlite_error("cannot read operations observation metadata", error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::store;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    fn fixture() -> io::Result<Connection> {
        let connection = Connection::open_in_memory().map_err(io::Error::other)?;
        // No command or snapshot BLOB columns exist: a minimal projection must not
        // accidentally deserialize either potentially large or secret-bearing body.
        connection.execute_batch(
        "CREATE TABLE proxy_policy_state(singleton INTEGER,revision INTEGER);
         INSERT INTO proxy_policy_state VALUES(1,7);
         CREATE TABLE peers(node_id TEXT PRIMARY KEY,active INTEGER,authorization_revision INTEGER);
         CREATE TABLE managed_targets(peer_id TEXT PRIMARY KEY,revision INTEGER,active INTEGER,retired INTEGER,rollback_detected INTEGER);
         CREATE TABLE remote_traffic_sources(peer_id TEXT PRIMARY KEY,authorization_revision INTEGER,target_revision INTEGER,last_success_at INTEGER,error TEXT,quarantined INTEGER,meter_epoch TEXT,cursor INTEGER);
         CREATE TABLE control_outbox(peer_id TEXT PRIMARY KEY,job_id TEXT,state TEXT,attempts INTEGER);"
    ).map_err(io::Error::other)?;
        Ok(connection)
    }

    fn insert(connection: &Connection, number: u128) -> io::Result<String> {
        let id = URL_SAFE_NO_PAD.encode(number.to_be_bytes());
        connection
            .execute("INSERT INTO peers VALUES(?1,1,3)", [&id])
            .map_err(io::Error::other)?;
        connection
            .execute("INSERT INTO managed_targets VALUES(?1,2,1,0,0)", [&id])
            .map_err(io::Error::other)?;
        Ok(id)
    }

    #[test]
    fn batch_reads_only_metadata_and_does_not_change_storage() -> io::Result<()> {
        let connection = fixture()?;
        let id = insert(&connection, 1)?;
        let job = URL_SAFE_NO_PAD.encode(2u128.to_be_bytes());
        let epoch = URL_SAFE_NO_PAD.encode(3u128.to_be_bytes());
        connection
            .execute(
                "INSERT INTO remote_traffic_sources VALUES(?1,3,2,100,'unavailable',0,?2,8)",
                [&id, &epoch],
            )
            .map_err(io::Error::other)?;
        connection
            .execute(
                "INSERT INTO control_outbox VALUES(?1,?2,'blocked',4)",
                [&id, &job],
            )
            .map_err(io::Error::other)?;
        let before = connection.total_changes();
        let snapshot = read_in(&connection, None)?;
        assert_eq!(snapshot.policy_revision, 7);
        assert!(snapshot.admission.is_none());
        assert_eq!(snapshot.targets.len(), 1);
        assert_eq!(snapshot.targets[0].cursor, Some(8));
        assert_eq!(
            snapshot.targets[0].source_error.as_deref(),
            Some("unavailable")
        );
        assert_eq!(snapshot.targets[0].job_state.as_deref(), Some("blocked"));
        assert_eq!(connection.total_changes(), before);
        Ok(())
    }

    #[test]
    fn over_capacity_and_missing_peer_are_errors_not_partial_health() -> io::Result<()> {
        let connection = fixture()?;
        for number in 0..128 {
            insert(&connection, number)?;
        }
        assert_eq!(read_in(&connection, None)?.targets.len(), 128);
        insert(&connection, 128)?;
        assert!(read_in(&connection, None).is_err());
        let connection = fixture()?;
        let id = insert(&connection, 1)?;
        connection
            .execute("DELETE FROM peers WHERE node_id=?1", [&id])
            .map_err(io::Error::other)?;
        assert!(read_in(&connection, None).is_err());
        Ok(())
    }

    #[test]
    fn malformed_or_unpaired_evidence_is_rejected() -> io::Result<()> {
        for sql in [
            "UPDATE peers SET active=2",
            "UPDATE managed_targets SET revision=0",
            "UPDATE managed_targets SET retired=1",
            "INSERT INTO remote_traffic_sources(peer_id,target_revision,last_success_at,quarantined) SELECT peer_id,2,100,0 FROM managed_targets",
            "INSERT INTO control_outbox SELECT peer_id,NULL,'blocked',1 FROM managed_targets",
            "INSERT INTO control_outbox SELECT peer_id,peer_id,'blocked',4294967296 FROM managed_targets",
        ] {
            let connection = fixture()?;
            insert(&connection, 1)?;
            connection.execute_batch(sql).map_err(io::Error::other)?;
            assert!(
                read_in(&connection, None).is_err(),
                "accepted malformed metadata: {sql}"
            );
        }
        Ok(())
    }

    struct Database {
        directory: std::path::PathBuf,
        node_id: String,
        administrator: String,
    }

    impl Database {
        fn new() -> io::Result<Self> {
            let directory =
                std::env::temp_dir().join(format!("vproxy-alert-store-{}", store::random_id()?));
            let overview =
                store::initialize(&directory, "alert metadata fixture", "admin", "fixture PHC")?;
            let connection = store::peers::open_existing(&directory, false)?;
            let administrator = connection
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)?;
            Ok(Self {
                directory,
                node_id: overview.node_id,
                administrator,
            })
        }
    }

    impl Drop for Database {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn current_snapshot_binds_admission_to_actual_node_owner_and_validated_boolean()
    -> io::Result<()> {
        let fixture = Database::new()?;
        let initial = read(&fixture.directory)?;
        assert_eq!(initial.policy_revision, 1);
        assert_eq!(
            initial.admission,
            Some(Admission {
                node_id: fixture.node_id.clone(),
                ownership: store::Ownership {
                    controller_node_id: None,
                    epoch: 1,
                    last_terminal_command: 0
                },
                accepting: true,
            })
        );
        store::apply_policy_asserted(
            &fixture.directory,
            &fixture.administrator,
            1,
            store::PolicyChange::SetAdmission { accepting: false },
            &store::update_lock(&fixture.directory)?,
            &store::admission::Assertion {
                node_id: fixture.node_id.clone(),
                epoch: 1,
            },
        )?;
        let connection = store::peers::open_existing(&fixture.directory, true)?;
        let peer = URL_SAFE_NO_PAD.encode(1_u128.to_be_bytes());
        connection.execute("INSERT INTO peers(node_id,name,active,authorization_revision) VALUES(?1,'metadata owner',1,1)", [&peer])
        .map_err(io::Error::other)?;
        let owner = store::set_owner(
            &fixture.directory,
            &store::update_lock(&fixture.directory)?,
            &fixture.administrator,
            1,
            Some(&peer),
        )?;
        let observed = read(&fixture.directory)?;
        assert_eq!(observed.policy_revision, 2);
        assert_eq!(
            observed.admission,
            Some(Admission {
                node_id: fixture.node_id.clone(),
                ownership: owner,
                accepting: false,
            })
        );
        assert!(observed.targets.is_empty());

        // Only this new private fixture bypasses CHECK. A corrupt current gate must
        // fail the observation, never masquerade as absent legacy metadata or true.
        connection.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE proxy_admission_state SET accepting=2 WHERE singleton=1;")
        .map_err(io::Error::other)?;
        assert_eq!(
            read(&fixture.directory).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        let saved: i64 = connection
            .query_row("SELECT accepting FROM proxy_admission_state", [], |row| {
                row.get(0)
            })
            .map_err(io::Error::other)?;
        assert_eq!(saved, 2, "the read must not repair malformed durable state");
        Ok(())
    }

    #[test]
    fn legacy_snapshots_do_not_query_or_invent_the_new_admission_namespace() -> io::Result<()> {
        for version in [17, 18] {
            let fixture = Database::new()?;
            let connection = store::peers::open_existing(&fixture.directory, true)?;
            if version == 17 {
                store::recovery::restore_schema_seventeen_for_test(&connection)?;
            } else {
                store::recovery::restore_schema_eighteen_for_test(&connection)?;
            }
            let tables: i64 = connection.query_row("SELECT count(*) FROM sqlite_schema WHERE name IN('proxy_admission_state','proxy_admission_audit')", [], |row| row.get(0))
            .map_err(io::Error::other)?;
            assert_eq!(tables, 0);
            let before = store::inspect(&fixture.directory)?;
            assert_eq!(before.schema_version, version);
            let snapshot = read(&fixture.directory)?;
            assert_eq!(snapshot.policy_revision, 1);
            assert!(snapshot.admission.is_none());
            assert!(snapshot.targets.is_empty());
            assert_eq!(store::inspect(&fixture.directory)?.schema_version, version);
            let tables: i64 = connection.query_row("SELECT count(*) FROM sqlite_schema WHERE name IN('proxy_admission_state','proxy_admission_audit')", [], |row| row.get(0))
            .map_err(io::Error::other)?;
            assert_eq!(tables, 0, "observation cannot migrate a legacy fixture");
        }
        Ok(())
    }
}
