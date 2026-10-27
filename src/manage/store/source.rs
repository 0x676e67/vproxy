//! Local source floors, independent of the optional SQLite Session build.
//! A bound source is fenced from ordinary startup/writers until the complete
//! witnessed runtime is connected. Missing state never creates a new binding.

use super::{invalid_data, sqlite_error};
use crate::manage::witness::{Enrollment, digest};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{fs, io, path::Path};

pub(super) const REQUIRED: &str = "witness-source.json";
const MAX_STATE: usize = 4096;

/// The operation identity committed with the original business rows. It does
/// not contain its own changeset hash, which would create a circular encoding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Floor {
    pub(super) sequence: u64,
    /// Random local operation ID; absent only for the initial baseline.
    pub(super) intent_id: Option<String>,
    /// Commitment of the preceding operation, not this row's changeset.
    pub(super) previous: Option<String>,
}

impl Floor {
    pub(super) fn validate(&self) -> io::Result<()> {
        if self.sequence > i64::MAX as u64
            || if self.sequence == 0 {
                self.intent_id.is_some() || self.previous.is_some()
            } else {
                !self.intent_id.as_deref().is_some_and(super::valid_id)
                    || !self.previous.as_deref().is_some_and(digest)
            }
        {
            return Err(corrupt());
        }
        Ok(())
    }
}

/// One immutable enrollment and its latest committed local operation identity.
/// Confirmation lives on the witness, never in an unwitnessed follow-up write.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub(super) enrollment: Enrollment,
    pub(super) floor: Floor,
    /// Accepted portable configuration and static-asset digest. Absence keeps
    /// pre-binding canonical bytes unchanged; it is not a startup permission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) configuration: Option<Configuration>,
}

/// Small local reference, not the configuration or secret material itself.
/// Revisions use CAS and advance in the same witnessed transaction as the floor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Configuration {
    pub(in crate::manage) revision: u64,
    pub(in crate::manage) sha256: [u8; 32],
}

impl Configuration {
    pub(super) fn validate(self) -> io::Result<()> {
        if self.revision == 0 || self.revision > i64::MAX as u64 {
            return Err(corrupt());
        }
        Ok(())
    }
}

impl State {
    pub(super) fn validate(&self) -> io::Result<()> {
        self.enrollment.validate().map_err(|_| corrupt())?;
        self.floor.validate()?;
        if let Some(configuration) = self.configuration {
            configuration.validate()?;
            if self.floor.sequence < configuration.revision {
                return Err(corrupt());
            }
        }
        Ok(())
    }
}

pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection
        .execute_batch(
            "CREATE TABLE recovery_source(
      singleton INTEGER PRIMARY KEY CHECK(singleton=1),
      payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 4096)
    ) STRICT;",
        )
        .map_err(|e| sqlite_error("cannot create local source floor", e))
}

/// Bounded canonical decode, including malformed singleton rows. No repair,
/// migration, witness request or freshness decision is made here.
pub(super) fn load(connection: &Connection, version: u32) -> io::Result<Option<State>> {
    if version < 26 {
        return Ok(None);
    }
    let count: i64 = connection
        .query_row("SELECT count(*) FROM recovery_source", [], |r| r.get(0))
        .map_err(|e| sqlite_error("cannot inspect local source floor", e))?;
    if !(0..=1).contains(&count) {
        return Err(corrupt());
    }
    let row = connection
        .query_row(
            "SELECT payload FROM recovery_source WHERE singleton=1",
            [],
            |r| match r.get_ref(0)? {
                rusqlite::types::ValueRef::Blob(b) if b.len() <= MAX_STATE => Ok(b.to_vec()),
                _ => Err(rusqlite::Error::InvalidQuery),
            },
        )
        .optional()
        .map_err(|e| sqlite_error("cannot read local source floor", e))?;
    if count != i64::from(row.is_some()) {
        return Err(corrupt());
    }
    row.map(|bytes| {
        let state: State = serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
        state.validate()?;
        if serde_json::to_vec(&state).map_err(|_| corrupt())? != bytes {
            return Err(corrupt());
        }
        Ok(state)
    })
    .transpose()
}

/// The common reader validates the namespace even in feature-off builds.
pub(super) fn validate_schema(connection: &Connection, version: u32) -> io::Result<()> {
    if let Some(state) = load(connection, version)? {
        let node: String = connection
            .query_row(
                "SELECT node_id FROM node_identity WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(|e| sqlite_error("cannot inspect bound source identity", e))?;
        if state.enrollment.peer_node_id != node {
            return Err(corrupt());
        }
    }
    Ok(())
}

/// Any object at this reserved leaf fences partial activation, even before the
/// first SQL binding exists. Never remove or silently reinterpret it.
pub(super) fn reject_marker(directory: &Path) -> io::Result<()> {
    match fs::symlink_metadata(directory.join(REQUIRED)) {
        Ok(_) => Err(fenced()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Ordinary writable connections and service startup cannot ignore a SQL
/// binding if its marker is missing. This is a refusal, not a runtime adapter.
pub(super) fn require_unprotected(connection: &Connection) -> io::Result<()> {
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| sqlite_error("cannot inspect source admission version", e))?;
    if load(connection, version)?.is_some() {
        return Err(fenced());
    }
    Ok(())
}

#[cfg(feature = "witness-journal")]
pub(super) fn save(connection: &Connection, state: &State) -> io::Result<()> {
    state.validate()?;
    let bytes = serde_json::to_vec(state).map_err(|_| corrupt())?;
    if bytes.len() > MAX_STATE {
        return Err(corrupt());
    }
    let changed = connection
        .execute(
            "INSERT INTO recovery_source(singleton,payload) VALUES(1,?1)
      ON CONFLICT(singleton) DO UPDATE SET payload=excluded.payload",
            [bytes],
        )
        .map_err(|e| sqlite_error("cannot store local source floor", e))?;
    if changed != 1 || load(connection, super::SCHEMA_VERSION)?.as_ref() != Some(state) {
        return Err(corrupt());
    }
    Ok(())
}

fn fenced() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "witnessed source requires guarded startup and writes; ordinary access is refused",
    )
}
fn corrupt() -> io::Error {
    invalid_data("local source floor is malformed")
}

#[cfg(test)]
pub(in crate::manage) fn remove_schema_for_test(connection: &Connection) -> io::Result<()> {
    super::proxy_service::remove_schema_for_test(connection)?;
    ensure_unused_for_test(connection)?;
    connection
        .execute_batch("DROP TABLE IF EXISTS recovery_source;")
        .map_err(|e| sqlite_error("cannot reconstruct pre-source fixture", e))
}

#[cfg(test)]
pub(in crate::manage) fn ensure_unused_for_test(connection: &Connection) -> io::Result<()> {
    let present: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='recovery_source')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot inspect source fixture", e))?;
    if present && load(connection, 26)?.is_some() {
        return Err(corrupt());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::{node::tests::Fixture, store};

    fn state(f: &Fixture) -> io::Result<State> {
        Ok(State {
            enrollment: Enrollment {
                witness_node_id: f.server_id.clone(),
                peer_node_id: f.client_id.clone(),
                binding_id: store::random_id()?,
                writer_id: store::random_id()?,
                baseline: "0".repeat(64),
            },
            floor: Floor {
                sequence: 0,
                intent_id: None,
                previous: None,
            },
            configuration: None,
        })
    }

    #[test]
    fn optional_configuration_keeps_legacy_bytes_and_validates_floor_and_revision() -> io::Result<()>
    {
        let f = Fixture::new_with_private_source(true, true)?;
        let c = store::peers::open_existing(&f.client_state, true)?;
        let mut s = state(&f)?;
        let legacy = format!(
            "{{\"enrollment\":{},\"floor\":{}}}",
            serde_json::to_string(&s.enrollment).map_err(io::Error::other)?,
            serde_json::to_string(&s.floor).map_err(io::Error::other)?
        );
        assert_eq!(
            serde_json::to_vec(&s).map_err(io::Error::other)?,
            legacy.as_bytes()
        );
        for revision in [0, 1, i64::MAX as u64 + 1] {
            s.configuration = Some(Configuration {
                revision,
                sha256: [1; 32],
            });
            assert!(s.validate().is_err());
        }
        s.floor = Floor {
            sequence: 1,
            intent_id: Some(store::random_id()?),
            previous: Some("0".repeat(64)),
        };
        s.configuration = Some(Configuration {
            revision: 1,
            sha256: [1; 32],
        });
        s.validate()?;
        c.execute(
            "INSERT INTO recovery_source VALUES(1,?1)",
            [serde_json::to_vec(&s).map_err(io::Error::other)?],
        )
        .map_err(io::Error::other)?;
        assert_eq!(load(&c, 26)?, Some(s));
        assert!(store::recovery::startup(&f.client_state).is_err());
        Ok(())
    }

    #[test]
    fn ordinary_build_fences_marker_and_sql_binding_but_retains_readonly_diagnostics()
    -> io::Result<()> {
        for sql in [false, true] {
            let f = Fixture::new_with_private_source(true, true)?;
            let c = store::peers::open_existing(&f.client_state, true)?;
            let expected = state(&f)?;
            if sql {
                let bytes = serde_json::to_vec(&expected).map_err(io::Error::other)?;
                c.execute("INSERT INTO recovery_source VALUES(1,?1)", [bytes])
                    .map_err(io::Error::other)?;
            } else {
                // Even an undecodable/non-file marker is a fence before SQL bind.
                crate::manage::files::create_directory(&f.client_state.join(REQUIRED))?;
            }
            assert_eq!(
                store::peers::open_existing(&f.client_state, true)
                    .err()
                    .map(|e| e.kind()),
                Some(io::ErrorKind::PermissionDenied)
            );
            assert_eq!(
                store::recovery::startup(&f.client_state)
                    .err()
                    .map(|e| e.kind()),
                Some(io::ErrorKind::PermissionDenied)
            );
            assert_eq!(store::inspect(&f.client_state)?.node_id, f.client_id);
            assert_eq!(store::recovery::diagnostic_startup(&f.client_state)?, None);
            assert_eq!(load(&c, 26)?, sql.then_some(expected));
        }
        Ok(())
    }

    #[test]
    fn canonical_floor_decode_refuses_bad_identity_shape_and_future_sequence() -> io::Result<()> {
        let f = Fixture::new_with_private_source(true, true)?;
        let c = store::peers::open_existing(&f.client_state, true)?;
        let s = state(&f)?;
        for mode in 0..5 {
            let mut bad = s.clone();
            match mode {
                0 => bad.floor.sequence = i64::MAX as u64 + 1,
                1 => bad.floor.intent_id = Some(store::random_id()?),
                2 => bad.enrollment.peer_node_id = store::random_id()?,
                3 => {}
                _ => bad.floor.sequence = 1,
            }
            let mut bytes = serde_json::to_vec(&bad).map_err(io::Error::other)?;
            if mode == 3 {
                bytes.pop();
                bytes.extend_from_slice(b",\"extra\":true}");
            }
            c.execute("INSERT INTO recovery_source VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET payload=excluded.payload",[&bytes]).map_err(io::Error::other)?;
            assert!(store::inspect(&f.client_state).is_err());
            let retained: Vec<u8> = c
                .query_row("SELECT payload FROM recovery_source", [], |r| r.get(0))
                .map_err(io::Error::other)?;
            assert_eq!(retained, bytes);
        }
        Ok(())
    }

    #[test]
    fn schema25_upgrade_preserves_old_file_and_rolls_back_source_table_collision() -> io::Result<()>
    {
        for collision in [false, true] {
            let f = Fixture::new_with_private_source(true, false)?;
            let c = store::peers::open_existing(&f.client_state, true)?;
            store::recovery::restore_schema_twenty_five_for_test(&c)?;
            let ddl: String = c
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE name='recovery_state'",
                    [],
                    |r| r.get(0),
                )
                .map_err(io::Error::other)?;
            if collision {
                c.execute_batch("CREATE TABLE recovery_source(note TEXT); INSERT INTO recovery_source VALUES('retain');").map_err(io::Error::other)?;
            }
            drop(c);
            let backup = f
                .server_state
                .parent()
                .ok_or_else(corrupt)?
                .join("before26.sqlite3");
            let result = store::migrate(&f.client_state, &backup);
            let old =
                Connection::open_with_flags(&backup, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                    .map_err(io::Error::other)?;
            assert_eq!(
                old.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                    .map_err(io::Error::other)?,
                25
            );
            assert_eq!(
                old.query_row(
                    "SELECT sql FROM sqlite_schema WHERE name='recovery_state'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .map_err(io::Error::other)?,
                ddl
            );
            if collision {
                assert!(result.is_err());
                assert_eq!(store::inspect(&f.client_state)?.schema_version, 25);
                let c = store::peers::open_existing(&f.client_state, false)?;
                assert_eq!(
                    c.query_row("SELECT note FROM recovery_source", [], |r| r
                        .get::<_, String>(0))
                        .map_err(io::Error::other)?,
                    "retain"
                );
            } else {
                assert_eq!(result?.schema_version, store::SCHEMA_VERSION);
                let c = store::peers::open_existing(&f.client_state, false)?;
                assert_eq!(load(&c, 26)?, None);
                assert_eq!(store::inspect(&f.client_state)?.node_id, f.client_id);
            }
        }
        Ok(())
    }
}
