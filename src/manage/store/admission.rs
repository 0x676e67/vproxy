//! Durable node-wide proxy admission, sharing the access-policy revision and
//! publication boundary. This is not permission to terminate admitted flows.

mod schema;

use std::{fmt, io, path::Path};

use rusqlite::{Connection, params};

use super::{
    Ownership, RemoteAuthorization, control, read_overview, sqlite_error, users, valid_id,
};

pub(super) use schema::create_schema;
#[cfg(test)]
pub(in crate::manage) use schema::remove_schema_for_test;

const MAX_AUDIT: u32 = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::manage) enum Error {
    UpgradeRequired,
}
impl Error {
    pub(in crate::manage) const fn code(self) -> &'static str {
        "management_upgrade_required"
    }
    pub(super) fn error(self) -> io::Error {
        // The schema gate runs before mutation. Keep this definitive refusal
        // distinct from an uncertain I/O/commit failure at publication.
        io::Error::new(io::ErrorKind::InvalidInput, self)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("proxy admission requires explicit schema migration")
    }
}
impl std::error::Error for Error {}

/// The local request's exact node and owner namespace. Browser values are
/// assertions, not authority; a real administrator is checked separately.
#[derive(Clone)]
pub(in crate::manage) struct Assertion {
    pub(in crate::manage) node_id: String,
    pub(in crate::manage) epoch: u64,
}

/// One coherent durable observation. Applied is historical publication of the
/// policy, not this process's readiness or evidence that its flows have drained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct Snapshot {
    pub(in crate::manage) node_id: String,
    pub(in crate::manage) ownership: Ownership,
    pub(in crate::manage) saved_revision: u64,
    pub(in crate::manage) durable_applied_revision: Option<u64>,
    pub(in crate::manage) accepting: bool,
}

pub(in crate::manage) fn snapshot(directory: &Path) -> io::Result<Snapshot> {
    control::read_snapshot(directory, snapshot_in)
}

/// Recheck the real local administrator in the same snapshot as admission and
/// ownership. A write assertion additionally requires the local owner/epoch;
/// observing an externally controlled node does not itself claim its control.
pub(in crate::manage) fn local_runtime_snapshot(
    directory: &Path,
    administrator: &str,
    assertion: Option<&Assertion>,
) -> io::Result<Snapshot> {
    control::read_snapshot(directory, |connection| {
        control::check_administrator(connection, administrator)?;
        if let Some(assertion) = assertion {
            assert_local_in(connection, assertion)?;
        }
        snapshot_in(connection)
    })
}

pub(in crate::manage) fn remote_snapshot(
    directory: &Path,
    authorization: &RemoteAuthorization,
) -> io::Result<Snapshot> {
    control::read_snapshot(directory, |connection| {
        control::authorize_in(connection, authorization)?;
        snapshot_in(connection)
    })
}

fn snapshot_in(connection: &Connection) -> io::Result<Snapshot> {
    let overview = read_overview(connection)?;
    require_current(overview.schema_version)?;
    let ownership = control::read_ownership(connection)?;
    let status = users::status_in(connection)?;
    Ok(Snapshot {
        node_id: overview.node_id,
        ownership,
        saved_revision: status.revision,
        durable_applied_revision: status.applied_revision,
        accepting: read_in(connection, overview.schema_version)?,
    })
}

pub(super) fn assert_local_in(connection: &Connection, assertion: &Assertion) -> io::Result<()> {
    if !valid_id(&assertion.node_id) || assertion.epoch == 0 || assertion.epoch > i64::MAX as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid proxy admission assertion",
        ));
    }
    if read_overview(connection)?.node_id != assertion.node_id {
        return Err(super::ControlError::TargetMismatch.error());
    }
    if control::read_ownership(connection)?.epoch != assertion.epoch {
        return Err(super::ControlError::EpochConflict.error());
    }
    control::require_local(connection)
}

/// Legacy policies had no node-wide gate. A current schema must have exactly
/// its one canonical boolean row; missing or malformed state never opens access.
pub(super) fn read_in(connection: &Connection, version: u32) -> io::Result<bool> {
    if version < 19 {
        return Ok(true);
    }
    let count: i64 = connection
        .query_row("SELECT count(*) FROM proxy_admission_state", [], |row| {
            row.get(0)
        })
        .map_err(|error| sqlite_error("cannot count proxy admission state", error))?;
    if count != 1 {
        return Err(corrupt());
    }
    let (singleton, accepting): (i64, i64) = connection
        .query_row(
            "SELECT singleton,accepting FROM proxy_admission_state",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| sqlite_error("cannot read proxy admission state", error))?;
    if singleton != 1 {
        return Err(corrupt());
    }
    match accepting {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(corrupt()),
    }
}

pub(super) fn write_in(connection: &Connection, accepting: bool) -> io::Result<()> {
    require_current(read_overview(connection)?.schema_version)?;
    if connection.is_autocommit() {
        return Err(corrupt());
    }
    let changed = connection
        .execute(
            "UPDATE proxy_admission_state SET accepting=?1 WHERE singleton=1",
            [accepting],
        )
        .map_err(|error| sqlite_error("cannot save proxy admission state", error))?;
    if changed != 1 {
        return Err(corrupt());
    }
    Ok(())
}

pub(super) fn audit(
    connection: &Connection,
    actor: users::Actor<'_>,
    accepting: bool,
    revision: u64,
) -> io::Result<()> {
    let (entry, administrator, controller, epoch, command, source) = match actor {
        users::Actor::Local(id) => ("local_management", Some(id), None, None, None, None),
        users::Actor::Remote {
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
        users::Actor::Automation { .. } => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "automation admission changes are not authorized",
            ));
        }
    };
    let changed = connection.execute("INSERT INTO proxy_admission_audit(policy_revision,entry,administrator_id,controller_node_id,controller_epoch,command_id,source_administrator_id,accepting) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)", params![users::sql_revision(revision)?,entry,administrator,controller,epoch,command,source,accepting])
        .map_err(|error| sqlite_error("cannot record proxy admission audit",error))?;
    if changed != 1 {
        return Err(corrupt());
    }
    connection.execute("DELETE FROM proxy_admission_audit WHERE policy_revision IN(SELECT policy_revision FROM proxy_admission_audit ORDER BY policy_revision DESC LIMIT -1 OFFSET ?1)",[MAX_AUDIT])
        .map_err(|error| sqlite_error("cannot retain bounded proxy admission audit",error))?;
    Ok(())
}

pub(super) fn validate_schema(connection: &Connection, version: u32) -> io::Result<()> {
    let tables: i64 = connection.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN('proxy_admission_state','proxy_admission_audit')",[],|row|row.get(0))
        .map_err(|error|sqlite_error("cannot inspect proxy admission schema",error))?;
    if version < 19 {
        if tables != 0 {
            return Err(corrupt());
        }
    } else {
        if tables != 2 {
            return Err(corrupt());
        }
        read_in(connection, version)?;
    }
    Ok(())
}

/// Backup readers cannot rely on SQLite CHECK expressions being enforced on
/// immutable connections. Validate the bounded actor vocabulary explicitly.
pub(super) fn validate_snapshot(connection: &Connection) -> io::Result<()> {
    let overview = read_overview(connection)?;
    require_current(overview.schema_version)?;
    read_in(connection, overview.schema_version)?;
    let mut statement = connection.prepare("SELECT policy_revision,entry,administrator_id,controller_node_id,controller_epoch,command_id,source_administrator_id,accepting FROM proxy_admission_audit ORDER BY policy_revision LIMIT 16385")
        .map_err(|error|sqlite_error("cannot inspect proxy admission audit",error))?;
    let mut rows = statement
        .query([])
        .map_err(|error| sqlite_error("cannot query proxy admission audit", error))?;
    let policy = users::status_in(connection)?;
    let mut count = 0_u32;
    while let Some(row) = rows
        .next()
        .map_err(|error| sqlite_error("cannot read proxy admission audit", error))?
    {
        count = count
            .checked_add(1)
            .filter(|count| *count <= MAX_AUDIT)
            .ok_or_else(corrupt)?;
        let revision: i64 = row.get(0).map_err(|_| corrupt())?;
        let entry: String = row.get(1).map_err(|_| corrupt())?;
        let admin: Option<String> = row.get(2).map_err(|_| corrupt())?;
        let peer: Option<String> = row.get(3).map_err(|_| corrupt())?;
        let epoch: Option<i64> = row.get(4).map_err(|_| corrupt())?;
        let command: Option<i64> = row.get(5).map_err(|_| corrupt())?;
        let source: Option<String> = row.get(6).map_err(|_| corrupt())?;
        let accepting: i64 = row.get(7).map_err(|_| corrupt())?;
        let valid = match entry.as_str() {
            "local_management" => {
                admin.as_deref().is_some_and(valid_id)
                    && peer.is_none()
                    && epoch.is_none()
                    && command.is_none()
                    && source.is_none()
            }
            "node_management" => {
                admin.is_none()
                    && peer.as_deref().is_some_and(valid_id)
                    && epoch.is_some_and(|v| v > 0)
                    && command.is_some_and(|v| v > 0)
                    && source.as_deref().is_some_and(valid_id)
            }
            _ => false,
        };
        if !valid
            || !matches!(accepting, 0 | 1)
            || revision < 1
            || u64::try_from(revision)
                .ok()
                .is_none_or(|r| r > policy.revision)
        {
            return Err(corrupt());
        }
    }
    Ok(())
}

fn require_current(version: u32) -> io::Result<()> {
    if version < 19 {
        Err(Error::UpgradeRequired.error())
    } else {
        Ok(())
    }
}
fn corrupt() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "proxy admission state is malformed",
    )
}
