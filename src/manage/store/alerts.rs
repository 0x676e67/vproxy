//! Minimal read-only facts for the in-process operations monitor.
//!
//! Each round uses one SQLite read transaction and one bounded JOIN for all
//! targets. It never opens a connection per node, reads command/snapshot blobs,
//! starts a write transaction, or changes schema, ownership or authorization.

pub(in crate::manage) mod history;

use std::{io, num::NonZeroU64, path::Path};

use rusqlite::Connection;
use serde_with::{BoolFromInt, DefaultOnNull, FromInto, serde_as};

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

#[serde_as]
#[derive(serde::Deserialize)]
pub(in crate::manage) struct Target {
    pub(in crate::manage) id: String,
    #[serde_as(as = "FromInto<NonZeroU64>")]
    pub(in crate::manage) revision: u64,
    #[serde_as(as = "BoolFromInt")]
    pub(in crate::manage) active: bool,
    #[serde_as(as = "BoolFromInt")]
    pub(in crate::manage) retired: bool,
    #[serde_as(as = "BoolFromInt")]
    pub(in crate::manage) rollback: bool,
    #[serde_as(as = "BoolFromInt")]
    pub(in crate::manage) peer_active: bool,
    #[serde_as(as = "FromInto<NonZeroU64>")]
    pub(in crate::manage) authorization_revision: u64,
    #[serde_as(as = "Option<FromInto<NonZeroU64>>")]
    pub(in crate::manage) source_authorization_revision: Option<u64>,
    #[serde_as(as = "Option<FromInto<NonZeroU64>>")]
    pub(in crate::manage) source_target_revision: Option<u64>,
    pub(in crate::manage) last_success_at: Option<u64>,
    pub(in crate::manage) meter_epoch: Option<String>,
    pub(in crate::manage) cursor: Option<u64>,
    pub(in crate::manage) source_error: Option<String>,
    #[serde_as(as = "DefaultOnNull<BoolFromInt>")]
    pub(in crate::manage) quarantined: bool,
    pub(in crate::manage) job_id: Option<String>,
    pub(in crate::manage) job_state: Option<String>,
    #[serde_as(as = "Option<FromInto<u32>>")]
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
    let revision = connection
        .query_row_and_then(
            "SELECT revision FROM proxy_policy_state WHERE singleton=1",
            [],
            serde_rusqlite::from_row::<NonZeroU64>,
        )
        .map_err(sql_error)?;
    let mut statement = connection
        .prepare(
            "SELECT t.peer_id AS id,t.revision,t.active,t.retired,t.rollback_detected AS rollback,
         p.active AS peer_active,p.authorization_revision,
         s.authorization_revision AS source_authorization_revision,
         s.target_revision AS source_target_revision,s.last_success_at,s.error AS source_error,
         s.quarantined,j.job_id,j.state AS job_state,j.attempts AS job_attempts,s.meter_epoch,s.cursor
         FROM managed_targets t LEFT JOIN peers p ON p.node_id=t.peer_id
         LEFT JOIN remote_traffic_sources s ON s.peer_id=t.peer_id
         LEFT JOIN control_outbox j ON j.peer_id=t.peer_id
         ORDER BY t.peer_id LIMIT 129",
        )
        .map_err(sql_error)?;
    let rows = serde_rusqlite::from_rows::<Target>(statement.query([]).map_err(sql_error)?);
    let mut targets = Vec::new();
    for row in rows {
        let target = row.map_err(sql_error)?;
        if targets.len() == 128
            || !valid_id(&target.id)
            || target.source_error.as_deref().is_some_and(|value| {
                !matches!(
                    value,
                    "unavailable" | "unsupported" | "not_authorized" | "continuity_error"
                )
            })
            || target.job_id.as_ref().is_some_and(|value| !valid_id(value))
            || target.job_id.is_some() != target.job_state.is_some()
            || target.job_id.is_some() != target.job_attempts.is_some()
            || target
                .meter_epoch
                .as_ref()
                .is_some_and(|value| !valid_id(value))
            || target.meter_epoch.is_some() != target.cursor.is_some()
            || target.meter_epoch.is_some() != target.source_authorization_revision.is_some()
            || target.last_success_at.is_some() && target.meter_epoch.is_none()
            || target.active && target.retired
            || target.job_state.as_deref().is_some_and(|value| {
                !matches!(
                    value,
                    "pending" | "blocked" | "saved" | "applied" | "rejected" | "superseded"
                )
            })
        {
            return Err(corrupt());
        }
        targets.push(target);
    }
    Ok(Snapshot {
        policy_revision: revision.get(),
        admission,
        targets,
    })
}

fn corrupt() -> io::Error {
    invalid_data("operations observation metadata is malformed")
}

fn sql_error(error: impl Into<serde_rusqlite::Error>) -> io::Error {
    sqlite_error("cannot read operations observation metadata", error)
}
