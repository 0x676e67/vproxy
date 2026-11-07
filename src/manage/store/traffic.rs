//! Durable accepted-payload counters and bounded, approximate UTC history.
//!
//! Forwarding never calls this module. A single management collector supplies
//! absolute samples in batches of at most 256; each FULL transaction computes
//! deltas once, updates cumulative groups and all three history resolutions.
//! A crash can lose the uncheckpointed tail. Run markers expose that uncertainty
//! rather than presenting these lower bounds as an exact billing ledger.

mod write;

use std::{io, path::Path};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;

use crate::{
    access::traffic::{PROTOCOL_COUNT, PoolSeed, Protocol, Seed},
    traffic::Snapshot,
};

use super::{invalid_data, peers::open_existing, read_overview, sqlite_error, valid_id};

pub(in crate::manage) use write::{checkpoint, finish, start_run};

const MAX_SERIES: u64 = 46_725;
const MAX_WINDOWS: u64 = 500_000;
const MAX_BATCH: usize = 256;
const MAX_PAGE: u32 = 50;
const ZERO: Snapshot = Snapshot {
    upload: 0,
    download: 0,
    saturated: false,
};

/// Durable provenance, not an assertion that a data-plane process is running.
#[serde_with::serde_as]
#[derive(Clone, Deserialize)]
pub(in crate::manage) struct Status {
    /// False only for an older remote representation; two zero counters do not
    /// prove absence of HTTP/HTTPS traffic when the source did not distinguish it.
    #[serde_as(as = "serde_with::BoolFromInt")]
    pub(in crate::manage) http_split: bool,
    pub(in crate::manage) node_id: String,
    /// Stable accounting incarnation, independent of controller ownership epochs.
    pub(in crate::manage) meter_epoch: String,
    /// Last persisted run marker; `clean` distinguishes an orderly close.
    pub(in crate::manage) run_id: Option<String>,
    /// Monotonic durable checkpoint/state sequence, never a byte counter.
    pub(in crate::manage) cursor: u64,
    #[serde_as(as = "serde_with::BoolFromInt")]
    pub(in crate::manage) clean: bool,
    /// A previous run did not confirm final persistence after forwarding ended.
    #[serde_as(as = "serde_with::BoolFromInt")]
    pub(in crate::manage) loss_possible: bool,
    /// Retention/capacity/clock discontinuity omitted some historical detail.
    #[serde_as(as = "serde_with::BoolFromInt")]
    pub(in crate::manage) history_gap: bool,
    /// UTC attribution has encountered an unavailable or discontinuous clock.
    #[serde_as(as = "serde_with::BoolFromInt")]
    pub(in crate::manage) time_uncertain: bool,
    pub(in crate::manage) last_checkpoint_at: Option<u64>,
    /// First observed enable/run timestamp; migration does not invent a zero date.
    pub(in crate::manage) meter_started_at: Option<u64>,
}

/// Seeds are only leaf credential/pool values; derived groups must not be seeded
/// back into live meters or the next checkpoint would count them twice.
pub(in crate::manage) struct Restored {
    pub(in crate::manage) status: Status,
    pub(in crate::manage) credential_seeds: Vec<Seed>,
    pub(in crate::manage) pool_seeds: Vec<PoolSeed>,
}

/// A successful open marker recorded before starting real proxy listeners.
pub(in crate::manage) struct Run {
    pub(in crate::manage) status: Status,
}

/// Fixed local identity scope. Credential history is deliberately unsupported;
/// minute/hour/day rows are bounded to node, user and actual selected pool.
#[derive(Clone)]
pub(in crate::manage) enum Scope {
    Node,
    User(String),
    Credential(String),
    Pool(String),
}

/// UTC-aligned windows; all three resolutions are updated in one transaction.
#[derive(Clone, Copy)]
pub(in crate::manage) enum Resolution {
    Minute,
    Hour,
    Day,
}

impl Resolution {
    fn code(self) -> i64 {
        match self {
            Self::Minute => 0,
            Self::Hour => 1,
            Self::Day => 2,
        }
    }
    fn width(self) -> u64 {
        match self {
            Self::Minute => 60_000,
            Self::Hour => 3_600_000,
            Self::Day => 86_400_000,
        }
    }
    fn retention(self) -> u64 {
        match self {
            Self::Minute => 60,
            Self::Hour => 48,
            Self::Day => 30,
        }
    }
    /// Apply the UTC cutoff before pagination and export.
    fn floor(self, time: u64) -> u64 {
        (time / self.width() * self.width()).saturating_sub((self.retention() - 1) * self.width())
    }
}

/// One protocol's cumulative accepted payload. Saturated values are lower bounds.
pub(in crate::manage) struct ProtocolTotal {
    pub(in crate::manage) protocol: Protocol,
    pub(in crate::manage) value: Snapshot,
}
pub(in crate::manage) struct Totals {
    pub(in crate::manage) status: Status,
    pub(in crate::manage) items: Vec<ProtocolTotal>,
}
/// A page groups all protocols in a window so cursors cannot skip a protocol.
pub(in crate::manage) struct Bucket {
    pub(in crate::manage) window_id: u64,
    pub(in crate::manage) items: Vec<ProtocolTotal>,
}
pub(in crate::manage) struct BucketPage {
    pub(in crate::manage) status: Status,
    pub(in crate::manage) items: Vec<Bucket>,
    pub(in crate::manage) next_cursor: Option<u64>,
    /// Earliest retained window for this scope/resolution, not complete coverage.
    pub(in crate::manage) floor: Option<u64>,
}

/// One complete, bounded durable node history. The protocol positions are
/// historical HTTP family, SOCKS5, MASQUE, plain HTTP, TLS HTTPS. Absence is
/// unknown/no stored window, never a zero row.
pub(in crate::manage) struct Window {
    pub(in crate::manage) window_id: u64,
    pub(in crate::manage) values: [Option<Snapshot>; PROTOCOL_COUNT],
}

/// Only this node's own accepted payload; imported child totals are excluded.
pub(in crate::manage) struct NodeSnapshot {
    pub(in crate::manage) status: Status,
    pub(in crate::manage) totals: [Snapshot; PROTOCOL_COUNT],
    pub(in crate::manage) minute: Vec<Window>,
    pub(in crate::manage) hour: Vec<Window>,
    pub(in crate::manage) day: Vec<Window>,
    /// Persisted UTC retention cutoffs, not inferred from a missing row.
    pub(in crate::manage) floors: [Option<u64>; 3],
}

#[derive(Deserialize)]
struct State {
    #[serde(flatten)]
    status: Status,
    #[serde(rename = "last_observed_at")]
    last_observed: Option<u64>,
    series_count: u64,
    window_count: u64,
    #[serde(rename = "excluded_observed_at")]
    excluded_observed: Option<u64>,
    /// Committed logical cutoff time, not a claim that physical cleanup is done.
    retention_at: Option<u64>,
}

/// Creates schema7 inside initialization/migration's existing transaction.
/// The 128 MiB budget is a logical fixed-row payload bound, not a SQLite/WAL
/// filesystem quota; SQLite pages, indices and retained WAL consume extra space.
pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection.execute_batch(
        "CREATE TABLE traffic_state (
           singleton INTEGER PRIMARY KEY CHECK(singleton=1),
           meter_epoch TEXT NOT NULL CHECK(length(meter_epoch)=22),
           run_id TEXT CHECK(run_id IS NULL OR length(run_id)=22),
           cursor INTEGER NOT NULL CHECK(cursor>=0),
           clean INTEGER NOT NULL CHECK(clean IN(0,1)),
           loss_possible INTEGER NOT NULL CHECK(loss_possible IN(0,1)),
           history_gap INTEGER NOT NULL CHECK(history_gap IN(0,1)),
           time_uncertain INTEGER NOT NULL CHECK(time_uncertain IN(0,1)),
           last_checkpoint_at INTEGER CHECK(last_checkpoint_at>=0),
           meter_started_at INTEGER CHECK(meter_started_at>=0),
           last_observed_at INTEGER CHECK(last_observed_at>=0)
           ,series_count INTEGER NOT NULL CHECK(series_count BETWEEN 0 AND 28035)
           ,window_count INTEGER NOT NULL CHECK(window_count BETWEEN 0 AND 500000)
           ,excluded_observed_at INTEGER CHECK(excluded_observed_at>=0)
         ) STRICT;
         CREATE TABLE traffic_series (
           scope INTEGER NOT NULL CHECK(scope BETWEEN 0 AND 3),
           subject_id TEXT NOT NULL CHECK(length(subject_id)=22),
           protocol INTEGER NOT NULL CHECK(protocol BETWEEN 0 AND 2),
           user_id TEXT REFERENCES proxy_users(id) ON DELETE RESTRICT,
           credential_id TEXT REFERENCES proxy_credentials(id) ON DELETE RESTRICT,
           pool_id TEXT REFERENCES routing_pools(id) ON DELETE RESTRICT,
           node_id TEXT REFERENCES node_identity(node_id) ON DELETE RESTRICT,
           upload BLOB NOT NULL CHECK(length(upload)=8),
           download BLOB NOT NULL CHECK(length(download)=8),
           saturated INTEGER NOT NULL CHECK(saturated IN(0,1)),
           updated_cursor INTEGER NOT NULL CHECK(updated_cursor>=1),
           CHECK((scope=0 AND credential_id IS NOT NULL AND credential_id=subject_id AND user_id IS NOT NULL AND pool_id IS NULL AND node_id IS NULL)
              OR(scope=1 AND pool_id IS NOT NULL AND pool_id=subject_id AND credential_id IS NULL AND user_id IS NULL AND node_id IS NULL)
              OR(scope=2 AND node_id IS NOT NULL AND node_id=subject_id AND credential_id IS NULL AND user_id IS NULL AND pool_id IS NULL)
              OR(scope=3 AND user_id IS NOT NULL AND user_id=subject_id AND credential_id IS NULL AND pool_id IS NULL AND node_id IS NULL)),
           PRIMARY KEY(scope,subject_id,protocol)
         ) STRICT;
         CREATE TABLE traffic_windows (
           scope INTEGER NOT NULL CHECK(scope BETWEEN 1 AND 3),
           subject_id TEXT NOT NULL CHECK(length(subject_id)=22),
           protocol INTEGER NOT NULL CHECK(protocol BETWEEN 0 AND 2),
           resolution INTEGER NOT NULL CHECK(resolution BETWEEN 0 AND 2),
           window_id INTEGER NOT NULL CHECK(window_id>=0),
           user_id TEXT REFERENCES proxy_users(id) ON DELETE RESTRICT,
           pool_id TEXT REFERENCES routing_pools(id) ON DELETE RESTRICT,
           node_id TEXT REFERENCES node_identity(node_id) ON DELETE RESTRICT,
           upload BLOB NOT NULL CHECK(length(upload)=8),
           download BLOB NOT NULL CHECK(length(download)=8),
           saturated INTEGER NOT NULL CHECK(saturated IN(0,1)),
           updated_cursor INTEGER NOT NULL CHECK(updated_cursor>=1),
           CHECK((scope=1 AND pool_id IS NOT NULL AND pool_id=subject_id AND user_id IS NULL AND node_id IS NULL)
              OR(scope=2 AND node_id IS NOT NULL AND node_id=subject_id AND user_id IS NULL AND pool_id IS NULL)
              OR(scope=3 AND user_id IS NOT NULL AND user_id=subject_id AND pool_id IS NULL AND node_id IS NULL)),
           PRIMARY KEY(scope,subject_id,protocol,resolution,window_id)
         ) STRICT;
         CREATE INDEX traffic_windows_retention ON traffic_windows(resolution,window_id);"
    ).map_err(|error|sqlite_error("cannot create traffic accounting schema",error))?;
    connection.execute("INSERT INTO traffic_state(singleton,meter_epoch,cursor,clean,loss_possible,history_gap,time_uncertain,series_count,window_count) VALUES(1,?1,0,1,0,0,0,0,0)", [super::random_id()?]).map_err(|error|sqlite_error("cannot initialize traffic accounting epoch",error))?;
    Ok(())
}

/// Expand accounting slots atomically inside initialization/migration's owned
/// transaction. Original bytes, identities, cursors, flags and UTC history remain
/// in their existing slots; legacy HTTP-family traffic is not reclassified.
pub(super) fn upgrade_protocols(connection: &Connection) -> io::Result<()> {
    connection.execute_batch(
        "CREATE TABLE traffic_state_v29 (
           singleton INTEGER PRIMARY KEY CHECK(singleton=1),
           meter_epoch TEXT NOT NULL CHECK(length(meter_epoch)=22),
           run_id TEXT CHECK(run_id IS NULL OR length(run_id)=22),
           cursor INTEGER NOT NULL CHECK(cursor>=0),
           clean INTEGER NOT NULL CHECK(clean IN(0,1)),
           loss_possible INTEGER NOT NULL CHECK(loss_possible IN(0,1)),
           history_gap INTEGER NOT NULL CHECK(history_gap IN(0,1)),
           time_uncertain INTEGER NOT NULL CHECK(time_uncertain IN(0,1)),
           last_checkpoint_at INTEGER CHECK(last_checkpoint_at>=0),
           meter_started_at INTEGER CHECK(meter_started_at>=0),
           last_observed_at INTEGER CHECK(last_observed_at>=0)
           ,series_count INTEGER NOT NULL CHECK(series_count BETWEEN 0 AND 46725)
           ,window_count INTEGER NOT NULL CHECK(window_count BETWEEN 0 AND 500000)
           ,excluded_observed_at INTEGER CHECK(excluded_observed_at>=0)
           ,retention_at INTEGER CHECK(retention_at>=0)
         ) STRICT;
         CREATE TABLE traffic_series_v29 (
           scope INTEGER NOT NULL CHECK(scope BETWEEN 0 AND 3),
           subject_id TEXT NOT NULL CHECK(length(subject_id)=22),
           protocol INTEGER NOT NULL CHECK(protocol BETWEEN 0 AND 4),
           user_id TEXT REFERENCES proxy_users(id) ON DELETE RESTRICT,
           credential_id TEXT REFERENCES proxy_credentials(id) ON DELETE RESTRICT,
           pool_id TEXT REFERENCES routing_pools(id) ON DELETE RESTRICT,
           node_id TEXT REFERENCES node_identity(node_id) ON DELETE RESTRICT,
           upload BLOB NOT NULL CHECK(length(upload)=8),
           download BLOB NOT NULL CHECK(length(download)=8),
           saturated INTEGER NOT NULL CHECK(saturated IN(0,1)),
           updated_cursor INTEGER NOT NULL CHECK(updated_cursor>=1),
           CHECK((scope=0 AND credential_id IS NOT NULL AND credential_id=subject_id AND user_id IS NOT NULL AND pool_id IS NULL AND node_id IS NULL)
              OR(scope=1 AND pool_id IS NOT NULL AND pool_id=subject_id AND credential_id IS NULL AND user_id IS NULL AND node_id IS NULL)
              OR(scope=2 AND node_id IS NOT NULL AND node_id=subject_id AND credential_id IS NULL AND user_id IS NULL AND pool_id IS NULL)
              OR(scope=3 AND user_id IS NOT NULL AND user_id=subject_id AND credential_id IS NULL AND pool_id IS NULL AND node_id IS NULL)),
           PRIMARY KEY(scope,subject_id,protocol)
         ) STRICT;
         CREATE TABLE traffic_windows_v29 (
           scope INTEGER NOT NULL CHECK(scope BETWEEN 1 AND 3),
           subject_id TEXT NOT NULL CHECK(length(subject_id)=22),
           protocol INTEGER NOT NULL CHECK(protocol BETWEEN 0 AND 4),
           resolution INTEGER NOT NULL CHECK(resolution BETWEEN 0 AND 2),
           window_id INTEGER NOT NULL CHECK(window_id>=0),
           user_id TEXT REFERENCES proxy_users(id) ON DELETE RESTRICT,
           pool_id TEXT REFERENCES routing_pools(id) ON DELETE RESTRICT,
           node_id TEXT REFERENCES node_identity(node_id) ON DELETE RESTRICT,
           upload BLOB NOT NULL CHECK(length(upload)=8),
           download BLOB NOT NULL CHECK(length(download)=8),
           saturated INTEGER NOT NULL CHECK(saturated IN(0,1)),
           updated_cursor INTEGER NOT NULL CHECK(updated_cursor>=1),
           CHECK((scope=1 AND pool_id IS NOT NULL AND pool_id=subject_id AND user_id IS NULL AND node_id IS NULL)
              OR(scope=2 AND node_id IS NOT NULL AND node_id=subject_id AND user_id IS NULL AND pool_id IS NULL)
              OR(scope=3 AND user_id IS NOT NULL AND user_id=subject_id AND pool_id IS NULL AND node_id IS NULL)),
           PRIMARY KEY(scope,subject_id,protocol,resolution,window_id)
         ) STRICT;

         INSERT INTO traffic_state_v29 SELECT * FROM traffic_state;
         INSERT INTO traffic_series_v29 SELECT * FROM traffic_series;
         INSERT INTO traffic_windows_v29 SELECT * FROM traffic_windows;
         DROP TABLE traffic_windows;
         DROP TABLE traffic_series;
         DROP TABLE traffic_state;
         ALTER TABLE traffic_state_v29 RENAME TO traffic_state;
         ALTER TABLE traffic_series_v29 RENAME TO traffic_series;
         ALTER TABLE traffic_windows_v29 RENAME TO traffic_windows;
         CREATE INDEX traffic_windows_retention ON traffic_windows(resolution,window_id);"
    ).map_err(|error| sqlite_error("cannot separate HTTP transport accounting", error))?;
    Ok(())
}

/// Loads bounded absolute leaf seeds and provenance in one read-only snapshot.
/// It never opens a run or changes an unclean marker merely because the API is
/// online. Missing/old schemas and corrupt identities/counts fail closed.
pub(in crate::manage) fn restore(directory: &Path) -> io::Result<Restored> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot inspect traffic restoration", error))?;
    let state = state_in(&transaction)?;
    validate_counts(&transaction, &state)?;
    let status = state.status;
    let mut statement = transaction.prepare("SELECT scope,subject_id,protocol,user_id,upload,download,saturated FROM traffic_series WHERE scope IN(0,1) ORDER BY scope,subject_id,protocol").map_err(|error|sqlite_error("cannot inspect traffic seeds",error))?;
    let mut rows = statement
        .query([])
        .map_err(|error| sqlite_error("cannot read traffic seeds", error))?;
    let mut credential_seeds = Vec::new();
    let mut pool_seeds = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| sqlite_error("cannot read traffic seed", error))?
    {
        let scope: i64 = row.get(0).map_err(decode_error)?;
        let id: String = row.get(1).map_err(decode_error)?;
        let protocol = protocol(row.get(2).map_err(decode_error)?)?;
        let user: Option<String> = row.get(3).map_err(decode_error)?;
        let value = value_in(row, 4)?;
        if !valid_id(&id) {
            return Err(invalid_data("traffic seed identity is malformed"));
        }
        match scope {
            0 => {
                let user = user
                    .filter(|id| valid_id(id))
                    .ok_or_else(|| invalid_data("traffic seed owner is malformed"))?;
                let owner: Option<String> = transaction
                    .query_row(
                        "SELECT user_id FROM proxy_credentials WHERE id=?1",
                        [&id],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(decode_error)?;
                if owner.as_deref() != Some(user.as_str()) {
                    return Err(invalid_data("traffic credential ownership is malformed"));
                }
                credential_seeds.push(Seed {
                    user_id: user,
                    credential_id: id,
                    protocol,
                    value,
                });
            }
            1 => {
                if user.is_some() || !exists(&transaction, 1, &id)? {
                    return Err(invalid_data("traffic pool identity is malformed"));
                }
                pool_seeds.push(PoolSeed {
                    pool_id: id,
                    protocol,
                    value,
                });
            }
            _ => return Err(invalid_data("traffic seed scope is malformed")),
        }
    }
    drop(rows);
    drop(statement);
    // The registry rechecks cross-row uniqueness/capacity before publication.
    Ok(Restored {
        status,
        credential_seeds,
        pool_seeds,
    })
}

/// Returns durable status only; runtime readiness is intentionally separate.
pub(in crate::manage) fn status(directory: &Path) -> io::Result<Status> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection.transaction().map_err(decode_error)?;
    Ok(state_in(&transaction)?.status)
}

/// Reads at most three cumulative protocol rows with status from the same
/// snapshot. An existing tombstone remains queryable; unknown IDs are errors,
/// not misleading zero-valued identities.
pub(in crate::manage) fn totals(directory: &Path, scope: Scope) -> io::Result<Totals> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection.transaction().map_err(decode_error)?;
    totals_in(&transaction, scope)
}

/// Reuse the caller's authorized snapshot; never opens another transaction.
pub(super) fn totals_in(transaction: &Connection, scope: Scope) -> io::Result<Totals> {
    let status = state_in(transaction)?.status;
    let (code, id) = scope_in(transaction, scope, &status.node_id)?;
    let mut items = Vec::with_capacity(PROTOCOL_COUNT);
    for protocol in 0..PROTOCOL_COUNT as i64 {
        items.push(ProtocolTotal {
            protocol: self::protocol(protocol)?,
            value: series_value(transaction, code, &id, protocol)?.unwrap_or(ZERO),
        });
    }
    Ok(Totals { status, items })
}

/// Pages at most 50 complete UTC windows, each with at most three protocols.
/// No empty windows are manufactured for downtime or retention gaps. Cursor
/// values and the floor are aligned Unix milliseconds, not an arrival ordering.
pub(in crate::manage) fn buckets(
    directory: &Path,
    scope: Scope,
    resolution: Resolution,
    after: Option<u64>,
    limit: u32,
) -> io::Result<BucketPage> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection.transaction().map_err(decode_error)?;
    buckets_in(&transaction, scope, resolution, after, limit)
}

/// Reuse the caller's authorized snapshot for both metadata and window rows.
pub(super) fn buckets_in(
    transaction: &Connection,
    scope: Scope,
    resolution: Resolution,
    after: Option<u64>,
    limit: u32,
) -> io::Result<BucketPage> {
    if limit == 0 || limit > MAX_PAGE {
        return Err(input("traffic page limit must be between 1 and 50"));
    }
    let after = after.map(sql_number).transpose()?;
    let state = state_in(transaction)?;
    let cutoff = state
        .retention_at
        .map(|time| resolution.floor(time))
        .map(sql_number)
        .transpose()?;
    let status = state.status;
    let (code, id) = scope_in(transaction, scope, &status.node_id)?;
    if code == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "credential traffic history is not collected",
        ));
    }
    let floor:Option<i64>=transaction.query_row("SELECT min(window_id) FROM traffic_windows WHERE scope=?1 AND subject_id=?2 AND resolution=?3 AND (?4 IS NULL OR window_id>=?4)",params![code,id,resolution.code(),cutoff],|row|row.get(0)).map_err(decode_error)?;
    let mut statement=transaction.prepare("SELECT DISTINCT window_id FROM traffic_windows WHERE scope=?1 AND subject_id=?2 AND resolution=?3 AND (?4 IS NULL OR window_id>?4) AND (?6 IS NULL OR window_id>=?6) ORDER BY window_id LIMIT ?5").map_err(decode_error)?;
    let rows = statement
        .query_map(
            params![
                code,
                id,
                resolution.code(),
                after,
                i64::from(limit) + 1,
                cutoff
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(decode_error)?;
    let mut windows = rows.collect::<Result<Vec<_>, _>>().map_err(decode_error)?;
    let more = windows.len() > limit as usize;
    windows.truncate(limit as usize);
    let mut items = Vec::with_capacity(windows.len());
    for window in windows {
        let window_id = positive_or_zero(window)?;
        if !window_id.is_multiple_of(resolution.width()) {
            return Err(invalid_data("traffic history window is malformed"));
        }
        let mut statement=transaction.prepare("SELECT protocol,upload,download,saturated FROM traffic_windows WHERE scope=?1 AND subject_id=?2 AND resolution=?3 AND window_id=?4 ORDER BY protocol").map_err(decode_error)?;
        let mut rows = statement
            .query(params![code, id, resolution.code(), window])
            .map_err(decode_error)?;
        let mut values = Vec::with_capacity(3);
        while let Some(row) = rows.next().map_err(decode_error)? {
            values.push(ProtocolTotal {
                protocol: protocol(row.get(0).map_err(decode_error)?)?,
                value: value_in(row, 1)?,
            });
        }
        if values.len() > 3 {
            return Err(invalid_data("traffic history exceeds protocol capacity"));
        }
        items.push(Bucket {
            window_id,
            items: values,
        });
    }
    let next_cursor = if more {
        items.last().map(|item| item.window_id)
    } else {
        None
    };
    Ok(BucketPage {
        status,
        items,
        next_cursor,
        floor: floor.map(positive_or_zero).transpose()?,
    })
}

/// At most 690 protocol rows / 138 windows, all from one SQLite read snapshot.
pub(super) fn node_snapshot_in(connection: &Connection) -> io::Result<NodeSnapshot> {
    use std::collections::BTreeMap;
    let retention = state_in(connection)?.retention_at;
    let floors = [Resolution::Minute, Resolution::Hour, Resolution::Day]
        .map(|resolution| retention.map(|time| resolution.floor(time)));
    let totals = totals_in(connection, Scope::Node)?;
    let protocol_totals: [ProtocolTotal; PROTOCOL_COUNT] = totals
        .items
        .try_into()
        .map_err(|_| invalid_data("invalid node protocol total count"))?;
    let values = protocol_totals.map(|total| total.value);
    let mut statement=connection.prepare("SELECT resolution,window_id,protocol,upload,download,saturated FROM traffic_windows WHERE scope=2 AND subject_id=?1 AND (
        resolution NOT BETWEEN 0 AND 2
        OR (resolution=0 AND (?2 IS NULL OR window_id>=?2))
        OR (resolution=1 AND (?3 IS NULL OR window_id>=?3))
        OR (resolution=2 AND (?4 IS NULL OR window_id>=?4)))
        ORDER BY resolution,window_id,protocol LIMIT 691").map_err(decode_error)?;
    let mut rows = statement
        .query(params![
            &totals.status.node_id,
            floors[0].map(sql_number).transpose()?,
            floors[1].map(sql_number).transpose()?,
            floors[2].map(sql_number).transpose()?
        ])
        .map_err(decode_error)?;
    let mut windows: BTreeMap<(i64, u64), [Option<Snapshot>; PROTOCOL_COUNT]> = BTreeMap::new();
    let mut count = 0usize;
    while let Some(row) = rows.next().map_err(decode_error)? {
        count += 1;
        if count > 690 {
            return Err(invalid_data("node traffic history exceeds capacity"));
        }
        let resolution: i64 = row.get(0).map_err(decode_error)?;
        let resolution_type = match resolution {
            0 => Resolution::Minute,
            1 => Resolution::Hour,
            2 => Resolution::Day,
            _ => return Err(invalid_data("invalid node traffic resolution")),
        };
        let window = positive_or_zero(row.get(1).map_err(decode_error)?)?;
        if !window.is_multiple_of(resolution_type.width()) {
            return Err(invalid_data("invalid node traffic window"));
        }
        let protocol = protocol_code(protocol(row.get(2).map_err(decode_error)?)?) as usize;
        if windows
            .entry((resolution, window))
            .or_insert([None; PROTOCOL_COUNT])[protocol]
            .replace(value_in(row, 3)?)
            .is_some()
        {
            return Err(invalid_data("duplicate node traffic series"));
        }
    }
    let (mut minute, mut hour, mut day) = (Vec::new(), Vec::new(), Vec::new());
    for ((resolution, window_id), values) in windows {
        let target = match resolution {
            0 => &mut minute,
            1 => &mut hour,
            _ => &mut day,
        };
        target.push(Window { window_id, values });
    }
    if minute.len() > 60 || hour.len() > 48 || day.len() > 30 {
        return Err(invalid_data(
            "node traffic history exceeds retention capacity",
        ));
    }
    Ok(NodeSnapshot {
        status: totals.status,
        totals: values,
        minute,
        hour,
        day,
        floors,
    })
}

fn state_in(connection: &Connection) -> io::Result<State> {
    let overview = read_overview(connection)?;
    if overview.schema_version < 7 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "traffic accounting requires explicit schema migration",
        ));
    }
    let retention = if overview.schema_version >= 8 {
        "retention_at"
    } else {
        "NULL AS retention_at"
    };
    let query = format!(
        "SELECT ?1 AS http_split,?2 AS node_id,meter_epoch,run_id,cursor,clean,loss_possible,history_gap,time_uncertain,last_checkpoint_at,meter_started_at,last_observed_at,series_count,window_count,excluded_observed_at,{retention} FROM traffic_state WHERE singleton=1"
    );
    let mut statement = connection.prepare(&query).map_err(decode_error)?;
    let state = serde_rusqlite::from_rows::<State>(
        statement
            .query(params![overview.schema_version >= 29, overview.node_id])
            .map_err(decode_error)?,
    )
    .next()
    .transpose()
    .map_err(|error| sqlite_error("cannot read traffic accounting state", error))?
    .ok_or_else(|| invalid_data("cannot read traffic accounting state"))?;
    if !valid_id(&state.status.meter_epoch)
        || state.status.run_id.as_ref().is_some_and(|id| !valid_id(id))
    {
        return Err(invalid_data("traffic accounting identity is malformed"));
    }
    if state.series_count > MAX_SERIES || state.window_count > MAX_WINDOWS {
        return Err(invalid_data("traffic capacity state is malformed"));
    }
    Ok(state)
}

fn validate_counts(connection: &Connection, state: &State) -> io::Result<()> {
    if check_count(connection, "traffic_series", MAX_SERIES)? != state.series_count
        || check_count(connection, "traffic_windows", MAX_WINDOWS)? != state.window_count
    {
        return Err(invalid_data(
            "traffic capacity state does not match stored rows",
        ));
    }
    Ok(())
}

fn scope_in(connection: &Connection, scope: Scope, node: &str) -> io::Result<(i64, String)> {
    let (code, id) = match scope {
        Scope::Node => (2, node.to_owned()),
        Scope::User(id) => (3, id),
        Scope::Credential(id) => (0, id),
        Scope::Pool(id) => (1, id),
    };
    if !valid_id(&id) {
        return Err(input("invalid traffic scope identity"));
    }
    if !exists(connection, code, &id)? {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "traffic scope is not registered",
        ));
    }
    Ok((code, id))
}

fn exists(connection: &Connection, scope: i64, id: &str) -> io::Result<bool> {
    let query = match scope {
        0 => "SELECT EXISTS(SELECT 1 FROM proxy_credentials WHERE id=?1)",
        1 => "SELECT EXISTS(SELECT 1 FROM routing_pools WHERE id=?1)",
        2 => "SELECT EXISTS(SELECT 1 FROM node_identity WHERE node_id=?1)",
        3 => "SELECT EXISTS(SELECT 1 FROM proxy_users WHERE id=?1)",
        _ => return Err(invalid_data("invalid traffic scope")),
    };
    flag(
        connection
            .query_row(query, [id], |row| row.get(0))
            .map_err(decode_error)?,
    )
}

fn series_value(
    connection: &Connection,
    scope: i64,
    id: &str,
    protocol: i64,
) -> io::Result<Option<Snapshot>> {
    let row=connection.query_row("SELECT upload,download,saturated FROM traffic_series WHERE scope=?1 AND subject_id=?2 AND protocol=?3",params![scope,id,protocol],|row|Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,Vec<u8>>(1)?,row.get::<_,i64>(2)?))).optional().map_err(decode_error)?;
    row.map(|(up, down, saturated)| decode_value(up, down, saturated))
        .transpose()
}

fn value_in(row: &rusqlite::Row<'_>, offset: usize) -> io::Result<Snapshot> {
    decode_value(
        row.get(offset).map_err(decode_error)?,
        row.get(offset + 1).map_err(decode_error)?,
        row.get(offset + 2).map_err(decode_error)?,
    )
}
fn decode_value(up: Vec<u8>, down: Vec<u8>, saturated: i64) -> io::Result<Snapshot> {
    let up: [u8; 8] = up
        .try_into()
        .map_err(|_| invalid_data("invalid traffic counter length"))?;
    let down: [u8; 8] = down
        .try_into()
        .map_err(|_| invalid_data("invalid traffic counter length"))?;
    Ok(Snapshot {
        upload: u64::from_be_bytes(up),
        download: u64::from_be_bytes(down),
        saturated: flag(saturated)?,
    })
}
fn protocol(value: i64) -> io::Result<Protocol> {
    match value {
        0 => Ok(Protocol::HttpLegacy),
        1 => Ok(Protocol::Socks5),
        2 => Ok(Protocol::Masque),
        3 => Ok(Protocol::Http),
        4 => Ok(Protocol::Https),
        _ => Err(invalid_data("traffic protocol is malformed")),
    }
}
fn protocol_code(value: Protocol) -> i64 {
    match value {
        Protocol::HttpLegacy => 0,
        Protocol::Socks5 => 1,
        Protocol::Masque => 2,
        Protocol::Http => 3,
        Protocol::Https => 4,
    }
}
fn flag(value: i64) -> io::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid_data("traffic flag is malformed")),
    }
}
fn positive_or_zero(value: i64) -> io::Result<u64> {
    u64::try_from(value).map_err(|_| invalid_data("traffic number is malformed"))
}
fn sql_number(value: u64) -> io::Result<i64> {
    i64::try_from(value).map_err(|_| input("traffic number exceeds SQLite range"))
}
fn input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn decode_error(error: rusqlite::Error) -> io::Error {
    sqlite_error("cannot read traffic accounting state", error)
}
fn check_count(connection: &Connection, table: &str, max: u64) -> io::Result<u64> {
    let sql = match table {
        "traffic_series" => "SELECT count(*) FROM traffic_series",
        "traffic_windows" => "SELECT count(*) FROM traffic_windows",
        _ => return Err(invalid_data("invalid traffic capacity table")),
    };
    let count = positive_or_zero(
        connection
            .query_row(sql, [], |row| row.get(0))
            .map_err(decode_error)?,
    )?;
    if count > max {
        return Err(invalid_data("traffic accounting exceeds capacity"));
    }
    Ok(count)
}

/// Reconstruct the actual pre-split constraints, not just its version number.
/// The caller owns a transaction and may only supply legacy-compatible rows.
#[cfg(test)]
pub(super) fn legacy_protocols_for_test(connection: &Connection) -> io::Result<()> {
    connection
        .execute_batch(
            "DROP INDEX traffic_windows_retention;
        ALTER TABLE traffic_state RENAME TO traffic_state_fixture29;
        ALTER TABLE traffic_series RENAME TO traffic_series_fixture29;
        ALTER TABLE traffic_windows RENAME TO traffic_windows_fixture29;
        ALTER TABLE remote_traffic_sources RENAME TO remote_traffic_sources_fixture29;",
        )
        .map_err(decode_error)?;
    create_schema(connection)?;
    super::remote_traffic::create_schema(connection)?;
    connection
        .execute_batch(
            "DELETE FROM traffic_state;
        INSERT INTO traffic_state SELECT * FROM traffic_state_fixture29;
        INSERT INTO traffic_series SELECT * FROM traffic_series_fixture29;
        INSERT INTO traffic_windows SELECT * FROM traffic_windows_fixture29;
        INSERT INTO remote_traffic_sources SELECT * FROM remote_traffic_sources_fixture29;
        DROP TABLE traffic_windows_fixture29; DROP TABLE traffic_series_fixture29;
        DROP TABLE traffic_state_fixture29; DROP TABLE remote_traffic_sources_fixture29;",
        )
        .map_err(decode_error)
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use super::*;

    use crate::access::traffic::{PoolSnapshot, SeriesSnapshot};
    use crate::{
        access::routing::AddressFamily,
        manage::store::{self, PolicyChange, UpdateGuard, initialize, random_id, update_lock},
    };

    struct Fixture {
        directory: PathBuf,
        admin: String,
        user: String,
        credential: String,
        pool: String,
    }
    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory =
                std::env::temp_dir().join(format!("vproxy-traffic-store-{}", random_id()?));
            initialize(&directory, "traffic node", "admin", "private fixture PHC")?;
            let connection = open_existing(&directory, false)?;
            let admin: String = connection
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(decode_error)?;
            let gate = update_lock(&directory)?;
            let user = store::apply_policy(
                &directory,
                &admin,
                1,
                PolicyChange::CreateUser {
                    name: "counter owner".into(),
                    protocols: vec![
                        crate::access::Protocol::Http,
                        crate::access::Protocol::Socks5,
                        crate::access::Protocol::Masque,
                    ],
                    concurrent_limit: 8,
                },
                &gate,
            )?
            .user
            .unwrap()
            .id;
            let credential = store::apply_policy(
                &directory,
                &admin,
                2,
                PolicyChange::CreateCredential {
                    user_id: user.clone(),
                },
                &gate,
            )?
            .credential
            .unwrap()
            .id;
            let pool = match store::apply_policy(
                &directory,
                &admin,
                3,
                PolicyChange::CreatePool {
                    name: "shared pool".into(),
                    family: AddressFamily::V4,
                },
                &gate,
            )?
            .routing
            .unwrap()
            {
                crate::access::routing::RoutingEntity::Pool(pool) => pool.id,
                _ => panic!("pool projection"),
            };
            drop(gate);
            Ok(Self {
                directory,
                admin,
                user,
                credential,
                pool,
            })
        }
        fn gate(&self) -> io::Result<UpdateGuard> {
            update_lock(&self.directory)
        }
        fn start(&self, gate: &UpdateGuard, time: Option<u64>) -> io::Result<Status> {
            let status = status(&self.directory)?;
            Ok(start_run(
                &self.directory,
                gate,
                &status.meter_epoch,
                status.cursor,
                time,
            )?
            .status)
        }
        fn sample(&self, upload: u64, download: u64) -> SeriesSnapshot {
            SeriesSnapshot {
                user_id: Arc::from(self.user.as_str()),
                credential_id: Arc::from(self.credential.as_str()),
                protocol: Protocol::Http,
                value: Snapshot {
                    upload,
                    download,
                    saturated: false,
                },
            }
        }
        fn pool_sample(&self, upload: u64, download: u64) -> PoolSnapshot {
            PoolSnapshot {
                pool_id: Arc::from(self.pool.as_str()),
                protocol: Protocol::Http,
                value: Snapshot {
                    upload,
                    download,
                    saturated: false,
                },
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn http(totals: Totals) -> Snapshot {
        totals
            .items
            .into_iter()
            .find(|item| item.protocol == Protocol::Http)
            .unwrap()
            .value
    }

    #[test]
    fn schema_twenty_eight_migration_keeps_legacy_identity_and_separates_new_scopes()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let gate = fixture.gate()?;
        let run = fixture.start(&gate, Some(60_000))?.run_id.unwrap();
        let mut legacy = fixture.sample(37, 19);
        legacy.protocol = Protocol::HttpLegacy;
        checkpoint(
            &fixture.directory,
            &gate,
            &run,
            Some(61_000),
            &[legacy],
            &[],
        )?;
        finish(&fixture.directory, &gate, &run, Some(62_000))?;
        drop(gate);
        let connection = open_existing(&fixture.directory, true)?;
        store::recovery::restore_schema_twenty_eight_for_test(&connection)?;
        let before = status(&fixture.directory)?;
        assert!(!before.http_split);
        let permissions = store::load_policy(&fixture.directory)?.users[0]
            .protocols
            .clone();
        let gate = fixture.gate()?;
        assert_eq!(
            start_run(
                &fixture.directory,
                &gate,
                &before.meter_epoch,
                before.cursor,
                Some(63_000)
            )
            .err()
            .unwrap()
            .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(status(&fixture.directory)?.cursor, before.cursor);
        drop(gate);
        let backup = fixture.directory.join("schema28-before-split.sqlite3");
        assert_eq!(
            store::migrate(&fixture.directory, &backup)?.schema_version,
            29
        );
        let original = Connection::open(&backup).map_err(decode_error)?;
        assert_eq!(store::read_overview(&original)?.schema_version, 28);
        assert!(!state_in(&original)?.status.http_split);
        assert_eq!(state_in(&original)?.status.cursor, before.cursor);
        assert!(store::load_policy(&fixture.directory)?.users[0].protocols == permissions);
        let after = status(&fixture.directory)?;
        assert!(after.http_split);
        assert_eq!(
            (
                &after.node_id,
                &after.meter_epoch,
                after.cursor,
                after.run_id.as_ref(),
                after.clean
            ),
            (
                &before.node_id,
                &before.meter_epoch,
                before.cursor,
                before.run_id.as_ref(),
                before.clean
            )
        );
        let gate = fixture.gate()?;
        let run = fixture.start(&gate, Some(63_000))?.run_id.unwrap();
        let plain = fixture.sample(11, 5);
        let mut secure = fixture.sample(17, 7);
        secure.protocol = Protocol::Https;
        checkpoint(
            &fixture.directory,
            &gate,
            &run,
            Some(64_000),
            &[plain, secure],
            &[],
        )?;
        finish(&fixture.directory, &gate, &run, Some(65_000))?;
        for scope in [
            Scope::Node,
            Scope::User(fixture.user.clone()),
            Scope::Credential(fixture.credential.clone()),
        ] {
            let rows = totals(&fixture.directory, scope)?.items;
            assert_eq!(rows[0].value.upload, 37);
            assert_eq!(
                rows[3].value,
                Snapshot {
                    upload: 11,
                    download: 5,
                    saturated: false
                }
            );
            assert_eq!(
                rows[4].value,
                Snapshot {
                    upload: 17,
                    download: 7,
                    saturated: false
                }
            );
            assert_eq!(
                rows.into_iter()
                    .fold(ZERO, |sum, item| sum.sum(item.value))
                    .upload,
                65
            );
        }
        let restored = restore(&fixture.directory)?;
        assert_eq!(restored.credential_seeds.len(), 3);
        assert!(
            restored
                .credential_seeds
                .iter()
                .any(|seed| seed.protocol == Protocol::HttpLegacy && seed.value.upload == 37)
        );
        assert!(
            restored
                .credential_seeds
                .iter()
                .any(|seed| seed.protocol == Protocol::Https && seed.value.upload == 17)
        );
        let windows = buckets(
            &fixture.directory,
            Scope::Node,
            Resolution::Minute,
            None,
            50,
        )?;
        assert_eq!(windows.items[0].items.len(), 3);
        Ok(())
    }

    #[test]
    fn absolute_batches_restore_leafs_and_do_not_double_count_pool_or_retries() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let gate = fixture.gate()?;
        let initial = restore(&fixture.directory)?;
        assert!(initial.credential_seeds.is_empty() && initial.pool_seeds.is_empty());
        assert!(initial.status.clean && initial.status.meter_started_at.is_none());
        let run = fixture.start(&gate, Some(3_600_000))?.run_id.unwrap();
        let samples = [fixture.sample(100, 40)];
        let pools = [fixture.pool_sample(30, 10)];
        checkpoint(
            &fixture.directory,
            &gate,
            &run,
            Some(3_605_000),
            &samples,
            &pools,
        )?;
        checkpoint(
            &fixture.directory,
            &gate,
            &run,
            Some(3_605_000),
            &samples,
            &pools,
        )?;
        assert_eq!(
            http(totals(&fixture.directory, Scope::Node)?),
            samples[0].value
        );
        assert_eq!(
            http(totals(
                &fixture.directory,
                Scope::User(fixture.user.clone())
            )?),
            samples[0].value
        );
        assert_eq!(
            http(totals(
                &fixture.directory,
                Scope::Credential(fixture.credential.clone())
            )?),
            samples[0].value
        );
        assert_eq!(
            http(totals(
                &fixture.directory,
                Scope::Pool(fixture.pool.clone())
            )?),
            pools[0].value
        );
        for resolution in [Resolution::Minute, Resolution::Hour, Resolution::Day] {
            let page = buckets(&fixture.directory, Scope::Node, resolution, None, 50)?;
            assert_eq!(page.items.len(), 1);
            assert_eq!(page.items[0].items[0].value, samples[0].value);
        }
        store::apply_policy(
            &fixture.directory,
            &fixture.admin,
            4,
            PolicyChange::RotateCredential {
                id: fixture.credential.clone(),
            },
            &gate,
        )?;
        store::apply_policy(
            &fixture.directory,
            &fixture.admin,
            5,
            PolicyChange::DeleteUser {
                id: fixture.user.clone(),
            },
            &gate,
        )?;
        checkpoint(
            &fixture.directory,
            &gate,
            &run,
            Some(3_610_000),
            &[fixture.sample(109, 42)],
            &[fixture.pool_sample(35, 12)],
        )?;
        let closed = finish(&fixture.directory, &gate, &run, Some(3_610_001))?;
        assert!(closed.clean && !closed.loss_possible);
        assert_eq!(
            finish(&fixture.directory, &gate, &run, Some(3_610_002))?.cursor,
            closed.cursor
        );
        let restored = restore(&fixture.directory)?;
        assert_eq!(restored.credential_seeds.len(), 1);
        assert_eq!(restored.pool_seeds.len(), 1);
        assert_eq!(restored.credential_seeds[0].value.upload, 109);
        assert_eq!(restored.pool_seeds[0].value.upload, 35);
        assert_eq!(restored.status.meter_epoch, initial.status.meter_epoch);
        assert_eq!(restored.status.meter_started_at, Some(3_600_000));
        assert!(checkpoint(&fixture.directory, &gate, &run, None, &samples, &pools).is_err());
        assert!(
            buckets(
                &fixture.directory,
                Scope::Credential(fixture.credential.clone()),
                Resolution::Minute,
                None,
                1
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn crash_run_fencing_regression_and_time_gaps_are_explicit_and_atomic() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let gate = fixture.gate()?;
        let first = fixture.start(&gate, Some(60_000))?;
        let old = first.run_id.clone().unwrap();
        checkpoint(
            &fixture.directory,
            &gate,
            &old,
            Some(65_000),
            &[fixture.sample(10, 0)],
            &[],
        )?;
        let before = status(&fixture.directory)?;
        let restored = restore(&fixture.directory)?;
        assert!(!restored.status.clean);
        assert!(!restored.status.loss_possible);
        assert!(
            start_run(
                &fixture.directory,
                &gate,
                &before.meter_epoch,
                before.cursor - 1,
                Some(70_000)
            )
            .is_err()
        );
        let second = fixture.start(&gate, Some(70_000))?;
        let run = second.run_id.unwrap();
        assert!(second.loss_possible);
        assert_ne!(run, old);
        assert!(checkpoint(&fixture.directory, &gate, &old, Some(71_000), &[], &[]).is_err());
        checkpoint(
            &fixture.directory,
            &gate,
            &run,
            Some(30_000),
            &[fixture.sample(20, 0)],
            &[],
        )?;
        checkpoint(
            &fixture.directory,
            &gate,
            &run,
            Some(35_000),
            &[fixture.sample(25, 0)],
            &[],
        )?;
        checkpoint(
            &fixture.directory,
            &gate,
            &run,
            None,
            &[fixture.sample(30, 0)],
            &[],
        )?;
        let discontinuous = checkpoint(
            &fixture.directory,
            &gate,
            &run,
            Some(2_000_000),
            &[fixture.sample(40, 0)],
            &[],
        )?;
        assert!(discontinuous.history_gap && discontinuous.time_uncertain);
        // One collector snapshot can span multiple transactions. Its later pool
        // batch shares the first batch's rejected timestamp, not a fresh baseline.
        checkpoint(
            &fixture.directory,
            &gate,
            &run,
            Some(2_000_000),
            &[],
            &[fixture.pool_sample(7, 0)],
        )?;
        assert!(
            buckets(
                &fixture.directory,
                Scope::Pool(fixture.pool.clone()),
                Resolution::Day,
                None,
                50
            )?
            .items
            .is_empty()
        );
        checkpoint(
            &fixture.directory,
            &gate,
            &run,
            Some(2_005_000),
            &[fixture.sample(45, 0)],
            &[],
        )?;
        assert_eq!(http(totals(&fixture.directory, Scope::Node)?).upload, 45);
        let history = buckets(&fixture.directory, Scope::Node, Resolution::Day, None, 50)?;
        assert_eq!(history.items[0].items[0].value.upload, 15); // 10 valid +5 after new baseline
        let cursor = status(&fixture.directory)?.cursor;
        assert!(
            checkpoint(
                &fixture.directory,
                &gate,
                &run,
                Some(2_006_000),
                &[fixture.sample(44, 0)],
                &[]
            )
            .is_err()
        );
        assert_eq!(status(&fixture.directory)?.cursor, cursor);
        assert_eq!(http(totals(&fixture.directory, Scope::Node)?).upload, 45);
        Ok(())
    }
}
