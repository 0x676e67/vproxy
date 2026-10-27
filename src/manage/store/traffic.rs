//! Durable accepted-payload counters and bounded, approximate UTC history.
//!
//! Forwarding never calls this module. A single management collector supplies
//! absolute samples in batches of at most 256; each FULL transaction computes
//! deltas once, updates cumulative groups and all three history resolutions.
//! A crash can lose the uncheckpointed tail. Run markers expose that uncertainty
//! rather than presenting these lower bounds as an exact billing ledger.

mod write;
mod writer;

use std::{io, path::Path};

use rusqlite::{Connection, OptionalExtension, params};

use crate::{
    access::{
        Protocol,
        traffic::{PoolSeed, Seed},
    },
    traffic::Snapshot,
};

use super::{invalid_data, peers::open_existing, read_overview, sqlite_error, valid_id};

pub(in crate::manage) use write::{checkpoint, finish, start_run};
pub(in crate::manage) use writer::Writer;

const MAX_SERIES: u64 = 28_035;
const MAX_WINDOWS: u64 = 500_000;
const MAX_BATCH: usize = 256;
const MAX_PAGE: u32 = 50;
const ZERO: Snapshot = Snapshot {
    upload: 0,
    download: 0,
    saturated: false,
};

/// Durable provenance, not an assertion that a data-plane process is running.
#[derive(Clone)]
pub(in crate::manage) struct Status {
    pub(in crate::manage) node_id: String,
    /// Stable accounting incarnation, independent of controller ownership epochs.
    pub(in crate::manage) meter_epoch: String,
    /// Last persisted run marker; `clean` distinguishes an orderly close.
    pub(in crate::manage) run_id: Option<String>,
    /// Monotonic durable checkpoint/state sequence, never a byte counter.
    pub(in crate::manage) cursor: u64,
    pub(in crate::manage) clean: bool,
    /// A previous run did not confirm final persistence after forwarding ended.
    pub(in crate::manage) loss_possible: bool,
    /// Retention/capacity/clock discontinuity omitted some historical detail.
    pub(in crate::manage) history_gap: bool,
    /// UTC attribution has encountered an unavailable or discontinuous clock.
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
    /// The logical UTC cutoff applies before pagination/export, even while
    /// expired physical rows are being removed in bounded Source transactions.
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
/// HTTP, SOCKS5, MASQUE; absence is unknown/no stored window, never a zero row.
pub(in crate::manage) struct Window {
    pub(in crate::manage) window_id: u64,
    pub(in crate::manage) values: [Option<Snapshot>; 3],
}

/// Only this node's own accepted payload; imported child totals are excluded.
pub(in crate::manage) struct NodeSnapshot {
    pub(in crate::manage) status: Status,
    pub(in crate::manage) totals: [Snapshot; 3],
    pub(in crate::manage) minute: Vec<Window>,
    pub(in crate::manage) hour: Vec<Window>,
    pub(in crate::manage) day: Vec<Window>,
    /// Persisted UTC retention cutoffs, not inferred from a missing row.
    pub(in crate::manage) floors: [Option<u64>; 3],
}

struct State {
    status: Status,
    last_observed: Option<u64>,
    series_count: u64,
    window_count: u64,
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
    let mut items = Vec::with_capacity(3);
    for protocol in 0..3 {
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

/// At most 414 protocol rows / 138 windows, all from one SQLite read snapshot.
pub(super) fn node_snapshot_in(connection: &Connection) -> io::Result<NodeSnapshot> {
    use std::collections::BTreeMap;
    let retention = state_in(connection)?.retention_at;
    let floors = [Resolution::Minute, Resolution::Hour, Resolution::Day]
        .map(|resolution| retention.map(|time| resolution.floor(time)));
    let totals = totals_in(connection, Scope::Node)?;
    let [first, second, third]: [ProtocolTotal; 3] = totals
        .items
        .try_into()
        .map_err(|_| invalid_data("invalid node protocol total count"))?;
    let values = [first.value, second.value, third.value];
    let mut statement=connection.prepare("SELECT resolution,window_id,protocol,upload,download,saturated FROM traffic_windows WHERE scope=2 AND subject_id=?1 AND (
        resolution NOT BETWEEN 0 AND 2
        OR (resolution=0 AND (?2 IS NULL OR window_id>=?2))
        OR (resolution=1 AND (?3 IS NULL OR window_id>=?3))
        OR (resolution=2 AND (?4 IS NULL OR window_id>=?4)))
        ORDER BY resolution,window_id,protocol LIMIT 415").map_err(decode_error)?;
    let mut rows = statement
        .query(params![
            &totals.status.node_id,
            floors[0].map(sql_number).transpose()?,
            floors[1].map(sql_number).transpose()?,
            floors[2].map(sql_number).transpose()?
        ])
        .map_err(decode_error)?;
    let mut windows: BTreeMap<(i64, u64), [Option<Snapshot>; 3]> = BTreeMap::new();
    let mut count = 0usize;
    while let Some(row) = rows.next().map_err(decode_error)? {
        count += 1;
        if count > 414 {
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
        if windows.entry((resolution, window)).or_insert([None; 3])[protocol]
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
    let query = if overview.schema_version >= 8 {
        "SELECT meter_epoch,run_id,cursor,clean,loss_possible,history_gap,time_uncertain,last_checkpoint_at,meter_started_at,last_observed_at,series_count,window_count,excluded_observed_at,retention_at FROM traffic_state WHERE singleton=1"
    } else {
        "SELECT meter_epoch,run_id,cursor,clean,loss_possible,history_gap,time_uncertain,last_checkpoint_at,meter_started_at,last_observed_at,series_count,window_count,excluded_observed_at,NULL FROM traffic_state WHERE singleton=1"
    };
    connection
        .query_row(query, [], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, Option<i64>>(12)?,
                row.get::<_, Option<i64>>(13)?,
            ))
        })
        .map_err(decode_error)
        .and_then(
            |(
                epoch,
                run,
                cursor,
                clean,
                loss,
                gap,
                uncertain,
                checkpoint,
                started,
                observed,
                series,
                windows,
                excluded,
                retention,
            )| {
                if !valid_id(&epoch) || run.as_ref().is_some_and(|id| !valid_id(id)) {
                    return Err(invalid_data("traffic accounting identity is malformed"));
                }
                let series_count = positive_or_zero(series)?;
                let window_count = positive_or_zero(windows)?;
                if series_count > MAX_SERIES || window_count > MAX_WINDOWS {
                    return Err(invalid_data("traffic capacity state is malformed"));
                }
                Ok(State {
                    status: Status {
                        node_id: overview.node_id,
                        meter_epoch: epoch,
                        run_id: run,
                        cursor: positive_or_zero(cursor)?,
                        clean: flag(clean)?,
                        loss_possible: flag(loss)?,
                        history_gap: flag(gap)?,
                        time_uncertain: flag(uncertain)?,
                        last_checkpoint_at: checkpoint.map(positive_or_zero).transpose()?,
                        meter_started_at: started.map(positive_or_zero).transpose()?,
                    },
                    last_observed: observed.map(positive_or_zero).transpose()?,
                    series_count,
                    window_count,
                    excluded_observed: excluded.map(positive_or_zero).transpose()?,
                    retention_at: retention.map(positive_or_zero).transpose()?,
                })
            },
        )
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
        0 => Ok(Protocol::Http),
        1 => Ok(Protocol::Socks5),
        2 => Ok(Protocol::Masque),
        _ => Err(invalid_data("traffic protocol is malformed")),
    }
}
fn protocol_code(value: Protocol) -> i64 {
    match value {
        Protocol::Http => 0,
        Protocol::Socks5 => 1,
        Protocol::Masque => 2,
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

/// Historical fixtures must remove actual schema7 objects before changing the
/// version, not leave a current table behind under an older version number.
#[cfg(test)]
pub(super) fn remove_schema_for_test(connection: &Connection) -> io::Result<()> {
    if super::read_overview(connection)?.schema_version >= 9 {
        super::control::reconstruct_v8(connection)?;
    }
    connection
        .execute_batch(
            "DROP TABLE remote_traffic_sources; DROP TABLE traffic_windows; DROP TABLE traffic_series; DROP TABLE traffic_state;",
        )
        .map_err(decode_error)
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use super::*;

    #[cfg(feature = "witness-journal")]
    mod retention {
        //! The full existing history capacity is seeded before Source binding. Only
        //! small witnessed cleanup transactions run afterward; no live DB is migrated.

        use super::*;
        use crate::manage::{node, store::journal::SourceFixture};
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use rusqlite::{
            Connection, fallible_streaming_iterator::FallibleStreamingIterator, hooks::Action,
            params, session::ChangesetIter,
        };
        use std::fs;
        use tokio::time::{Duration, timeout};

        const OLD_TIME: u64 = 30 * 86_400_000;
        const NOW: u64 = 62 * 86_400_000;
        const ROWS: i64 = 500_000;

        fn invalid() -> io::Error {
            io::Error::other("retention source fixture failed")
        }

        fn seed(f: &node::tests::Fixture) -> io::Result<()> {
            let mut c = Connection::open(f.client_state.join("management.sqlite3"))
                .map_err(io::Error::other)?;
            c.execute_batch("PRAGMA foreign_keys=ON")
                .map_err(io::Error::other)?;
            let tx = c.transaction().map_err(io::Error::other)?;
            let zero = 0u64.to_be_bytes();
            let one = 1u64.to_be_bytes();
            let mut inserted = 0i64;
            {
                let mut user = tx
                    .prepare("INSERT INTO proxy_users VALUES(?1,'retention fixture',0,1,7,1,1)")
                    .map_err(io::Error::other)?;
                let mut series = tx
                    .prepare(
                        "INSERT INTO traffic_series VALUES(3,?1,?2,?1,NULL,NULL,NULL,?3,?4,0,1)",
                    )
                    .map_err(io::Error::other)?;
                let mut row = tx
                    .prepare(
                        "INSERT INTO traffic_windows VALUES(3,?1,?2,?3,?4,?1,NULL,NULL,?5,?6,0,1)",
                    )
                    .map_err(io::Error::other)?;
                for index in 0..1024u128 {
                    let id = URL_SAFE_NO_PAD.encode(index.to_be_bytes());
                    user.execute([&id]).map_err(io::Error::other)?;
                    for protocol in 0..3i64 {
                        series
                            .execute(params![
                                id,
                                protocol,
                                138u64.to_be_bytes().as_slice(),
                                zero.as_slice()
                            ])
                            .map_err(io::Error::other)?;
                    }
                    // Existing Source cleanup debt may remain below its logical floor.
                    // Fill physical capacity without exceeding the actual user limit
                    // or making the node export exceed its 60/48/30 visible windows.
                    let minute_floor = OLD_TIME / 60_000 * 60_000 - 59 * 60_000;
                    for window in 0..25u64 {
                        for protocol in 0..3i64 {
                            if inserted == ROWS - 414 {
                                break;
                            }
                            row.execute(params![
                                id,
                                protocol,
                                0,
                                i64::try_from(minute_floor - (25 - window) * 60_000)
                                    .map_err(io::Error::other)?,
                                one.as_slice(),
                                zero.as_slice()
                            ])
                            .map_err(io::Error::other)?;
                            inserted += 1;
                        }
                    }
                    for (resolution, width, count) in [
                        (0i64, 60_000u64, 60u64),
                        (1, 3_600_000, 48),
                        (2, 86_400_000, 30),
                    ] {
                        let floor = OLD_TIME / width * width - (count - 1) * width;
                        for window in 0..count {
                            for protocol in 0..3i64 {
                                if inserted == ROWS - 414 {
                                    break;
                                }
                                row.execute(params![
                                    id,
                                    protocol,
                                    resolution,
                                    i64::try_from(floor + window * width)
                                        .map_err(io::Error::other)?,
                                    one.as_slice(),
                                    zero.as_slice()
                                ])
                                .map_err(io::Error::other)?;
                                inserted += 1;
                            }
                        }
                    }
                }
            }
            assert_eq!(inserted, ROWS - 414);
            {
                let mut series = tx
                    .prepare(
                        "INSERT INTO traffic_series VALUES(2,?1,?2,NULL,NULL,NULL,?1,?3,?4,0,1)",
                    )
                    .map_err(io::Error::other)?;
                for protocol in 0..3i64 {
                    series
                        .execute(params![
                            f.client_id,
                            protocol,
                            1_000_000u64.to_be_bytes().as_slice(),
                            zero.as_slice()
                        ])
                        .map_err(io::Error::other)?;
                }
                let mut row = tx
                    .prepare(
                        "INSERT INTO traffic_windows VALUES(2,?1,?2,?3,?4,NULL,NULL,?1,?5,?6,0,1)",
                    )
                    .map_err(io::Error::other)?;
                for (resolution, width, count) in [
                    (0i64, 60_000u64, 60u64),
                    (1, 3_600_000, 48),
                    (2, 86_400_000, 30),
                ] {
                    let floor = OLD_TIME / width * width - (count - 1) * width;
                    for window in 0..count {
                        for protocol in 0..3i64 {
                            row.execute(params![
                                f.client_id,
                                protocol,
                                resolution,
                                i64::try_from(floor + window * width).map_err(io::Error::other)?,
                                one.as_slice(),
                                zero.as_slice()
                            ])
                            .map_err(io::Error::other)?;
                            inserted += 1;
                        }
                    }
                }
            }
            assert_eq!(inserted, ROWS);
            // Complete the same explicit default rows as normal user creation. Missing
            // routing/preset rows are corruption, including for historical tombstones.
            tx.execute_batch(
                "INSERT INTO routing_permissions SELECT id,1 FROM proxy_users;
        INSERT INTO user_presets SELECT id,NULL,0 FROM proxy_users;",
            )
            .map_err(io::Error::other)?;
            tx.execute("UPDATE traffic_state SET cursor=1,series_count=3075,window_count=?1,last_observed_at=?2,last_checkpoint_at=?2,meter_started_at=0,retention_at=?2",params![ROWS,i64::try_from(OLD_TIME).map_err(io::Error::other)?]).map_err(io::Error::other)?;
            tx.commit().map_err(io::Error::other)
        }

        fn counts(live: &SourceFixture) -> io::Result<(i64, i64)> {
            let c = Connection::open(live.fixture.client_state.join("management.sqlite3"))
                .map_err(io::Error::other)?;
            let count = c
                .query_row("SELECT count(*) FROM traffic_windows", [], |r| r.get(0))
                .map_err(io::Error::other)?;
            let recorded: i64 = c
                .query_row("SELECT window_count FROM traffic_state", [], |r| r.get(0))
                .map_err(io::Error::other)?;
            assert_eq!(count, recorded);
            let node = c
                .query_row(
                    "SELECT count(*) FROM traffic_windows WHERE scope=2",
                    [],
                    |r| r.get(0),
                )
                .map_err(io::Error::other)?;
            Ok((count, node))
        }

        fn snapshot(live: &SourceFixture) -> io::Result<store::traffic::NodeSnapshot> {
            let mut c = Connection::open(live.fixture.client_state.join("management.sqlite3"))
                .map_err(io::Error::other)?;
            let tx = c.transaction().map_err(io::Error::other)?;
            store::traffic::node_snapshot_in(&tx)
        }

        fn delta(live: &SourceFixture, sequence: u64) -> io::Result<(usize, usize)> {
            let root = live.fixture.client_state.join("witness-intents");
            let location: serde_json::Value =
                serde_json::from_slice(&fs::read(root.join(format!("{sequence}.json")))?)
                    .map_err(io::Error::other)?;
            let path = root
                .join(location["intent_id"].as_str().ok_or_else(invalid)?)
                .join("changeset.bin");
            assert!(fs::metadata(&path)?.len() < 16 * 1024 * 1024);
            let bytes = fs::read(path)?;
            let mut input = bytes.as_slice();
            let reader: &mut dyn io::Read = &mut input;
            let mut iter = ChangesetIter::start_strm(&reader).map_err(io::Error::other)?;
            let (mut rows, mut deleted) = (0usize, 0usize);
            while let Some(item) = iter.next().map_err(io::Error::other)? {
                rows += 1;
                let op = item.op().map_err(io::Error::other)?;
                if op.table_name() == "traffic_windows" {
                    assert!(matches!(op.code(), Action::SQLITE_DELETE));
                    deleted += 1;
                }
            }
            assert_eq!(deleted, 6144);
            assert_eq!(rows, 6146); // windows + traffic provenance + source floor
            Ok((rows, bytes.len()))
        }

        #[tokio::test]
        async fn full_capacity_cleanup_is_bounded_logically_atomic_and_survives_cancelled_unknown_confirmation()
        -> io::Result<()> {
            let pause = Arc::new(node::tests::ResponsePause::default());
            let live = SourceFixture::new_with(
                node::tests::CutResponse {
                    witness_only: true,
                    witness_confirm: true,
                    witness_sequence: Some(2),
                    pause: Some(pause.clone()),
                    cut_after_pause: true,
                    ..Default::default()
                },
                seed,
            )
            .await?;
            let result = async {
                let initial = store::traffic::status(&live.fixture.client_state)?;
                let epoch = initial.meter_epoch;
                let run = live
                    .source
                    .traffic_write(move |w| w.start_run(&epoch, initial.cursor, Some(NOW)))
                    .await?
                    .status
                    .run_id
                    .ok_or_else(invalid)?;
                assert_eq!(counts(&live)?.0, ROWS);
                let old = snapshot(&live)?;
                store::remote_traffic::validate_snapshot(&old)?;
                let expected = run.clone();
                live.arm();
                let mut checkpoint = Box::pin(
                    live.source
                        .traffic_write(move |w| w.checkpoint(&expected, Some(NOW), &[], &[])),
                );
                assert!(futures_util::poll!(&mut checkpoint).is_pending());
                timeout(Duration::from_secs(30), pause.entered.notified())
                    .await
                    .map_err(io::Error::other)?;
                drop(checkpoint);
                assert!(live.source.reader().revision().is_err());
                assert_eq!(live.source.write_work().available_permits(), 0);
                let (physical, node) = counts(&live)?;
                assert_eq!(physical, ROWS - 6144);
                assert!(node > 0); // Old node rows still exist after the physical slice.
                let new = snapshot(&live)?;
                store::remote_traffic::validate_snapshot(&new)?;
                store::remote_traffic::check_progress_for_test(&old, &new)?;
                assert!(new.minute.is_empty() && new.hour.is_empty() && new.day.is_empty());
                for resolution in [
                    store::traffic::Resolution::Minute,
                    store::traffic::Resolution::Hour,
                    store::traffic::Resolution::Day,
                ] {
                    let page = store::traffic::buckets(
                        &live.fixture.client_state,
                        store::traffic::Scope::Node,
                        resolution,
                        Some(0),
                        50,
                    )?;
                    assert!(
                        page.items.is_empty() && page.floor.is_none() && page.next_cursor.is_none()
                    );
                    let user = URL_SAFE_NO_PAD.encode(0u128.to_be_bytes());
                    assert!(
                        store::traffic::buckets(
                            &live.fixture.client_state,
                            store::traffic::Scope::User(user),
                            resolution,
                            None,
                            50
                        )?
                        .items
                        .is_empty()
                    );
                }
                pause.release.notify_one();
                timeout(Duration::from_secs(30), async {
                    while live.source.write_work().available_permits() != 1 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .map_err(io::Error::other)?;
                live.source.reconcile_source().await?;
                assert_eq!(live.floor()?.sequence, "2");
                assert_eq!(counts(&live)?.0, physical);
                let stats = delta(&live, 2)?;
                let expected = run.clone();
                live.source
                    .traffic_write(move |w| w.checkpoint(&expected, Some(NOW), &[], &[]))
                    .await?;
                assert_eq!(counts(&live)?.0, ROWS - 2 * 6144);
                let next = snapshot(&live)?;
                store::remote_traffic::check_progress_for_test(&new, &next)?;
                assert_eq!(delta(&live, 3)?.0, stats.0);
                let expected = run.clone();
                live.source
                    .traffic_write(move |w| w.checkpoint(&expected, Some(OLD_TIME), &[], &[]))
                    .await?;
                assert_eq!(counts(&live)?.0, ROWS - 2 * 6144);
                assert_eq!(snapshot(&live)?.floors, next.floors);
                live.source
                    .traffic_write(move |w| w.finish(&run, Some(NOW)))
                    .await?;
                assert_eq!(live.source.reader().revision()?, 1);
                Ok(())
            }
            .await;
            pause.release.notify_one();
            let closed = live.close().await;
            result.and(closed)
        }
    }
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
                    protocols: vec![Protocol::Http, Protocol::Socks5, Protocol::Masque],
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
    fn logical_retention_filters_before_paging_and_export_while_native_cleanup_remains_complete()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let gate = fixture.gate()?;
        let time = 129 * 60_000u64;
        let run = fixture.start(&gate, Some(time))?.run_id.unwrap();
        checkpoint(
            &fixture.directory,
            &gate,
            &run,
            Some(time),
            &[fixture.sample(130, 0)],
            &[],
        )?;
        let node = status(&fixture.directory)?.node_id;
        let mut c = open_existing(&fixture.directory, true)?;
        let tx = c.transaction().map_err(decode_error)?;
        tx.execute("DELETE FROM traffic_windows", [])
            .map_err(decode_error)?;
        {
            let mut row = tx
                .prepare("INSERT INTO traffic_windows VALUES(2,?1,0,0,?2,NULL,NULL,?1,?3,?4,0,1)")
                .map_err(decode_error)?;
            for index in 0..130i64 {
                row.execute(params![
                    node,
                    index * 60_000,
                    1u64.to_be_bytes().as_slice(),
                    0u64.to_be_bytes().as_slice()
                ])
                .map_err(decode_error)?;
            }
        }
        tx.execute("UPDATE traffic_state SET window_count=130", [])
            .map_err(decode_error)?;
        let first = buckets_in(&tx, Scope::Node, Resolution::Minute, Some(0), 50)?;
        assert_eq!(first.floor, Some(70 * 60_000));
        assert_eq!(
            (first.items.len(), first.items[0].window_id),
            (50, 70 * 60_000)
        );
        let second = buckets_in(&tx, Scope::Node, Resolution::Minute, first.next_cursor, 50)?;
        assert_eq!(second.items.len(), 10);
        assert_eq!(second.items[0].window_id, 120 * 60_000);
        assert!(second.next_cursor.is_none());
        let snapshot = node_snapshot_in(&tx)?;
        assert_eq!(snapshot.minute.len(), 60);
        assert_eq!(snapshot.floors[0], first.floor);
        super::super::remote_traffic::validate_snapshot(&snapshot)?;
        // Legacy unknown cutoffs still expose their actual rows; no current time
        // is invented while reading old schema/provenance.
        tx.execute("UPDATE traffic_state SET retention_at=NULL", [])
            .map_err(decode_error)?;
        assert_eq!(
            buckets_in(&tx, Scope::Node, Resolution::Minute, None, 50)?.floor,
            Some(0)
        );
        let mut plan=tx.prepare("EXPLAIN QUERY PLAN SELECT rowid FROM traffic_windows WHERE resolution=?1 AND window_id<?2 ORDER BY window_id LIMIT ?3").map_err(decode_error)?;
        let details = plan
            .query_map(params![0, 70 * 60_000, 2048], |r| r.get::<_, String>(3))
            .map_err(decode_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(decode_error)?;
        assert!(
            details
                .iter()
                .any(|detail| detail.contains("traffic_windows_retention"))
        );
        assert!(!details.iter().any(|detail| detail.contains("TEMP B-TREE")));
        drop(plan);
        tx.commit().map_err(decode_error)?;
        checkpoint(
            &fixture.directory,
            &gate,
            &run,
            Some(time + 1),
            &[fixture.sample(130, 0)],
            &[],
        )?;
        let count: i64 = c
            .query_row("SELECT count(*) FROM traffic_windows", [], |r| r.get(0))
            .map_err(decode_error)?;
        assert_eq!(count, 60);
        assert_eq!(
            buckets(
                &fixture.directory,
                Scope::Node,
                Resolution::Minute,
                None,
                50
            )?
            .floor,
            first.floor
        );
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
        let duplicate = [fixture.sample(46, 0), fixture.sample(46, 0)];
        assert!(
            checkpoint(
                &fixture.directory,
                &gate,
                &run,
                Some(2_006_000),
                &duplicate,
                &[]
            )
            .is_err()
        );
        assert_eq!(status(&fixture.directory)?.cursor, cursor);
        Ok(())
    }

    #[test]
    fn retention_keeps_coarse_history_and_pages_complete_protocol_windows() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let gate = fixture.gate()?;
        let run = fixture.start(&gate, Some(86_400_000))?.run_id.unwrap();
        for index in 0..65u64 {
            let mut socks = fixture.sample(index + 1, 0);
            socks.protocol = Protocol::Socks5;
            let mut masque = fixture.sample(index + 1, 0);
            masque.protocol = Protocol::Masque;
            checkpoint(
                &fixture.directory,
                &gate,
                &run,
                Some(86_400_000 + index * 60_000),
                &[fixture.sample(index + 1, 0), socks, masque],
                &[],
            )?;
        }
        let first = buckets(
            &fixture.directory,
            Scope::Node,
            Resolution::Minute,
            None,
            50,
        )?;
        assert_eq!(first.items.len(), 50);
        assert!(first.status.history_gap);
        assert!(first.items.iter().all(|item| item.items.len() == 3));
        assert_eq!(first.floor, Some(86_400_000 + 5 * 60_000));
        let second = buckets(
            &fixture.directory,
            Scope::Node,
            Resolution::Minute,
            first.next_cursor,
            50,
        )?;
        assert_eq!(second.items.len(), 10);
        assert!(second.next_cursor.is_none());
        let day = buckets(&fixture.directory, Scope::Node, Resolution::Day, None, 50)?;
        assert_eq!(day.items[0].items[0].value.upload, 65);
        let hour = buckets(&fixture.directory, Scope::Node, Resolution::Hour, None, 50)?;
        assert_eq!(hour.items.len(), 2);
        assert_eq!(
            hour.items
                .iter()
                .map(|bucket| bucket.items[0].value.upload)
                .sum::<u64>(),
            65
        );
        assert!(
            buckets(
                &fixture.directory,
                Scope::Node,
                Resolution::Minute,
                None,
                51
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn saturated_u64_values_and_history_budget_preserve_visible_lower_bounds() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let gate = fixture.gate()?;
        let run = fixture.start(&gate, Some(60_000))?.run_id.unwrap();
        let mut first = fixture.sample(u64::MAX, 0);
        first.value.saturated = true;
        checkpoint(&fixture.directory, &gate, &run, Some(61_000), &[first], &[])?;
        let value = http(totals(&fixture.directory, Scope::Node)?);
        assert_eq!(value.upload, u64::MAX);
        assert!(value.saturated);
        let connection = open_existing(&fixture.directory, true)?;
        let transaction = connection.unchecked_transaction().map_err(decode_error)?;
        let mut state = state_in(&transaction)?;
        assert!(write::exhausted_budget_for_test(
            &transaction,
            &mut state.status,
            &fixture.pool
        )?);
        assert!(state.status.history_gap);
        transaction.rollback().map_err(decode_error)?;
        let before = status(&fixture.directory)?.cursor;
        assert!(
            checkpoint(
                &fixture.directory,
                &gate,
                &run,
                Some(62_000),
                &[fixture.sample(u64::MAX, 0)],
                &[]
            )
            .is_err()
        );
        assert_eq!(status(&fixture.directory)?.cursor, before);
        Ok(())
    }

    #[test]
    fn schema_six_migration_preserves_existing_policy_identity_and_backup() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let original = store::load_policy(&fixture.directory)?;
        let original_node = store::inspect(&fixture.directory)?.node_id;
        let connection = open_existing(&fixture.directory, true)?;
        remove_schema_for_test(&connection)?;
        connection
            .pragma_update(None, "user_version", 6)
            .map_err(decode_error)?;
        assert!(restore(&fixture.directory).is_err());
        let backup = fixture.directory.join("schema6-before-traffic.sqlite3");
        assert_eq!(
            store::migrate(&fixture.directory, &backup)?.schema_version,
            store::SCHEMA_VERSION
        );
        let after = store::load_policy(&fixture.directory)?;
        assert_eq!(after.revision, original.revision);
        assert_eq!(
            after.credentials[0].secret_digest,
            original.credentials[0].secret_digest
        );
        assert_eq!(after.routing.pools[0].id, fixture.pool);
        let fresh = restore(&fixture.directory)?;
        assert_eq!(fresh.status.node_id, original_node);
        assert!(
            fresh.status.clean
                && fresh.status.meter_started_at.is_none()
                && fresh.credential_seeds.is_empty()
        );
        let copied = Connection::open(backup).map_err(decode_error)?;
        assert_eq!(store::read_overview(&copied)?.schema_version, 6);
        let phc: String = copied
            .query_row("SELECT password_hash FROM administrators", [], |row| {
                row.get(0)
            })
            .map_err(decode_error)?;
        assert_eq!(phc, "private fixture PHC");
        Ok(())
    }

    #[test]
    fn failed_schema_seven_migration_rolls_back_and_retains_old_backup() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let connection = open_existing(&fixture.directory, true)?;
        remove_schema_for_test(&connection)?;
        connection
            .execute_batch(
                "PRAGMA user_version=6; CREATE TABLE traffic_state(operator_fixture TEXT);",
            )
            .map_err(decode_error)?;
        let backup = fixture.directory.join("failed-schema7.sqlite3");
        assert!(store::migrate(&fixture.directory, &backup).is_err());
        assert_eq!(store::inspect(&fixture.directory)?.schema_version, 6);
        assert_eq!(
            store::load_policy(&fixture.directory)?.credentials[0].id,
            fixture.credential
        );
        assert_eq!(
            store::read_overview(&Connection::open(backup).map_err(decode_error)?)?.schema_version,
            6
        );
        Ok(())
    }

    #[test]
    fn malformed_owner_capacity_flags_and_exhausted_cursor_never_reset_counters() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        let gate = fixture.gate()?;
        let run = fixture.start(&gate, Some(60_000))?.run_id.unwrap();
        checkpoint(
            &fixture.directory,
            &gate,
            &run,
            Some(61_000),
            &[fixture.sample(10, 0)],
            &[],
        )?;
        let before = status(&fixture.directory)?.cursor;
        let mut forged = fixture.sample(11, 0);
        forged.user_id = Arc::from(random_id()?);
        assert!(
            checkpoint(
                &fixture.directory,
                &gate,
                &run,
                Some(62_000),
                &[forged],
                &[]
            )
            .is_err()
        );
        let oversized: Vec<_> = (0..257).map(|_| fixture.sample(11, 0)).collect();
        assert!(
            checkpoint(
                &fixture.directory,
                &gate,
                &run,
                Some(62_000),
                &oversized,
                &[]
            )
            .is_err()
        );
        assert_eq!(status(&fixture.directory)?.cursor, before);
        assert_eq!(http(totals(&fixture.directory, Scope::Node)?).upload, 10);
        let connection = open_existing(&fixture.directory, true)?;
        connection
            .execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE traffic_state SET clean=2;")
            .map_err(decode_error)?;
        assert!(
            matches!(status(&fixture.directory),Err(error)if error.kind()==io::ErrorKind::InvalidData)
        );
        connection
            .execute_batch("UPDATE traffic_state SET clean=0,series_count=series_count+1;")
            .map_err(decode_error)?;
        assert!(restore(&fixture.directory).is_err());
        connection
            .execute_batch(
                "UPDATE traffic_state SET series_count=series_count-1,cursor=9223372036854775807;",
            )
            .map_err(decode_error)?;
        assert!(
            checkpoint(
                &fixture.directory,
                &gate,
                &run,
                Some(62_000),
                &[fixture.sample(11, 0)],
                &[]
            )
            .is_err()
        );
        assert_eq!(http(totals(&fixture.directory, Scope::Node)?).upload, 10);
        Ok(())
    }
}
