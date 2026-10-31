//! Serialized checkpoint transactions. Absolute leaf counters are the retry
//! key: publishing a sample twice cannot add its bytes twice after an uncertain
//! commit. A run marker additionally fences an obsolete collector after restart.

use std::{collections::HashSet, io, path::Path};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{
    access::traffic::{PoolSnapshot, SeriesSnapshot},
    traffic::Snapshot,
};

use super::super::{
    UpdateGuard, invalid_data, peers::open_existing, random_id, sqlite_error, valid_id,
};
use super::{
    MAX_BATCH, MAX_SERIES, MAX_WINDOWS, Resolution, Run, State, Status, ZERO, decode_error,
    decode_value, exists, input, protocol_code, series_value, sql_number, state_in,
    validate_counts,
};

// A long collector interruption cannot be attributed to a single UTC window.
// Cumulative totals remain valid; that interval's detail is explicitly missing.
const MAX_CLOCK_STEP_MS: u64 = 10 * 60 * 1_000;

/// Source captures at most 2,048 expired rows per resolution (6,144 total).
/// Together with a 256-sample checkpoint this stays below the journal row cap;
/// logical retention floors hide the remaining expired rows until later batches.
#[cfg(feature = "witness-journal")]
const SOURCE_PRUNE_ROWS: i64 = 2_048;

/// Native removes all expired rows. Source bounds physical deletion while all
/// readers use the atomically committed logical cutoff, including between batches.
#[derive(Clone, Copy)]
pub(super) enum Retention {
    Complete,
    #[cfg(feature = "witness-journal")]
    Batched,
}

impl Retention {
    fn limit(self) -> Option<i64> {
        match self {
            Self::Complete => None,
            #[cfg(feature = "witness-journal")]
            Self::Batched => Some(SOURCE_PRUNE_ROWS),
        }
    }
}

/// Records an open run before real proxy startup. The expected epoch/cursor
/// must match the restoration used to initialize the live counters. An old open
/// marker exposes possible lost crash-tail bytes; API-only startup must not call
/// this function. Blocking I/O requires the shared management update gate.
pub(in crate::manage) fn start_run(
    directory: &Path,
    gate: &UpdateGuard,
    expected_epoch: &str,
    expected_cursor: u64,
    observed_at: Option<u64>,
) -> io::Result<Run> {
    gate.ensure(directory)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(decode_error)?;
    let run = start_run_in(&transaction, expected_epoch, expected_cursor, observed_at)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit traffic run marker", error))?;
    Ok(run)
}

/// Stage the original run/CAS marker in a held transaction. Only the caller's
/// commit and witness confirmation may make it a live collector run.
pub(super) fn start_run_in(
    transaction: &Connection,
    expected_epoch: &str,
    expected_cursor: u64,
    observed_at: Option<u64>,
) -> io::Result<Run> {
    require_transaction(transaction)?;
    let mut state = state_in(transaction)?;
    if !state.status.http_split {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "split traffic accounting requires explicit schema migration",
        ));
    }
    validate_counts(transaction, &state)?;
    if state.status.meter_epoch != expected_epoch || state.status.cursor != expected_cursor {
        return Err(conflict("traffic restoration is no longer current"));
    }
    if !state.status.clean {
        state.status.loss_possible = true;
    }
    state.status.clean = false;
    state.status.run_id = Some(random_id()?);
    advance_cursor(&mut state)?;
    let now = valid_time(observed_at)?;
    if state.status.meter_started_at.is_none() {
        state.status.meter_started_at = now;
    }
    if now.is_none()
        || now
            .zip(state.last_observed)
            .is_some_and(|(now, old)| now < old)
    {
        state.status.time_uncertain = true;
        state.status.history_gap = true;
    }
    if let Some(now) = now {
        state.last_observed = Some(state.last_observed.map_or(now, |old| old.max(now)));
    }
    state.excluded_observed = None;
    save_state(transaction, &state)?;
    Ok(Run {
        status: state.status,
    })
}

/// Persists one bounded batch of absolute samples. Credential deltas update
/// node/user totals; pool samples update only pool totals, never node totals a
/// second time. Regressing values, reassignment, bad IDs and stale run IDs roll
/// the whole transaction back. Uncertain time drops history, not lifetime data.
/// All work is blocking and must stay under the caller's owned update gate.
pub(in crate::manage) fn checkpoint(
    directory: &Path,
    gate: &UpdateGuard,
    run_id: &str,
    observed_at: Option<u64>,
    samples: &[SeriesSnapshot],
    pools: &[PoolSnapshot],
) -> io::Result<Status> {
    gate.ensure(directory)?;
    validate_checkpoint(samples, pools)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(decode_error)?;
    let status = checkpoint_in(
        &transaction,
        run_id,
        observed_at,
        samples,
        pools,
        Retention::Complete,
    )?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit traffic checkpoint", error))?;
    Ok(status)
}

/// Stage one already-bounded absolute batch. Run identity, ownership, monotonic
/// counters, UTC attribution and retention are checked in this same SQL view.
pub(super) fn checkpoint_in(
    transaction: &Connection,
    run_id: &str,
    observed_at: Option<u64>,
    samples: &[SeriesSnapshot],
    pools: &[PoolSnapshot],
    retention: Retention,
) -> io::Result<Status> {
    require_transaction(transaction)?;
    let mut state = state_in(transaction)?;
    require_run(&state, run_id, false)?;
    advance_cursor(&mut state)?;
    let now = sample_time(&mut state, observed_at)?;
    let mut capacity = Capacity {
        series: state.series_count,
        windows: state.window_count,
    };
    let limit = retention.limit();
    if let Some(now) =
        now.filter(|_| state.status.last_checkpoint_at != observed_at || limit.is_some())
    {
        // A Source cycle can contain several 256-sample batches at one instant.
        // Each gets a bounded cleanup slice, so expired rows cannot consume the
        // entire capacity while later batches add their current windows.
        prune_windows(transaction, &mut capacity, &mut state.status, now, limit)?;
        state.retention_at = Some(now);
    }
    let node_id = state.status.node_id.clone();
    for sample in samples {
        let owner: Option<String> = transaction
            .query_row(
                "SELECT user_id FROM proxy_credentials WHERE id=?1",
                [sample.credential_id.as_ref()],
                |row| row.get(0),
            )
            .optional()
            .map_err(decode_error)?;
        if owner.as_deref() != Some(sample.user_id.as_ref()) {
            return Err(invalid_data("traffic credential is missing or reassigned"));
        }
        let protocol = protocol_code(sample.protocol);
        let previous =
            series_value(transaction, 0, &sample.credential_id, protocol)?.unwrap_or(ZERO);
        let delta = delta(previous, sample.value)?;
        if previous == sample.value {
            continue;
        }
        save_series(
            transaction,
            &mut capacity,
            Subject {
                scope: 0,
                id: &sample.credential_id,
                protocol,
            },
            Some(&sample.user_id),
            sample.value,
            state.status.cursor,
        )?;
        for (scope, id) in [(2, node_id.as_str()), (3, sample.user_id.as_ref())] {
            let old = series_value(transaction, scope, id, protocol)?.unwrap_or(ZERO);
            save_series(
                transaction,
                &mut capacity,
                Subject {
                    scope,
                    id,
                    protocol,
                },
                None,
                add(old, delta),
                state.status.cursor,
            )?;
            if let Some(now) = now {
                add_windows(
                    transaction,
                    &mut capacity,
                    &mut state.status,
                    Subject {
                        scope,
                        id,
                        protocol,
                    },
                    delta,
                    now,
                )?;
            }
        }
    }
    for sample in pools {
        if !exists(transaction, 1, &sample.pool_id)? {
            return Err(invalid_data("traffic pool is not registered"));
        }
        let protocol = protocol_code(sample.protocol);
        let old = series_value(transaction, 1, &sample.pool_id, protocol)?.unwrap_or(ZERO);
        let delta = delta(old, sample.value)?;
        if old == sample.value {
            continue;
        }
        save_series(
            transaction,
            &mut capacity,
            Subject {
                scope: 1,
                id: &sample.pool_id,
                protocol,
            },
            None,
            sample.value,
            state.status.cursor,
        )?;
        if let Some(now) = now {
            add_windows(
                transaction,
                &mut capacity,
                &mut state.status,
                Subject {
                    scope: 1,
                    id: &sample.pool_id,
                    protocol,
                },
                delta,
                now,
            )?;
        }
    }
    state.status.last_checkpoint_at = valid_time(observed_at)?;
    state.series_count = capacity.series;
    state.window_count = capacity.windows;
    save_state(transaction, &state)?;
    Ok(state.status)
}

/// Closes only the matching run, after the caller has stopped all forwarding
/// and completed its final checkpoint. Repeating the close is harmless. Failure
/// deliberately leaves the open marker instead of falsely asserting durability.
pub(in crate::manage) fn finish(
    directory: &Path,
    gate: &UpdateGuard,
    run_id: &str,
    observed_at: Option<u64>,
) -> io::Result<Status> {
    gate.ensure(directory)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(decode_error)?;
    let status = finish_in(&transaction, run_id, observed_at)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit traffic clean marker", error))?;
    Ok(status)
}

/// Close only the matching run after forwarding has stopped. A repeated close
/// is read-only; an error cannot fabricate a clean marker.
pub(super) fn finish_in(
    transaction: &Connection,
    run_id: &str,
    observed_at: Option<u64>,
) -> io::Result<Status> {
    require_transaction(transaction)?;
    let mut state = state_in(transaction)?;
    require_run(&state, run_id, true)?;
    if !state.status.clean {
        advance_cursor(&mut state)?;
        sample_time(&mut state, observed_at)?;
        state.status.clean = true;
        save_state(transaction, &state)?;
    }
    Ok(state.status)
}

fn require_transaction(connection: &Connection) -> io::Result<()> {
    if connection.is_autocommit() {
        return Err(input("traffic write requires a held transaction"));
    }
    Ok(())
}

pub(super) fn validate_checkpoint(
    samples: &[SeriesSnapshot],
    pools: &[PoolSnapshot],
) -> io::Result<()> {
    if samples
        .len()
        .checked_add(pools.len())
        .is_none_or(|count| count > MAX_BATCH)
    {
        return Err(input("traffic checkpoint exceeds 256 series"));
    }
    let mut keys = HashSet::with_capacity(samples.len() + pools.len());
    for sample in samples {
        if !valid_id(&sample.user_id)
            || !valid_id(&sample.credential_id)
            || !keys.insert((
                0,
                sample.credential_id.as_ref(),
                protocol_code(sample.protocol),
            ))
        {
            return Err(input("invalid or duplicate traffic credential sample"));
        }
    }
    for sample in pools {
        if !valid_id(&sample.pool_id)
            || !keys.insert((1, sample.pool_id.as_ref(), protocol_code(sample.protocol)))
        {
            return Err(input("invalid or duplicate traffic pool sample"));
        }
    }
    Ok(())
}

struct Capacity {
    series: u64,
    windows: u64,
}

/// Fixed identity/protocol tuple; owner is separately required only for a leaf.
struct Subject<'a> {
    scope: i64,
    id: &'a str,
    protocol: i64,
}

fn require_run(state: &State, run: &str, allow_clean: bool) -> io::Result<()> {
    if !valid_id(run)
        || state.status.run_id.as_deref() != Some(run)
        || (!allow_clean && state.status.clean)
    {
        return Err(conflict("traffic collector run is no longer current"));
    }
    Ok(())
}

fn advance_cursor(state: &mut State) -> io::Result<()> {
    state.status.cursor = state
        .status
        .cursor
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| invalid_data("traffic cursor exhausted"))?;
    Ok(())
}

fn valid_time(value: Option<u64>) -> io::Result<Option<u64>> {
    value
        .map(|value| sql_number(value).map(|_| value))
        .transpose()
}

fn sample_time(state: &mut State, value: Option<u64>) -> io::Result<Option<u64>> {
    let Some(now) = valid_time(value)? else {
        state.status.time_uncertain = true;
        state.status.history_gap = true;
        return Ok(None);
    };
    if state.status.meter_started_at.is_none() {
        state.status.meter_started_at = Some(now);
    }
    if state.excluded_observed == Some(now) {
        return Ok(None);
    }
    let acceptable = state
        .last_observed
        .is_none_or(|old| now >= old && now - old <= MAX_CLOCK_STEP_MS);
    // Backward time remains fenced until UTC catches up; a forward jump omits
    // one interval then establishes a new baseline for subsequent samples.
    if !acceptable {
        state.status.time_uncertain = true;
        state.status.history_gap = true;
        // All batches from this same sampled instant share its discontinuity.
        // Otherwise batch two would see a zero step and misattribute its delta.
        state.excluded_observed = Some(now);
    } else {
        state.excluded_observed = None;
    }
    state.last_observed = Some(state.last_observed.map_or(now, |old| old.max(now)));
    Ok(acceptable.then_some(now))
}

fn save_state(connection: &Connection, state: &State) -> io::Result<()> {
    connection.execute("UPDATE traffic_state SET run_id=?1,cursor=?2,clean=?3,loss_possible=?4,history_gap=?5,time_uncertain=?6,last_checkpoint_at=?7,meter_started_at=?8,last_observed_at=?9,series_count=?10,window_count=?11,excluded_observed_at=?12 WHERE singleton=1",params![state.status.run_id,sql_number(state.status.cursor)?,state.status.clean,state.status.loss_possible,state.status.history_gap,state.status.time_uncertain,state.status.last_checkpoint_at.map(sql_number).transpose()?,state.status.meter_started_at.map(sql_number).transpose()?,state.last_observed.map(sql_number).transpose()?,sql_number(state.series_count)?,sql_number(state.window_count)?,state.excluded_observed.map(sql_number).transpose()?]).map_err(|error|sqlite_error("cannot save traffic provenance",error))?;
    if super::super::read_overview(connection)?.schema_version >= 8 {
        connection
            .execute(
                "UPDATE traffic_state SET retention_at=?1 WHERE singleton=1",
                [state.retention_at.map(sql_number).transpose()?],
            )
            .map_err(decode_error)?;
    }
    Ok(())
}

fn delta(previous: Snapshot, next: Snapshot) -> io::Result<Snapshot> {
    if previous.saturated && !next.saturated {
        return Err(invalid_data("traffic saturation flag cannot regress"));
    }
    Ok(Snapshot {
        upload: next
            .upload
            .checked_sub(previous.upload)
            .ok_or_else(|| invalid_data("traffic upload counter regressed"))?,
        download: next
            .download
            .checked_sub(previous.download)
            .ok_or_else(|| invalid_data("traffic download counter regressed"))?,
        saturated: next.saturated,
    })
}

fn add(left: Snapshot, right: Snapshot) -> Snapshot {
    let upload = left.upload.checked_add(right.upload);
    let download = left.download.checked_add(right.download);
    Snapshot {
        upload: upload.unwrap_or(u64::MAX),
        download: download.unwrap_or(u64::MAX),
        saturated: left.saturated || right.saturated || upload.is_none() || download.is_none(),
    }
}

fn save_series(
    connection: &Connection,
    capacity: &mut Capacity,
    subject: Subject<'_>,
    owner: Option<&str>,
    value: Snapshot,
    cursor: u64,
) -> io::Result<()> {
    let Subject {
        scope,
        id,
        protocol,
    } = subject;
    if series_value(connection, scope, id, protocol)?.is_none() {
        capacity.series = capacity
            .series
            .checked_add(1)
            .filter(|count| *count <= MAX_SERIES)
            .ok_or_else(|| invalid_data("traffic series capacity exhausted"))?;
    }
    let user = if scope == 0 {
        owner
    } else if scope == 3 {
        Some(id)
    } else {
        None
    };
    let credential = (scope == 0).then_some(id);
    let pool = (scope == 1).then_some(id);
    let node = (scope == 2).then_some(id);
    connection.execute("INSERT INTO traffic_series(scope,subject_id,protocol,user_id,credential_id,pool_id,node_id,upload,download,saturated,updated_cursor) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) ON CONFLICT(scope,subject_id,protocol) DO UPDATE SET upload=excluded.upload,download=excluded.download,saturated=excluded.saturated,updated_cursor=excluded.updated_cursor",params![scope,id,protocol,user,credential,pool,node,value.upload.to_be_bytes().as_slice(),value.download.to_be_bytes().as_slice(),value.saturated,sql_number(cursor)?]).map_err(|error|sqlite_error("cannot persist traffic cumulative series",error))?;
    Ok(())
}

fn add_windows(
    connection: &Connection,
    capacity: &mut Capacity,
    status: &mut Status,
    subject: Subject<'_>,
    value: Snapshot,
    now: u64,
) -> io::Result<()> {
    let Subject {
        scope,
        id,
        protocol,
    } = subject;
    // Zero rows provide no coverage information and would create artificial
    // history during idle/offline periods. Saturation itself remains visible.
    if value.upload == 0 && value.download == 0 && !value.saturated {
        return Ok(());
    }
    for resolution in [Resolution::Minute, Resolution::Hour, Resolution::Day] {
        let window = now / resolution.width() * resolution.width();
        let old=connection.query_row("SELECT upload,download,saturated FROM traffic_windows WHERE scope=?1 AND subject_id=?2 AND protocol=?3 AND resolution=?4 AND window_id=?5",params![scope,id,protocol,resolution.code(),sql_number(window)?],|row|Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,Vec<u8>>(1)?,row.get::<_,i64>(2)?))).optional().map_err(decode_error)?;
        let old = old
            .map(|(up, down, flag)| decode_value(up, down, flag))
            .transpose()?;
        if old.is_none() {
            if capacity.windows >= MAX_WINDOWS {
                status.history_gap = true;
                continue;
            }
            capacity.windows += 1;
        }
        let value = add(old.unwrap_or(ZERO), value);
        connection.execute("INSERT INTO traffic_windows(scope,subject_id,protocol,resolution,window_id,user_id,pool_id,node_id,upload,download,saturated,updated_cursor) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT(scope,subject_id,protocol,resolution,window_id) DO UPDATE SET upload=excluded.upload,download=excluded.download,saturated=excluded.saturated,updated_cursor=excluded.updated_cursor",params![scope,id,protocol,resolution.code(),sql_number(window)?,(scope==3).then_some(id),(scope==1).then_some(id),(scope==2).then_some(id),value.upload.to_be_bytes().as_slice(),value.download.to_be_bytes().as_slice(),value.saturated,sql_number(status.cursor)?]).map_err(|error|sqlite_error("cannot persist traffic history window",error))?;
    }
    Ok(())
}

fn prune_windows(
    connection: &Connection,
    capacity: &mut Capacity,
    status: &mut Status,
    now: u64,
    limit: Option<i64>,
) -> io::Result<()> {
    // Apply a global UTC floor, including dormant/deleted identities. Keeping
    // the last 60 *active* minutes per identity would not be 60-minute retention.
    for resolution in [Resolution::Minute, Resolution::Hour, Resolution::Day] {
        let floor = sql_number(resolution.floor(now))?;
        let removed = match limit {
            Some(limit) => connection.execute(
                "DELETE FROM traffic_windows WHERE rowid IN (
                 SELECT rowid FROM traffic_windows WHERE resolution=?1 AND window_id<?2
                 ORDER BY window_id LIMIT ?3)",
                params![resolution.code(), floor, limit],
            ),
            None => connection.execute(
                "DELETE FROM traffic_windows WHERE resolution=?1 AND window_id<?2",
                params![resolution.code(), floor],
            ),
        }
        .map_err(decode_error)?;
        let removed =
            u64::try_from(removed).map_err(|_| invalid_data("traffic retention count overflow"))?;
        capacity.windows = capacity
            .windows
            .checked_sub(removed)
            .ok_or_else(|| invalid_data("traffic history count underflow"))?;
        if removed > 0 {
            status.history_gap = true;
        }
    }
    Ok(())
}

fn conflict(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}

#[cfg(test)]
pub(super) fn exhausted_budget_for_test(
    connection: &Connection,
    status: &mut Status,
    pool: &str,
) -> io::Result<bool> {
    let mut capacity = Capacity {
        series: 0,
        windows: MAX_WINDOWS,
    };
    add_windows(
        connection,
        &mut capacity,
        status,
        Subject {
            scope: 1,
            id: pool,
            protocol: 0,
        },
        Snapshot {
            upload: 9,
            download: 0,
            saturated: false,
        },
        120_000,
    )?;
    Ok(capacity.windows == MAX_WINDOWS)
}
