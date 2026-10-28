//! Durable, non-executable incident transitions, separate from live evidence.
//!
//! The collector has one stable batch at a time. A committed batch can be
//! confirmed exactly after a lost answer; neither a missing event nor a new
//! monitor boot permits replaying policy, probes or remote commands.

use std::{
    collections::{BTreeMap, HashSet},
    io,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params, types::ValueRef};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::super::{
    UpdateGuard, invalid_data, peers::open_existing, read_overview, sqlite_error, valid_id,
};
use crate::manage::{
    alerts::{Kind, Status},
    health::CheckKind,
};

mod encoding;
mod write;
pub(in crate::manage) use write::Writer;

/// Ends a bounded history capture without committing its SQL transaction. A
/// Source writer supplies this hook so long batches release Session preimages;
/// Native writers use no hook. Failure aborts the entire original operation.
pub(in crate::manage) trait Checkpoints {
    fn checkpoint(&mut self) -> io::Result<()>;
}
fn checkpoint(checkpoints: &mut Option<&mut dyn Checkpoints>) -> io::Result<()> {
    if let Some(checkpoints) = checkpoints {
        checkpoints.checkpoint()?;
    }
    Ok(())
}

pub(in crate::manage) const MAX_ACTIVE: usize = 12_288;
const MAX_LOCAL: usize = 6_144;
const MAX_REMOTE: usize = 4_096;
const MAX_SOURCES: usize = 128;
pub(in crate::manage) const MAX_CLOSED: usize = 4_096;
pub(in crate::manage) const MAX_EVENTS: usize = 16_384;
const MAX_BATCH: usize = MAX_ACTIVE * 2;
const MAX_PAYLOAD: usize = 1_024;
const MAX_PAGE: u32 = 50;
pub(in crate::manage) const MAX_ACK_BATCH: usize = 32;

/// A fixed event vocabulary, not a user-supplied message or remediation command.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum TransitionKind {
    Opened,
    ReasonChanged,
    Recovered,
    Unmonitored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum EventKind {
    Opened,
    ReasonChanged,
    Recovered,
    Unmonitored,
    Acknowledged,
}

/// Losing the source or restarting its observer never establishes recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum EndReason {
    SourceUnmonitored,
    MonitorRestarted,
}

/// Public source metadata accepted by the existing live state machine. The RAM
/// incident ID and evidence counter keep their full u64 domain; only durable
/// event/episode IDs use SQLite's positive signed-integer sequence domain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Observation {
    pub(in crate::manage) incident_id: u64,
    pub(in crate::manage) kind: Kind,
    pub(in crate::manage) origin_node_id: String,
    pub(in crate::manage) resource_id: Option<String>,
    pub(in crate::manage) slot: String,
    pub(in crate::manage) check: Option<CheckKind>,
    pub(in crate::manage) target: Option<SocketAddr>,
    pub(in crate::manage) code: String,
    pub(in crate::manage) first_observed_at_unix_ms: Option<u64>,
    pub(in crate::manage) last_observed_at_unix_ms: Option<u64>,
    pub(in crate::manage) evidence_sequence: Option<u64>,
}

/// Conversion time is independent of the last failure observation, especially
/// for Unmonitored. Nullable wall time never orders or authorizes an event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Transition {
    pub(in crate::manage) kind: TransitionKind,
    pub(in crate::manage) observation: Observation,
    pub(in crate::manage) observed_at_unix_ms: Option<u64>,
    pub(in crate::manage) ended_reason: Option<EndReason>,
}

/// Stable producer identity retained until commit is known. Store computes the
/// digest over this closed canonical representation; callers cannot substitute
/// their own hash or change content while reusing the original sequence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Batch {
    pub(in crate::manage) boot_id: String,
    pub(in crate::manage) sequence: u64,
    pub(in crate::manage) transitions: Vec<Transition>,
}

/// The local directory facts used to classify one peer. Failure and retirement
/// have no successful remote TLS proof, but still require this exact binding.
#[derive(Clone)]
pub(in crate::manage) struct Binding {
    pub(in crate::manage) peer_id: String,
    pub(in crate::manage) target_revision: u64,
    pub(in crate::manage) authorization_revision: u64,
    pub(in crate::manage) active: bool,
    pub(in crate::manage) retired: bool,
    pub(in crate::manage) rollback: bool,
    pub(in crate::manage) peer_active: bool,
}

/// Exact commit proof. A start without old active episodes has no event range;
/// regular nonempty batches always have a positive inclusive range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct Commit {
    pub(in crate::manage) boot_id: String,
    pub(in crate::manage) batch_sequence: u64,
    pub(in crate::manage) first_event_sequence: Option<u64>,
    pub(in crate::manage) last_event_sequence: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Acknowledgement {
    pub(in crate::manage) transition_sequence: u64,
    pub(in crate::manage) administrator_id: String,
    pub(in crate::manage) observed_at_unix_ms: Option<u64>,
    pub(in crate::manage) event_sequence: u64,
}

/// Latest retained projection, not a current-health or process-liveness claim.
/// A later transition keeps the earlier acknowledgement as historical evidence
/// but makes is_acknowledged false until that exact new transition is confirmed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Episode {
    pub(in crate::manage) id: u64,
    pub(in crate::manage) observer_node_id: String,
    pub(in crate::manage) boot_id: String,
    pub(in crate::manage) observation: Observation,
    pub(in crate::manage) status: Status,
    pub(in crate::manage) last_transition_sequence: u64,
    pub(in crate::manage) ended_at_unix_ms: Option<u64>,
    pub(in crate::manage) ended_reason: Option<EndReason>,
    pub(in crate::manage) acknowledgement: Option<Acknowledgement>,
    pub(in crate::manage) is_acknowledged: bool,
}

/// Immutable accepted event. Origin is the observed subject, while observer is
/// the local node that accepted it; remote cache facts remain cache facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Event {
    pub(in crate::manage) sequence: u64,
    pub(in crate::manage) observer_node_id: String,
    pub(in crate::manage) episode_id: u64,
    pub(in crate::manage) boot_id: String,
    pub(in crate::manage) kind: EventKind,
    pub(in crate::manage) observation: Observation,
    pub(in crate::manage) observed_at_unix_ms: Option<u64>,
    pub(in crate::manage) recorded_at_unix_ms: Option<u64>,
    pub(in crate::manage) ended_reason: Option<EndReason>,
    pub(in crate::manage) administrator_id: Option<String>,
    pub(in crate::manage) transition_sequence: u64,
}

pub(in crate::manage) struct Query {
    pub(in crate::manage) before: Option<u64>,
    pub(in crate::manage) limit: u32,
    pub(in crate::manage) origin_node_id: Option<String>,
    pub(in crate::manage) episode_id: Option<u64>,
}
pub(in crate::manage) struct Page {
    pub(in crate::manage) items: Vec<Event>,
    pub(in crate::manage) next_cursor: Option<u64>,
    pub(in crate::manage) oldest_event_sequence: Option<u64>,
    pub(in crate::manage) trimmed: u64,
}
pub(in crate::manage) struct Summary {
    pub(in crate::manage) observer_node_id: String,
    pub(in crate::manage) active_count: u32,
    pub(in crate::manage) closed_count: u32,
    pub(in crate::manage) event_count: u32,
    pub(in crate::manage) unacknowledged_count: u32,
    pub(in crate::manage) oldest_event_sequence: Option<u64>,
    pub(in crate::manage) trimmed: u64,
    #[cfg(test)]
    pub(in crate::manage) last_event_sequence: u64,
}
pub(in crate::manage) struct Ack {
    pub(in crate::manage) expected_node_id: String,
    pub(in crate::manage) episode_id: u64,
    pub(in crate::manage) expected_transition_sequence: u64,
}

/// Exclusive episode-ID pages stay bounded by the transition watermark seen
/// when the inbox opened. Later transitions remain unread, even while paging.
pub(in crate::manage) struct UnreadQuery {
    pub(in crate::manage) before: Option<u64>,
    pub(in crate::manage) through: Option<u64>,
}
pub(in crate::manage) struct UnreadPage {
    pub(in crate::manage) items: Vec<Episode>,
    pub(in crate::manage) next_cursor: Option<u64>,
    pub(in crate::manage) through_sequence: u64,
}

/// Fixed failures contain no paths, SQL, producer messages or credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(in crate::manage) enum Error {
    #[error("alert history requires explicit schema migration")]
    UpgradeRequired,
    #[error("invalid alert history input")]
    Invalid,
    #[error("alert history binding conflicts")]
    Conflict,
    #[error("alert history record is not queryable")]
    NotQueryable,
    #[error("alert history sequence or storage capacity is exhausted")]
    Capacity,
    #[error("alert history administrator is not authorized")]
    Denied,
}
impl Error {
    pub(in crate::manage) const fn code(self) -> &'static str {
        match self {
            Self::UpgradeRequired => "management_upgrade_required",
            Self::Invalid => "invalid_alert_history",
            Self::Conflict => "alert_history_conflict",
            Self::NotQueryable => "alert_history_not_queryable",
            Self::Capacity => "alert_history_capacity",
            Self::Denied => "alert_history_denied",
        }
    }
    fn error(self) -> io::Error {
        io::Error::new(
            match self {
                Self::UpgradeRequired => io::ErrorKind::Unsupported,
                Self::Invalid => io::ErrorKind::InvalidInput,
                Self::Conflict | Self::Capacity => io::ErrorKind::AlreadyExists,
                Self::NotQueryable => io::ErrorKind::NotFound,
                Self::Denied => io::ErrorKind::PermissionDenied,
            },
            self,
        )
    }
}

/// Create only in initialization or the caller's backed-up migration transaction.
/// Canonical bounded payloads are projections, never commands to execute.
pub(in crate::manage) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection.execute_batch(
        "CREATE TABLE alert_history_state(
          singleton INTEGER PRIMARY KEY CHECK(singleton=1),
          last_sequence INTEGER NOT NULL CHECK(last_sequence>=0),
          trimmed INTEGER NOT NULL CHECK(trimmed>=0),
          boot_id TEXT CHECK(boot_id IS NULL OR length(boot_id)=22),
          batch_sequence INTEGER NOT NULL CHECK(batch_sequence>=0),
          batch_digest BLOB CHECK(batch_digest IS NULL OR length(batch_digest)=32),
          batch_first INTEGER CHECK(batch_first IS NULL OR batch_first>=1),
          batch_last INTEGER CHECK(batch_last IS NULL OR batch_last>=batch_first),
          last_incident_id TEXT NOT NULL CHECK(length(last_incident_id) BETWEEN 1 AND 20),
          CHECK((batch_first IS NULL)=(batch_last IS NULL)),
          CHECK((batch_sequence=0 AND batch_digest IS NULL) OR (batch_sequence>0 AND batch_digest IS NOT NULL AND batch_first IS NOT NULL)),
          CHECK(boot_id IS NOT NULL OR (last_sequence=0 AND batch_sequence=0 AND batch_first IS NULL))
         ) STRICT;
         INSERT INTO alert_history_state VALUES(1,0,0,NULL,0,NULL,NULL,NULL,'0');
         CREATE TABLE alert_episodes(
          id INTEGER PRIMARY KEY CHECK(id>=1),boot_id TEXT NOT NULL CHECK(length(boot_id)=22),
          incident_id TEXT NOT NULL CHECK(length(incident_id) BETWEEN 1 AND 20),
          status TEXT NOT NULL CHECK(status IN('active','recovered','unmonitored')),
          transition_sequence INTEGER NOT NULL CHECK(transition_sequence>=id),
          origin_node_id TEXT NOT NULL CHECK(length(origin_node_id)=22),
          ack_sequence INTEGER CHECK(ack_sequence IS NULL OR ack_sequence>=id),
          ack_administrator_id TEXT REFERENCES administrators(id) ON DELETE RESTRICT,
          ack_event_sequence INTEGER CHECK(ack_event_sequence IS NULL OR ack_event_sequence>=id),
          payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 1024),
          CHECK((ack_sequence IS NULL)=(ack_administrator_id IS NULL) AND (ack_sequence IS NULL)=(ack_event_sequence IS NULL)),
          UNIQUE(boot_id,incident_id)
         ) STRICT;
         CREATE INDEX alert_episodes_status ON alert_episodes(status,transition_sequence);
         CREATE TABLE alert_events(
          sequence INTEGER PRIMARY KEY CHECK(sequence>=1),episode_id INTEGER NOT NULL CHECK(episode_id>=1 AND episode_id<=sequence),
          origin_node_id TEXT NOT NULL CHECK(length(origin_node_id)=22),
          administrator_id TEXT REFERENCES administrators(id) ON DELETE RESTRICT,
          payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 1024)
         ) STRICT;
         CREATE INDEX alert_events_origin ON alert_events(origin_node_id,sequence DESC);
         CREATE INDEX alert_events_episode ON alert_events(episode_id,sequence DESC);"
    ).map_err(|error| sql_error("cannot create alert history", error))
}

#[derive(Clone)]
struct State {
    last: u64,
    trimmed: u64,
    boot: Option<String>,
    batch: u64,
    digest: Option<Vec<u8>>,
    first: Option<u64>,
    end: Option<u64>,
    incident: u64,
}

fn state(connection: &Connection) -> io::Result<State> {
    let batch_limit = batch_limit(connection)?;
    let count: i64 = connection
        .query_row("SELECT count(*) FROM alert_history_state", [], |r| r.get(0))
        .map_err(|e| sql_error("cannot inspect alert history state", e))?;
    if count != 1 {
        return Err(corrupt());
    }
    let (mut value,incident)=connection.query_row("SELECT last_sequence,trimmed,boot_id,batch_sequence,batch_digest,batch_first,batch_last,last_incident_id FROM alert_history_state WHERE singleton=1",[],|r|Ok((State {
        last:unsigned(r.get(0)?,0)?,trimmed:unsigned(r.get(1)?,1)?,boot:optional_text(r,2,22)?,batch:unsigned(r.get(3)?,3)?,digest:match r.get_ref(4)?{ValueRef::Null=>None,ValueRef::Blob(v) if v.len()==32=>Some(v.to_vec()),_=>return Err(rusqlite::Error::InvalidQuery)},first:optional_unsigned(r.get(5)?,5)?,end:optional_unsigned(r.get(6)?,6)?,incident:0
    },text(r,7,20)?))).map_err(|e|sql_error("cannot read alert history state",e))?;
    value.incident = decimal(&incident).ok_or_else(corrupt)?;
    if value.boot.as_ref().is_some_and(|v| !valid_id(v))
        || value.trimmed > value.last
        || value.first.is_some() != value.end.is_some()
        || value.first.is_some_and(|n| n == 0)
        || value
            .first
            .zip(value.end)
            .is_some_and(|(a, b)| a > b || b > value.last)
        || value.batch == 0 && value.digest.is_some()
        || value.batch > 0
            && (value.digest.as_ref().is_none_or(|d| d.len() != 32)
                || value.first.is_none()
                || value.incident == 0)
        || value
            .first
            .zip(value.end)
            .is_some_and(|(a, b)| b - a + 1 > batch_limit as u64)
        || value.boot.is_none()
            && (value.last != 0 || value.batch != 0 || value.first.is_some() || value.incident != 0)
    {
        return Err(corrupt());
    }
    Ok(value)
}
impl State {
    fn commit(&self) -> io::Result<Commit> {
        Ok(Commit {
            boot_id: self.boot.clone().ok_or_else(corrupt)?,
            batch_sequence: self.batch,
            first_event_sequence: self.first,
            last_event_sequence: self.end,
        })
    }
    fn next(&mut self) -> io::Result<u64> {
        self.last = self
            .last
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or_else(|| Error::Capacity.error())?;
        Ok(self.last)
    }
    fn save(&self, connection: &Connection) -> io::Result<()> {
        let rows=connection.execute("UPDATE alert_history_state SET last_sequence=?1,trimmed=?2,boot_id=?3,batch_sequence=?4,batch_digest=?5,batch_first=?6,batch_last=?7,last_incident_id=?8 WHERE singleton=1",params![sql(self.last)?,sql(self.trimmed)?,self.boot,sql(self.batch)?,self.digest,self.first.map(sql).transpose()?,self.end.map(sql).transpose()?,self.incident.to_string()]).map_err(|e|sql_error("cannot save alert history state",e))?;
        if rows != 1 {
            return Err(corrupt());
        }
        Ok(())
    }
}

/// Lightweight namespace validation; never recursively reads an overview or scans
/// event payloads. Older schemas must not carry a smuggled newer namespace.
pub(in crate::manage) fn validate_schema(connection: &Connection, version: u32) -> io::Result<()> {
    let count:i64=connection.query_row("SELECT count(*) FROM sqlite_schema WHERE name IN('alert_history_state','alert_episodes','alert_events')",[],|r|r.get(0)).map_err(|e|sql_error("cannot inspect alert history namespace",e))?;
    if version < 21 {
        return if count == 0 { Ok(()) } else { Err(corrupt()) };
    }
    if count != 3 {
        return Err(corrupt());
    }
    state(connection).map(|_| ())
}

fn sql(value: u64) -> io::Result<i64> {
    i64::try_from(value).map_err(|_| Error::Invalid.error())
}
fn positive(value: u64) -> bool {
    value > 0 && value <= i64::MAX as u64
}
fn unsigned(value: i64, index: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}
fn optional_unsigned(value: Option<i64>, index: usize) -> rusqlite::Result<Option<u64>> {
    value.map(|n| unsigned(n, index)).transpose()
}
fn sql_error(message: &'static str, error: rusqlite::Error) -> io::Error {
    sqlite_error(message, error)
}
fn corrupt() -> io::Error {
    invalid_data("alert history state is malformed")
}
fn now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|v| u64::try_from(v.as_millis()).ok())
}
fn encode<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| corrupt())?;
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD {
        return Err(Error::Capacity.error());
    }
    Ok(bytes)
}
fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> io::Result<T> {
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD {
        return Err(corrupt());
    }
    let value = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
    if encode(&value)? != bytes {
        return Err(corrupt());
    }
    Ok(value)
}
fn blob(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Vec<u8>> {
    match row.get_ref(index)? {
        ValueRef::Blob(v) if !v.is_empty() && v.len() <= MAX_PAYLOAD => Ok(v.to_vec()),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
fn text(row: &rusqlite::Row<'_>, index: usize, max: usize) -> rusqlite::Result<String> {
    match row.get_ref(index)? {
        ValueRef::Text(v) if !v.is_empty() && v.len() <= max => std::str::from_utf8(v)
            .map(str::to_owned)
            .map_err(|_| rusqlite::Error::InvalidQuery),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
fn optional_text(
    row: &rusqlite::Row<'_>,
    index: usize,
    max: usize,
) -> rusqlite::Result<Option<String>> {
    if matches!(row.get_ref(index)?, ValueRef::Null) {
        Ok(None)
    } else {
        text(row, index, max).map(Some)
    }
}

fn decimal(value: &str) -> Option<u64> {
    let n = value.parse::<u64>().ok()?;
    (n.to_string() == value).then_some(n)
}
fn require(connection: &Connection) -> io::Result<String> {
    let overview = read_overview(connection)?;
    if overview.schema_version < 21 {
        return Err(Error::UpgradeRequired.error());
    }
    Ok(overview.node_id)
}

fn version(connection: &Connection) -> io::Result<u32> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| sql_error("cannot inspect alert history version", error))
}

fn active_limit(connection: &Connection) -> io::Result<usize> {
    Ok(if version(connection)? >= 22 {
        MAX_ACTIVE
    } else {
        MAX_LOCAL
    })
}

fn batch_limit(connection: &Connection) -> io::Result<usize> {
    Ok(if version(connection)? >= 22 {
        MAX_BATCH
    } else {
        MAX_LOCAL * 2
    })
}

/// A source slot is a remote monitor identity, never a user-supplied message.
/// Its boot and positive u64 ID are kept separate from this observer's IDs.
fn source_slot(slot: &str) -> bool {
    source_boot(slot).is_some()
}

fn source_boot(slot: &str) -> Option<&str> {
    let (boot, id) = slot.strip_prefix("source:")?.split_once(':')?;
    (valid_id(boot) && decimal(id).is_some_and(|id| id > 0)).then_some(boot)
}

fn mirrored(observation: &Observation, node: &str) -> bool {
    observation.origin_node_id != node
        && !matches!(
            observation.kind,
            Kind::RemoteTraffic | Kind::RemoteJob | Kind::RemoteObservation
        )
}

fn check_version(version: u32, observation: &Observation, node: &str) -> io::Result<()> {
    if version < 22
        && (mirrored(observation, node)
            || observation.kind == Kind::RemoteObservation
            || source_slot(&observation.slot))
    {
        return Err(Error::UpgradeRequired.error());
    }
    Ok(())
}
fn administrator(connection: &Connection, id: &str) -> io::Result<()> {
    if !valid_id(id) {
        return Err(Error::Denied.error());
    }
    let yes: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM administrators WHERE id=?1)",
            [id],
            |r| r.get(0),
        )
        .map_err(|e| sql_error("cannot authorize alert history administrator", e))?;
    if !yes {
        return Err(Error::Denied.error());
    }
    Ok(())
}

/// Start one monitor generation under the existing update gate. Old active
/// episodes leave monitoring explicitly; their failure code and last observed
/// time remain intact. Repeating the current boot never resets its batch fence.
pub(in crate::manage) fn start(
    directory: &Path,
    gate: &UpdateGuard,
    boot_id: &str,
) -> io::Result<Commit> {
    validate_boot(boot_id)?;
    gate.ensure(directory)?;
    let mut connection = open_existing(directory, true)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sql_error("cannot begin alert monitor generation", e))?;
    let (answer, changed) = start_in(&tx, boot_id)?;
    if changed {
        tx.commit()
            .map_err(|e| sql_error("cannot commit alert monitor generation", e))?;
    }
    Ok(answer)
}

/// Stage a monitor generation in the held transaction. The bool distinguishes
/// an actual restart from a read-only same-boot result; it is not commit proof.
fn start_in(tx: &Connection, boot_id: &str) -> io::Result<(Commit, bool)> {
    start_in_with(tx, boot_id, None)
}
fn start_in_with(
    tx: &Connection,
    boot_id: &str,
    mut checkpoints: Option<&mut dyn Checkpoints>,
) -> io::Result<(Commit, bool)> {
    require_transaction(tx)?;
    let node = require(tx)?;
    let mut s = state(tx)?;
    if s.boot.as_deref() == Some(boot_id) {
        return s.commit().map(|value| (value, false));
    }
    // A retained retired boot cannot be selected again because its RAM was lost.
    let reused: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM alert_episodes WHERE boot_id=?1)",
            [boot_id],
            |r| r.get(0),
        )
        .map_err(|e| sql_error("cannot bind alert monitor generation", e))?;
    if reused {
        return Err(Error::Conflict.error());
    }
    let episodes = episodes(tx, Some("active"))?;
    let first = s
        .last
        .checked_add(1)
        .ok_or_else(|| Error::Capacity.error())?;
    let at = now();
    for (index, mut episode) in episodes.into_iter().enumerate() {
        if episode.observer_node_id != node
            || s.boot.as_deref() != Some(episode.boot_id.as_str())
            || episode.last_transition_sequence > s.last
            || episode.observation.incident_id > s.incident
        {
            return Err(corrupt());
        }
        let seq = s.next()?;
        episode.status = Status::Unmonitored;
        episode.ended_reason = Some(EndReason::MonitorRestarted);
        episode.ended_at_unix_ms = at;
        episode.last_transition_sequence = seq;
        episode.is_acknowledged = false;
        let event = Event {
            sequence: seq,
            observer_node_id: node.clone(),
            episode_id: episode.id,
            boot_id: episode.boot_id.clone(),
            kind: EventKind::Unmonitored,
            observation: episode.observation.clone(),
            observed_at_unix_ms: at,
            recorded_at_unix_ms: at,
            ended_reason: episode.ended_reason,
            administrator_id: None,
            transition_sequence: seq,
        };
        save_event(tx, &event)?;
        save_episode(tx, &episode)?;
        if index % 256 == 255 {
            checkpoint(&mut checkpoints)?;
        }
    }
    s.boot = Some(boot_id.to_owned());
    s.batch = 0;
    s.digest = None;
    s.incident = 0;
    s.first = (s.last >= first).then_some(first);
    s.end = s.first.map(|_| s.last);
    trim_with(tx, &mut s, &mut checkpoints)?;
    s.save(tx)?;
    let answer = s.commit()?;
    Ok((answer, true))
}

fn digest(batch: &Batch, limit: usize) -> io::Result<[u8; 32]> {
    if !valid_id(&batch.boot_id)
        || !positive(batch.sequence)
        || batch.transitions.is_empty()
        || batch.transitions.len() > limit
    {
        return Err(Error::Invalid.error());
    }
    let mut total = 0usize;
    for transition in &batch.transitions {
        validate_observation(&transition.observation)?;
        if (transition.kind == TransitionKind::Unmonitored)
            != (transition.ended_reason == Some(EndReason::SourceUnmonitored))
        {
            return Err(Error::Invalid.error());
        }
        let bytes = encode(transition)?;
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| Error::Capacity.error())?;
    }
    if total
        > limit
            .checked_mul(MAX_PAYLOAD)
            .ok_or_else(|| Error::Capacity.error())?
    {
        return Err(Error::Capacity.error());
    }
    let max = limit
        .checked_mul(MAX_PAYLOAD + 1)
        .and_then(|n| n.checked_add(256))
        .ok_or_else(|| Error::Capacity.error())?;
    encoding::batch_digest(batch, max)
}
fn receipt_in(s: &State, batch: &Batch, hash: &[u8; 32]) -> io::Result<Option<Commit>> {
    if s.boot.as_deref() != Some(batch.boot_id.as_str()) {
        return Err(Error::Conflict.error());
    }
    if s.batch == batch.sequence {
        if s.digest.as_deref() != Some(hash.as_slice()) {
            return Err(Error::Conflict.error());
        }
        return s.commit().map(Some);
    }
    if s.batch.checked_add(1) == Some(batch.sequence) {
        return Ok(None);
    }
    Err(Error::NotQueryable.error())
}

/// Read the original batch proof after a lost response. None proves only that
/// the next exact batch is absent in this healthy current-boot snapshot. Errors,
/// older batches and another boot are not permission to choose a replacement ID.
pub(in crate::manage) fn receipt(directory: &Path, batch: &Batch) -> io::Result<Option<Commit>> {
    let mut connection = open_existing(directory, false)?;
    let tx = connection
        .transaction()
        .map_err(|e| sql_error("cannot begin alert batch confirmation", e))?;
    let answer = receipt_from(&tx, batch)?;
    tx.commit()
        .map_err(|e| sql_error("cannot finish alert batch confirmation", e))?;
    Ok(answer)
}

/// Observe only the original boot/sequence/digest in a coherent SQL snapshot.
fn receipt_from(tx: &Connection, batch: &Batch) -> io::Result<Option<Commit>> {
    require_transaction(tx)?;
    require(tx)?;
    let hash = digest(batch, batch_limit(tx)?)?;
    let answer = receipt_in(&state(tx)?, batch, &hash)?;
    Ok(answer)
}

/// Commit one bounded batch atomically. The caller retains the same batch until
/// this result or receipt() confirms it; an I/O/COMMIT error is not a statement
/// that no event was saved. Exact duplicates preserve the original event range.
pub(in crate::manage) fn record(
    directory: &Path,
    gate: &UpdateGuard,
    batch: &Batch,
) -> io::Result<Commit> {
    record_in(directory, gate, batch, None)
}

/// Only authenticated complete imports use this entry. Proofs are checked in
/// the very transaction that appends events, not in an earlier preflight view.
pub(in crate::manage) fn record_guarded(
    directory: &Path,
    gate: &UpdateGuard,
    batch: &Batch,
    proofs: &[Arc<crate::manage::observations::Proof>],
    bindings: &[Binding],
) -> io::Result<Commit> {
    record_in(directory, gate, batch, Some((proofs, bindings)))
}

fn record_in(
    directory: &Path,
    gate: &UpdateGuard,
    batch: &Batch,
    proofs: Option<(&[Arc<crate::manage::observations::Proof>], &[Binding])>,
) -> io::Result<Commit> {
    gate.ensure(directory)?;
    let mut connection = open_existing(directory, true)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sql_error("cannot begin alert event batch", e))?;
    let (answer, changed) = record_transaction(&tx, batch, proofs)?;
    if changed {
        tx.commit()
            .map_err(|e| sql_error("cannot commit alert event batch", e))?;
    }
    Ok(answer)
}

/// Stage the exact batch and its source proofs together. Terminal replay does
/// not write, allocate a sequence or independently authorize fresh evidence.
fn record_transaction(
    tx: &Connection,
    batch: &Batch,
    proofs: Option<(&[Arc<crate::manage::observations::Proof>], &[Binding])>,
) -> io::Result<(Commit, bool)> {
    record_transaction_with(tx, batch, proofs, None)
}
fn record_transaction_with(
    tx: &Connection,
    batch: &Batch,
    proofs: Option<(&[Arc<crate::manage::observations::Proof>], &[Binding])>,
    mut checkpoints: Option<&mut dyn Checkpoints>,
) -> io::Result<(Commit, bool)> {
    require_transaction(tx)?;
    let node = require(tx)?;
    let hash = digest(batch, batch_limit(tx)?)?;
    let mut s = state(tx)?;
    if let Some(answer) = receipt_in(&s, batch, &hash)? {
        return Ok((answer, false));
    }
    let version = version(tx)?;
    for transition in &batch.transitions {
        check_version(version, &transition.observation, &node)?;
    }
    match proofs {
        Some((proofs, bindings)) => {
            validate_bindings(tx, bindings)?;
            validate_imports(tx, batch, proofs, bindings, &node)?;
        }
        None if batch.transitions.iter().any(|transition| {
            mirrored(&transition.observation, &node)
                || transition.observation.kind == Kind::RemoteObservation
        }) =>
        {
            return Err(Error::Denied.error());
        }
        None => {}
    }
    let first = s
        .last
        .checked_add(1)
        .ok_or_else(|| Error::Capacity.error())?;
    let previous_incident = s.incident;
    for (index, transition) in batch.transitions.iter().enumerate() {
        let observation = &transition.observation;
        let existing = find_source_episode(tx, &batch.boot_id, observation.incident_id)?;
        if existing.as_ref().is_some_and(|episode| {
            episode.observer_node_id != node
                || episode.last_transition_sequence > s.last
                || episode
                    .acknowledgement
                    .as_ref()
                    .is_some_and(|ack| ack.event_sequence > s.last)
        }) {
            return Err(corrupt());
        }
        // An episode created earlier in this transaction is valid here, but a
        // future reference must be rejected before advancing to that number.
        let seq = s.next()?;
        let (mut episode, kind) = match transition.kind {
            TransitionKind::Opened => {
                if existing.is_some() || observation.incident_id <= previous_incident {
                    return Err(Error::Conflict.error());
                }
                s.incident = s.incident.max(observation.incident_id);
                (
                    Episode {
                        id: seq,
                        observer_node_id: node.clone(),
                        boot_id: batch.boot_id.clone(),
                        observation: observation.clone(),
                        status: Status::Active,
                        last_transition_sequence: seq,
                        ended_at_unix_ms: None,
                        ended_reason: None,
                        acknowledgement: None,
                        is_acknowledged: false,
                    },
                    EventKind::Opened,
                )
            }
            kind => {
                let mut episode = existing.ok_or_else(|| Error::NotQueryable.error())?;
                if episode.status != Status::Active
                    || !same_subject(&episode.observation, observation)
                {
                    return Err(Error::Conflict.error());
                }
                if kind == TransitionKind::ReasonChanged
                    && episode.observation.code == observation.code
                {
                    return Err(Error::Conflict.error());
                }
                if kind != TransitionKind::ReasonChanged
                    && episode.observation.code != observation.code
                {
                    return Err(Error::Conflict.error());
                }
                episode.observation = observation.clone();
                episode.last_transition_sequence = seq;
                episode.is_acknowledged = false;
                let event_kind = match kind {
                    TransitionKind::ReasonChanged => EventKind::ReasonChanged,
                    TransitionKind::Recovered => {
                        episode.status = Status::Recovered;
                        episode.ended_at_unix_ms = transition.observed_at_unix_ms;
                        EventKind::Recovered
                    }
                    TransitionKind::Unmonitored => {
                        episode.status = Status::Unmonitored;
                        episode.ended_at_unix_ms = transition.observed_at_unix_ms;
                        episode.ended_reason = transition.ended_reason;
                        EventKind::Unmonitored
                    }
                    TransitionKind::Opened => return Err(Error::Invalid.error()),
                };
                (episode, event_kind)
            }
        };
        episode.is_acknowledged = episode
            .acknowledgement
            .as_ref()
            .is_some_and(|a| a.transition_sequence == seq);
        let event = Event {
            sequence: seq,
            observer_node_id: node.clone(),
            episode_id: episode.id,
            boot_id: batch.boot_id.clone(),
            kind,
            observation: observation.clone(),
            observed_at_unix_ms: transition.observed_at_unix_ms,
            recorded_at_unix_ms: now(),
            ended_reason: transition.ended_reason,
            administrator_id: None,
            transition_sequence: seq,
        };
        save_event(tx, &event)?;
        save_episode(tx, &episode)?;
        if index % 256 == 255 {
            checkpoint(&mut checkpoints)?;
        }
    }
    s.batch = batch.sequence;
    s.digest = Some(hash.to_vec());
    s.first = Some(first);
    s.end = Some(s.last);
    trim_with(tx, &mut s, &mut checkpoints)?;
    s.save(tx)?;
    let answer = s.commit()?;
    Ok((answer, true))
}

fn validate_bindings(connection: &Connection, bindings: &[Binding]) -> io::Result<()> {
    if version(connection)? < 22 {
        return Err(Error::UpgradeRequired.error());
    }
    if bindings.len() > MAX_SOURCES {
        return Err(Error::Capacity.error());
    }
    let snapshot = super::read_in(connection, None)?;
    let current = snapshot
        .targets
        .iter()
        .map(|target| (target.id.as_str(), target))
        .collect::<BTreeMap<_, _>>();
    let mut ids = HashSet::new();
    for binding in bindings {
        let target = current
            .get(binding.peer_id.as_str())
            .ok_or_else(|| Error::Denied.error())?;
        if !ids.insert(binding.peer_id.as_str())
            || target.revision != binding.target_revision
            || target.authorization_revision != binding.authorization_revision
            || target.active != binding.active
            || target.retired != binding.retired
            || target.rollback != binding.rollback
            || target.peer_active != binding.peer_active
        {
            return Err(Error::Denied.error());
        }
    }
    Ok(())
}

fn validate_proofs(
    connection: &Connection,
    proofs: &[Arc<crate::manage::observations::Proof>],
) -> io::Result<()> {
    if proofs.len() > MAX_SOURCES {
        return Err(Error::Capacity.error());
    }
    let mut ids = HashSet::new();
    for proof in proofs {
        let authorization = &proof.authorization;
        if !ids.insert(authorization.node_id.as_str()) {
            return Err(Error::Invalid.error());
        }
        let target = super::super::targets::get_in(connection, &authorization.node_id)?;
        let peer = super::super::peers::authorize_in(connection, &authorization.leaf)?
            .ok_or_else(|| Error::Denied.error())?;
        if target.revision != proof.target_revision
            || !target.active
            || target.retired
            || target.rollback_detected
            || peer.node_id != authorization.node_id
            || peer.authorization_revision != authorization.authorization_revision
            || crate::manage::tls::verify_peer_name(&authorization.leaf, &peer.expected_san)
                .is_err()
        {
            return Err(Error::Denied.error());
        }
    }
    Ok(())
}

fn validate_imports(
    connection: &Connection,
    batch: &Batch,
    proofs: &[Arc<crate::manage::observations::Proof>],
    bindings: &[Binding],
    node: &str,
) -> io::Result<()> {
    validate_proofs(connection, proofs)?;
    for transition in &batch.transitions {
        let observation = &transition.observation;
        if !mirrored(observation, node) && observation.kind != Kind::RemoteObservation {
            continue;
        }
        let binding = bindings
            .iter()
            .find(|binding| binding.peer_id == observation.origin_node_id)
            .ok_or_else(|| Error::Denied.error())?;
        if observation.kind == Kind::RemoteObservation {
            continue;
        }
        if proofs
            .iter()
            .any(|proof| proof.authorization.node_id == observation.origin_node_id)
        {
            continue;
        }
        // Loss of local authority can retire old evidence, never create or
        // recover an incident. Binding equality was checked in this same tx.
        if transition.kind != TransitionKind::Unmonitored
            || binding.active && !binding.retired && binding.peer_active
        {
            return Err(Error::Denied.error());
        }
    }
    Ok(())
}

/// No event transition means no SQL write or new batch identity. The existing
/// update gate still fences directory changes through proof check/publication.
pub(in crate::manage) fn publish_guarded<T>(
    directory: &Path,
    gate: &UpdateGuard,
    proofs: &[Arc<crate::manage::observations::Proof>],
    bindings: &[Binding],
    publish: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    gate.ensure(directory)?;
    let mut connection = open_existing(directory, false)?;
    let tx = connection
        .transaction()
        .map_err(|error| sql_error("cannot begin guarded observation", error))?;
    validate_current(&tx, proofs, bindings)?;
    let result = publish()?;
    tx.commit()
        .map_err(|error| sql_error("cannot finish guarded observation", error))?;
    Ok(result)
}

/// Guard only current evidence. An old committed receipt remains historical
/// proof even if this check now refuses to publish that evidence as fresh.
fn validate_current(
    tx: &Connection,
    proofs: &[Arc<crate::manage::observations::Proof>],
    bindings: &[Binding],
) -> io::Result<()> {
    require_transaction(tx)?;
    validate_bindings(tx, bindings)?;
    validate_proofs(tx, proofs)
}

fn same_subject(a: &Observation, b: &Observation) -> bool {
    a.incident_id == b.incident_id
        && a.kind == b.kind
        && a.origin_node_id == b.origin_node_id
        && a.resource_id == b.resource_id
        && a.slot == b.slot
        && a.check == b.check
        && a.target == b.target
        && a.first_observed_at_unix_ms == b.first_observed_at_unix_ms
}

fn save_event(connection: &Connection, event: &Event) -> io::Result<()> {
    validate_event(event)?;
    let bytes = encode(event)?;
    connection.execute("INSERT INTO alert_events(sequence,episode_id,origin_node_id,administrator_id,payload) VALUES(?1,?2,?3,?4,?5)",params![sql(event.sequence)?,sql(event.episode_id)?,event.observation.origin_node_id,event.administrator_id,bytes]).map_err(|e|sql_error("cannot append alert event",e))?;
    Ok(())
}
fn save_episode(connection: &Connection, episode: &Episode) -> io::Result<()> {
    validate_episode(episode)?;
    let bytes = encode(episode)?;
    let ack = episode.acknowledgement.as_ref();
    connection.execute("INSERT INTO alert_episodes(id,boot_id,incident_id,status,transition_sequence,origin_node_id,ack_sequence,ack_administrator_id,ack_event_sequence,payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(id) DO UPDATE SET status=excluded.status,transition_sequence=excluded.transition_sequence,ack_sequence=excluded.ack_sequence,ack_administrator_id=excluded.ack_administrator_id,ack_event_sequence=excluded.ack_event_sequence,payload=excluded.payload",params![sql(episode.id)?,episode.boot_id,episode.observation.incident_id.to_string(),status(episode.status),sql(episode.last_transition_sequence)?,episode.observation.origin_node_id,ack.map(|a|sql(a.transition_sequence)).transpose()?,ack.map(|a|a.administrator_id.as_str()),ack.map(|a|sql(a.event_sequence)).transpose()?,bytes]).map_err(|e|sql_error("cannot save alert episode",e))?;
    Ok(())
}
fn status(status: Status) -> &'static str {
    match status {
        Status::Active => "active",
        Status::Recovered => "recovered",
        Status::Unmonitored => "unmonitored",
    }
}
const EPISODE_COLUMNS: &str = "id,boot_id,incident_id,status,transition_sequence,origin_node_id,ack_sequence,ack_administrator_id,ack_event_sequence,payload";
type EpisodeRow = (
    u64,
    String,
    String,
    String,
    u64,
    String,
    Option<u64>,
    Option<String>,
    Option<u64>,
    Vec<u8>,
);
fn episode_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EpisodeRow> {
    Ok((
        unsigned(row.get(0)?, 0)?,
        text(row, 1, 22)?,
        text(row, 2, 20)?,
        text(row, 3, 11)?,
        unsigned(row.get(4)?, 4)?,
        text(row, 5, 22)?,
        optional_unsigned(row.get(6)?, 6)?,
        optional_text(row, 7, 22)?,
        optional_unsigned(row.get(8)?, 8)?,
        blob(row, 9)?,
    ))
}
fn episode_value(row: EpisodeRow) -> io::Result<Episode> {
    let e: Episode = decode(&row.9)?;
    validate_episode(&e)?;
    let a = e.acknowledgement.as_ref();
    if e.id != row.0
        || e.boot_id != row.1
        || e.observation.incident_id.to_string() != row.2
        || status(e.status) != row.3
        || e.last_transition_sequence != row.4
        || e.observation.origin_node_id != row.5
        || a.map(|v| v.transition_sequence) != row.6
        || a.map(|v| v.administrator_id.as_str()) != row.7.as_deref()
        || a.map(|v| v.event_sequence) != row.8
    {
        return Err(corrupt());
    }
    Ok(e)
}
fn find_episode(connection: &Connection, id: u64) -> io::Result<Option<Episode>> {
    connection
        .query_row(
            &format!("SELECT {EPISODE_COLUMNS} FROM alert_episodes WHERE id=?1"),
            [sql(id)?],
            episode_row,
        )
        .optional()
        .map_err(|e| sql_error("cannot read alert episode", e))?
        .map(episode_value)
        .transpose()
}
fn find_source_episode(
    connection: &Connection,
    boot: &str,
    incident: u64,
) -> io::Result<Option<Episode>> {
    connection
        .query_row(
            &format!(
                "SELECT {EPISODE_COLUMNS} FROM alert_episodes WHERE boot_id=?1 AND incident_id=?2"
            ),
            params![boot, incident.to_string()],
            episode_row,
        )
        .optional()
        .map_err(|e| sql_error("cannot bind alert source episode", e))?
        .map(episode_value)
        .transpose()
}
fn episodes(connection: &Connection, filter: Option<&str>) -> io::Result<Vec<Episode>> {
    let limit = active_limit(connection)?;
    let schema = version(connection)?;
    let node = require(connection)?;
    let mut statement=connection.prepare(&format!("SELECT {EPISODE_COLUMNS} FROM alert_episodes WHERE (?1 IS NULL OR status=?1) ORDER BY id LIMIT ?2")).map_err(|e|sql_error("cannot inspect alert episodes",e))?;
    let rows = statement
        .query_map(
            params![filter, (limit + MAX_CLOSED + 1) as i64],
            episode_row,
        )
        .map_err(|e| sql_error("cannot read alert episodes", e))?;
    let mut answer = Vec::new();
    for row in rows {
        let episode = episode_value(row.map_err(|e| sql_error("cannot decode alert episode", e))?)?;
        check_version(schema, &episode.observation, &node)?;
        answer.push(episode);
    }
    let active = answer.iter().filter(|e| e.status == Status::Active).count();
    if active > limit || answer.len().saturating_sub(active) > MAX_CLOSED {
        return Err(corrupt());
    }
    Ok(answer)
}

fn trim_with(
    connection: &Connection,
    s: &mut State,
    checkpoints: &mut Option<&mut dyn Checkpoints>,
) -> io::Result<()> {
    // Source Sessions retain deleted preimages too. Chunk deletion under the
    // same transaction; Native keeps its original single-statement fast path.
    let active: i64 = connection
        .query_row(
            "SELECT count(*) FROM alert_episodes WHERE status='active'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sql_error("cannot inspect active alert capacity", e))?;
    if active > active_limit(connection)? as i64 {
        return Err(Error::Capacity.error());
    }
    let node = require(connection)?;
    let mut counts = [0_usize; 3];
    for episode in episodes(connection, Some("active"))? {
        let group = if episode.observation.kind == Kind::RemoteObservation {
            2
        } else if mirrored(&episode.observation, &node) {
            1
        } else {
            0
        };
        counts[group] = counts[group].checked_add(1).ok_or_else(corrupt)?;
    }
    if counts[0] > MAX_LOCAL || counts[1] > MAX_REMOTE || counts[2] > MAX_SOURCES {
        return Err(Error::Capacity.error());
    }
    if checkpoints.is_none() {
        connection.execute("DELETE FROM alert_episodes WHERE id IN(SELECT id FROM alert_episodes WHERE status<>'active' ORDER BY transition_sequence DESC LIMIT -1 OFFSET ?1)",[MAX_CLOSED as i64]).map_err(|e|sql_error("cannot retain alert episodes",e))?;
    } else {
        loop {
            let removed = connection.execute("DELETE FROM alert_episodes WHERE id IN(SELECT id FROM (SELECT id FROM alert_episodes WHERE status<>'active' ORDER BY transition_sequence DESC LIMIT -1 OFFSET ?1) LIMIT 256)",[MAX_CLOSED as i64]).map_err(|e|sql_error("cannot retain alert episodes",e))?;
            if removed == 0 {
                break;
            }
            checkpoint(checkpoints)?;
        }
    }
    let removed = if checkpoints.is_none() {
        connection.execute("DELETE FROM alert_events WHERE sequence IN(SELECT sequence FROM alert_events ORDER BY sequence DESC LIMIT -1 OFFSET ?1)",[MAX_EVENTS as i64]).map_err(|e|sql_error("cannot retain alert events",e))?
    } else {
        let mut total = 0usize;
        loop {
            let removed = connection.execute("DELETE FROM alert_events WHERE sequence IN(SELECT sequence FROM (SELECT sequence FROM alert_events ORDER BY sequence DESC LIMIT -1 OFFSET ?1) LIMIT 256)",[MAX_EVENTS as i64]).map_err(|e|sql_error("cannot retain alert events",e))?;
            if removed == 0 {
                break;
            }
            total = total.checked_add(removed).ok_or_else(corrupt)?;
            checkpoint(checkpoints)?;
        }
        total
    };
    s.trimmed = s
        .trimmed
        .checked_add(removed as u64)
        .ok_or_else(|| Error::Capacity.error())?;
    Ok(())
}

/// Acknowledges only this original transition, not its health. The same confirmed
/// transition is idempotent; stale CAS, another node or an unknown episode cannot
/// acknowledge a later occurrence. Actor verification and append share one tx.
pub(in crate::manage) fn acknowledge(
    directory: &Path,
    gate: &UpdateGuard,
    administrator_id: &str,
    input: &Ack,
) -> io::Result<Episode> {
    validate_ack(input)?;
    gate.ensure(directory)?;
    let mut connection = open_existing(directory, true)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sql_error("cannot begin alert acknowledgement", e))?;
    let (episode, changed) = acknowledge_in(&tx, administrator_id, input)?;
    if changed {
        tx.commit()
            .map_err(|e| sql_error("cannot commit alert acknowledgement", e))?;
    }
    Ok(episode)
}

/// Bind the acknowledgement to the current administrator and exact original
/// transition. A duplicate acknowledgement is a read-only result.
fn acknowledge_in(
    tx: &Connection,
    administrator_id: &str,
    input: &Ack,
) -> io::Result<(Episode, bool)> {
    acknowledge_in_with(tx, administrator_id, input, None)
}
fn acknowledge_in_with(
    tx: &Connection,
    administrator_id: &str,
    input: &Ack,
    mut checkpoints: Option<&mut dyn Checkpoints>,
) -> io::Result<(Episode, bool)> {
    let result = acknowledge_transition(tx, administrator_id, input)?;
    if result.1 {
        let mut s = state(tx)?;
        trim_with(tx, &mut s, &mut checkpoints)?;
        s.save(tx)?;
    }
    Ok(result)
}

// Batches share one retention/checkpoint pass, rather than rescanning the full
// active catalog for each of their at most 32 transitions.
fn acknowledge_transition(
    tx: &Connection,
    administrator_id: &str,
    input: &Ack,
) -> io::Result<(Episode, bool)> {
    require_transaction(tx)?;
    let node = require(tx)?;
    administrator(tx, administrator_id)?;
    if node != input.expected_node_id {
        return Err(Error::Conflict.error());
    }
    let mut episode =
        find_episode(tx, input.episode_id)?.ok_or_else(|| Error::NotQueryable.error())?;
    let mut s = state(tx)?;
    if episode.observer_node_id != node
        || episode.last_transition_sequence > s.last
        || episode
            .acknowledgement
            .as_ref()
            .is_some_and(|ack| ack.event_sequence > s.last)
    {
        return Err(corrupt());
    }
    if episode.last_transition_sequence != input.expected_transition_sequence {
        return Err(Error::Conflict.error());
    }
    if episode.is_acknowledged {
        return Ok((episode, false));
    }
    let seq = s.next()?;
    let at = now();
    let event = Event {
        sequence: seq,
        observer_node_id: node,
        episode_id: episode.id,
        boot_id: episode.boot_id.clone(),
        kind: EventKind::Acknowledged,
        observation: episode.observation.clone(),
        observed_at_unix_ms: at,
        recorded_at_unix_ms: at,
        ended_reason: None,
        administrator_id: Some(administrator_id.to_owned()),
        transition_sequence: episode.last_transition_sequence,
    };
    episode.acknowledgement = Some(Acknowledgement {
        transition_sequence: episode.last_transition_sequence,
        administrator_id: administrator_id.to_owned(),
        observed_at_unix_ms: at,
        event_sequence: seq,
    });
    episode.is_acknowledged = true;
    save_event(tx, &event)?;
    save_episode(tx, &episode)?;
    s.save(tx)?;
    Ok((episode, true))
}

fn require_transaction(connection: &Connection) -> io::Result<()> {
    if connection.is_autocommit() {
        return Err(Error::Invalid.error());
    }
    Ok(())
}

fn validate_boot(boot: &str) -> io::Result<()> {
    if !valid_id(boot) {
        return Err(Error::Invalid.error());
    }
    Ok(())
}

fn validate_ack(input: &Ack) -> io::Result<()> {
    if !valid_id(&input.expected_node_id)
        || !positive(input.episode_id)
        || !positive(input.expected_transition_sequence)
    {
        return Err(Error::Invalid.error());
    }
    Ok(())
}

fn validate_ack_batch(inputs: &[Ack]) -> io::Result<()> {
    if inputs.is_empty() || inputs.len() > MAX_ACK_BATCH {
        return Err(Error::Invalid.error());
    }
    let mut ids = HashSet::with_capacity(inputs.len());
    for input in inputs {
        validate_ack(input)?;
        if !ids.insert(input.episode_id) {
            return Err(Error::Invalid.error());
        }
    }
    Ok(())
}

/// A small explicit set of original transitions commits atomically. A changed
/// row rejects the entire batch; duplicate confirmed transitions stay read-only.
fn acknowledge_batch(
    directory: &Path,
    gate: &UpdateGuard,
    administrator_id: &str,
    inputs: &[Ack],
) -> io::Result<Vec<Episode>> {
    validate_ack_batch(inputs)?;
    gate.ensure(directory)?;
    let mut connection = open_existing(directory, true)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sql_error("cannot begin alert acknowledgement batch", e))?;
    let values = acknowledge_batch_in(&tx, administrator_id, inputs, None)?;
    tx.commit()
        .map_err(|e| sql_error("cannot commit alert acknowledgement batch", e))?;
    Ok(values)
}

fn acknowledge_batch_in(
    tx: &Connection,
    actor: &str,
    inputs: &[Ack],
    mut checkpoints: Option<&mut dyn Checkpoints>,
) -> io::Result<Vec<Episode>> {
    let mut values = Vec::with_capacity(inputs.len());
    let mut changed = false;
    for input in inputs {
        let (value, wrote) = acknowledge_transition(tx, actor, input)?;
        changed |= wrote;
        values.push(value);
    }
    if changed {
        let mut s = state(tx)?;
        trim_with(tx, &mut s, &mut checkpoints)?;
        s.save(tx)?;
    }
    Ok(values)
}

fn read<T>(
    directory: &Path,
    administrator_id: &str,
    operation: impl FnOnce(&Connection, &str) -> io::Result<T>,
) -> io::Result<T> {
    let mut connection = open_existing(directory, false)?;
    let tx = connection
        .transaction()
        .map_err(|e| sql_error("cannot begin alert history snapshot", e))?;
    let node = require(&tx)?;
    administrator(&tx, administrator_id)?;
    let answer = operation(&tx, &node)?;
    tx.commit()
        .map_err(|e| sql_error("cannot finish alert history snapshot", e))?;
    Ok(answer)
}
type EventRow = (u64, u64, String, Option<String>, Vec<u8>);
fn event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EventRow> {
    Ok((
        unsigned(row.get(0)?, 0)?,
        unsigned(row.get(1)?, 1)?,
        text(row, 2, 22)?,
        optional_text(row, 3, 22)?,
        blob(row, 4)?,
    ))
}
fn event_value(row: EventRow) -> io::Result<Event> {
    let e: Event = decode(&row.4)?;
    validate_event(&e)?;
    if e.sequence != row.0
        || e.episode_id != row.1
        || e.observation.origin_node_id != row.2
        || e.administrator_id != row.3
    {
        return Err(corrupt());
    }
    Ok(e)
}
fn find_event(connection: &Connection, id: u64) -> io::Result<Option<Event>> {
    connection.query_row("SELECT sequence,episode_id,origin_node_id,administrator_id,payload FROM alert_events WHERE sequence=?1",[sql(id)?],event_row).optional().map_err(|e|sql_error("cannot read exact alert event",e))?.map(event_value).transpose()
}

pub(in crate::manage) fn get(
    directory: &Path,
    administrator_id: &str,
    id: u64,
) -> io::Result<Option<Event>> {
    if !positive(id) {
        return Err(Error::Invalid.error());
    }
    read(directory, administrator_id, |connection, node| {
        let s = state(connection)?;
        let e = find_event(connection, id)?;
        if e.as_ref().is_some_and(|e| {
            e.observer_node_id != node || e.sequence > s.last || e.sequence <= s.trimmed
        }) {
            return Err(corrupt());
        }
        Ok(e)
    })
}
pub(in crate::manage) fn episode(
    directory: &Path,
    administrator_id: &str,
    id: u64,
) -> io::Result<Option<Episode>> {
    if !positive(id) {
        return Err(Error::Invalid.error());
    }
    read(directory, administrator_id, |connection, node| {
        let s = state(connection)?;
        let e = find_episode(connection, id)?;
        if e.as_ref().is_some_and(|e| {
            e.observer_node_id != node
                || e.last_transition_sequence > s.last
                || e.acknowledgement
                    .as_ref()
                    .is_some_and(|a| a.event_sequence > s.last)
        }) {
            return Err(corrupt());
        }
        Ok(e)
    })
}

/// Return only unread retained episode projections, never a fabricated health
/// result. An authenticated snapshot verifies every payload and keeps newer
/// transitions outside the original inbox watermark.
pub(in crate::manage) fn unread(
    directory: &Path,
    administrator_id: &str,
    query: &UnreadQuery,
) -> io::Result<UnreadPage> {
    if query.before.is_some_and(|value| !positive(value))
        || query.through.is_some_and(|value| value > i64::MAX as u64)
    {
        return Err(Error::Invalid.error());
    }
    read(directory, administrator_id, |connection, node| {
        let s = state(connection)?;
        let through = query.through.unwrap_or(s.last);
        if through > s.last {
            return Err(Error::Conflict.error());
        }
        let mut statement = connection
            .prepare(&format!(
                "SELECT {EPISODE_COLUMNS} FROM alert_episodes \
             WHERE (ack_sequence IS NULL OR ack_sequence<>transition_sequence) \
             AND (?1 IS NULL OR id<?1) AND transition_sequence<=?2 \
             ORDER BY id DESC LIMIT ?3"
            ))
            .map_err(|e| sql_error("cannot prepare unread alert episodes", e))?;
        let rows = statement
            .query_map(
                params![
                    query.before.map(sql).transpose()?,
                    sql(through)?,
                    (MAX_ACK_BATCH + 1) as i64
                ],
                episode_row,
            )
            .map_err(|e| sql_error("cannot read unread alert episodes", e))?;
        let mut items = Vec::with_capacity(MAX_ACK_BATCH + 1);
        for row in rows {
            let value = episode_value(
                row.map_err(|e| sql_error("cannot decode unread alert episode", e))?,
            )?;
            if value.observer_node_id != node
                || value.last_transition_sequence > through
                || value.is_acknowledged
                || value
                    .acknowledgement
                    .as_ref()
                    .is_some_and(|ack| ack.event_sequence > s.last)
            {
                return Err(corrupt());
            }
            items.push(value);
        }
        let more = items.len() > MAX_ACK_BATCH;
        items.truncate(MAX_ACK_BATCH);
        Ok(UnreadPage {
            next_cursor: if more {
                items.last().map(|value| value.id)
            } else {
                None
            },
            items,
            through_sequence: through,
        })
    })
}
/// Immutable sequence pages use an exclusive before cursor. Missing or pruned
/// data is unavailable history, never evidence that no incident occurred.
pub(in crate::manage) fn list(
    directory: &Path,
    administrator_id: &str,
    query: &Query,
) -> io::Result<Page> {
    if !(1..=MAX_PAGE).contains(&query.limit)
        || query.before.is_some_and(|n| !positive(n))
        || query.episode_id.is_some_and(|n| !positive(n))
        || query.origin_node_id.as_ref().is_some_and(|n| !valid_id(n))
    {
        return Err(Error::Invalid.error());
    }
    read(directory, administrator_id, |connection, node| {
        let s = state(connection)?;
        let mut statement=connection.prepare("SELECT sequence,episode_id,origin_node_id,administrator_id,payload FROM alert_events WHERE (?1 IS NULL OR sequence<?1) AND (?2 IS NULL OR origin_node_id=?2) AND (?3 IS NULL OR episode_id=?3) ORDER BY sequence DESC LIMIT ?4").map_err(|e|sql_error("cannot prepare alert event page",e))?;
        let rows = statement
            .query_map(
                params![
                    query.before.map(sql).transpose()?,
                    query.origin_node_id,
                    query.episode_id.map(sql).transpose()?,
                    i64::from(query.limit) + 1
                ],
                event_row,
            )
            .map_err(|e| sql_error("cannot read alert event page", e))?;
        let mut items = Vec::new();
        for row in rows {
            let e = event_value(row.map_err(|e| sql_error("cannot decode alert event page", e))?)?;
            if e.observer_node_id != node || e.sequence > s.last || e.sequence <= s.trimmed {
                return Err(corrupt());
            }
            items.push(e)
        }
        let more = items.len() > query.limit as usize;
        items.truncate(query.limit as usize);
        let next_cursor = if more {
            items.last().map(|e| e.sequence)
        } else {
            None
        };
        let oldest = oldest(connection)?;
        Ok(Page {
            items,
            next_cursor,
            oldest_event_sequence: oldest,
            trimmed: s.trimmed,
        })
    })
}
fn oldest(connection: &Connection) -> io::Result<Option<u64>> {
    connection
        .query_row("SELECT min(sequence) FROM alert_events", [], |r| {
            optional_unsigned(r.get(0)?, 0)
        })
        .map_err(|e| sql_error("cannot inspect alert event retention", e))
}

/// Internal forward page in the caller's existing snapshot. Notification
/// cursors advance only after receiver acceptance; retention gaps stay explicit.
/// This read never authorizes remote access or exposes historical commands.
pub(in crate::manage) fn notification_page(
    connection: &Connection,
    after: u64,
) -> io::Result<(u64, u64, Vec<Event>)> {
    let node = require(connection)?;
    let s = state(connection)?;
    if after > s.last {
        return Err(corrupt());
    }
    let mut statement = connection.prepare("SELECT sequence,episode_id,origin_node_id,administrator_id,payload FROM alert_events WHERE sequence>?1 ORDER BY sequence LIMIT 16")
        .map_err(|e| sql_error("cannot prepare webhook events", e))?;
    let rows = statement
        .query_map([sql(after)?], event_row)
        .map_err(|e| sql_error("cannot read webhook events", e))?;
    let mut items = Vec::new();
    let mut previous = after.max(s.trimmed);
    for row in rows {
        let event = event_value(row.map_err(|e| sql_error("cannot decode webhook event", e))?)?;
        if event.observer_node_id != node
            || previous.checked_add(1) != Some(event.sequence)
            || event.sequence > s.last
        {
            return Err(corrupt());
        }
        previous = event.sequence;
        items.push(event);
    }
    if items.is_empty() && previous != s.last {
        return Err(corrupt());
    }
    Ok((s.last, s.trimmed, items))
}

/// Configuration skips only to the journal's declared watermark. Disabling
/// delivery must not depend on decoding old event bodies that may be damaged.
pub(in crate::manage) fn notification_watermark(connection: &Connection) -> io::Result<u64> {
    require(connection)?;
    Ok(state(connection)?.last)
}
/// Counts describe retained records, never live health or listener readiness.
pub(in crate::manage) fn summary(directory: &Path, administrator_id: &str) -> io::Result<Summary> {
    read(directory, administrator_id, |connection, node| {
        let s = state(connection)?;
        let (active,closed,events,unack):(u32,u32,u32,u32)=connection.query_row("SELECT (SELECT count(*) FROM alert_episodes WHERE status='active'),(SELECT count(*) FROM alert_episodes WHERE status<>'active'),(SELECT count(*) FROM alert_events),(SELECT count(*) FROM alert_episodes WHERE ack_sequence IS NULL OR ack_sequence<>transition_sequence)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(|e|sql_error("cannot inspect alert history summary",e))?;
        if active as usize > active_limit(connection)?
            || closed as usize > MAX_CLOSED
            || events as usize > MAX_EVENTS
            || unack > active + closed
            || s.trimmed.checked_add(u64::from(events)) != Some(s.last)
        {
            return Err(corrupt());
        }
        Ok(Summary {
            observer_node_id: node.to_owned(),
            active_count: active,
            closed_count: closed,
            event_count: events,
            unacknowledged_count: unack,
            oldest_event_sequence: oldest(connection)?,
            trimmed: s.trimmed,
            #[cfg(test)]
            last_event_sequence: s.last,
        })
    })
}

fn validate_observation(o: &Observation) -> io::Result<()> {
    if o.incident_id == 0
        || !valid_id(&o.origin_node_id)
        || o.resource_id.as_ref().is_some_and(|v| !valid_id(v))
        || o.slot.len() > 96
        || !o.slot.is_ascii()
    {
        return Err(Error::Invalid.error());
    }
    let code = o.code.as_str();
    let imported = source_slot(&o.slot);
    let slot = if imported {
        match o.kind {
            Kind::EgressCheck => "bind",
            Kind::HealthCatalog => "catalog",
            Kind::ManagementHttps => match code {
                "https_identity_metadata_unavailable" => "metadata",
                "acme_attempt_unavailable" | "acme_review_required" => "attempt",
                "acme_worker_stopped" => "worker",
                _ => "certificate",
            },
            Kind::NodeTls | Kind::ProxyTls if code.ends_with("_metadata_unavailable") => "metadata",
            Kind::NodeTls | Kind::ProxyTls => "certificate",
            Kind::Policy if matches!(code, "proxy_drain_failed" | "proxy_drain_interrupted") => {
                "runtime"
            }
            Kind::Policy => "policy",
            Kind::TrafficCheckpoint => "checkpoint",
            Kind::TrafficContinuity => match code {
                "traffic_loss_possible" => "loss",
                "traffic_history_gap" => "history",
                "traffic_time_uncertain" => "time",
                _ => "",
            },
            Kind::RemoteTraffic | Kind::RemoteJob | Kind::RemoteObservation => "",
        }
    } else {
        o.slot.as_str()
    };
    let valid = match o.kind {
        Kind::EgressCheck => {
            o.resource_id.is_some()
                && match o.check {
                    Some(CheckKind::Bind) => o.target.is_none() && slot == "bind",
                    Some(CheckKind::Tcp) => o.target.is_some_and(|v| {
                        v.port() != 0
                            && crate::access::routing::valid_ip(v.ip())
                            && !matches!(v,SocketAddr::V6(a) if a.scope_id()!=0||a.flowinfo()!=0)
                    }) && o
                        .target
                        .is_some_and(|v| imported || o.slot == format!("tcp:{v}")),
                    None => false,
                }
                && matches!(
                    code,
                    "egress_address_unavailable"
                        | "egress_connection_refused"
                        | "egress_timed_out"
                        | "egress_permission_denied"
                        | "egress_network_unreachable"
                        | "egress_failed"
                        | "egress_family_mismatch"
                )
        }
        Kind::HealthCatalog => {
            o.resource_id.is_none()
                && slot == "catalog"
                && matches!(code, "health_catalog_unavailable" | "health_catalog_stale")
        }
        Kind::ManagementHttps => {
            o.resource_id.is_none()
                && match slot {
                    "certificate" => matches!(
                        code,
                        "https_identity_unavailable"
                            | "https_identity_expiring"
                            | "https_identity_expired"
                            | "https_identity_not_yet_valid"
                    ),
                    "metadata" => code == "https_identity_metadata_unavailable",
                    "attempt" => {
                        matches!(code, "acme_attempt_unavailable" | "acme_review_required")
                    }
                    "worker" => code == "acme_worker_stopped",
                    _ => false,
                }
        }
        Kind::NodeTls => {
            o.resource_id.is_none()
                && match slot {
                    "certificate" => matches!(
                        code,
                        "node_tls_identity_unavailable"
                            | "node_tls_identity_expiring"
                            | "node_tls_identity_expired"
                            | "node_tls_identity_not_yet_valid"
                    ),
                    "metadata" => code == "node_tls_identity_metadata_unavailable",
                    _ => false,
                }
        }
        Kind::ProxyTls => {
            o.resource_id.is_some()
                && match slot {
                    "certificate" => matches!(
                        code,
                        "proxy_tls_identity_unavailable"
                            | "proxy_tls_identity_expiring"
                            | "proxy_tls_identity_expired"
                            | "proxy_tls_identity_not_yet_valid"
                    ),
                    "metadata" => code == "proxy_tls_identity_metadata_unavailable",
                    _ => false,
                }
        }
        Kind::Policy => {
            o.resource_id.is_none()
                && match slot {
                    "policy" => matches!(
                        code,
                        "proxy_not_running"
                            | "policy_publication_unavailable"
                            | "policy_not_applied"
                    ),
                    "runtime" => matches!(code, "proxy_drain_failed" | "proxy_drain_interrupted"),
                    _ => false,
                }
        }
        Kind::TrafficCheckpoint => {
            o.resource_id.is_none()
                && slot == "checkpoint"
                && matches!(
                    code,
                    "traffic_checkpoint_failed" | "traffic_checkpoint_stale"
                )
        }
        Kind::TrafficContinuity => {
            o.resource_id.is_none()
                && matches!(
                    (slot, code),
                    ("loss", "traffic_loss_possible")
                        | ("history", "traffic_history_gap")
                        | ("time", "traffic_time_uncertain")
                )
        }
        Kind::RemoteTraffic => {
            o.resource_id.is_none()
                && slot == "traffic"
                && matches!(
                    code,
                    "remote_traffic_continuity_error"
                        | "remote_traffic_not_authorized"
                        | "remote_collector_unavailable"
                        | "remote_traffic_unsupported"
                        | "remote_traffic_unavailable"
                        | "remote_traffic_stale"
                )
        }
        Kind::RemoteJob => {
            o.resource_id.is_some()
                && slot == "job"
                && matches!(code, "remote_job_blocked" | "remote_job_rejected")
        }
        Kind::RemoteObservation => {
            o.resource_id.is_none()
                && slot == "operations"
                && matches!(
                    code,
                    "remote_observation_unavailable"
                        | "remote_observation_unsupported"
                        | "remote_observation_not_authorized"
                        | "remote_observation_stale"
                        | "remote_observation_incomplete"
                        | "remote_observation_capacity"
                        | "remote_observation_pending"
                        | "remote_observation_changed"
                )
        }
    };
    if !valid || o.kind != Kind::EgressCheck && (o.check.is_some() || o.target.is_some()) {
        return Err(Error::Invalid.error());
    }
    encode(o).map(|_| ())
}
fn observer(observation: &Observation, node: &str) -> bool {
    match observation.kind {
        Kind::RemoteTraffic | Kind::RemoteJob => true,
        Kind::RemoteObservation => observation.origin_node_id != node,
        _ if observation.origin_node_id != node => source_slot(&observation.slot),
        _ => !source_slot(&observation.slot),
    }
}
fn validate_episode(e: &Episode) -> io::Result<()> {
    validate_observation(&e.observation).map_err(|_| corrupt())?;
    if !positive(e.id)
        || !positive(e.last_transition_sequence)
        || e.last_transition_sequence < e.id
        || !valid_id(&e.observer_node_id)
        || !valid_id(&e.boot_id)
        || !observer(&e.observation, &e.observer_node_id)
        || (e.status == Status::Unmonitored) != e.ended_reason.is_some()
        || e.status == Status::Active && e.ended_at_unix_ms.is_some()
    {
        return Err(corrupt());
    }
    if let Some(a) = &e.acknowledgement
        && (!positive(a.transition_sequence)
            || a.transition_sequence < e.id
            || a.transition_sequence > e.last_transition_sequence
            || !positive(a.event_sequence)
            || a.event_sequence <= a.transition_sequence
            || !valid_id(&a.administrator_id))
    {
        return Err(corrupt());
    }
    if e.is_acknowledged
        != e.acknowledgement
            .as_ref()
            .is_some_and(|a| a.transition_sequence == e.last_transition_sequence)
    {
        return Err(corrupt());
    }
    Ok(())
}
fn validate_event(e: &Event) -> io::Result<()> {
    validate_observation(&e.observation).map_err(|_| corrupt())?;
    if !positive(e.sequence)
        || !positive(e.episode_id)
        || !positive(e.transition_sequence)
        || e.episode_id > e.transition_sequence
        || e.transition_sequence > e.sequence
        || !valid_id(&e.observer_node_id)
        || !valid_id(&e.boot_id)
        || !observer(&e.observation, &e.observer_node_id)
    {
        return Err(corrupt());
    }
    if e.kind == EventKind::Acknowledged {
        if e.administrator_id.as_ref().is_none_or(|a| !valid_id(a))
            || e.transition_sequence >= e.sequence
            || e.ended_reason.is_some()
        {
            return Err(corrupt());
        }
    } else if e.administrator_id.is_some()
        || e.transition_sequence != e.sequence
        || (e.kind == EventKind::Unmonitored) != e.ended_reason.is_some()
    {
        return Err(corrupt());
    }
    if e.kind == EventKind::Opened && e.sequence != e.episode_id {
        return Err(corrupt());
    }
    Ok(())
}

/// Cold backup/migration validation. Payloads and relation counts are bounded;
/// pruning an episode does not erase its retained immutable events, and pruning
/// an event does not invalidate a still-retained projection or acknowledgement.
pub(in crate::manage) fn validate_snapshot(connection: &Connection) -> io::Result<()> {
    let node = require(connection)?;
    let schema = version(connection)?;
    let s = state(connection)?;
    let episodes = episodes(connection, None)?;
    let mut retained = BTreeMap::new();
    for e in episodes {
        check_version(schema, &e.observation, &node)?;
        if e.observer_node_id != node
            || e.id > s.last
            || e.last_transition_sequence > s.last
            || e.acknowledgement
                .as_ref()
                .is_some_and(|a| a.event_sequence > s.last)
            || e.status == Status::Active
                && (s.boot.as_deref() != Some(e.boot_id.as_str())
                    || e.observation.incident_id > s.incident)
        {
            return Err(corrupt());
        }
        if let Some(a) = &e.acknowledgement {
            administrator(connection, &a.administrator_id).map_err(|_| corrupt())?
        }
        retained.insert(e.id, e);
    }
    let bad_actor:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM alert_events e LEFT JOIN administrators a ON a.id=e.administrator_id WHERE e.administrator_id IS NOT NULL AND a.id IS NULL) OR EXISTS(SELECT 1 FROM alert_episodes e LEFT JOIN administrators a ON a.id=e.ack_administrator_id WHERE e.ack_administrator_id IS NOT NULL AND a.id IS NULL)",[],|r|r.get(0)).map_err(|e|sql_error("cannot validate alert history actors",e))?;
    if bad_actor {
        return Err(corrupt());
    }
    // Check references in both directions. Iterating events alone misses a
    // forged projection that points at another otherwise valid episode's event.
    // Only an event below the explicit retained window may be absent.
    for p in retained.values() {
        if p.last_transition_sequence > s.trimmed {
            let e = find_event(connection, p.last_transition_sequence)?.ok_or_else(corrupt)?;
            let kind = match p.status {
                Status::Active => {
                    if p.id == p.last_transition_sequence {
                        EventKind::Opened
                    } else {
                        EventKind::ReasonChanged
                    }
                }
                Status::Recovered => EventKind::Recovered,
                Status::Unmonitored => EventKind::Unmonitored,
            };
            if e.episode_id != p.id
                || e.boot_id != p.boot_id
                || e.observer_node_id != p.observer_node_id
                || e.kind != kind
                || e.transition_sequence != p.last_transition_sequence
                || e.observation != p.observation
                || e.ended_reason != p.ended_reason
                || p.status != Status::Active && e.observed_at_unix_ms != p.ended_at_unix_ms
            {
                return Err(corrupt());
            }
        }
        if let Some(a) = &p.acknowledgement
            && a.event_sequence > s.trimmed
        {
            let e = find_event(connection, a.event_sequence)?.ok_or_else(corrupt)?;
            if e.episode_id != p.id
                || e.boot_id != p.boot_id
                || e.observer_node_id != p.observer_node_id
                || e.kind != EventKind::Acknowledged
                || e.transition_sequence != a.transition_sequence
                || e.administrator_id.as_deref() != Some(a.administrator_id.as_str())
                || e.observed_at_unix_ms != a.observed_at_unix_ms
                || !same_subject(&e.observation, &p.observation)
            {
                return Err(corrupt());
            }
            if a.transition_sequence > s.trimmed {
                let transition =
                    find_event(connection, a.transition_sequence)?.ok_or_else(corrupt)?;
                if transition.episode_id != p.id
                    || transition.boot_id != p.boot_id
                    || transition.observer_node_id != p.observer_node_id
                    || transition.kind == EventKind::Acknowledged
                    || transition.observation != e.observation
                {
                    return Err(corrupt());
                }
            }
        }
    }
    let mut statement=connection.prepare("SELECT sequence,episode_id,origin_node_id,administrator_id,payload FROM alert_events ORDER BY sequence LIMIT ?1").map_err(|e|sql_error("cannot inspect alert history events",e))?;
    let rows = statement
        .query_map([(MAX_EVENTS + 1) as i64], event_row)
        .map_err(|e| sql_error("cannot validate alert history events", e))?;
    let mut count = 0usize;
    let mut expected = s.trimmed.checked_add(1).ok_or_else(corrupt)?;
    for row in rows {
        count += 1;
        if count > MAX_EVENTS {
            return Err(corrupt());
        }
        let e = event_value(row.map_err(|e| sql_error("cannot decode alert history events", e))?)?;
        check_version(schema, &e.observation, &node)?;
        if e.observer_node_id != node || e.sequence != expected || e.sequence > s.last {
            return Err(corrupt());
        }
        expected = expected.checked_add(1).ok_or_else(corrupt)?;
        if let Some(p) = retained.get(&e.episode_id) {
            if p.boot_id != e.boot_id || !same_subject(&p.observation, &e.observation) {
                return Err(corrupt());
            }
            if p.last_transition_sequence == e.sequence {
                let expected_kind = match p.status {
                    Status::Active => {
                        if p.id == e.sequence {
                            EventKind::Opened
                        } else {
                            EventKind::ReasonChanged
                        }
                    }
                    Status::Recovered => EventKind::Recovered,
                    Status::Unmonitored => EventKind::Unmonitored,
                };
                if e.kind != expected_kind
                    || e.observation != p.observation
                    || e.ended_reason != p.ended_reason
                {
                    return Err(corrupt());
                }
            }
            if let Some(a) = &p.acknowledgement
                && a.event_sequence == e.sequence
                && (e.kind != EventKind::Acknowledged
                    || e.transition_sequence != a.transition_sequence
                    || e.administrator_id.as_deref() != Some(a.administrator_id.as_str())
                    || e.observed_at_unix_ms != a.observed_at_unix_ms)
            {
                return Err(corrupt());
            }
        }
    }
    if s.trimmed.checked_add(count as u64) != Some(s.last) {
        return Err(corrupt());
    }
    Ok(())
}

/// Include bounded public identities when generating disjoint recovered IDs;
/// event/episode integer sequences are not node-identity namespaces.
pub(in crate::manage) fn collect_source_ids(
    connection: &Connection,
    ids: &mut HashSet<String>,
) -> io::Result<()> {
    validate_snapshot(connection)?;
    let s = state(connection)?;
    ids.extend(s.boot);
    for e in episodes(connection, None)? {
        ids.extend([e.observer_node_id, e.boot_id, e.observation.origin_node_id]);
        ids.extend(e.observation.resource_id);
        ids.extend(source_boot(&e.observation.slot).map(str::to_owned));
        if let Some(a) = e.acknowledgement {
            ids.insert(a.administrator_id);
        }
    }
    let mut statement=connection.prepare("SELECT sequence,episode_id,origin_node_id,administrator_id,payload FROM alert_events ORDER BY sequence LIMIT ?1").map_err(|e|sql_error("cannot inspect alert history identities",e))?;
    let rows = statement
        .query_map([MAX_EVENTS as i64], event_row)
        .map_err(|e| sql_error("cannot read alert history identities", e))?;
    for row in rows {
        let e =
            event_value(row.map_err(|e| sql_error("cannot decode alert history identities", e))?)?;
        ids.extend([e.observer_node_id, e.boot_id, e.observation.origin_node_id]);
        ids.extend(e.observation.resource_id);
        ids.extend(source_boot(&e.observation.slot).map(str::to_owned));
        ids.extend(e.administrator_id);
    }
    Ok(())
}

/// New-identity restoration may not import observations, acknowledgements or a
/// monitor generation. This is also the pure preflight for legacy test fixtures.
pub(in crate::manage) fn require_empty(connection: &Connection) -> io::Result<()> {
    let s = state(connection)?;
    let empty:bool=connection.query_row("SELECT NOT EXISTS(SELECT 1 FROM alert_events) AND NOT EXISTS(SELECT 1 FROM alert_episodes)",[],|r|r.get(0)).map_err(|e|sql_error("cannot inspect empty alert history",e))?;
    if !empty
        || s.last != 0
        || s.trimmed != 0
        || s.boot.is_some()
        || s.batch != 0
        || s.incident != 0
    {
        return Err(corrupt());
    }
    Ok(())
}
#[cfg(test)]
pub(in crate::manage) fn ensure_unused_for_test(connection: &Connection) -> io::Result<()> {
    let count:i64=connection.query_row("SELECT count(*) FROM sqlite_schema WHERE name IN('alert_history_state','alert_episodes','alert_events')",[],|r|r.get(0)).map_err(|e|sql_error("cannot inspect legacy alert fixture",e))?;
    if count == 0 {
        return Ok(());
    }
    if count != 3 {
        return Err(corrupt());
    }
    require_empty(connection)
}
#[cfg(test)]
pub(in crate::manage) fn remove_schema_for_test(connection: &Connection) -> io::Result<()> {
    ensure_unused_for_test(connection)?;
    connection.execute_batch("DROP TABLE IF EXISTS alert_events; DROP TABLE IF EXISTS alert_episodes; DROP TABLE IF EXISTS alert_history_state;").map_err(|e|sql_error("cannot reconstruct pre-event fixture",e))
}

#[cfg(test)]
pub(in crate::manage) fn require_legacy_for_test(connection: &Connection) -> io::Result<()> {
    validate_snapshot(connection)?;
    let node = require(connection)?;
    let s = state(connection)?;
    if s.first
        .zip(s.end)
        .is_some_and(|(first, last)| last - first + 1 > (MAX_LOCAL * 2) as u64)
    {
        return Err(corrupt());
    }
    let episodes = episodes(connection, None)?;
    if episodes
        .iter()
        .filter(|episode| episode.status == Status::Active)
        .count()
        > MAX_LOCAL
    {
        return Err(corrupt());
    }
    for episode in episodes {
        check_version(21, &episode.observation, &node)?;
    }
    let mut statement=connection.prepare("SELECT sequence,episode_id,origin_node_id,administrator_id,payload FROM alert_events ORDER BY sequence LIMIT ?1").map_err(|error|sql_error("cannot inspect legacy event compatibility",error))?;
    let rows = statement
        .query_map([MAX_EVENTS as i64], event_row)
        .map_err(|error| sql_error("cannot read legacy event compatibility", error))?;
    for row in rows {
        let event = event_value(
            row.map_err(|error| sql_error("cannot decode legacy event compatibility", error))?,
        )?;
        check_version(21, &event.observation, &node)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::store::{self, random_id, update_lock};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    mod guarded {
        use super::*;
        use crate::manage::observations::Proof;

        fn peer(f: &Fixture) -> io::Result<(String, Arc<Proof>, Binding)> {
            let id = random_id()?;
            let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .map_err(io::Error::other)?;
            let leaf: Arc<[u8]> = Arc::from(certificate.cert.der().as_ref());
            store::register_peer(&f.directory, &id, "source", &leaf, "localhost", None)?;
            store::targets::configure(
                &f.directory,
                &f.administrator,
                &id,
                None,
                "https://localhost:9443",
                true,
                None,
            )?;
            let proof = Arc::new(Proof {
                target_revision: 1,
                authorization: store::RemoteAuthorization {
                    node_id: id.clone(),
                    authorization_revision: 1,
                    leaf,
                },
            });
            let binding = Binding {
                peer_id: id.clone(),
                target_revision: 1,
                authorization_revision: 1,
                active: true,
                retired: false,
                rollback: false,
                peer_active: true,
            };
            Ok((id, proof, binding))
        }

        #[test]
        fn foreign_record_and_no_event_publication_revalidate_the_same_directory_binding()
        -> io::Result<()> {
            let f = Fixture::new()?;
            let (peer, proof, binding) = peer(&f)?;
            f.start()?;
            let remote_boot = random_id()?;
            let mut observation = f.observation(1);
            observation.origin_node_id = peer.clone();
            observation.slot = format!("source:{remote_boot}:1");
            let batch = f.batch(1, TransitionKind::Opened, observation.clone());
            assert_eq!(source_boot(&observation.slot), Some(remote_boot.as_str()));
            assert!(
                f.record(&batch).is_err(),
                "plain local record cannot import a peer"
            );
            {
                let gate = update_lock(&f.directory)?;
                record_guarded(
                    &f.directory,
                    &gate,
                    &batch,
                    std::slice::from_ref(&proof),
                    std::slice::from_ref(&binding),
                )?;
                let called = std::cell::Cell::new(false);
                publish_guarded(
                    &f.directory,
                    &gate,
                    std::slice::from_ref(&proof),
                    std::slice::from_ref(&binding),
                    || {
                        called.set(true);
                        Ok(())
                    },
                )?;
                assert!(called.get());
            }
            let mut ids = HashSet::new();
            collect_source_ids(&f.connection()?, &mut ids)?;
            assert!(ids.contains(&remote_boot));
            assert_eq!(f.episode(1)?.observation.origin_node_id, peer);
            let before = summary(&f.directory, &f.administrator)?.last_event_sequence;
            store::set_peer_active(&f.directory, &peer, 1, false)?;
            let called = std::cell::Cell::new(false);
            {
                let gate = update_lock(&f.directory)?;
                let rejected = publish_guarded(
                    &f.directory,
                    &gate,
                    std::slice::from_ref(&proof),
                    std::slice::from_ref(&binding),
                    || {
                        called.set(true);
                        Ok(())
                    },
                )
                .unwrap_err();
                assert_eq!(
                    rejected.get_ref().and_then(|e| e.downcast_ref::<Error>()),
                    Some(&Error::Denied)
                );
                let recovery = f.batch(2, TransitionKind::Recovered, observation.clone());
                assert!(
                    record_guarded(
                        &f.directory,
                        &gate,
                        &recovery,
                        std::slice::from_ref(&proof),
                        std::slice::from_ref(&binding)
                    )
                    .is_err()
                );
            }
            assert!(!called.get());
            assert_eq!(
                summary(&f.directory, &f.administrator)?.last_event_sequence,
                before
            );
            let retired = Binding {
                authorization_revision: 2,
                peer_active: false,
                ..binding
            };
            let terminal = f.batch(2, TransitionKind::Unmonitored, observation);
            record_guarded(
                &f.directory,
                &update_lock(&f.directory)?,
                &terminal,
                &[],
                &[retired],
            )?;
            assert_eq!(f.episode(1)?.status, Status::Unmonitored);
            validate_snapshot(&f.connection()?)?;
            Ok(())
        }

        #[test]
        fn real_twenty_one_keeps_original_event_ack_and_batch_limit_through_upgrade()
        -> io::Result<()> {
            for collision in [false, true] {
                let f = Fixture::new()?;
                f.start()?;
                f.record(&f.batch(1, TransitionKind::Opened, f.observation(1)))?;
                f.ack(1, 1)?;
                let connection = f.connection()?;
                store::recovery::restore_schema_twenty_one_for_test(&connection)?;
                assert_eq!(store::inspect(&f.directory)?.schema_version, 21);
                let rows = |connection: &Connection| -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
                    connection.query_row("SELECT (SELECT payload FROM alert_events WHERE sequence=1),(SELECT payload FROM alert_events WHERE sequence=2),(SELECT payload FROM alert_episodes WHERE id=1)",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).map_err(io::Error::other)
                };
                let original = rows(&connection)?;
                let original_state = state(&connection)?;
                let mut too_large = f.batch(2, TransitionKind::ReasonChanged, f.observation(1));
                too_large.transitions = vec![too_large.transitions[0].clone(); MAX_LOCAL * 2 + 1];
                assert!(receipt(&f.directory, &too_large).is_err());
                assert!(f.record(&too_large).is_err());
                assert_eq!(state(&connection)?.last, original_state.last);
                if collision {
                    connection.execute_batch("CREATE TABLE recovery_state_v22(sentinel TEXT); INSERT INTO recovery_state_v22 VALUES('operator material');").map_err(io::Error::other)?;
                }
                let copied = f.directory.join("before22.sqlite3");
                let migrated = store::migrate(&f.directory, &copied);
                assert_eq!(rows(&connection)?, original);
                let copied = Connection::open(copied).map_err(io::Error::other)?;
                assert_eq!(store::read_overview(&copied)?.schema_version, 21);
                assert_eq!(rows(&copied)?, original);
                if collision {
                    assert!(migrated.is_err());
                    assert_eq!(store::inspect(&f.directory)?.schema_version, 21);
                    let sentinel: String = connection
                        .query_row("SELECT sentinel FROM recovery_state_v22", [], |row| {
                            row.get(0)
                        })
                        .map_err(io::Error::other)?;
                    assert_eq!(sentinel, "operator material");
                } else {
                    assert_eq!(migrated?.schema_version, store::SCHEMA_VERSION);
                    let current = state(&connection)?;
                    assert_eq!(
                        (current.last, current.batch, current.digest),
                        (
                            original_state.last,
                            original_state.batch,
                            original_state.digest
                        )
                    );
                    assert!(f.episode(1)?.is_acknowledged);
                    validate_snapshot(&connection)?;
                }
            }
            Ok(())
        }
    }

    struct Fixture {
        directory: std::path::PathBuf,
        administrator: String,
        node: String,
        boot: String,
    }
    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory =
                std::env::temp_dir().join(format!("vproxy-alert-history-{}", random_id()?));
            let overview =
                store::initialize(&directory, "event fixture", "admin", "fixture PHC bytes")?;
            let connection = open_existing(&directory, false)?;
            let administrator = connection
                .query_row("SELECT id FROM administrators", [], |r| r.get(0))
                .map_err(io::Error::other)?;
            Ok(Self {
                directory,
                administrator,
                node: overview.node_id,
                boot: random_id()?,
            })
        }
        fn connection(&self) -> io::Result<Connection> {
            open_existing(&self.directory, true)
        }
        fn start(&self) -> io::Result<Commit> {
            start(&self.directory, &update_lock(&self.directory)?, &self.boot)
        }
        fn record(&self, batch: &Batch) -> io::Result<Commit> {
            record(&self.directory, &update_lock(&self.directory)?, batch)
        }
        fn observation(&self, id: u64) -> Observation {
            Observation {
                incident_id: id,
                kind: Kind::Policy,
                origin_node_id: self.node.clone(),
                resource_id: None,
                slot: "policy".into(),
                check: None,
                target: None,
                code: "proxy_not_running".into(),
                first_observed_at_unix_ms: Some(20),
                last_observed_at_unix_ms: Some(20),
                evidence_sequence: Some(u64::MAX),
            }
        }
        fn batch(&self, sequence: u64, kind: TransitionKind, observation: Observation) -> Batch {
            Batch {
                boot_id: self.boot.clone(),
                sequence,
                transitions: vec![Transition {
                    kind,
                    observation,
                    observed_at_unix_ms: Some(30),
                    ended_reason: (kind == TransitionKind::Unmonitored)
                        .then_some(EndReason::SourceUnmonitored),
                }],
            }
        }
        fn episode(&self, id: u64) -> io::Result<Episode> {
            episode(&self.directory, &self.administrator, id)?.ok_or_else(corrupt)
        }
        fn ack(&self, id: u64, transition: u64) -> io::Result<Episode> {
            acknowledge(
                &self.directory,
                &update_lock(&self.directory)?,
                &self.administrator,
                &Ack {
                    expected_node_id: self.node.clone(),
                    episode_id: id,
                    expected_transition_sequence: transition,
                },
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn unread_pages_and_bulk_acknowledgements_keep_a_finite_original_scope() -> io::Result<()> {
        let f = Fixture::new()?;
        f.start()?;
        let mut batch = f.batch(1, TransitionKind::Opened, f.observation(1));
        batch.transitions.clear();
        for id in 1..=33 {
            for kind in [TransitionKind::Opened, TransitionKind::Recovered] {
                batch.transitions.push(Transition {
                    kind,
                    observation: f.observation(id),
                    observed_at_unix_ms: Some(30),
                    ended_reason: None,
                });
            }
        }
        f.record(&batch)?;
        let first = unread(
            &f.directory,
            &f.administrator,
            &UnreadQuery {
                before: None,
                through: None,
            },
        )?;
        assert_eq!(first.items.len(), MAX_ACK_BATCH);
        assert_eq!(first.items[0].id, 65);
        assert_eq!(first.next_cursor, Some(3));
        assert_eq!(first.through_sequence, 66);
        f.record(&f.batch(2, TransitionKind::Opened, f.observation(34)))?;
        let inputs: Vec<_> = first
            .items
            .iter()
            .map(|value| Ack {
                expected_node_id: f.node.clone(),
                episode_id: value.id,
                expected_transition_sequence: value.last_transition_sequence,
            })
            .collect();
        let values = acknowledge_batch(
            &f.directory,
            &update_lock(&f.directory)?,
            &f.administrator,
            &inputs,
        )?;
        assert_eq!(values.len(), 32);
        assert!(
            values
                .iter()
                .all(|value| value.is_acknowledged && value.status == Status::Recovered)
        );
        let before = summary(&f.directory, &f.administrator)?;
        acknowledge_batch(
            &f.directory,
            &update_lock(&f.directory)?,
            &f.administrator,
            &inputs,
        )?;
        assert_eq!(
            summary(&f.directory, &f.administrator)?.last_event_sequence,
            before.last_event_sequence
        );
        let older = unread(
            &f.directory,
            &f.administrator,
            &UnreadQuery {
                before: first.next_cursor,
                through: Some(66),
            },
        )?;
        assert_eq!(older.items.len(), 1);
        assert_eq!(older.items[0].id, 1);
        assert!(older.next_cursor.is_none());
        let fresh = unread(
            &f.directory,
            &f.administrator,
            &UnreadQuery {
                before: None,
                through: None,
            },
        )?;
        assert_eq!(
            fresh.items.iter().map(|value| value.id).collect::<Vec<_>>(),
            [67, 1]
        );
        validate_snapshot(&f.connection()?)?;
        Ok(())
    }

    #[cfg(feature = "witness-journal")]
    #[test]
    fn source_ack_batch_keeps_partial_changes_inside_the_held_transaction() -> io::Result<()> {
        struct Budget;
        impl Checkpoints for Budget {
            fn checkpoint(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let f = Fixture::new()?;
        f.start()?;
        f.record(&f.batch(1, TransitionKind::Opened, f.observation(1)))?;
        let input = |id| Ack {
            expected_node_id: f.node.clone(),
            episode_id: id,
            expected_transition_sequence: id,
        };
        let mut connection = f.connection()?;
        {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(io::Error::other)?;
            let mut budget = Budget;
            let failed = Writer::Source {
                tx: &tx,
                checkpoints: &mut budget,
            }
            .acknowledge_batch(&f.administrator, &[input(1), input(99)]);
            assert_eq!(failed.unwrap_err().kind(), io::ErrorKind::NotFound);
            // The Source coordinator discards this entire held transaction on
            // failure, rather than confirming a partial acknowledgement intent.
        }
        assert!(!f.episode(1)?.is_acknowledged);
        assert_eq!(
            summary(&f.directory, &f.administrator)?.last_event_sequence,
            1
        );
        {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(io::Error::other)?;
            let mut budget = Budget;
            let values = Writer::Source {
                tx: &tx,
                checkpoints: &mut budget,
            }
            .acknowledge_batch(&f.administrator, &[input(1)])?;
            assert!(values[0].is_acknowledged);
            tx.commit().map_err(io::Error::other)?;
        }
        assert_eq!(f.episode(1)?.status, Status::Active);
        validate_snapshot(&connection)?;
        Ok(())
    }

    #[test]
    fn exact_batches_acknowledgements_and_restart_keep_distinct_evidence() -> io::Result<()> {
        let f = Fixture::new()?;
        assert_eq!(f.start()?.batch_sequence, 0);
        let mut observation = f.observation(u64::MAX);
        let first = f.batch(1, TransitionKind::Opened, observation.clone());
        assert!(receipt(&f.directory, &first)?.is_none());
        let committed = f.record(&first)?;
        assert_eq!(
            (
                committed.first_event_sequence,
                committed.last_event_sequence
            ),
            (Some(1), Some(1))
        );
        assert_eq!(f.record(&first)?, committed);
        assert_eq!(receipt(&f.directory, &first)?, Some(committed));
        assert!(f.ack(1, 1)?.is_acknowledged);
        assert_eq!(f.ack(1, 1)?.acknowledgement.unwrap().event_sequence, 2);
        observation.code = "policy_not_applied".into();
        observation.last_observed_at_unix_ms = Some(10); // clock rollback is informational
        let second = f.batch(2, TransitionKind::ReasonChanged, observation.clone());
        f.record(&second)?;
        let changed = f.episode(1)?;
        assert!(!changed.is_acknowledged);
        assert_eq!(changed.acknowledgement.unwrap().transition_sequence, 1);
        assert!(f.ack(1, 1).is_err());
        assert!(f.ack(1, 3)?.is_acknowledged);
        let mut substitution = second.clone();
        substitution.transitions[0].observation.code = "policy_publication_unavailable".into();
        assert!(f.record(&substitution).is_err());
        f.record(&f.batch(3, TransitionKind::Recovered, observation))?;
        assert_eq!(f.episode(1)?.status, Status::Recovered);
        assert!(!f.episode(1)?.is_acknowledged);
        let next_boot = random_id()?;
        start(&f.directory, &update_lock(&f.directory)?, &next_boot)?;
        let mut active = f.batch(1, TransitionKind::Opened, f.observation(1));
        active.boot_id = next_boot;
        let created = f.record(&active)?;
        let id = created.first_event_sequence.unwrap();
        start(&f.directory, &update_lock(&f.directory)?, &random_id()?)?;
        let ended = f.episode(id)?;
        assert_eq!(ended.status, Status::Unmonitored);
        assert_eq!(ended.ended_reason, Some(EndReason::MonitorRestarted));
        assert_eq!(ended.observation.last_observed_at_unix_ms, Some(20));
        assert!(receipt(&f.directory, &active).is_err());
        assert_eq!(f.episode(1)?.status, Status::Recovered);
        validate_snapshot(&f.connection()?)?;
        Ok(())
    }

    #[test]
    fn maximum_public_egress_metadata_fits_and_round_trips_with_acknowledgement() -> io::Result<()>
    {
        let f = Fixture::new()?;
        f.start()?;
        let target: SocketAddr = "[7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"
            .parse()
            .map_err(io::Error::other)?;
        let observation = Observation {
            kind: Kind::EgressCheck,
            resource_id: Some(random_id()?),
            slot: format!("tcp:{target}"),
            check: Some(CheckKind::Tcp),
            target: Some(target),
            code: "egress_address_unavailable".into(),
            first_observed_at_unix_ms: Some(u64::MAX),
            last_observed_at_unix_ms: Some(u64::MAX),
            ..f.observation(u64::MAX)
        };
        let high = i64::MAX as u64;
        let event = Event {
            sequence: high,
            observer_node_id: f.node.clone(),
            episode_id: high - 2,
            boot_id: f.boot.clone(),
            kind: EventKind::Acknowledged,
            observation: observation.clone(),
            observed_at_unix_ms: Some(u64::MAX),
            recorded_at_unix_ms: Some(u64::MAX),
            ended_reason: None,
            administrator_id: Some(f.administrator.clone()),
            transition_sequence: high - 1,
        };
        validate_event(&event)?;
        assert!(encode(&event)?.len() <= MAX_PAYLOAD);
        let projection = Episode {
            id: high - 2,
            observer_node_id: f.node.clone(),
            boot_id: f.boot.clone(),
            observation: observation.clone(),
            status: Status::Unmonitored,
            last_transition_sequence: high - 1,
            ended_at_unix_ms: Some(u64::MAX),
            ended_reason: Some(EndReason::SourceUnmonitored),
            acknowledgement: Some(Acknowledgement {
                transition_sequence: high - 1,
                administrator_id: f.administrator.clone(),
                observed_at_unix_ms: Some(u64::MAX),
                event_sequence: high,
            }),
            is_acknowledged: true,
        };
        validate_episode(&projection)?;
        assert!(encode(&projection)?.len() <= MAX_PAYLOAD);
        let remote_boot = random_id()?;
        let remote_peer = random_id()?;
        let mut imported_event = event.clone();
        imported_event.observation.origin_node_id = remote_peer.clone();
        imported_event.observation.slot = format!("source:{remote_boot}:{}", u64::MAX);
        validate_event(&imported_event)?;
        assert!(encode(&imported_event)?.len() <= MAX_PAYLOAD);
        let mut imported_projection = projection.clone();
        imported_projection.observation.origin_node_id = remote_peer;
        imported_projection.observation.slot = imported_event.observation.slot;
        validate_episode(&imported_projection)?;
        assert!(encode(&imported_projection)?.len() <= MAX_PAYLOAD);
        let mut batch = f.batch(1, TransitionKind::Opened, observation.clone());
        batch.transitions[0].observed_at_unix_ms = Some(u64::MAX);
        f.record(&batch)?;
        let acknowledged = f.ack(1, 1)?;
        assert!(acknowledged.is_acknowledged);
        assert_eq!(acknowledged.observation, observation);
        assert_eq!(
            get(&f.directory, &f.administrator, 2)?.unwrap().observation,
            observation
        );
        validate_snapshot(&f.connection()?)?;
        Ok(())
    }

    #[test]
    fn rejected_writes_and_statement_or_commit_failures_leave_no_partial_events() -> io::Result<()>
    {
        let f = Fixture::new()?;
        f.start()?;
        let mut batch = f.batch(1, TransitionKind::Opened, f.observation(2));
        batch.transitions.push(
            f.batch(1, TransitionKind::Opened, f.observation(1))
                .transitions
                .remove(0),
        );
        let connection = f.connection()?;
        connection.execute_batch("CREATE TRIGGER event_statement_failure BEFORE INSERT ON alert_events WHEN NEW.sequence=2 BEGIN SELECT RAISE(ABORT,'fixture'); END;").map_err(io::Error::other)?;
        assert!(f.record(&batch).is_err());
        assert!(receipt(&f.directory, &batch)?.is_none());
        assert_eq!(
            summary(&f.directory, &f.administrator)?.last_event_sequence,
            0
        );
        connection.execute_batch("DROP TRIGGER event_statement_failure; CREATE TABLE event_commit_failure(administrator_id TEXT REFERENCES administrators(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER event_deferred_failure AFTER INSERT ON alert_events BEGIN INSERT INTO event_commit_failure VALUES('AAAAAAAAAAAAAAAAAAAAAA'); END;").map_err(io::Error::other)?;
        assert!(f.record(&batch).is_err());
        assert!(receipt(&f.directory, &batch)?.is_none());
        let counts = summary(&f.directory, &f.administrator)?;
        assert_eq!(
            (counts.active_count, counts.closed_count, counts.event_count),
            (0, 0, 0)
        );
        connection
            .execute_batch("DROP TRIGGER event_deferred_failure; DROP TABLE event_commit_failure;")
            .map_err(io::Error::other)?;
        f.record(&batch)?;
        let id = 1;
        let input = Ack {
            expected_node_id: random_id()?,
            episode_id: id,
            expected_transition_sequence: 1,
        };
        assert!(
            acknowledge(
                &f.directory,
                &update_lock(&f.directory)?,
                &f.administrator,
                &input
            )
            .is_err()
        );
        let valid = Ack {
            expected_node_id: f.node.clone(),
            ..input
        };
        assert!(
            acknowledge(
                &f.directory,
                &update_lock(&f.directory)?,
                &random_id()?,
                &valid
            )
            .is_err()
        );
        assert_eq!(
            summary(&f.directory, &f.administrator)?.last_event_sequence,
            2
        );
        assert!(store::recovery::restore_schema_twenty_for_test(&connection).is_err());
        let mut changes = f.batch(2, TransitionKind::ReasonChanged, f.observation(2));
        changes.transitions[0].observation.code = "policy_not_applied".into();
        let mut other = changes.transitions[0].clone();
        other.observation.incident_id = 1;
        changes.transitions.push(other);
        f.record(&changes)?;
        let first = f.ack(1, 3)?;
        let second = f.ack(2, 4)?;
        // Both attacks keep canonical payload bytes and every indexed SQL column
        // coherent. The target event itself is valid, but belongs to episode B.
        let mut crossed = first.clone();
        crossed.last_transition_sequence = second.last_transition_sequence;
        crossed.is_acknowledged = false;
        save_episode(&connection, &crossed)?;
        assert!(validate_snapshot(&connection).is_err());
        save_episode(&connection, &first)?;
        let mut crossed = first.clone();
        let original_ack = crossed.acknowledgement.as_mut().unwrap();
        let other_ack = second.acknowledgement.as_ref().unwrap();
        original_ack.event_sequence = other_ack.event_sequence;
        original_ack.observed_at_unix_ms = other_ack.observed_at_unix_ms;
        save_episode(&connection, &crossed)?;
        assert!(validate_snapshot(&connection).is_err());
        save_episode(&connection, &first)?;
        let mut next = f.batch(3, TransitionKind::ReasonChanged, f.observation(2));
        next.transitions[0].observation.code = "policy_publication_unavailable".into();
        // Canonical but future references cannot be returned by an already-acked
        // shortcut or silently repaired when the next producer advances its counter.
        let mut future = first.clone();
        future.acknowledgement.as_mut().unwrap().event_sequence = 7;
        save_episode(&connection, &future)?;
        assert!(episode(&f.directory, &f.administrator, 1).is_err());
        assert!(f.ack(1, 3).is_err());
        assert!(f.record(&next).is_err());
        assert_eq!(find_episode(&connection, 1)?, Some(future));
        save_episode(&connection, &first)?;
        let mut future = first.clone();
        future.last_transition_sequence = 7;
        future.is_acknowledged = false;
        save_episode(&connection, &future)?;
        assert!(episode(&f.directory, &f.administrator, 1).is_err());
        assert!(f.record(&next).is_err());
        assert_eq!(find_episode(&connection, 1)?, Some(future));
        save_episode(&connection, &first)?;
        let mut future = find_event(&connection, 6)?.unwrap();
        future.sequence = 7;
        save_event(&connection, &future)?;
        assert!(get(&f.directory, &f.administrator, 7).is_err());
        connection
            .execute("DELETE FROM alert_events WHERE sequence=7", [])
            .map_err(io::Error::other)?;
        assert_eq!(state(&connection)?.last, 6);
        validate_snapshot(&connection)?;
        Ok(())
    }

    #[test]
    fn retention_is_bounded_and_never_reuses_pruned_sequence_or_incident_ids() -> io::Result<()> {
        let f = Fixture::new()?;
        f.start()?;
        // Synthetic distinct historical resources exercise the store's global
        // bound, not a claim that the live IPAM permits this many addresses.
        let observation = |id| Observation {
            kind: Kind::EgressCheck,
            resource_id: Some(URL_SAFE_NO_PAD.encode(u128::from(id).to_be_bytes())),
            slot: "bind".into(),
            check: Some(CheckKind::Bind),
            code: "egress_address_unavailable".into(),
            ..f.observation(id)
        };
        let mut batch = Batch {
            boot_id: f.boot.clone(),
            sequence: 1,
            transitions: Vec::with_capacity(MAX_BATCH),
        };
        for id in 1..=MAX_LOCAL as u64 {
            batch.transitions.push(Transition {
                kind: TransitionKind::Opened,
                observation: observation(id),
                observed_at_unix_ms: None,
                ended_reason: None,
            });
        }
        for id in 1..=MAX_LOCAL as u64 {
            batch.transitions.push(Transition {
                kind: TransitionKind::Unmonitored,
                observation: observation(id),
                observed_at_unix_ms: None,
                ended_reason: Some(EndReason::SourceUnmonitored),
            });
        }
        f.record(&batch)?;
        batch.sequence = 2;
        batch.transitions.clear();
        for id in MAX_LOCAL as u64 + 1..=(MAX_LOCAL * 2) as u64 {
            batch.transitions.push(Transition {
                kind: TransitionKind::Opened,
                observation: observation(id),
                observed_at_unix_ms: None,
                ended_reason: None,
            });
        }
        f.record(&batch)?;
        let counts = summary(&f.directory, &f.administrator)?;
        assert_eq!(
            (counts.active_count, counts.closed_count, counts.event_count),
            (6144, 4096, 16384)
        );
        assert_eq!(
            (
                counts.trimmed,
                counts.oldest_event_sequence,
                counts.last_event_sequence
            ),
            (2048, Some(2049), 18432)
        );
        let page = list(
            &f.directory,
            &f.administrator,
            &Query {
                before: None,
                limit: 2,
                origin_node_id: Some(f.node.clone()),
                episode_id: None,
            },
        )?;
        assert_eq!(
            page.items.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            vec![18432, 18431]
        );
        assert_eq!(page.next_cursor, Some(18431));
        assert!(get(&f.directory, &f.administrator, 1)?.is_none());
        assert!(episode(&f.directory, &f.administrator, 1)?.is_none());
        assert!(
            f.record(&f.batch(3, TransitionKind::Opened, observation(1)))
                .is_err()
        );
        assert_eq!(
            summary(&f.directory, &f.administrator)?.last_event_sequence,
            18432
        );
        validate_snapshot(&f.connection()?)?;
        Ok(())
    }

    #[test]
    fn real_twenty_upgrade_preserves_issued_controller_history_and_rolls_back_conflicts()
    -> io::Result<()> {
        for collision in [false, true] {
            let f = Fixture::new()?;
            let connection = f.connection()?;
            store::recovery::restore_schema_twenty_for_test(&connection)?;
            let peer = random_id()?;
            store::register_peer(
                &f.directory,
                &peer,
                "legacy child",
                b"public event migration fixture",
                "child.example",
                None,
            )?;
            store::targets::configure(
                &f.directory,
                &f.administrator,
                &peer,
                None,
                "https://child.example",
                true,
                None,
            )?;
            store::targets::observe(&f.directory, &peer, 1, 2, 0, 1)?;
            let job = store::targets::enqueue(
                &f.directory,
                &f.administrator,
                1,
                store::Command {
                    target_node_id: peer.clone(),
                    epoch: 2,
                    command_id: 1,
                    expected_policy_revision: 1,
                    source_administrator_id: f.administrator.clone(),
                    change: store::PolicyChange::CreateUser {
                        name: "legacy intent".into(),
                        protocols: vec![],
                        concurrent_limit: 1,
                    },
                },
            )?;
            let before:(Vec<u8>,Vec<u8>,i64)=connection.query_row("SELECT (SELECT command FROM control_outbox),(SELECT snapshot FROM controller_history),(SELECT last_sequence FROM controller_history_state)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(io::Error::other)?;
            if collision {
                connection.execute_batch("CREATE TABLE recovery_state_v21(sentinel TEXT); INSERT INTO recovery_state_v21 VALUES('operator material');").map_err(io::Error::other)?;
            }
            let backup = f.directory.join("schema20-before-events.sqlite3");
            let migrated = store::migrate(&f.directory, &backup);
            let after:(Vec<u8>,Vec<u8>,i64)=connection.query_row("SELECT (SELECT command FROM control_outbox),(SELECT snapshot FROM controller_history),(SELECT last_sequence FROM controller_history_state)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(io::Error::other)?;
            assert_eq!(after, before);
            assert_eq!(
                store::targets::history::get(&f.directory, &f.administrator, &peer, &job.job_id)?
                    .unwrap()
                    .sequence,
                1
            );
            if collision {
                assert!(migrated.is_err());
                assert_eq!(store::inspect(&f.directory)?.schema_version, 20);
                let s: String = connection
                    .query_row("SELECT sentinel FROM recovery_state_v21", [], |r| r.get(0))
                    .map_err(io::Error::other)?;
                assert_eq!(s, "operator material");
            } else {
                assert_eq!(migrated?.schema_version, store::SCHEMA_VERSION);
                require_empty(&connection)?;
                validate_snapshot(&connection)?;
            }
            let copied = Connection::open(backup).map_err(io::Error::other)?;
            assert_eq!(store::read_overview(&copied)?.schema_version, 20);
            assert!(copied.prepare("SELECT * FROM alert_events").is_err());
        }
        Ok(())
    }
}
