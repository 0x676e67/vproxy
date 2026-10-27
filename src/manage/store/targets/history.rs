//! Bounded controller-local results, separate from the executable outbox.
//!
//! Only public identifiers and a closed Job projection are retained. No command
//! bytes, names, credentials or returned secrets enter this namespace. A missing
//! row is not evidence that the remote mutation never ran.

use std::{
    collections::{BTreeMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use super::*;

const PER_PEER: usize = 128;
const MAX_ROWS: usize = PER_PEER * MAX_TARGETS as usize;
const MAX_SNAPSHOT: usize = 4_096;
const COLUMNS: &str = "sequence,controller_node_id,administrator_id,protocol_version,action,snapshot,user_id,credential_id,imported,recorded_at,updated_at,trimmed_count,peer_id,job_id";

/// A durable result identity, not authority to retry or regain a one-time secret.
pub(in crate::manage) struct StoredEntry {
    /// Node-wide issuance order, never reused after peer-window pruning.
    pub(in crate::manage) sequence: u64,
    pub(in crate::manage) controller_node_id: String,
    pub(in crate::manage) administrator_id: String,
    pub(in crate::manage) protocol_version: u8,
    pub(in crate::manage) action: String,
    pub(in crate::manage) job: Job,
    pub(in crate::manage) user_id: Option<String>,
    pub(in crate::manage) credential_id: Option<String>,
    pub(in crate::manage) imported: bool,
    /// Local wall time is informational; it never orders or authorizes work.
    pub(in crate::manage) recorded_at_unix_s: Option<u64>,
    pub(in crate::manage) updated_at_unix_s: Option<u64>,
}

/// Descending global sequence within one peer. Retention metadata describes the
/// whole retained peer window, not only this page or a coherent remote snapshot.
pub(in crate::manage) struct Page {
    pub(in crate::manage) items: Vec<StoredEntry>,
    pub(in crate::manage) next_cursor: Option<u64>,
    pub(in crate::manage) oldest_sequence: Option<u64>,
    /// Cumulative peer-window removals, carried by its newest retained row.
    pub(in crate::manage) trimmed: u64,
}

/// Create an unused namespace in initialization or an explicit migration's
/// existing transaction. Existing objects are never replaced or repaired.
pub(in crate::manage) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection.execute_batch(
        "CREATE TABLE controller_history_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            last_sequence INTEGER NOT NULL CHECK(last_sequence>=0)
         ) STRICT;
         INSERT INTO controller_history_state(singleton,last_sequence) VALUES(1,0);
         CREATE TABLE controller_history (
            sequence INTEGER PRIMARY KEY CHECK(sequence>=1),
            controller_node_id TEXT NOT NULL CHECK(length(controller_node_id)=22),
            administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
            peer_id TEXT NOT NULL REFERENCES managed_targets(peer_id) ON DELETE RESTRICT,
            job_id TEXT NOT NULL UNIQUE CHECK(length(job_id)=22),
            protocol_version INTEGER NOT NULL CHECK(protocol_version BETWEEN 1 AND 5),
            action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 32),
            snapshot BLOB NOT NULL CHECK(length(snapshot) BETWEEN 1 AND 4096),
            user_id TEXT CHECK(user_id IS NULL OR length(user_id)=22),
            credential_id TEXT CHECK(credential_id IS NULL OR length(credential_id)=22),
            imported INTEGER NOT NULL CHECK(imported IN(0,1)),
            recorded_at INTEGER CHECK(recorded_at IS NULL OR recorded_at>=0),
            updated_at INTEGER CHECK(updated_at IS NULL OR updated_at>=0),
            trimmed_count INTEGER NOT NULL CHECK(trimmed_count>=0),
            CHECK(imported=0 OR recorded_at IS NULL)
         ) STRICT;
         CREATE INDEX controller_history_peer_sequence ON controller_history(peer_id,sequence DESC);"
    ).map_err(|error| sqlite_error("cannot create controller history", error))
}

/// Backfill only slots actually retained by the old controller, after the
/// caller created the empty namespace and set version 20 in its transaction.
/// This lets normal typed readers validate all upgraded namespaces together.
pub(in crate::manage) fn migrate(connection: &Connection) -> io::Result<()> {
    let node = read_overview(connection)?.node_id;
    let peers = connection
        .prepare("SELECT peer_id FROM control_outbox ORDER BY peer_id")
        .map_err(|error| sqlite_error("cannot inspect legacy controller slots", error))?
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| sqlite_error("cannot read legacy controller slots", error))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|error| sqlite_error("cannot collect legacy controller slots", error))?;
    if peers.len() > MAX_TARGETS as usize {
        return Err(corrupt());
    }
    let mut retained = Vec::with_capacity(peers.len());
    for peer in peers {
        let job = super::current_job(connection, &peer)?.ok_or_else(corrupt)?;
        let (administrator, version, action) = descriptor(connection, &job)?;
        retained.push((job, administrator, version, action));
    }
    for (job, administrator, version, action) in retained {
        insert(
            connection,
            &node,
            &administrator,
            version,
            action,
            &job,
            true,
        )?;
    }
    Ok(())
}

/// Small namespace validation used by read_overview; never reads command blobs
/// or recursively asks for another overview.
pub(in crate::manage) fn validate_schema(connection: &Connection, version: u32) -> io::Result<()> {
    let count: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name IN('controller_history','controller_history_state')", [], |row| row.get(0)
    ).map_err(|error| sqlite_error("cannot inspect controller history namespace", error))?;
    if version < 20 {
        return if count == 0 { Ok(()) } else { Err(corrupt()) };
    }
    if count != 2 {
        return Err(corrupt());
    }
    high_water(connection).map(|_| ())
}

fn high_water(connection: &Connection) -> io::Result<u64> {
    let (count, value): (u32, Option<u64>) = connection.query_row(
        "SELECT count(*),max(CASE WHEN singleton=1 THEN last_sequence END) FROM controller_history_state", [], |row| Ok((row.get(0)?, optional_unsigned(row.get(1)?, 1)?))
    ).map_err(|error| sqlite_error("cannot read controller history high-water", error))?;
    if count != 1 {
        return Err(corrupt());
    }
    value
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(corrupt)
}

fn descriptor(connection: &Connection, job: &Job) -> io::Result<(String, u8, &'static str)> {
    let actor: String = connection
        .query_row(
            "SELECT administrator_id FROM control_outbox WHERE peer_id=?1 AND job_id=?2",
            params![job.peer_id, job.job_id],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot inspect controller history actor", error))?;
    let intent = super::endpoints::read_intent(connection, job)?;
    let action = match &intent {
        super::super::ControlIntent::Policy(command) => super::mutation_action(&command.change)?,
        super::super::ControlIntent::Endpoint(_) => "set_public_address",
    };
    Ok((actor, intent.version(), action))
}

pub(super) fn insert_current(connection: &Connection, job: &Job) -> io::Result<()> {
    let overview = read_overview(connection)?;
    if overview.schema_version < 20 {
        return Ok(());
    }
    let (actor, version, action) = descriptor(connection, job)?;
    insert(
        connection,
        &overview.node_id,
        &actor,
        version,
        action,
        job,
        false,
    )
}

fn insert(
    connection: &Connection,
    node: &str,
    actor: &str,
    version: u8,
    action: &str,
    job: &Job,
    imported: bool,
) -> io::Result<()> {
    let sequence = high_water(connection)?
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(conflict)?;
    let retained = read_entries(connection, Some(&job.peer_id))?;
    validate_window(&retained)?;
    let previous_trimmed = retained.first().map_or(0, |(_, trimmed)| *trimmed);
    let trimmed = previous_trimmed
        .checked_add(u64::from(retained.len() == PER_PEER))
        .ok_or_else(conflict)?;
    let time = if imported { None } else { timestamp() };
    let entry = StoredEntry {
        sequence,
        controller_node_id: node.to_owned(),
        administrator_id: actor.to_owned(),
        protocol_version: version,
        action: action.to_owned(),
        job: job.clone(),
        user_id: None,
        credential_id: None,
        imported,
        recorded_at_unix_s: time,
        updated_at_unix_s: time,
    };
    validate_entry(&entry)?;
    let bytes = snapshot(job)?;
    connection.execute(
        "INSERT INTO controller_history(sequence,controller_node_id,administrator_id,peer_id,job_id,protocol_version,action,snapshot,user_id,credential_id,imported,recorded_at,updated_at,trimmed_count) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL,NULL,?9,?10,?10,?11)",
        params![sql(sequence)?,node,actor,job.peer_id,job.job_id,version,action,bytes,i64::from(imported),time.map(sql).transpose()?,sql(trimmed)?]
    ).map_err(|error| sqlite_error("cannot append controller history", error))?;
    connection
        .execute(
            "UPDATE controller_history_state SET last_sequence=?1 WHERE singleton=1",
            [sql(sequence)?],
        )
        .map_err(|error| sqlite_error("cannot advance controller history high-water", error))?;
    connection.execute("DELETE FROM controller_history WHERE peer_id=?1 AND sequence IN (SELECT sequence FROM controller_history WHERE peer_id=?1 ORDER BY sequence DESC LIMIT -1 OFFSET 128)", [&job.peer_id])
        .map_err(|error| sqlite_error("cannot retain controller history window", error))?;
    Ok(())
}

/// Update the exact original row in the outbox's transaction. Receipt identity
/// changes are rejected even when old outbox metadata alone would look equal.
pub(super) fn update_current(
    connection: &Connection,
    job: &Job,
    result: Option<(&Option<String>, &Option<String>)>,
) -> io::Result<()> {
    if read_overview(connection)?.schema_version < 20 {
        return Ok(());
    }
    let entries = read_entries(connection, Some(&job.peer_id))?;
    let mut entry = entries
        .into_iter()
        .find(|(entry, _)| entry.job.job_id == job.job_id)
        .map(|(entry, _)| entry)
        .ok_or_else(corrupt)?;
    let (actor, version, action) = descriptor(connection, job)?;
    if entry.administrator_id != actor
        || entry.protocol_version != version
        || entry.action != action
        || entry.job.epoch != job.epoch
        || entry.job.command_id != job.command_id
        || entry.job.expected_policy_revision != job.expected_policy_revision
        || entry.job.expected_metadata_revision != job.expected_metadata_revision
        || entry.job.endpoint != job.endpoint
        || entry.job.maintenance != job.maintenance
        || entry.job.user_creation != job.user_creation
    {
        return Err(corrupt());
    }
    let mut unchanged = entry.job == *job;
    if let Some((user, credential)) = result {
        if entry
            .user_id
            .as_ref()
            .is_some_and(|old| Some(old) != user.as_ref())
            || entry
                .credential_id
                .as_ref()
                .is_some_and(|old| Some(old) != credential.as_ref())
        {
            return Err(corrupt());
        }
        unchanged &= entry.user_id == *user && entry.credential_id == *credential;
        if entry.user_id != *user {
            entry.user_id = user.clone();
        }
        if entry.credential_id != *credential {
            entry.credential_id = credential.clone();
        }
    }
    let time = timestamp();
    if unchanged && entry.updated_at_unix_s == time {
        // Preserve last-observation time semantics, but an exact same-tick
        // replay must not record a net-zero write in the source journal.
        validate_entry(&entry)?;
        return Ok(());
    }
    entry.job = job.clone();
    entry.updated_at_unix_s = time;
    validate_entry(&entry)?;
    let changed = connection.execute(
        "UPDATE controller_history SET snapshot=?1,user_id=?2,credential_id=?3,updated_at=?4 WHERE sequence=?5 AND peer_id=?6 AND job_id=?7",
        params![snapshot(job)?,entry.user_id,entry.credential_id,entry.updated_at_unix_s.map(sql).transpose()?,sql(entry.sequence)?,job.peer_id,job.job_id]
    ).map_err(|error| sqlite_error("cannot update original controller history", error))?;
    if changed != 1 {
        return Err(corrupt());
    }
    Ok(())
}

fn timestamp() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs())
        .filter(|value| *value <= i64::MAX as u64)
}

fn snapshot(job: &Job) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(job).map_err(|_| corrupt())?;
    if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT {
        return Err(corrupt());
    }
    Ok(bytes)
}

struct Raw {
    sequence: u64,
    node: String,
    actor: String,
    version: u8,
    action: String,
    bytes: Vec<u8>,
    user: Option<String>,
    credential: Option<String>,
    imported: i64,
    recorded: Option<u64>,
    updated: Option<u64>,
    trimmed: u64,
    peer: String,
    id: String,
}
impl Raw {
    fn row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        let bytes = match row.get_ref(5)? {
            ValueRef::Blob(value) if !value.is_empty() && value.len() <= MAX_SNAPSHOT => {
                value.to_vec()
            }
            _ => return Err(rusqlite::Error::InvalidQuery),
        };
        Ok(Self {
            sequence: unsigned(row.get(0)?, 0)?,
            node: row.get(1)?,
            actor: row.get(2)?,
            version: row.get(3)?,
            action: row.get(4)?,
            bytes,
            user: row.get(6)?,
            credential: row.get(7)?,
            imported: row.get(8)?,
            recorded: optional_unsigned(row.get(9)?, 9)?,
            updated: optional_unsigned(row.get(10)?, 10)?,
            trimmed: unsigned(row.get(11)?, 11)?,
            peer: row.get(12)?,
            id: row.get(13)?,
        })
    }
    fn decode(self) -> io::Result<(StoredEntry, u64)> {
        let job: Job = serde_json::from_slice(&self.bytes).map_err(|_| corrupt())?;
        if ![0, 1].contains(&self.imported)
            || job.peer_id != self.peer
            || job.job_id != self.id
            || snapshot(&job)? != self.bytes
        {
            return Err(corrupt());
        }
        let entry = StoredEntry {
            sequence: self.sequence,
            controller_node_id: self.node,
            administrator_id: self.actor,
            protocol_version: self.version,
            action: self.action,
            job,
            user_id: self.user,
            credential_id: self.credential,
            imported: self.imported == 1,
            recorded_at_unix_s: self.recorded,
            updated_at_unix_s: self.updated,
        };
        validate_entry(&entry)?;
        Ok((entry, self.trimmed))
    }
}

fn read_entries(
    connection: &Connection,
    peer: Option<&str>,
) -> io::Result<Vec<(StoredEntry, u64)>> {
    let high = high_water(connection)?;
    let node: String = connection
        .query_row(
            "SELECT node_id FROM node_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot bind controller history identity", error))?;
    let (sql, bound) = if peer.is_some() {
        (
            format!(
                "SELECT {COLUMNS} FROM controller_history WHERE peer_id=?1 ORDER BY sequence DESC LIMIT 129"
            ),
            PER_PEER,
        )
    } else {
        (
            format!(
                "SELECT {COLUMNS} FROM controller_history WHERE ?1 IS NULL ORDER BY sequence DESC LIMIT 16385"
            ),
            MAX_ROWS,
        )
    };
    let mut statement = connection
        .prepare(&sql)
        .map_err(|error| sqlite_error("cannot prepare controller history", error))?;
    let rows = statement
        .query_map([peer], Raw::row)
        .map_err(|error| sqlite_error("cannot read controller history", error))?;
    let mut result = Vec::new();
    for row in rows {
        if result.len() == bound {
            return Err(corrupt());
        }
        let decoded = row
            .map_err(|error| sqlite_error("cannot decode controller history row", error))?
            .decode()?;
        if decoded.0.sequence > high || decoded.0.controller_node_id != node {
            return Err(corrupt());
        }
        result.push(decoded);
    }
    Ok(result)
}

fn action_version(action: &str) -> Option<u8> {
    Some(match action {
        "create_user"
        | "update_user"
        | "set_user_active"
        | "delete_user"
        | "create_credential"
        | "set_credential_active"
        | "rotate_credential"
        | "revoke_credential" => 1,
        "create_prefix"
        | "retire_prefix"
        | "create_address"
        | "set_address_state"
        | "create_pool"
        | "set_pool_state"
        | "add_pool_member"
        | "remove_pool_member"
        | "set_route_permission" => 2,
        "set_user_presets" | "set_pool_preset" => 3,
        "set_public_address" => 4,
        "set_admission" => 5,
        _ => return None,
    })
}

fn validate_entry(entry: &StoredEntry) -> io::Result<()> {
    let job = &entry.job;
    let success = matches!(job.state, JobState::Saved | JobState::Applied);
    let positive = |value: u64| value > 0 && value <= i64::MAX as u64;
    if !positive(entry.sequence)
        || !positive(job.epoch)
        || !positive(job.command_id)
        || job.next_attempt > i64::MAX as u64
        || !valid_id(&entry.controller_node_id)
        || !valid_id(&entry.administrator_id)
        || !valid_id(&job.peer_id)
        || !valid_id(&job.job_id)
        || job.peer_id == entry.controller_node_id
        || action_version(&entry.action) != Some(entry.protocol_version)
        || entry
            .recorded_at_unix_s
            .into_iter()
            .chain(entry.updated_at_unix_s)
            .any(|time| time > i64::MAX as u64)
        || entry.imported && entry.recorded_at_unix_s.is_some()
        || entry.user_id.as_deref().is_some_and(|id| !valid_id(id))
        || entry
            .credential_id
            .as_deref()
            .is_some_and(|id| !valid_id(id))
        || (!success && (entry.user_id.is_some() || entry.credential_id.is_some()))
        || (entry.protocol_version != 1
            && (entry.user_id.is_some() || entry.credential_id.is_some()))
        || job.user_creation != (entry.action == "create_user")
        || (entry.protocol_version == 5) != job.maintenance.is_some()
        || (entry.protocol_version == 4) != job.endpoint.is_some()
        || (!job.state.unsettled() && job.next_attempt != 0)
    {
        return Err(corrupt());
    }
    if entry.protocol_version == 1 {
        if success && !entry.imported && entry.user_id.is_none() {
            return Err(corrupt());
        }
        let credential_action = matches!(
            entry.action.as_str(),
            "create_credential"
                | "set_credential_active"
                | "rotate_credential"
                | "revoke_credential"
        );
        if (!credential_action && entry.credential_id.is_some())
            || (credential_action && success && !entry.imported && entry.credential_id.is_none())
        {
            return Err(corrupt());
        }
    }
    let (expected, saved) = if entry.protocol_version == 4 {
        if job.expected_policy_revision.is_some()
            || job.policy_revision.is_some()
            || job.maintenance.is_some()
            || job.state == JobState::Applied
        {
            return Err(corrupt());
        }
        let reference = job.endpoint.as_ref().ok_or_else(corrupt)?;
        if !valid_id(&reference.listener_id)
            || reference.generation.len() != 64
            || !reference
                .generation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(corrupt());
        }
        (job.expected_metadata_revision, job.metadata_revision)
    } else {
        if job.expected_metadata_revision.is_some() || job.metadata_revision.is_some() {
            return Err(corrupt());
        }
        (job.expected_policy_revision, job.policy_revision)
    };
    if expected.is_none_or(|value| !positive(value)) || saved.is_some_and(|value| !positive(value))
    {
        return Err(corrupt());
    }
    let valid_state = match job.state {
        JobState::Pending => {
            saved.is_none()
                && matches!(job.outcome_code.as_deref(), None | Some("node_unavailable"))
        }
        JobState::Blocked => {
            saved.is_none() && job.outcome_code.as_deref() == Some("node_permission_or_state")
        }
        JobState::Saved | JobState::Applied => {
            saved.is_some()
                && saved
                    == expected
                        .and_then(|value| value.checked_add(1))
                        .filter(|value| *value <= i64::MAX as u64)
                && job.outcome_code.is_none()
        }
        JobState::Rejected => {
            saved.is_none() && job.outcome_code.as_deref() == Some("remote_rejected")
        }
        JobState::Superseded => saved.is_none() && job.outcome_code.is_none(),
    };
    if !valid_state
        || job.routing.is_some() != (entry.protocol_version == 2 && success)
        || job.preset.is_some() != (entry.protocol_version == 3 && success)
    {
        return Err(corrupt());
    }
    if let Some(reference) = &job.routing {
        let kind = match entry.action.as_str() {
            "create_prefix" | "retire_prefix" => RoutingKind::Prefix,
            "create_address" | "set_address_state" => RoutingKind::Address,
            "set_route_permission" => RoutingKind::Permission,
            _ => RoutingKind::Pool,
        };
        if reference.kind != kind || !valid_id(&reference.id) {
            return Err(corrupt());
        }
    }
    if let Some(reference) = &job.preset {
        let kind = if entry.action == "set_user_presets" {
            PresetKind::User
        } else {
            PresetKind::Pool
        };
        if reference.kind != kind || !valid_id(&reference.id) {
            return Err(corrupt());
        }
    }
    Ok(())
}

fn validate_window(entries: &[(StoredEntry, u64)]) -> io::Result<()> {
    if entries.len() > PER_PEER {
        return Err(corrupt());
    }
    let trimmed = entries.first().map_or(0, |(_, value)| *value);
    if entries.len() < PER_PEER && trimmed != 0 {
        return Err(corrupt());
    }
    for (index, (entry, count)) in entries.iter().enumerate() {
        let offset = u64::try_from(index).map_err(|_| corrupt())?;
        if *count != trimmed.saturating_sub(offset)
            || index > 0 && entries[index - 1].0.sequence <= entry.sequence
        {
            return Err(corrupt());
        }
    }
    Ok(())
}

fn read_authorized<T>(
    directory: &Path,
    administrator: &str,
    peer: &str,
    operation: impl FnOnce(&Connection) -> io::Result<T>,
) -> io::Result<T> {
    if !valid_id(peer) {
        return Err(input());
    }
    let mut connection = super::super::peers::open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin controller history snapshot", error))?;
    let overview = read_overview(&transaction)?;
    super::authorize_administrator(&transaction, administrator)?;
    if overview.schema_version < 20 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "management schema migration is required for controller history",
        ));
    }
    if super::find_target(&transaction, peer)?.is_none() {
        return Err(missing());
    }
    let result = operation(&transaction)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot finish controller history snapshot", error))?;
    Ok(result)
}

/// Read at most fifty rows with an exclusive positive sequence cursor. Current
/// administrator and target existence share the same RO transaction; retired
/// peers and old ownership do not erase local historical visibility.
pub(in crate::manage) fn list(
    directory: &Path,
    administrator: &str,
    peer: &str,
    before: Option<u64>,
    limit: u32,
) -> io::Result<Page> {
    if !(1..=50).contains(&limit)
        || before.is_some_and(|value| value == 0 || value > i64::MAX as u64)
    {
        return Err(input());
    }
    read_authorized(directory, administrator, peer, |connection| {
        let entries = read_entries(connection, Some(peer))?;
        validate_window(&entries)?;
        let oldest_sequence = entries.last().map(|(entry, _)| entry.sequence);
        let trimmed = entries.first().map_or(0, |(_, trimmed)| *trimmed);
        let mut items: Vec<_> = entries
            .into_iter()
            .filter(|(entry, _)| before.is_none_or(|before| entry.sequence < before))
            .map(|(entry, _)| entry)
            .take(limit as usize + 1)
            .collect();
        let next_cursor = if items.len() > limit as usize {
            items.pop();
            items.last().map(|entry| entry.sequence)
        } else {
            None
        };
        Ok(Page {
            items,
            next_cursor,
            oldest_sequence,
            trimmed,
        })
    })
}

/// Read only this peer's exact retained job identity. None means unavailable
/// history, not proof of non-execution. No remote contact or replay is started.
pub(in crate::manage) fn get(
    directory: &Path,
    administrator: &str,
    peer: &str,
    job_id: &str,
) -> io::Result<Option<StoredEntry>> {
    if !valid_id(job_id) {
        return Err(input());
    }
    read_authorized(directory, administrator, peer, |connection| {
        let entries = read_entries(connection, Some(peer))?;
        validate_window(&entries)?;
        Ok(entries
            .into_iter()
            .find(|(entry, _)| entry.job.job_id == job_id)
            .map(|(entry, _)| entry))
    })
}

/// Validate bounded typed history and retained-current consistency for offline
/// backup/migration. This is intentionally not a full scan on every API read.
pub(in crate::manage) fn validate_snapshot(connection: &Connection) -> io::Result<()> {
    let high = high_water(connection)?;
    let node: String = connection
        .query_row(
            "SELECT node_id FROM node_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot bind controller history node", error))?;
    let bad:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM controller_history h LEFT JOIN administrators a ON a.id=h.administrator_id LEFT JOIN managed_targets t ON t.peer_id=h.peer_id WHERE a.id IS NULL OR t.peer_id IS NULL)",[],|row|row.get(0)).map_err(|error|sqlite_error("cannot validate controller history owners",error))?;
    if bad || !valid_id(&node) {
        return Err(corrupt());
    }
    let mut peers: BTreeMap<String, Vec<(StoredEntry, u64)>> = BTreeMap::new();
    for row in read_entries(connection, None)? {
        if row.0.controller_node_id != node || row.0.sequence > high {
            return Err(corrupt());
        }
        peers
            .entry(row.0.job.peer_id.clone())
            .or_default()
            .push(row);
    }
    if peers.len() > MAX_TARGETS as usize {
        return Err(corrupt());
    }
    let mut issued = 0u64;
    for (peer, rows) in &peers {
        validate_window(rows)?;
        issued = issued
            .checked_add(rows.len() as u64)
            .and_then(|value| value.checked_add(rows.first().map_or(0, |(_, trimmed)| *trimmed)))
            .ok_or_else(corrupt)?;
        if let Some(job) = super::current_job(connection, peer)? {
            let latest = rows.first().ok_or_else(corrupt)?;
            let (actor, version, action) = descriptor(connection, &job)?;
            if latest.0.job != job
                || latest.0.administrator_id != actor
                || latest.0.protocol_version != version
                || latest.0.action != action
            {
                return Err(corrupt());
            }
        }
    }
    let slots: u32 = connection
        .query_row("SELECT count(*) FROM control_outbox", [], |row| row.get(0))
        .map_err(|error| sqlite_error("cannot inspect retained history slots", error))?;
    if issued != high || slots as usize != peers.len() {
        return Err(corrupt());
    }
    Ok(())
}

/// Keep recovered identities disjoint from all retained historical result IDs.
pub(in crate::manage) fn collect_source_ids(
    connection: &Connection,
    ids: &mut HashSet<String>,
) -> io::Result<()> {
    for (entry, _) in read_entries(connection, None)? {
        ids.extend([
            entry.controller_node_id,
            entry.administrator_id,
            entry.job.peer_id,
            entry.job.job_id,
        ]);
        ids.extend(entry.user_id);
        ids.extend(entry.credential_id);
        if let Some(value) = entry.job.routing {
            ids.insert(value.id);
        }
        if let Some(value) = entry.job.preset {
            ids.insert(value.id);
        }
        if let Some(value) = entry.job.endpoint {
            ids.insert(value.listener_id);
        }
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::manage) fn ensure_unused_for_test(connection: &Connection) -> io::Result<()> {
    let count:u32=connection.query_row("SELECT count(*) FROM sqlite_schema WHERE name IN('controller_history','controller_history_state')",[],|row|row.get(0)).map_err(|error|sqlite_error("cannot inspect legacy history fixture",error))?;
    if count == 0 {
        return Ok(());
    }
    if count != 2 || high_water(connection)? != 0 {
        return Err(corrupt());
    }
    let rows: u32 = connection
        .query_row("SELECT count(*) FROM controller_history", [], |row| {
            row.get(0)
        })
        .map_err(|error| sqlite_error("cannot inspect unused history fixture", error))?;
    if rows != 0 {
        return Err(corrupt());
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::manage) fn remove_schema_for_test(connection: &Connection) -> io::Result<()> {
    ensure_unused_for_test(connection)?;
    connection.execute_batch("DROP TABLE IF EXISTS controller_history; DROP TABLE IF EXISTS controller_history_state;")
        .map_err(|error|sqlite_error("cannot reconstruct legacy history fixture",error))
}
