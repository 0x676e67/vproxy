//! Controller-local target configuration and one durable pending command per peer.
//!
//! The target node owns policy versions and idempotent execution. This outbox
//! remembers intent across controller failure, never a returned machine secret.
//! Database work is bounded and belongs on the management blocking executor.

mod endpoints;
pub(in crate::manage) mod history;
mod schema15;
mod schema6;
mod schema9;
pub(in crate::manage) use endpoints::{complete_endpoint, enqueue_intent};
pub(super) use schema6::upgrade_schema;
pub(super) use schema9::upgrade_presets;
pub(super) use schema15::upgrade_endpoints;

use std::{io, net::IpAddr, path::Path};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params, types::ValueRef};
use serde::{Deserialize, Serialize};

use super::{
    Command, Overview, PolicyChange, PresetKind, PresetReceipt, RoutingKind, RoutingReceipt,
    random_id, read_overview, sqlite_error, valid_id,
};
use crate::manage::api::PublicOrigin;

const MAX_TARGETS: u32 = 128;
const MAX_AUDIT: i64 = 16_384;
const MAX_COMMAND_BYTES: usize = 4_096;
const MAX_RETRY_DELAY: u64 = 60;

/// Schema ten adds optional operator-registered display metadata. Existing
/// destinations remain NULL; no identity, authorization or routing row changes.
pub(super) fn upgrade_metadata(connection: &Connection) -> io::Result<()> {
    connection
        .execute_batch("ALTER TABLE managed_targets ADD COLUMN server_ip TEXT CHECK(server_ip IS NULL OR length(server_ip) BETWEEN 2 AND 45);")
        .map_err(|error| sqlite_error("cannot add managed target display metadata", error))
}

/// Accept numeric IP syntax and canonicalize it when storing/serializing. RFC
/// 5952 accepts all RFC 4291 IPv6 representations, not just recommended output:
/// <https://www.rfc-editor.org/rfc/rfc5952.html>. Section 4 defines output form.
/// Private/loopback registration is display metadata, not verified ownership,
/// reachability, public egress, TLS identity or a connection destination.
pub(in crate::manage) fn parse_server_ip(value: &str) -> io::Result<IpAddr> {
    let address: IpAddr = value.parse().map_err(|_| input())?;
    if !valid_server_ip(address) {
        return Err(input());
    }
    Ok(address)
}

fn valid_server_ip(address: IpAddr) -> bool {
    // Classify mapped IPv4 by its actual address range without changing the
    // originally registered family in the display value.
    match address.to_canonical() {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

/// Create the actual controller objects in the caller's schema-4 transaction.
pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection.execute_batch(
        "CREATE TABLE managed_targets (
            peer_id TEXT PRIMARY KEY NOT NULL REFERENCES peers(node_id) ON DELETE RESTRICT,
            origin TEXT NOT NULL CHECK (length(origin) BETWEEN 1 AND 300),
            active INTEGER NOT NULL CHECK (active IN (0,1)),
            retired INTEGER NOT NULL CHECK (retired IN (0,1)),
            revision INTEGER NOT NULL CHECK (revision >= 1),
            observed_epoch INTEGER CHECK (observed_epoch >= 1),
            observed_command INTEGER CHECK (observed_command >= 0),
            observed_policy_revision INTEGER CHECK (observed_policy_revision >= 1),
            rollback_detected INTEGER NOT NULL CHECK (rollback_detected IN (0,1)),
            CHECK (retired = 0 OR active = 0),
            CHECK ((observed_epoch IS NULL AND observed_command IS NULL AND observed_policy_revision IS NULL)
                OR (observed_epoch IS NOT NULL AND observed_command IS NOT NULL AND observed_policy_revision IS NOT NULL))
         ) STRICT;
         CREATE TABLE control_outbox (
            peer_id TEXT PRIMARY KEY NOT NULL REFERENCES managed_targets(peer_id) ON DELETE RESTRICT,
            job_id TEXT NOT NULL UNIQUE CHECK (length(job_id) = 22),
            administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
            controller_epoch INTEGER NOT NULL CHECK (controller_epoch >= 1),
            command_id INTEGER NOT NULL CHECK (command_id >= 1),
            expected_policy_revision INTEGER NOT NULL CHECK (expected_policy_revision >= 1),
            command BLOB NOT NULL CHECK (length(command) BETWEEN 1 AND 4096),
            state TEXT NOT NULL CHECK (state IN ('pending','blocked','saved','applied','rejected','superseded')),
            policy_revision INTEGER CHECK (policy_revision >= 1),
            outcome_code TEXT CHECK(outcome_code IN ('remote_rejected','node_permission_or_state','node_unavailable')),
            attempts INTEGER NOT NULL CHECK (attempts BETWEEN 0 AND 4294967295),
            next_attempt INTEGER NOT NULL CHECK (next_attempt >= 0),
            CHECK((state IN ('pending','blocked','rejected','superseded') AND policy_revision IS NULL)
                OR (state IN ('saved','applied') AND expected_policy_revision < 9223372036854775807
                    AND policy_revision = expected_policy_revision + 1))
         ) STRICT;
         CREATE TABLE controller_audit (
            sequence INTEGER PRIMARY KEY CHECK (sequence >= 1),
            administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
            action TEXT NOT NULL CHECK (action IN ('register','update','state','retire','enqueue','retry','supersede')),
            peer_id TEXT NOT NULL REFERENCES managed_targets(peer_id) ON DELETE RESTRICT,
            target_revision INTEGER NOT NULL CHECK (target_revision >= 1),
            job_id TEXT CHECK (job_id IS NULL OR length(job_id) = 22),
            controller_epoch INTEGER CHECK (controller_epoch >= 1),
            command_id INTEGER CHECK (command_id >= 1),
            mutation_action TEXT CHECK (mutation_action IN ('create_user','update_user',
                'set_user_active','delete_user','create_credential','set_credential_active',
                'rotate_credential','revoke_credential')),
            recorded_at INTEGER NOT NULL CHECK (recorded_at >= 0),
            CHECK ((action IN ('register','update','state','retire') AND job_id IS NULL
                    AND controller_epoch IS NULL AND command_id IS NULL AND mutation_action IS NULL)
                OR (action IN ('enqueue','retry','supersede') AND job_id IS NOT NULL
                    AND controller_epoch IS NOT NULL AND command_id IS NOT NULL AND mutation_action IS NOT NULL))
         ) STRICT;"
    ).map_err(|error| sqlite_error("cannot create controller target schema", error))
}

/// Explicitly configured destination. Observations are rollback floors, not a
/// claim that this peer or its proxy is currently reachable or healthy.
#[derive(Clone)]
pub(in crate::manage) struct Target {
    pub(in crate::manage) peer_id: String,
    pub(in crate::manage) name: String,
    pub(in crate::manage) origin: String,
    /// Display-only registration, not a TLS identity, destination or observed egress.
    pub(in crate::manage) server_ip: Option<IpAddr>,
    pub(in crate::manage) active: bool,
    /// Reversible local retirement, unlike a permanent certificate tombstone.
    pub(in crate::manage) retired: bool,
    pub(in crate::manage) revision: u64,
    pub(in crate::manage) observed_epoch: Option<u64>,
    pub(in crate::manage) observed_command: Option<u64>,
    pub(in crate::manage) observed_policy_revision: Option<u64>,
    pub(in crate::manage) rollback_detected: bool,
}

/// Current job status is non-secret metadata. A terminal row may be replaced by
/// the next explicit operation; the target's receipt window is authoritative.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Job {
    /// Exact retained v5 intent, including pending/rejected jobs. This is not
    /// inferred from a reply and cannot identify a user/routing operation.
    pub(in crate::manage) maintenance: Option<bool>,
    /// Derived from the retained typed intent, not a promise that its receipt
    /// or the created user's current metadata is still available.
    pub(in crate::manage) user_creation: bool,
    pub(in crate::manage) routing: Option<RoutingReceipt>,
    pub(in crate::manage) preset: Option<PresetReceipt>,
    pub(in crate::manage) peer_id: String,
    pub(in crate::manage) job_id: String,
    pub(in crate::manage) epoch: u64,
    pub(in crate::manage) command_id: u64,
    pub(in crate::manage) expected_policy_revision: Option<u64>,
    pub(in crate::manage) expected_metadata_revision: Option<u64>,
    pub(in crate::manage) metadata_revision: Option<u64>,
    pub(in crate::manage) endpoint: Option<super::endpoint_control::Reference>,
    pub(in crate::manage) state: JobState,
    pub(in crate::manage) policy_revision: Option<u64>,
    pub(in crate::manage) outcome_code: Option<String>,
    pub(in crate::manage) attempts: u32,
    pub(in crate::manage) next_attempt: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum JobState {
    Pending,
    Blocked,
    Saved,
    Applied,
    Rejected,
    Superseded,
}

impl JobState {
    pub(in crate::manage) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Blocked => "blocked",
            Self::Saved => "saved",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "blocked" => Ok(Self::Blocked),
            "saved" => Ok(Self::Saved),
            "applied" => Ok(Self::Applied),
            "rejected" => Ok(Self::Rejected),
            "superseded" => Ok(Self::Superseded),
            _ => Err(corrupt()),
        }
    }
    fn unsettled(self) -> bool {
        matches!(self, Self::Pending | Self::Blocked)
    }
}

/// A bounded, typed delivery; no arbitrary URL/method/body is recovered from a job.
pub(in crate::manage) struct Delivery {
    pub(in crate::manage) target: Target,
    pub(in crate::manage) job: Job,
    pub(in crate::manage) command: super::ControlIntent,
}

fn corrupt() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "controller target state is malformed",
    )
}

/// A consistent bounded page; no per-card network calls are made by storage.
pub(in crate::manage) struct TargetPage {
    pub(in crate::manage) items: Vec<Target>,
    pub(in crate::manage) next_cursor: Option<String>,
}

pub(in crate::manage) fn list(
    directory: &Path,
    after: Option<&str>,
    limit: u32,
    include_retired: bool,
) -> io::Result<TargetPage> {
    list_filtered(directory, after, limit, include_retired, None)
}

/// A literal local-registry filter, not a wildcard or remote discovery request.
/// Validate before trimming so controls and oversized input cannot be hidden.
pub(in crate::manage) fn query_filter(value: &str) -> io::Result<&str> {
    if value.len() > 256 || value.chars().any(char::is_control) {
        return Err(input());
    }
    Ok(value.trim())
}

/// Filter before LIMIT, keeping ordinary ID continuation and snapshot semantics.
/// Matching is literal, ASCII-case-insensitive for names/origins/IP text and
/// case-sensitive for node IDs. Full numeric IPs also match canonical spelling.
/// Callers must keep the same filter/retirement options on following pages;
/// this is not a revision-bound multi-request snapshot or operation receipt.
pub(in crate::manage) fn list_filtered(
    directory: &Path,
    after: Option<&str>,
    limit: u32,
    include_retired: bool,
    query: Option<&str>,
) -> io::Result<TargetPage> {
    if !(1..=25).contains(&limit) || after.is_some_and(|id| !valid_id(id)) {
        return Err(input());
    }
    let query = query.map(query_filter).transpose()?.unwrap_or("");
    let canonical_ip = query.parse::<IpAddr>().ok().map(|ip| ip.to_string());
    let mut connection = super::peers::open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|e| sqlite_error("cannot list targets", e))?;
    require_schema(&transaction)?;
    let mut items =
        {
            let mut statement = transaction.prepare(
            "SELECT t.peer_id,p.name,t.origin,t.active,t.retired,t.revision,t.observed_epoch,
             t.observed_command,t.observed_policy_revision,t.rollback_detected,t.server_ip
             FROM managed_targets t LEFT JOIN peers p ON p.node_id=t.peer_id
             WHERE t.peer_id>?1 AND (?2 OR t.retired=0)
             AND (?4='' OR instr(lower(p.name),lower(?4))>0
                  OR instr(lower(t.origin),lower(?4))>0 OR instr(t.peer_id,?4)>0
                  OR instr(lower(COALESCE(t.server_ip,'')),lower(?4))>0
                  OR (?5 IS NOT NULL AND t.server_ip=?5))
             ORDER BY t.peer_id LIMIT ?3"
        ).map_err(|e| sqlite_error("cannot prepare target listing", e))?;
            let rows = statement
                .query_map(
                    params![
                        after.unwrap_or(""),
                        include_retired,
                        i64::from(limit) + 1,
                        query,
                        canonical_ip
                    ],
                    target_row,
                )
                .map_err(|e| sqlite_error("cannot query targets", e))?;
            let mut items = Vec::new();
            for row in rows {
                let target = row.map_err(|e| sqlite_error("cannot read target", e))?;
                validate_target(&target)?;
                items.push(target);
            }
            items
        };
    let next_cursor = if items.len() > limit as usize {
        items.pop();
        items.last().map(|item| item.peer_id.clone())
    } else {
        None
    };
    transaction
        .commit()
        .map_err(|e| sqlite_error("cannot finish target listing", e))?;
    Ok(TargetPage { items, next_cursor })
}

pub(in crate::manage) fn get(directory: &Path, peer: &str) -> io::Result<Target> {
    if !valid_id(peer) {
        return Err(input());
    }
    let connection = super::peers::open_existing(directory, false)?;
    require_schema(&connection)?;
    find_target(&connection, peer)?.ok_or_else(missing)
}

/// Authorise one explicit scoped request against the exact registration the
/// administrator inspected. The same bounded snapshot is used before and after
/// networking; a later failure cannot undo work already accepted by the peer.
pub(in crate::manage) fn scoped_target(
    directory: &Path,
    administrator: &str,
    peer: &str,
    expected_revision: u64,
) -> io::Result<Target> {
    if !valid_id(peer) || expected_revision == 0 || expected_revision > i64::MAX as u64 {
        return Err(input());
    }
    super::control::read_snapshot(directory, |connection| {
        require_schema(connection)?;
        authorize_administrator(connection, administrator)?;
        require_peer(connection, peer)?;
        let target = find_target(connection, peer)?.ok_or_else(missing)?;
        if !target.active || target.retired || target.rollback_detected {
            return Err(denied());
        }
        if target.revision != expected_revision {
            return Err(conflict());
        }
        Ok(target)
    })
}

/// Reuses an existing snapshot when registration must agree with imported data.
pub(super) fn get_in(connection: &Connection, peer: &str) -> io::Result<Target> {
    if !valid_id(peer) {
        return Err(input());
    }
    require_schema(connection)?;
    find_target(connection, peer)?.ok_or_else(missing)
}

/// Add or replace an explicit destination using its local configuration CAS.
/// Retiring/reactivating preserves rollback floors and the latest command row.
/// `server_ip` is missing to preserve existing metadata, `Some(None)` to clear,
/// or `Some(Some(address))` to set. Registration without metadata stores NULL.
pub(in crate::manage) fn configure(
    directory: &Path,
    administrator: &str,
    peer: &str,
    expected_revision: Option<u64>,
    origin: &str,
    active: bool,
    server_ip: Option<Option<IpAddr>>,
) -> io::Result<Target> {
    validate_configuration(peer, origin, server_ip)?;
    let _gate = super::update_lock(directory)?;
    let mut connection = super::peers::open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin target configuration", e))?;
    let target = configure_in(
        &transaction,
        administrator,
        peer,
        expected_revision,
        origin,
        active,
        server_ip,
    )?;
    transaction
        .commit()
        .map_err(|e| sqlite_error("cannot commit target configuration", e))?;
    Ok(target)
}

/// Recheck administrator, peer and local CAS in the caller's transaction.
/// An unsettled intent cannot be replaced; prior observation floors survive.
fn configure_in(
    transaction: &Connection,
    administrator: &str,
    peer: &str,
    expected_revision: Option<u64>,
    origin: &str,
    active: bool,
    server_ip: Option<Option<IpAddr>>,
) -> io::Result<Target> {
    require_transaction(transaction)?;
    let local = require_schema(transaction)?.node_id;
    authorize_administrator(transaction, administrator)?;
    if peer == local {
        return Err(input());
    }
    require_peer(transaction, peer)?;
    let previous = find_target(transaction, peer)?;
    let server_ip =
        server_ip.unwrap_or_else(|| previous.as_ref().and_then(|target| target.server_ip));
    let (next, action) = match previous {
        Some(previous) => {
            if expected_revision != Some(previous.revision) {
                return Err(conflict());
            }
            if current_job(transaction, peer)?.is_some_and(|job| job.state.unsettled()) {
                return Err(conflict());
            }
            (increment(previous.revision)?, "update")
        }
        None => {
            if expected_revision.is_some() {
                return Err(conflict());
            }
            let count: u32 = transaction
                .query_row("SELECT count(*) FROM managed_targets", [], |r| r.get(0))
                .map_err(|e| sqlite_error("cannot count managed targets", e))?;
            if count >= MAX_TARGETS {
                return Err(conflict());
            }
            (1, "register")
        }
    };
    transaction
        .execute(
            "INSERT INTO managed_targets(peer_id,origin,active,retired,revision,rollback_detected,server_ip)
         VALUES(?1,?2,?3,0,?4,0,?5) ON CONFLICT(peer_id) DO UPDATE SET origin=excluded.origin,
         active=excluded.active,retired=0,revision=excluded.revision,server_ip=excluded.server_ip",
            params![peer, origin, active, sql(next)?, server_ip.map(|ip| ip.to_string())],
        )
        .map_err(|e| sqlite_error("cannot save managed target", e))?;
    audit(transaction, administrator, action, peer, next, None, None)?;
    let target = find_target(transaction, peer)?.ok_or_else(corrupt)?;
    Ok(target)
}

/// Pausing stops future deliveries, not a request the target already accepted.
/// A paused job retains exactly its original command and idempotency identity.
/// Retirement is the same delivery stop with a reversible metadata marker;
/// an unreachable node must remain retireable without discarding an uncertain job.
pub(in crate::manage) fn set_state(
    directory: &Path,
    administrator: &str,
    peer: &str,
    expected_revision: u64,
    active: bool,
    retire: bool,
) -> io::Result<Target> {
    validate_state(peer, active, retire)?;
    let _gate = super::update_lock(directory)?;
    let mut connection = super::peers::open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin target state change", e))?;
    let target = set_state_in(
        &transaction,
        administrator,
        peer,
        expected_revision,
        active,
        retire,
    )?;
    transaction
        .commit()
        .map_err(|e| sqlite_error("cannot commit target state", e))?;
    Ok(target)
}

/// Stop future deliveries without discarding the original command. A request
/// already accepted by the child may still finish after pause or retirement.
fn set_state_in(
    transaction: &Connection,
    administrator: &str,
    peer: &str,
    expected_revision: u64,
    active: bool,
    retire: bool,
) -> io::Result<Target> {
    require_transaction(transaction)?;
    require_schema(transaction)?;
    authorize_administrator(transaction, administrator)?;
    let previous = find_target(transaction, peer)?.ok_or_else(missing)?;
    if previous.revision != expected_revision {
        return Err(conflict());
    }
    let next = increment(previous.revision)?;
    transaction
        .execute(
            "UPDATE managed_targets SET active=?1,retired=?2,revision=?3 WHERE peer_id=?4",
            params![active, retire, sql(next)?, peer],
        )
        .map_err(|e| sqlite_error("cannot save target state", e))?;
    audit(
        transaction,
        administrator,
        if retire { "retire" } else { "state" },
        peer,
        next,
        None,
        None,
    )?;
    let target = find_target(transaction, peer)?.ok_or_else(corrupt)?;
    Ok(target)
}

/// Save an authenticated remote observation. A backwards epoch, high-water mark
/// or policy generation disables automatic delivery; it is never silently reset.
pub(in crate::manage) fn observe(
    directory: &Path,
    peer: &str,
    target_revision: u64,
    epoch: u64,
    command: u64,
    policy_revision: u64,
) -> io::Result<Target> {
    validate_observation(peer, epoch, command, policy_revision)?;
    let _gate = super::update_lock(directory)?;
    let mut connection = super::peers::open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin target observation", e))?;
    let target = observe_in(
        &transaction,
        peer,
        target_revision,
        epoch,
        command,
        policy_revision,
    )?;
    transaction
        .commit()
        .map_err(|e| sqlite_error("cannot commit target observation", e))?;
    Ok(target)
}

/// Keep monotonic position floors and a sticky rollback marker in this
/// transaction. Exact repeated observations need no write or source sequence.
fn observe_in(
    transaction: &Connection,
    peer: &str,
    target_revision: u64,
    epoch: u64,
    command: u64,
    policy_revision: u64,
) -> io::Result<Target> {
    require_transaction(transaction)?;
    require_schema(transaction)?;
    let previous = find_target(transaction, peer)?.ok_or_else(missing)?;
    if previous.revision != target_revision {
        return Err(conflict());
    }
    let backwards = previous.observed_epoch.is_some_and(|old| epoch < old)
        || previous
            .observed_policy_revision
            .is_some_and(|old| policy_revision < old)
        || (previous.observed_epoch == Some(epoch)
            && previous.observed_command.is_some_and(|old| command < old));
    // Exact repeats need no SQL write or source-journal sequence. Keep the
    // sticky rollback flag and the original monotonic observation semantics.
    if backwards && !previous.rollback_detected {
        transaction
            .execute(
                "UPDATE managed_targets SET rollback_detected=1 WHERE peer_id=?1",
                [peer],
            )
            .map_err(|e| sqlite_error("cannot record target rollback", e))?;
    } else if !backwards
        && (previous.observed_epoch != Some(epoch)
            || previous.observed_command != Some(command)
            || previous.observed_policy_revision != Some(policy_revision))
    {
        transaction
            .execute(
                "UPDATE managed_targets SET observed_epoch=?1,observed_command=?2,
            observed_policy_revision=?3 WHERE peer_id=?4",
                params![sql(epoch)?, sql(command)?, sql(policy_revision)?, peer],
            )
            .map_err(|e| sqlite_error("cannot save target observation", e))?;
    }
    let target = find_target(transaction, peer)?.ok_or_else(corrupt)?;
    Ok(target)
}

/// Commit one typed intent before the worker may contact its destination. One
/// outstanding command per target prevents unbounded offline mutation queues.
pub(in crate::manage) fn enqueue(
    directory: &Path,
    administrator: &str,
    target_revision: u64,
    command: Command,
) -> io::Result<Job> {
    let payload = encode(&command)?;
    let _gate = super::update_lock(directory)?;
    let mut connection = super::peers::open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin controller command", e))?;
    let job = enqueue_in(
        &transaction,
        administrator,
        target_revision,
        command,
        payload,
    )?;
    transaction
        .commit()
        .map_err(|e| sqlite_error("cannot commit controller command", e))?;
    Ok(job)
}

/// Bind a new outbox slot to the current target/owner position. Intent,
/// audit and history stage together before any child I/O; no commit occurs here.
fn enqueue_in(
    transaction: &Connection,
    administrator: &str,
    target_revision: u64,
    command: Command,
    payload: Vec<u8>,
) -> io::Result<Job> {
    require_transaction(transaction)?;
    require_schema(transaction)?;
    authorize_administrator(transaction, administrator)?;
    if command.source_administrator_id != administrator {
        return Err(denied());
    }
    if command.change.control_version() == 5 && read_overview(transaction)?.schema_version < 19 {
        return Err(super::admission::Error::UpgradeRequired.error());
    }
    let target = find_target(transaction, &command.target_node_id)?.ok_or_else(missing)?;
    require_peer(transaction, &target.peer_id)?;
    if !target.active || target.retired || target.rollback_detected {
        return Err(denied());
    }
    if target.revision != target_revision
        || target.observed_epoch != Some(command.epoch)
        || target
            .observed_command
            .and_then(|value| value.checked_add(1))
            != Some(command.command_id)
        || target.observed_policy_revision != Some(command.expected_policy_revision)
        || current_job(transaction, &target.peer_id)?.is_some_and(|job| job.state.unsettled())
    {
        return Err(conflict());
    }
    let job_id = random_id()?;
    let insert = if read_overview(transaction)?.schema_version >= 15 {
        "INSERT INTO control_outbox(peer_id,job_id,administrator_id,controller_epoch,command_id,expected_policy_revision,command,state,attempts,next_attempt) VALUES(?1,?2,?3,?4,?5,?6,?7,'pending',0,0)
         ON CONFLICT(peer_id) DO UPDATE SET job_id=excluded.job_id,administrator_id=excluded.administrator_id,controller_epoch=excluded.controller_epoch,command_id=excluded.command_id,expected_policy_revision=excluded.expected_policy_revision,command=excluded.command,state='pending',policy_revision=NULL,outcome_code=NULL,attempts=0,next_attempt=0,routing_kind=NULL,routing_id=NULL,preset_kind=NULL,preset_id=NULL,resource='proxy_policy',expected_metadata_revision=NULL,metadata_revision=NULL"
    } else {
        "INSERT INTO control_outbox(peer_id,job_id,administrator_id,controller_epoch,command_id,
         expected_policy_revision,command,state,attempts,next_attempt) VALUES(?1,?2,?3,?4,?5,?6,?7,'pending',0,0)
         ON CONFLICT(peer_id) DO UPDATE SET job_id=excluded.job_id,administrator_id=excluded.administrator_id,
         controller_epoch=excluded.controller_epoch,command_id=excluded.command_id,
         expected_policy_revision=excluded.expected_policy_revision,command=excluded.command,
         state='pending',policy_revision=NULL,outcome_code=NULL,attempts=0,next_attempt=0,routing_kind=NULL,routing_id=NULL,preset_kind=NULL,preset_id=NULL"
    };
    transaction
        .execute(
            insert,
            params![
                target.peer_id,
                job_id,
                administrator,
                sql(command.epoch)?,
                sql(command.command_id)?,
                sql(command.expected_policy_revision)?,
                payload
            ],
        )
        .map_err(|e| sqlite_error("cannot save controller command", e))?;
    audit(
        transaction,
        administrator,
        "enqueue",
        &target.peer_id,
        target.revision,
        Some(&job_id),
        Some(&command),
    )?;
    let job = current_job(transaction, &target.peer_id)?.ok_or_else(corrupt)?;
    history::insert_current(transaction, &job)?;
    Ok(job)
}

pub(in crate::manage) fn job(directory: &Path, peer: &str) -> io::Result<Option<Job>> {
    if !valid_id(peer) {
        return Err(input());
    }
    let mut connection = super::peers::open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin controller command snapshot", error))?;
    let schema_version = require_schema(&transaction)?.schema_version;
    // The read-only transaction retains the fully validated snapshot. Reuse its
    // version for dispatch without repeating all namespace and identity checks.
    let job = current_job_for_schema(&transaction, peer, schema_version)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot finish controller command snapshot", error))?;
    Ok(job)
}

/// Inspect the exact job's durable typed protocol, including terminal jobs.
/// Job replacement or malformed payload is an error, never a guessed version.
pub(in crate::manage) fn job_version(directory: &Path, peer: &str, job_id: &str) -> io::Result<u8> {
    if !valid_id(peer) || !valid_id(job_id) {
        return Err(input());
    }
    let mut connection = super::peers::open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|e| sqlite_error("cannot begin command version inspection", e))?;
    require_schema(&transaction)?;
    let job = current_job(&transaction, peer)?.ok_or_else(missing)?;
    if job.job_id != job_id {
        return Err(conflict());
    }
    let version = endpoints::read_intent(&transaction, &job)?.version();
    transaction
        .commit()
        .map_err(|e| sqlite_error("cannot finish command version inspection", e))?;
    Ok(version)
}

/// Returns at most 128 due candidates; the scheduler admits at most two in flight.
///
/// An implausibly distant retry timestamp is due as well: system-clock rollback
/// must not strand a job for months. A normal backoff never exceeds 60 seconds.
pub(in crate::manage) fn pending(directory: &Path, now: u64) -> io::Result<Vec<Delivery>> {
    let current_time = sql(now)?;
    let future_limit = now
        .checked_add(MAX_RETRY_DELAY)
        .filter(|value| *value <= i64::MAX as u64)
        .unwrap_or(i64::MAX as u64);
    let mut connection = super::peers::open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|e| sqlite_error("cannot inspect pending commands", e))?;
    require_schema(&transaction)?;
    let peers = {
        let mut statement = transaction
            .prepare(
                "SELECT o.peer_id FROM control_outbox o
            WHERE o.state='pending' AND (o.next_attempt<=?1 OR o.next_attempt>?2)
            ORDER BY o.next_attempt,o.peer_id LIMIT 128",
            )
            .map_err(|e| sqlite_error("cannot prepare pending commands", e))?;
        let rows = statement
            .query_map([current_time, sql(future_limit)?], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|e| sqlite_error("cannot query pending commands", e))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| sqlite_error("cannot read pending commands", e))?
    };
    let mut deliveries = Vec::with_capacity(peers.len());
    for peer in peers {
        let target = find_target(&transaction, &peer)?.ok_or_else(corrupt)?;
        if !target.active || target.retired || target.rollback_detected {
            continue;
        }
        match require_peer(&transaction, &peer) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => continue,
            Err(error) => return Err(error),
        }
        let job = current_job(&transaction, &peer)?.ok_or_else(corrupt)?;
        let command = endpoints::read_intent(&transaction, &job)?;
        deliveries.push(Delivery {
            target,
            job,
            command,
        });
    }
    transaction
        .commit()
        .map_err(|e| sqlite_error("cannot finish pending inspection", e))?;
    Ok(deliveries)
}

/// Loads one precise pending job for synchronous first delivery, not a broad scan.
///
/// Paused/retired/rollback-detected targets and blocked jobs require explicit
/// operator repair/retry. Identity, target and payload share a read snapshot.
pub(in crate::manage) fn load_delivery(
    directory: &Path,
    peer: &str,
    job_id: &str,
) -> io::Result<Delivery> {
    validate_job(peer, job_id)?;
    let mut connection = super::peers::open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin exact delivery inspection", error))?;
    let delivery = load_delivery_in(&transaction, peer, job_id)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot complete exact delivery inspection", error))?;
    Ok(delivery)
}

/// Resolve one exact pending job from the caller's coherent SQL snapshot.
/// Paused, retired, rollback-detected or unauthorized peers cannot be delivered.
fn load_delivery_in(transaction: &Connection, peer: &str, job_id: &str) -> io::Result<Delivery> {
    require_transaction(transaction)?;
    require_schema(transaction)?;
    let target = find_target(transaction, peer)?.ok_or_else(missing)?;
    if !target.active || target.retired || target.rollback_detected {
        return Err(denied());
    }
    require_peer(transaction, peer)?;
    let job = current_job(transaction, peer)?.ok_or_else(missing)?;
    if job.job_id != job_id || job.state != JobState::Pending {
        return Err(conflict());
    }
    let command = endpoints::read_intent(transaction, &job)?;
    Ok(Delivery {
        target,
        job,
        command,
    })
}

/// Validates the bounded private payload and metadata binding without exporting it.
fn read_command(connection: &Connection, job: &Job) -> io::Result<Command> {
    let (command, administrator) = connection
        .query_row(
            "SELECT command,administrator_id FROM control_outbox WHERE peer_id=?1 AND job_id=?2",
            params![job.peer_id, job.job_id],
            |row| match row.get_ref(0)? {
                ValueRef::Blob(bytes) if !bytes.is_empty() && bytes.len() <= MAX_COMMAND_BYTES => {
                    Ok((bytes.to_vec(), row.get::<_, String>(1)?))
                }
                value => Err(rusqlite::Error::InvalidColumnType(
                    0,
                    "command".into(),
                    value.data_type(),
                )),
            },
        )
        .map_err(|error| sqlite_error("cannot read bounded pending command", error))?;
    let command = decode(&command)?;
    if command.change.control_version() == 5 && read_overview(connection)?.schema_version < 19 {
        return Err(corrupt());
    }
    if command.target_node_id != job.peer_id
        || command.epoch != job.epoch
        || command.command_id != job.command_id
        || Some(command.expected_policy_revision) != job.expected_policy_revision
        || !valid_id(&administrator)
        || command.source_administrator_id != administrator
    {
        return Err(corrupt());
    }
    Ok(command)
}

/// Persist only public terminal receipt metadata, never the returned secret.
/// A stale response cannot finish a replacement job with another stable ID.
pub(in crate::manage) fn complete(
    directory: &Path,
    peer: &str,
    job_id: &str,
    receipt: &super::Receipt,
) -> io::Result<Job> {
    complete_inner(directory, peer, job_id, receipt, None)
}

/// Complete only the exact retained CreateUser observation. The target and
/// action are checked again in the receipt transaction, after network I/O.
/// This may record a rejection, but never returns or reconstructs a secret.
pub(in crate::manage) fn complete_user_result(
    directory: &Path,
    peer: &str,
    job_id: &str,
    target_revision: u64,
    receipt: &super::Receipt,
) -> io::Result<Job> {
    complete_inner(directory, peer, job_id, receipt, Some(target_revision))
}

fn complete_inner(
    directory: &Path,
    peer: &str,
    job_id: &str,
    receipt: &super::Receipt,
    user_result_target_revision: Option<u64>,
) -> io::Result<Job> {
    validate_job(peer, job_id)?;
    let _gate = super::update_lock(directory)?;
    let mut connection = super::peers::open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin command receipt", e))?;
    let job = complete_inner_in(
        &transaction,
        peer,
        job_id,
        receipt,
        user_result_target_revision,
    )?;
    transaction
        .commit()
        .map_err(|e| sqlite_error("cannot commit command receipt", e))?;
    Ok(job)
}

/// Bind public receipt metadata to the original intent before changing its
/// outbox/history and monotonic floors. No secret or replacement result is saved.
fn complete_inner_in(
    transaction: &Connection,
    peer: &str,
    job_id: &str,
    receipt: &super::Receipt,
    user_result_target_revision: Option<u64>,
) -> io::Result<Job> {
    require_transaction(transaction)?;
    require_schema(transaction)?;
    let previous = current_job(transaction, peer)?.ok_or_else(missing)?;
    if previous.job_id != job_id
        || previous.epoch != receipt.epoch
        || previous.command_id != receipt.command_id
    {
        return Err(conflict());
    }
    if let Some(revision) = user_result_target_revision {
        if !previous.user_creation || previous.endpoint.is_some() {
            return Err(input());
        }
        if !matches!(
            previous.state,
            JobState::Pending | JobState::Blocked | JobState::Saved | JobState::Applied
        ) {
            return Err(conflict());
        }
        let target = find_target(transaction, peer)?.ok_or_else(missing)?;
        if target.revision != revision
            || !target.active
            || target.retired
            || target.rollback_detected
        {
            return Err(denied());
        }
        require_peer(transaction, peer)?;
        if receipt.version != 1
            || receipt.credential_id.is_some()
            || receipt.routing.is_some()
            || receipt.preset.is_some()
        {
            return Err(corrupt());
        }
    }
    let command = read_command(transaction, &previous)?;
    validate_receipt_reference(&command, receipt)?;
    let state = match receipt.status {
        super::ReceiptStatus::Saved => JobState::Saved,
        super::ReceiptStatus::Applied => JobState::Applied,
        super::ReceiptStatus::Rejected => JobState::Rejected,
    };
    let expected = previous
        .expected_policy_revision
        .and_then(|revision| revision.checked_add(1))
        .filter(|value| *value <= i64::MAX as u64);
    if state == JobState::Rejected {
        if receipt.policy_revision.is_some()
            || receipt.user_id.is_some()
            || receipt.credential_id.is_some()
            || receipt.routing.is_some()
            || receipt.preset.is_some()
            || !matches!(
                receipt.rejection,
                Some(
                    "invalid_policy" | "policy_conflict" | "resource_not_found" | "policy_capacity"
                )
            )
        {
            return Err(corrupt());
        }
    } else if expected.is_none()
        || receipt.policy_revision != expected
        || receipt.rejection.is_some()
        || (receipt.version == 1 && !receipt.user_id.as_ref().is_some_and(|id| valid_id(id)))
        || receipt
            .credential_id
            .as_ref()
            .is_some_and(|id| !valid_id(id))
    {
        return Err(corrupt());
    }
    let allowed = match previous.state {
        JobState::Pending | JobState::Blocked => true,
        JobState::Saved => {
            matches!(state, JobState::Saved | JobState::Applied)
                && previous.policy_revision == receipt.policy_revision
                && previous.routing == receipt.routing
                && previous.preset == receipt.preset
        }
        JobState::Applied => {
            state == JobState::Applied
                && previous.policy_revision == receipt.policy_revision
                && previous.routing == receipt.routing
                && previous.preset == receipt.preset
        }
        JobState::Rejected => state == JobState::Rejected,
        JobState::Superseded => false,
    };
    if !allowed {
        return Err(conflict());
    }
    transaction.execute("UPDATE control_outbox SET state=?1,policy_revision=?2,outcome_code=?3,next_attempt=0,routing_kind=?5,routing_id=?6,preset_kind=?7,preset_id=?8 WHERE peer_id=?4 AND NOT(state IS ?1 AND policy_revision IS ?2 AND outcome_code IS ?3 AND next_attempt=0 AND routing_kind IS ?5 AND routing_id IS ?6 AND preset_kind IS ?7 AND preset_id IS ?8)",
        params![state.as_str(),receipt.policy_revision.map(sql).transpose()?,
            receipt.rejection.map(|_| "remote_rejected"),peer,receipt.routing.as_ref().map(|value|value.kind.as_str()),receipt.routing.as_ref().map(|value|value.id.as_str()),receipt.preset.as_ref().map(|value|value.kind.as_str()),receipt.preset.as_ref().map(|value|value.id.as_str())])
        .map_err(|e| sqlite_error("cannot save command receipt", e))?;
    // The receipt advances this epoch's observed high-water mark. A rejected
    // command changes no policy; its previous saved revision remains the floor.
    transaction
        .execute(
            "UPDATE managed_targets SET observed_command=max(observed_command,?1),
        observed_policy_revision=max(observed_policy_revision,coalesce(?2,observed_policy_revision))
        WHERE peer_id=?3 AND observed_epoch=?4
          AND (observed_command<?1 OR observed_policy_revision<?2)",
            params![
                sql(receipt.command_id)?,
                receipt.policy_revision.map(sql).transpose()?,
                peer,
                sql(receipt.epoch)?
            ],
        )
        .map_err(|e| sqlite_error("cannot save command observation", e))?;
    let job = current_job(transaction, peer)?.ok_or_else(corrupt)?;
    history::update_current(
        transaction,
        &job,
        Some((&receipt.user_id, &receipt.credential_id)),
    )?;
    Ok(job)
}

/// Transport uncertainty retains the original sequence and payload. Only a
/// fixed local error category is stored, not an untrusted transport/body string.
pub(in crate::manage) fn failed(
    directory: &Path,
    peer: &str,
    job_id: &str,
    blocked: bool,
    now: u64,
) -> io::Result<()> {
    validate_job(peer, job_id)?;
    sql(now)?;
    let _gate = super::update_lock(directory)?;
    let mut connection = super::peers::open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin controller retry", e))?;
    failed_in(&transaction, peer, job_id, blocked, now)?;
    transaction
        .commit()
        .map_err(|e| sqlite_error("cannot commit controller retry", e))?;
    Ok(())
}

/// Retain original command identity while recording bounded retry backoff.
/// Telemetry saturation and exact repeats must not fabricate another effect.
fn failed_in(
    transaction: &Connection,
    peer: &str,
    job_id: &str,
    blocked: bool,
    now: u64,
) -> io::Result<()> {
    require_transaction(transaction)?;
    require_schema(transaction)?;
    let previous = current_job(transaction, peer)?.ok_or_else(missing)?;
    if previous.job_id != job_id || !previous.state.unsettled() {
        return Err(conflict());
    }
    // Saturate telemetry, not the retry state machine. Explicit retry can reset
    // the count, and wall-clock rollback is handled by pending's bounded horizon.
    let attempts = previous.attempts.saturating_add(1);
    let delay = (1_u64 << attempts.min(6)).min(MAX_RETRY_DELAY);
    let next = now
        .checked_add(delay)
        .filter(|v| *v <= i64::MAX as u64)
        .unwrap_or(i64::MAX as u64);
    transaction.execute("UPDATE control_outbox SET state=?1,attempts=?2,next_attempt=?3,outcome_code=?4 WHERE peer_id=?5 AND NOT(state IS ?1 AND attempts IS ?2 AND next_attempt IS ?3 AND outcome_code IS ?4)",
        params![if blocked {"blocked"} else {"pending"},i64::from(attempts),sql(next)?,
            if blocked {"node_permission_or_state"} else {"node_unavailable"},peer])
        .map_err(|e| sqlite_error("cannot save controller retry", e))?;
    let job = current_job(transaction, peer)?.ok_or_else(corrupt)?;
    history::update_current(transaction, &job, None)?;
    Ok(())
}

/// Explicitly retries exactly one unresolved command without changing its identity.
///
/// Only a real local administrator may reset pending/blocked backoff. Terminal
/// outcomes cannot be replayed through retry, and rollback floors are preserved.
pub(in crate::manage) fn retry(
    directory: &Path,
    administrator: &str,
    peer: &str,
    job_id: &str,
) -> io::Result<Job> {
    validate_job(peer, job_id)?;
    let _gate = super::update_lock(directory)?;
    let mut connection = super::peers::open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin explicit command retry", error))?;
    let job = retry_in(&transaction, administrator, peer, job_id)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit explicit command retry", error))?;
    Ok(job)
}

/// Recheck administrator and current target/peer before rescheduling the
/// same validated bytes and ID. Explicit retry never allocates a command number.
fn retry_in(
    transaction: &Connection,
    administrator: &str,
    peer: &str,
    job_id: &str,
) -> io::Result<Job> {
    require_transaction(transaction)?;
    require_schema(transaction)?;
    authorize_administrator(transaction, administrator)?;
    let target = find_target(transaction, peer)?.ok_or_else(missing)?;
    if !target.active || target.retired || target.rollback_detected {
        return Err(denied());
    }
    require_peer(transaction, peer)?;
    let job = current_job(transaction, peer)?.ok_or_else(missing)?;
    if job.job_id != job_id || !job.state.unsettled() {
        return Err(conflict());
    }
    // Validate stored bytes before rescheduling, not after a successful audit.
    let command = endpoints::read_intent(transaction, &job)?;
    transaction.execute("UPDATE control_outbox SET state='pending',attempts=0,next_attempt=0,outcome_code=NULL WHERE peer_id=?1 AND job_id=?2",params![peer,job_id]).map_err(|error|sqlite_error("cannot reset command retry",error))?;
    endpoints::audit_intent(
        transaction,
        administrator,
        "retry",
        &target,
        job_id,
        &command,
    )?;
    let job = current_job(transaction, peer)?.ok_or_else(corrupt)?;
    history::update_current(transaction, &job, None)?;
    Ok(job)
}

/// Retires uncertainty only after a trusted observation proves the old slot is spent.
///
/// A newer epoch or this epoch's high-water >= command proves resending cannot
/// become a new mutation. This is not proof whether the old command applied.
/// Preserves all observation floors and records the actual local administrator.
pub(in crate::manage) fn supersede(
    directory: &Path,
    administrator: &str,
    peer: &str,
    job_id: &str,
) -> io::Result<Job> {
    validate_job(peer, job_id)?;
    let _gate = super::update_lock(directory)?;
    let mut connection = super::peers::open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin command supersession", error))?;
    let job = supersede_in(&transaction, administrator, peer, job_id)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit command supersession", error))?;
    Ok(job)
}

/// Retire uncertainty only when trusted floors prove the old slot is spent.
/// This does not prove whether the child's original mutation applied.
fn supersede_in(
    transaction: &Connection,
    administrator: &str,
    peer: &str,
    job_id: &str,
) -> io::Result<Job> {
    require_transaction(transaction)?;
    require_schema(transaction)?;
    authorize_administrator(transaction, administrator)?;
    let target = find_target(transaction, peer)?.ok_or_else(missing)?;
    let previous = current_job(transaction, peer)?.ok_or_else(missing)?;
    if previous.job_id != job_id || !previous.state.unsettled() {
        return Err(conflict());
    }
    let spent = target
        .observed_epoch
        .is_some_and(|epoch| epoch > previous.epoch)
        || (target.observed_epoch == Some(previous.epoch)
            && target
                .observed_command
                .is_some_and(|command| command >= previous.command_id));
    if !spent {
        return Err(conflict());
    }
    let command = endpoints::read_intent(transaction, &previous)?;
    transaction.execute("UPDATE control_outbox SET state='superseded',next_attempt=0,outcome_code=NULL WHERE peer_id=?1 AND job_id=?2",params![peer,job_id]).map_err(|error|sqlite_error("cannot supersede command",error))?;
    endpoints::audit_intent(
        transaction,
        administrator,
        "supersede",
        &target,
        job_id,
        &command,
    )?;
    let job = current_job(transaction, peer)?.ok_or_else(corrupt)?;
    history::update_current(transaction, &job, None)?;
    Ok(job)
}

fn require_schema(connection: &Connection) -> io::Result<Overview> {
    let overview = read_overview(connection)?;
    if overview.schema_version < 10 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "management schema migration is required for target metadata",
        ));
    }
    Ok(overview)
}

fn require_transaction(connection: &Connection) -> io::Result<()> {
    if connection.is_autocommit() {
        return Err(input());
    }
    Ok(())
}

fn validate_configuration(
    peer: &str,
    origin: &str,
    server_ip: Option<Option<IpAddr>>,
) -> io::Result<()> {
    if !valid_id(peer) {
        return Err(input());
    }
    PublicOrigin::parse(origin).map_err(|_| input())?;
    if server_ip.flatten().is_some_and(|ip| !valid_server_ip(ip)) {
        return Err(input());
    }
    Ok(())
}

fn validate_state(peer: &str, active: bool, retire: bool) -> io::Result<()> {
    if !valid_id(peer) || (retire && active) {
        return Err(input());
    }
    Ok(())
}

fn validate_observation(peer: &str, epoch: u64, command: u64, revision: u64) -> io::Result<()> {
    if !valid_id(peer) || epoch == 0 || revision == 0 {
        return Err(input());
    }
    sql(epoch)?;
    sql(command)?;
    sql(revision)?;
    Ok(())
}

fn validate_job(peer: &str, job_id: &str) -> io::Result<()> {
    if !valid_id(peer) || !valid_id(job_id) {
        return Err(input());
    }
    Ok(())
}
fn authorize_administrator(connection: &Connection, administrator: &str) -> io::Result<()> {
    if !valid_id(administrator) {
        return Err(denied());
    }
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM administrators WHERE id=?1)",
            [administrator],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot authorize controller administrator", e))?;
    if exists { Ok(()) } else { Err(denied()) }
}
fn require_peer(connection: &Connection, peer: &str) -> io::Result<()> {
    let state:Option<(i64,i64,i64)>=connection.query_row("SELECT p.active,
        sum(CASE WHEN c.revoked=0 THEN 1 ELSE 0 END),sum(CASE WHEN c.revoked NOT IN (0,1) THEN 1 ELSE 0 END)
        FROM peers p LEFT JOIN peer_certificates c ON c.node_id=p.node_id WHERE p.node_id=?1 GROUP BY p.node_id",[peer],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()
        .map_err(|error|sqlite_error("cannot authorize controller destination",error))?;
    match state {
        Some((active, _, bad)) if ![0, 1].contains(&active) || bad != 0 => Err(corrupt()),
        Some((1, certificates, 0)) if certificates > 0 => Ok(()),
        _ => Err(denied()),
    }
}
fn find_target(connection: &Connection, peer: &str) -> io::Result<Option<Target>> {
    let target = connection
        .query_row(
            "SELECT t.peer_id,p.name,t.origin,t.active,t.retired,t.revision,
        t.observed_epoch,t.observed_command,t.observed_policy_revision,t.rollback_detected,t.server_ip
        FROM managed_targets t LEFT JOIN peers p ON p.node_id=t.peer_id WHERE t.peer_id=?1",
            [peer],
            target_row,
        )
        .optional()
        .map_err(|e| sqlite_error("cannot inspect managed target", e))?;
    if let Some(target) = &target {
        validate_target(target)?;
    }
    Ok(target)
}
fn target_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Target> {
    Ok(Target {
        peer_id: row.get(0)?,
        name: row.get(1)?,
        origin: row.get(2)?,
        active: read_bool(row, 3)?,
        retired: read_bool(row, 4)?,
        revision: unsigned(row.get(5)?, 5)?,
        observed_epoch: optional_unsigned(row.get(6)?, 6)?,
        observed_command: optional_unsigned(row.get(7)?, 7)?,
        observed_policy_revision: optional_unsigned(row.get(8)?, 8)?,
        rollback_detected: read_bool(row, 9)?,
        server_ip: row
            .get::<_, Option<String>>(10)?
            .map(|value| {
                parse_server_ip(&value)
                    .and_then(|ip| {
                        if ip.to_string() == value {
                            Ok(ip)
                        } else {
                            Err(corrupt())
                        }
                    })
                    .map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            10,
                            rusqlite::types::Type::Text,
                            Box::new(corrupt()),
                        )
                    })
            })
            .transpose()?,
    })
}
fn read_bool(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<bool> {
    match row.get::<_, i64>(index)? {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(rusqlite::Error::IntegralValueOutOfRange(index, value)),
    }
}
fn validate_target(target: &Target) -> io::Result<()> {
    if !valid_id(&target.peer_id)
        || target.name.is_empty()
        || target.name.len() > 128
        || target.name.trim() != target.name
        || target.name.chars().any(char::is_control)
        || target.revision == 0
        || (target.retired && target.active)
        || target.observed_epoch == Some(0)
        || target.observed_policy_revision == Some(0)
        || target.observed_epoch.is_some() != target.observed_command.is_some()
        || target.observed_epoch.is_some() != target.observed_policy_revision.is_some()
        || PublicOrigin::parse(&target.origin).is_err()
    {
        return Err(corrupt());
    }
    Ok(())
}
fn current_job(connection: &Connection, peer: &str) -> io::Result<Option<Job>> {
    current_job_for_schema(connection, peer, read_overview(connection)?.schema_version)
}

/// Reads typed job state using a version validated by `read_overview` in the
/// same unchanged snapshot. Never reuse the version across transactions or
/// after a write; resource, row and payload validation still runs on every read.
fn current_job_for_schema(
    connection: &Connection,
    peer: &str,
    schema_version: u32,
) -> io::Result<Option<Job>> {
    if schema_version >= 15 {
        let resource: Option<(String, bool)> = connection
            .query_row(
                "SELECT resource,CASE resource WHEN 'proxy_policy' THEN expected_metadata_revision IS NULL AND metadata_revision IS NULL WHEN 'proxy_endpoints' THEN expected_policy_revision IS NULL AND policy_revision IS NULL AND routing_kind IS NULL AND routing_id IS NULL AND preset_kind IS NULL AND preset_id IS NULL ELSE 0 END FROM control_outbox WHERE peer_id=?1",
                [peer],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| sqlite_error("cannot inspect controller command resource", e))?;
        match resource
            .as_ref()
            .map(|(kind, valid)| (kind.as_str(), *valid))
        {
            Some(("proxy_endpoints", true)) => return endpoints::current_job(connection, peer),
            Some(("proxy_policy", true)) | None => {}
            _ => return Err(corrupt()),
        }
    }
    let job = connection.query_row("SELECT peer_id,job_id,controller_epoch,command_id,expected_policy_revision,
        state,policy_revision,outcome_code,attempts,next_attempt,routing_kind,routing_id,preset_kind,preset_id FROM control_outbox WHERE peer_id=?1", [peer], |row| {
        Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,unsigned(row.get(2)?,2)?,unsigned(row.get(3)?,3)?,
            unsigned(row.get(4)?,4)?,row.get::<_,String>(5)?,optional_unsigned(row.get(6)?,6)?,row.get::<_,Option<String>>(7)?,
            row.get::<_,u32>(8)?,unsigned(row.get(9)?,9)?,row.get::<_,Option<String>>(10)?,row.get::<_,Option<String>>(11)?,row.get::<_,Option<String>>(12)?,row.get::<_,Option<String>>(13)?))
    }).optional().map_err(|e| sqlite_error("cannot inspect controller command", e))?;
    job.map(
        |(
            peer_id,
            job_id,
            epoch,
            command_id,
            expected_policy_revision,
            state,
            policy_revision,
            outcome_code,
            attempts,
            next_attempt,
            kind,
            id,
            preset_kind,
            preset_id,
        )| {
            let routing = super::control::read_routing(kind, id)?;
            let preset = super::control::read_preset(preset_kind, preset_id)?;
            if !valid_id(&peer_id)
                || !valid_id(&job_id)
                || epoch == 0
                || command_id == 0
                || expected_policy_revision == 0
                || policy_revision == Some(0)
                || outcome_code.as_ref().is_some_and(|code| {
                    !matches!(
                        code.as_str(),
                        "remote_rejected" | "node_permission_or_state" | "node_unavailable"
                    )
                })
            {
                return Err(corrupt());
            }
            let state = JobState::parse(&state)?;
            let expected = expected_policy_revision
                .checked_add(1)
                .filter(|value| *value <= i64::MAX as u64);
            let valid = match state {
                JobState::Pending => {
                    policy_revision.is_none()
                        && matches!(outcome_code.as_deref(), None | Some("node_unavailable"))
                }
                JobState::Blocked => {
                    policy_revision.is_none()
                        && outcome_code.as_deref() == Some("node_permission_or_state")
                }
                JobState::Saved | JobState::Applied => {
                    expected.is_some() && policy_revision == expected && outcome_code.is_none()
                }
                JobState::Rejected => {
                    policy_revision.is_none() && outcome_code.as_deref() == Some("remote_rejected")
                }
                JobState::Superseded => policy_revision.is_none() && outcome_code.is_none(),
            };
            if !valid
                || (!state.unsettled() && next_attempt != 0)
                || (!matches!(state, JobState::Saved | JobState::Applied) && routing.is_some())
                || (!matches!(state, JobState::Saved | JobState::Applied) && preset.is_some())
            {
                return Err(corrupt());
            }
            let mut job = Job {
                maintenance: None,
                user_creation: false,
                routing,
                preset,
                peer_id,
                job_id,
                epoch,
                command_id,
                expected_policy_revision: Some(expected_policy_revision),
                expected_metadata_revision: None,
                metadata_revision: None,
                endpoint: None,
                state,
                policy_revision,
                outcome_code,
                attempts,
                next_attempt,
            };
            let command = read_command(connection, &job)?;
            job.user_creation = matches!(&command.change, PolicyChange::CreateUser { .. });
            job.maintenance = match &command.change {
                PolicyChange::SetAdmission { accepting } => Some(*accepting),
                _ => None,
            };
            if matches!(job.state, JobState::Saved | JobState::Applied) {
                if (command.change.control_version() == 2) != job.routing.is_some() {
                    return Err(corrupt());
                }
                if (command.change.control_version() == 3) != job.preset.is_some() {
                    return Err(corrupt());
                }
                if job.routing.is_some() || job.preset.is_some() {
                    validate_receipt_reference(
                        &command,
                        &super::Receipt {
                            version: command.change.control_version(),
                            epoch: job.epoch,
                            command_id: job.command_id,
                            status: super::ReceiptStatus::Saved,
                            policy_revision: job.policy_revision,
                            rejection: None,
                            user_id: None,
                            credential_id: None,
                            routing: job.routing.clone(),
                            preset: job.preset.clone(),
                        },
                    )?;
                }
            }
            Ok(job)
        },
    )
    .transpose()
}
fn audit(
    connection: &Connection,
    administrator: &str,
    action: &str,
    peer: &str,
    revision: u64,
    job_id: Option<&str>,
    command: Option<&Command>,
) -> io::Result<()> {
    let latest: i64 = connection
        .query_row(
            "SELECT coalesce(max(sequence),0) FROM controller_audit",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot read controller audit sequence", e))?;
    let next = latest.checked_add(1).ok_or_else(conflict)?;
    connection
        .execute(
            "INSERT INTO controller_audit(sequence,administrator_id,action,peer_id,target_revision,
                job_id,controller_epoch,command_id,mutation_action,recorded_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,unixepoch())",
            params![
                next,
                administrator,
                action,
                peer,
                sql(revision)?,
                job_id,
                command.map(|command| sql(command.epoch)).transpose()?,
                command.map(|command| sql(command.command_id)).transpose()?,
                command
                    .map(|command| mutation_action(&command.change))
                    .transpose()?,
            ],
        )
        .map_err(|e| sqlite_error("cannot audit controller operation", e))?;
    connection
        .execute(
            "DELETE FROM controller_audit WHERE sequence IN (SELECT sequence FROM controller_audit
        ORDER BY sequence DESC LIMIT -1 OFFSET ?1)",
            [MAX_AUDIT],
        )
        .map_err(|e| sqlite_error("cannot prune controller audit", e))?;
    Ok(())
}

/// Retains only the fixed operation category after the replaceable outbox advances.
/// Wall-clock audit timestamps aid operators but never order or authorize commands.
fn mutation_action(change: &PolicyChange) -> io::Result<&'static str> {
    Ok(match change {
        PolicyChange::SetAdmission { .. } => "set_admission",
        PolicyChange::CreateUser { .. } => "create_user",
        PolicyChange::UpdateUser { .. } => "update_user",
        PolicyChange::SetUserActive { .. } => "set_user_active",
        PolicyChange::DeleteUser { .. } => "delete_user",
        PolicyChange::CreateCredential { .. } => "create_credential",
        PolicyChange::SetCredentialActive { .. } => "set_credential_active",
        PolicyChange::RotateCredential { .. } => "rotate_credential",
        PolicyChange::RevokeCredential { .. } => "revoke_credential",
        PolicyChange::CreatePrefix { .. } => "create_prefix",
        PolicyChange::RetirePrefix { .. } => "retire_prefix",
        PolicyChange::CreateAddress { .. } => "create_address",
        PolicyChange::SetAddressState { .. } => "set_address_state",
        PolicyChange::CreatePool { .. } => "create_pool",
        PolicyChange::SetPoolState { .. } => "set_pool_state",
        PolicyChange::AddPoolMember { .. } => "add_pool_member",
        PolicyChange::RemovePoolMember { .. } => "remove_pool_member",
        PolicyChange::SetRoutePermission(..) => "set_route_permission",
        PolicyChange::SetUserPresets { .. } => "set_user_presets",
        PolicyChange::SetPoolPreset { .. } => "set_pool_preset",
    })
}
fn unsigned(value: i64, index: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}
fn optional_unsigned(value: Option<i64>, index: usize) -> rusqlite::Result<Option<u64>> {
    value.map(|v| unsigned(v, index)).transpose()
}
fn sql(value: u64) -> io::Result<i64> {
    i64::try_from(value).map_err(|_| input())
}
fn increment(value: u64) -> io::Result<u64> {
    value
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or_else(conflict)
}
fn input() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid controller target input",
    )
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "controller operation is not authorized",
    )
}
fn conflict() -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        "controller target or command changed",
    )
}
fn missing() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "controller target or command not found",
    )
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCommand {
    version: u8,
    target_node_id: String,
    epoch: u64,
    command_id: u64,
    expected_policy_revision: u64,
    source_administrator_id: String,
    mutation: PolicyChange,
}

fn encode(command: &Command) -> io::Result<Vec<u8>> {
    let stored = StoredCommand {
        version: command.change.control_version(),
        target_node_id: command.target_node_id.clone(),
        epoch: command.epoch,
        command_id: command.command_id,
        expected_policy_revision: command.expected_policy_revision,
        source_administrator_id: command.source_administrator_id.clone(),
        mutation: command.change.clone(),
    };
    validate_command(&stored)?;
    let bytes = serde_json::to_vec(&stored).map_err(|_| input())?;
    if bytes.len() > MAX_COMMAND_BYTES {
        return Err(input());
    }
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> io::Result<Command> {
    if bytes.len() > MAX_COMMAND_BYTES {
        return Err(corrupt());
    }
    let stored: StoredCommand = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
    validate_command(&stored).map_err(|_| corrupt())?;
    Ok(Command {
        target_node_id: stored.target_node_id,
        epoch: stored.epoch,
        command_id: stored.command_id,
        expected_policy_revision: stored.expected_policy_revision,
        source_administrator_id: stored.source_administrator_id,
        change: stored.mutation,
    })
}
fn validate_command(command: &StoredCommand) -> io::Result<()> {
    if command.version != command.mutation.control_version()
        || !valid_id(&command.target_node_id)
        || !valid_id(&command.source_administrator_id)
        || command.epoch == 0
        || command.command_id == 0
        || command.expected_policy_revision == 0
    {
        return Err(input());
    }
    sql(command.epoch)?;
    sql(command.command_id)?;
    sql(command.expected_policy_revision)?;
    Ok(())
}
/// Correlate terminal identities against the exact durable action, before any
/// outbox state transition. A well-shaped receipt for another entity is invalid.
fn validate_receipt_reference(command: &Command, receipt: &super::Receipt) -> io::Result<()> {
    if receipt.version != command.change.control_version() {
        return Err(corrupt());
    }
    if receipt.status == super::ReceiptStatus::Rejected {
        return if receipt.routing.is_none()
            && receipt.preset.is_none()
            && receipt.user_id.is_none()
            && receipt.credential_id.is_none()
        {
            Ok(())
        } else {
            Err(corrupt())
        };
    }
    if receipt.version == 5 {
        return if matches!(&command.change, PolicyChange::SetAdmission { .. })
            && receipt.user_id.is_none()
            && receipt.credential_id.is_none()
            && receipt.routing.is_none()
            && receipt.preset.is_none()
        {
            Ok(())
        } else {
            Err(corrupt())
        };
    }
    if receipt.version == 3 {
        if receipt.user_id.is_some() || receipt.credential_id.is_some() || receipt.routing.is_some()
        {
            return Err(corrupt());
        }
        let expected = match &command.change {
            PolicyChange::SetUserPresets { presets } => PresetReceipt {
                kind: PresetKind::User,
                id: presets.user_id.clone(),
            },
            PolicyChange::SetPoolPreset { preset } => PresetReceipt {
                kind: PresetKind::Pool,
                id: preset.pool_id.clone(),
            },
            _ => return Err(corrupt()),
        };
        return if valid_id(&expected.id) && receipt.preset.as_ref() == Some(&expected) {
            Ok(())
        } else {
            Err(corrupt())
        };
    }
    if receipt.preset.is_some() {
        return Err(corrupt());
    }
    if receipt.version == 1 {
        if receipt.routing.is_some() || !receipt.user_id.as_ref().is_some_and(|id| valid_id(id)) {
            return Err(corrupt());
        }
        let (user, credential) = match &command.change {
            PolicyChange::CreateUser { .. } => (None, None),
            PolicyChange::UpdateUser { id, .. }
            | PolicyChange::SetUserActive { id, .. }
            | PolicyChange::DeleteUser { id } => (Some(id), None),
            PolicyChange::CreateCredential { user_id } => (Some(user_id), None),
            PolicyChange::SetCredentialActive { id, .. }
            | PolicyChange::RotateCredential { id }
            | PolicyChange::RevokeCredential { id } => (None, Some(id)),
            _ => return Err(corrupt()),
        };
        if user.is_some_and(|id| receipt.user_id.as_ref() != Some(id))
            || credential.is_some_and(|id| receipt.credential_id.as_ref() != Some(id))
        {
            return Err(corrupt());
        }
        return Ok(());
    }
    if receipt.user_id.is_some() || receipt.credential_id.is_some() {
        return Err(corrupt());
    }
    let reference = receipt
        .routing
        .as_ref()
        .filter(|reference| valid_id(&reference.id))
        .ok_or_else(corrupt)?;
    let (kind, id) = match &command.change {
        PolicyChange::CreatePrefix { .. } => (RoutingKind::Prefix, None),
        PolicyChange::RetirePrefix { id } => (RoutingKind::Prefix, Some(id)),
        PolicyChange::CreateAddress { .. } => (RoutingKind::Address, None),
        PolicyChange::SetAddressState { id, .. } => (RoutingKind::Address, Some(id)),
        PolicyChange::CreatePool { .. } => (RoutingKind::Pool, None),
        PolicyChange::SetPoolState { id, .. } => (RoutingKind::Pool, Some(id)),
        PolicyChange::AddPoolMember { pool_id, .. }
        | PolicyChange::RemovePoolMember { pool_id, .. } => (RoutingKind::Pool, Some(pool_id)),
        PolicyChange::SetRoutePermission(permission) => {
            (RoutingKind::Permission, Some(&permission.user_id))
        }
        _ => return Err(corrupt()),
    };
    if reference.kind != kind || id.is_some_and(|id| id != &reference.id) {
        return Err(corrupt());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_host_prefix_outbox_json_keeps_bare_hosts_and_exact_bytes() -> io::Result<()> {
        let cases: [(&str, &[u8]); 2] = [
        (
            "192.0.2.1/32",
            br#"{"version":2,"target_node_id":"AAAAAAAAAAAAAAAAAAAAAA","epoch":2,"command_id":1,"expected_policy_revision":1,"source_administrator_id":"AQEBAQEBAQEBAQEBAQEBAQ","mutation":{"action":"create_prefix","name":"golden host prefix","cidr":"192.0.2.1"}}"#,
        ),
        (
            "2001:db8::1/128",
            br#"{"version":2,"target_node_id":"AAAAAAAAAAAAAAAAAAAAAA","epoch":2,"command_id":1,"expected_policy_revision":1,"source_administrator_id":"AQEBAQEBAQEBAQEBAQEBAQ","mutation":{"action":"create_prefix","name":"golden host prefix","cidr":"2001:db8::1"}}"#,
        ),
    ];
        for (masked, expected) in cases {
            let command = decode(expected)?;
            let PolicyChange::CreatePrefix { name, cidr } = &command.change else {
                panic!("old host prefix decoded as another mutation")
            };
            assert_eq!(name, "golden host prefix");
            assert_eq!(
                *cidr,
                masked.parse::<cidr::IpCidr>().map_err(io::Error::other)?
            );
            assert_eq!(encode(&command)?, expected);
        }
        Ok(())
    }
}
