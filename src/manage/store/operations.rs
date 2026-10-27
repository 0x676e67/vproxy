//! Bounded, actor-bound identities for non-secret local user changes.
//!
//! Reservations do not alter policy. Only an existing reservation may execute;
//! clearing old rows never turns their IDs into permission to execute again.
//! Policy and its terminal saved receipt commit in one immediate transaction.

use std::{collections::HashMap, fmt, io, path::Path, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{Connection, Row, TransactionBehavior, params, types::ValueRef};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    UpdateGuard, automation, invalid_data,
    peers::open_existing,
    read_overview, sqlite_error,
    users::{self, Actor, ChangeResult, PolicyChange},
    valid_id,
};
use crate::access::Protocol;

const MAX_OPERATIONS: usize = 4_096;
const MAX_ACTOR_OPERATIONS: usize = 256;
const MAX_PAGE: u32 = 50;
const COLUMNS: &str = "id,node_id,administrator_id,sequence,expected_revision,expected_epoch,action,digest,user_id,state,saved_revision,rejection";

/// Verified request material is retained until the real transaction rechecks it.
/// An automation principal never borrows its creator's administrator authority.
#[derive(Clone)]
pub(in crate::manage) enum Caller {
    Administrator(String),
    Automation(Arc<automation::Credential>),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum ActorKey {
    Administrator(String),
    Automation(String),
}

impl ActorKey {
    fn id(&self) -> &str {
        match self {
            Self::Administrator(id) | Self::Automation(id) => id,
        }
    }
    fn column(&self) -> &'static str {
        match self {
            Self::Administrator(_) => "administrator_id",
            Self::Automation(_) => "automation_principal_id",
        }
    }
}

#[derive(Clone, Copy)]
struct Layout {
    automation: bool,
}

impl Layout {
    fn columns(self) -> String {
        format!(
            "{COLUMNS},{}",
            if self.automation {
                "automation_principal_id"
            } else {
                "NULL"
            }
        )
    }
}

struct Authorized {
    node: String,
    actor: ActorKey,
    generation: Option<u64>,
    layout: Layout,
}

/// One authorized read snapshot, not permission for a later mutation. An owned
/// node remains inspectable so callers can explain why local writes are denied.
#[derive(Serialize)]
pub(in crate::manage) struct Context {
    pub(in crate::manage) node_id: String,
    pub(in crate::manage) policy_revision: u64,
    pub(in crate::manage) expected_epoch: u64,
    pub(in crate::manage) local: bool,
}

/// Fixed, wire-safe failures. A missing/pruned ID is never an invitation to
/// reserve or execute that ID again, and is not proof that no effect occurred.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(in crate::manage) enum Error {
    #[error("operation management requires explicit schema migration")]
    UpgradeRequired,
    #[error("invalid local user operation")]
    InvalidOperation,
    #[error("operation result is not queryable")]
    NotQueryable,
    #[error("operation binding conflicts")]
    Conflict,
    #[error("operation sequence capacity is exhausted")]
    Capacity,
    #[error("operation administrator is not authorized")]
    Denied,
}

impl Error {
    pub(in crate::manage) const fn code(self) -> &'static str {
        match self {
            Self::UpgradeRequired => "management_upgrade_required",
            Self::InvalidOperation => "invalid_operation",
            Self::NotQueryable => "operation_not_queryable",
            Self::Conflict => "operation_conflict",
            Self::Capacity => "operation_capacity",
            Self::Denied => "operation_denied",
        }
    }

    fn error(self) -> io::Error {
        let kind = match self {
            Self::InvalidOperation => io::ErrorKind::InvalidInput,
            Self::NotQueryable => io::ErrorKind::NotFound,
            Self::Conflict | Self::Capacity => io::ErrorKind::AlreadyExists,
            Self::Denied => io::ErrorKind::PermissionDenied,
            Self::UpgradeRequired => io::ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }
}

/// The first slice intentionally cannot create, rotate or return a secret.
/// Protocol order is immaterial to the digest; duplicates remain invalid.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::manage) enum UserChange {
    CreateUser {
        name: String,
        protocols: Vec<Protocol>,
        concurrent_limit: u32,
    },
    UpdateUser {
        id: String,
        name: String,
        protocols: Vec<Protocol>,
        concurrent_limit: u32,
    },
    SetUserActive {
        id: String,
        active: bool,
    },
    DeleteUser {
        id: String,
    },
}

impl UserChange {
    pub(in crate::manage) const fn action(&self) -> &'static str {
        match self {
            Self::CreateUser { .. } => "create_user",
            Self::UpdateUser { .. } => "update_user",
            Self::SetUserActive { .. } => "set_user_active",
            Self::DeleteUser { .. } => "delete_user",
        }
    }

    pub(in crate::manage) fn user_id(&self) -> Option<&str> {
        match self {
            Self::CreateUser { .. } => None,
            Self::UpdateUser { id, .. }
            | Self::SetUserActive { id, .. }
            | Self::DeleteUser { id } => Some(id),
        }
    }

    pub(in crate::manage) fn validate(&self) -> io::Result<()> {
        if self.user_id().is_some_and(|id| !valid_id(id)) {
            return Err(Error::InvalidOperation.error());
        }
        match self {
            Self::CreateUser {
                name,
                protocols,
                concurrent_limit,
            }
            | Self::UpdateUser {
                name,
                protocols,
                concurrent_limit,
                ..
            } => users::validate_user_input(name, protocols, *concurrent_limit)
                .map_err(|_| Error::InvalidOperation.error()),
            _ => Ok(()),
        }
    }

    fn policy(self) -> PolicyChange {
        match self {
            Self::CreateUser {
                name,
                protocols,
                concurrent_limit,
            } => PolicyChange::CreateUser {
                name,
                protocols,
                concurrent_limit,
            },
            Self::UpdateUser {
                id,
                name,
                protocols,
                concurrent_limit,
            } => PolicyChange::UpdateUser {
                id,
                name,
                protocols,
                concurrent_limit,
            },
            Self::SetUserActive { id, active } => PolicyChange::SetUserActive { id, active },
            Self::DeleteUser { id } => PolicyChange::DeleteUser { id },
        }
    }
}

/// Actor/node identities come from storage and the authenticated session. An
/// optional node assertion is checked in that transaction, not used to select
/// an identity. It does not change the existing reservation payload digest.
#[derive(Clone)]
pub(in crate::manage) struct Input {
    pub(in crate::manage) expected_node_id: Option<String>,
    pub(in crate::manage) expected_revision: u64,
    pub(in crate::manage) expected_epoch: u64,
    pub(in crate::manage) change: UserChange,
}

impl Input {
    fn digest(&self) -> io::Result<[u8; 32]> {
        if self
            .expected_node_id
            .as_deref()
            .is_some_and(|id| !valid_id(id))
        {
            return Err(Error::InvalidOperation.error());
        }
        users::sql_revision(self.expected_revision).map_err(|_| Error::InvalidOperation.error())?;
        users::sql_revision(self.expected_epoch).map_err(|_| Error::InvalidOperation.error())?;
        self.change.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"vproxy-local-user-operation-v1\0");
        hash.update(self.expected_revision.to_be_bytes());
        hash.update(self.expected_epoch.to_be_bytes());
        text(&mut hash, self.change.action());
        if let Some(id) = self.change.user_id() {
            text(&mut hash, id);
        }
        match &self.change {
            UserChange::CreateUser {
                name,
                protocols,
                concurrent_limit,
            }
            | UserChange::UpdateUser {
                name,
                protocols,
                concurrent_limit,
                ..
            } => {
                text(&mut hash, name);
                let mask = protocols.iter().fold(0_u8, |mask, protocol| {
                    mask | match protocol {
                        Protocol::Http => 1,
                        Protocol::Socks5 => 2,
                        Protocol::Masque => 4,
                    }
                });
                hash.update([mask]);
                hash.update(concurrent_limit.to_be_bytes());
            }
            UserChange::SetUserActive { active, .. } => hash.update([u8::from(*active)]),
            UserChange::DeleteUser { .. } => {}
        }
        Ok(hash.finalize().into())
    }

    /// The caller has already been reauthorized in the write transaction. A
    /// mismatched node must fail before allocation, execution or terminal replay.
    fn require_node(&self, node: &str) -> io::Result<()> {
        if self
            .expected_node_id
            .as_deref()
            .is_some_and(|expected| expected != node)
        {
            return Err(Error::Conflict.error());
        }
        Ok(())
    }
}

fn text(hash: &mut Sha256, value: &str) {
    // Only bounded, already-validated action/name/ID text reaches here.
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value.as_bytes());
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum State {
    Reserved,
    Saved,
    Rejected,
}

/// Immutable request identity plus a non-secret historical result. Saved does
/// not mean that any current runtime or restart has published that revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct Operation {
    pub(in crate::manage) id: String,
    pub(in crate::manage) node_id: String,
    pub(in crate::manage) expected_revision: u64,
    pub(in crate::manage) expected_epoch: u64,
    pub(in crate::manage) action: &'static str,
    pub(in crate::manage) user_id: Option<String>,
    pub(in crate::manage) state: State,
    pub(in crate::manage) saved_revision: Option<u64>,
    pub(in crate::manage) rejection: Option<&'static str>,
    pub(in crate::manage) sequence: u64,
}

pub(in crate::manage) struct Page {
    pub(in crate::manage) items: Vec<Operation>,
    pub(in crate::manage) next_cursor: Option<u64>,
}

/// Only first acceptance contains a policy candidate. Replays must not publish
/// an old policy or reconstruct a user from mutable current data.
pub(in crate::manage) enum Outcome {
    Accepted {
        change: Box<ChangeResult>,
        operation: Operation,
    },
    Replayed(Operation),
    Rejected(Operation),
}

/// Metadata inspection failures cannot invalidate a live Reader. Once policy
/// SQL is attempted, uncertain rollback/commit failures must fail closed in the
/// coordinator. The original I/O error remains available to its usual mapper.
#[derive(Debug)]
pub(in crate::manage) struct ExecuteError {
    policy_uncertain: bool,
    error: io::Error,
}

impl ExecuteError {
    pub(in crate::manage) const fn policy_uncertain(&self) -> bool {
        self.policy_uncertain
    }
    pub(in crate::manage) fn into_error(self) -> io::Error {
        self.error
    }
    fn before(error: io::Error) -> Self {
        Self {
            policy_uncertain: false,
            error,
        }
    }
    fn uncertain(error: io::Error) -> Self {
        Self {
            policy_uncertain: true,
            error,
        }
    }
}

impl fmt::Display for ExecuteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for ExecuteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Initialize inside the caller's init/migration transaction. Sequence is not
/// derived from retained rows, so pruning cannot make a former ID reusable.
pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection
        .execute_batch(
            "CREATE TABLE operations_state (
           singleton INTEGER PRIMARY KEY CHECK(singleton=1),
           last_sequence INTEGER NOT NULL CHECK(last_sequence>=0)
         ) STRICT;
         INSERT INTO operations_state VALUES(1,0);",
        )
        .map_err(|error| sqlite_error("cannot create operation sequence state", error))?;
    create_table(connection, "user_operations", true)?;
    create_indexes(connection, true)
}

// Table names and the actor layout are fixed internal migration choices.
fn create_table(connection: &Connection, name: &str, automation: bool) -> io::Result<()> {
    let actor = if automation {
        "administrator_id TEXT REFERENCES administrators(id) ON DELETE RESTRICT,"
    } else {
        "administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,"
    };
    let principal = if automation {
        "automation_principal_id TEXT REFERENCES automation_principals(id) ON DELETE RESTRICT,
           CHECK((administrator_id IS NOT NULL AND automation_principal_id IS NULL)
             OR (administrator_id IS NULL AND automation_principal_id IS NOT NULL)),"
    } else {
        ""
    };
    connection.execute_batch(&format!(
        "CREATE TABLE {name} (
           id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=22),
           node_id TEXT NOT NULL CHECK(length(node_id)=22),
           {actor}
           sequence INTEGER NOT NULL UNIQUE CHECK(sequence>=1),
           expected_revision INTEGER NOT NULL CHECK(expected_revision>=1),
           expected_epoch INTEGER NOT NULL CHECK(expected_epoch>=1),
           action TEXT NOT NULL CHECK(action IN('create_user','update_user','set_user_active','delete_user')),
           digest BLOB NOT NULL CHECK(length(digest)=32),
           user_id TEXT CHECK(length(user_id)=22),
           state TEXT NOT NULL CHECK(state IN('reserved','saved','rejected')),
           saved_revision INTEGER CHECK(saved_revision>=1),
           rejection TEXT CHECK(rejection IN('invalid_policy','policy_conflict','resource_not_found','policy_capacity','resource_managed','owner_conflict')),
           {principal}
           CHECK((action='create_user' AND (state='saved')=(user_id IS NOT NULL)) OR (action<>'create_user' AND user_id IS NOT NULL)),
           CHECK((state='reserved' AND saved_revision IS NULL AND rejection IS NULL)
             OR (state='saved' AND saved_revision IS NOT NULL AND saved_revision=expected_revision+1 AND rejection IS NULL)
             OR (state='rejected' AND saved_revision IS NULL AND rejection IS NOT NULL))
         ) STRICT;"
    )).map_err(|error| sqlite_error("cannot create local user operation identities", error))
}

fn create_indexes(connection: &Connection, automation: bool) -> io::Result<()> {
    connection.execute_batch("CREATE INDEX user_operations_actor_sequence ON user_operations(administrator_id,sequence);")
        .map_err(|error| sqlite_error("cannot index administrator operations", error))?;
    if automation {
        connection.execute_batch("CREATE INDEX user_operations_principal_sequence ON user_operations(automation_principal_id,sequence);")
            .map_err(|error| sqlite_error("cannot index automation operations", error))?;
    }
    Ok(())
}

/// Preserve every old request byte and the independent sequence highwater.
/// The caller has already backed up and owns the schema migration transaction.
pub(super) fn upgrade_schema(connection: &Connection) -> io::Result<()> {
    create_table(connection, "user_operations_v18", true)?;
    connection
        .execute_batch(&format!(
            "INSERT INTO user_operations_v18({COLUMNS}) SELECT {COLUMNS} FROM user_operations;
         DROP TABLE user_operations; ALTER TABLE user_operations_v18 RENAME TO user_operations;"
        ))
        .map_err(|error| sqlite_error("cannot migrate operation actor identities", error))?;
    create_indexes(connection, true)
}

/// Cheap namespace validation must not call read_overview back or scan retained
/// history on every policy read. Explicit snapshot validation owns the full scan.
pub(super) fn validate_schema(connection: &Connection, version: u32) -> io::Result<()> {
    if version >= 16 {
        let objects: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE (name IN('operations_state','user_operations') AND type='table') OR (name IN('user_operations_actor_sequence','user_operations_principal_sequence') AND type='index')",
            [], |row| row.get(0),
        ).map_err(|error| sqlite_error("cannot inspect operation namespace", error))?;
        if objects != if version >= 18 { 4 } else { 3 } {
            return Err(corrupt());
        }
        let highwater = highwater(connection)?;
        let latest: Option<i64> = connection
            .query_row("SELECT max(sequence) FROM user_operations", [], |row| {
                row.get(0)
            })
            .map_err(|error| sqlite_error("cannot inspect retained operation sequence", error))?;
        if latest.is_some_and(|sequence| sequence < 1 || sequence as u64 > highwater) {
            return Err(corrupt());
        }
        Ok(())
    } else {
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name IN('operations_state','user_operations','user_operations_actor_sequence'))",
            [], |row| row.get(0),
        ).map_err(|error| sqlite_error("cannot inspect legacy operation namespace", error))?;
        if present { Err(corrupt()) } else { Ok(()) }
    }
}

/// Bounded validation for live opens and immutable backups. This never reads
/// policy verifiers, payload text or wall-clock state, and performs no writes.
pub(super) fn validate_snapshot(connection: &Connection) -> io::Result<()> {
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| sqlite_error("cannot inspect operation snapshot version", error))?;
    let layout = Layout {
        automation: version >= 18,
    };
    let highwater = highwater(connection)?;
    let node = node_id(connection)?;
    let mut counts: HashMap<ActorKey, usize> = HashMap::new();
    let mut statement = connection
        .prepare(&format!(
            "SELECT {} FROM user_operations ORDER BY sequence LIMIT 4097",
            layout.columns()
        ))
        .map_err(|error| sqlite_error("cannot prepare operation validation", error))?;
    let mut rows = statement
        .query([])
        .map_err(|error| sqlite_error("cannot inspect operation validation", error))?;
    let mut total = 0;
    while let Some(row) = rows
        .next()
        .map_err(|error| sqlite_error("cannot read operation validation", error))?
    {
        total += 1;
        if total > MAX_OPERATIONS {
            return Err(corrupt());
        }
        let stored = read_operation(row)?;
        if stored.operation.node_id != node || stored.operation.sequence > highwater {
            return Err(corrupt());
        }
        let count = counts.entry(stored.actor.clone()).or_default();
        *count += 1;
        if *count > MAX_ACTOR_OPERATIONS {
            return Err(corrupt());
        }
    }
    // Scope never changes. Revocation preserves legitimate write history, but
    // a read-only principal could never have reserved a machine operation.
    let actor_check = if layout.automation {
        "SELECT EXISTS(SELECT 1 FROM user_operations o LEFT JOIN administrators a ON a.id=o.administrator_id LEFT JOIN automation_principals p ON p.id=o.automation_principal_id WHERE (o.administrator_id IS NOT NULL AND a.id IS NULL) OR (o.automation_principal_id IS NOT NULL AND (p.id IS NULL OR p.scope IS NOT 'users:write')))"
    } else {
        "SELECT EXISTS(SELECT 1 FROM user_operations o LEFT JOIN administrators a ON a.id=o.administrator_id WHERE a.id IS NULL)"
    };
    let missing_actor: bool = connection
        .query_row(actor_check, [], |row| row.get(0))
        .map_err(|error| sqlite_error("cannot verify retained operation administrators", error))?;
    if missing_actor {
        return Err(corrupt());
    }
    Ok(())
}

/// Allocate an actor-bound ID without changing policy. Retention is sequence-
/// based, not time-based: oldest reservations or terminal rows can be removed.
/// On an uncertain response callers inspect/list, never auto-reserve and submit.
pub(in crate::manage) fn reserve(
    directory: &Path,
    guard: &UpdateGuard,
    actor: &str,
    input: &Input,
) -> io::Result<Operation> {
    reserve_as(
        directory,
        guard,
        &Caller::Administrator(actor.to_owned()),
        input,
    )
}

/// Reserve under the current transaction's administrator or write-scoped key.
/// Parsed credentials alone do not authorize a durable actor identity.
pub(in crate::manage) fn reserve_as(
    directory: &Path,
    guard: &UpdateGuard,
    caller: &Caller,
    input: &Input,
) -> io::Result<Operation> {
    guard.ensure(directory)?;
    let digest = input.digest()?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin operation reservation", error))?;
    let operation = reserve_with_digest(&transaction, caller, input, digest)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit operation reservation", error))?;
    Ok(operation)
}

/// Reserve under the same current actor/node/owner/epoch/CAS checks, without
/// opening another database or committing. The caller owns durable sequencing
/// and confirmation, including cancellation of the requesting wait.
#[cfg(feature = "witness-journal")]
pub(in crate::manage) fn reserve_in(
    transaction: &rusqlite::Transaction<'_>,
    caller: &Caller,
    input: &Input,
) -> io::Result<Operation> {
    reserve_with_digest(transaction, caller, input, input.digest()?)
}

fn reserve_with_digest(
    transaction: &rusqlite::Transaction<'_>,
    caller: &Caller,
    input: &Input,
    digest: [u8; 32],
) -> io::Result<Operation> {
    let authorized = authorize(transaction, caller)?;
    input.require_node(&authorized.node)?;
    let (node, actor) = (&authorized.node, &authorized.actor);
    super::control::require_local(transaction)?;
    if epoch(transaction)? != input.expected_epoch {
        return Err(super::control::ControlError::OwnerConflict.error());
    }
    if users::read_state(transaction)?.0 != input.expected_revision {
        return Err(Error::Conflict.error());
    }
    validate_counts(transaction, actor)?;
    let previous = highwater(transaction)?;
    let sequence = previous
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| Error::Capacity.error())?;
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes[..8])
        .map_err(|_| io::Error::other("cannot obtain operation identity randomness"))?;
    bytes[8..].copy_from_slice(&sequence.to_be_bytes());
    let id = URL_SAFE_NO_PAD.encode(bytes);
    let actor_column = actor.column();
    transaction.execute(&format!("DELETE FROM user_operations WHERE {actor_column}=?1 AND sequence IN (SELECT sequence FROM user_operations WHERE {actor_column}=?1 ORDER BY sequence DESC LIMIT -1 OFFSET 255)"), [actor.id()])
        .map_err(|error| sqlite_error("cannot retain actor operation identities", error))?;
    transaction.execute("DELETE FROM user_operations WHERE sequence IN (SELECT sequence FROM user_operations ORDER BY sequence DESC LIMIT -1 OFFSET 4095)", [])
        .map_err(|error| sqlite_error("cannot retain node operation identities", error))?;
    exactly_one(transaction.execute(
        &format!("INSERT INTO user_operations(id,node_id,{actor_column},sequence,expected_revision,expected_epoch,action,digest,user_id,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'reserved')"),
        params![id,node,actor.id(),sql(sequence)?,sql(input.expected_revision)?,sql(input.expected_epoch)?,input.change.action(),digest.as_slice(),input.change.user_id()],
    ), "cannot store operation reservation")?;
    exactly_one(
        transaction.execute(
            "UPDATE operations_state SET last_sequence=?1 WHERE singleton=1 AND last_sequence=?2",
            params![sql(sequence)?, nonnegative_sql(previous)?],
        ),
        "cannot advance operation sequence",
    )?;
    // A trigger that silently ignores pruning must not let a successful
    // reservation exceed retention limits or consume a permanent sequence.
    validate_counts(transaction, actor)?;
    let operation = find(transaction, &authorized, &id)?
        .ok_or_else(corrupt)?
        .operation;
    Ok(operation)
}

/// Execute only a pre-existing reservation. Same binding terminal replay does
/// not re-evaluate policy CAS or current ownership, and never returns a policy.
/// Business rejection first rolls back all candidate writes. HTTP cancellation
/// must not release the caller's writer/update ownership while this runs.
pub(in crate::manage) fn execute(
    directory: &Path,
    guard: &UpdateGuard,
    actor: &str,
    id: &str,
    input: Input,
) -> Result<Outcome, ExecuteError> {
    execute_as(
        directory,
        guard,
        &Caller::Administrator(actor.to_owned()),
        id,
        input,
    )
}

/// Reauthenticate the same actor before both first execution and terminal replay.
/// Rotation changes key authority, not the principal's reservation namespace.
pub(in crate::manage) fn execute_as(
    directory: &Path,
    guard: &UpdateGuard,
    caller: &Caller,
    id: &str,
    input: Input,
) -> Result<Outcome, ExecuteError> {
    guard.ensure(directory).map_err(ExecuteError::before)?;
    let digest = input.digest().map_err(ExecuteError::before)?;
    if !valid_id(id) {
        return Err(ExecuteError::before(Error::InvalidOperation.error()));
    }
    let mut connection = open_existing(directory, true).map_err(ExecuteError::before)?;
    let mut transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| {
            ExecuteError::before(sqlite_error("cannot begin reserved user operation", error))
        })?;
    let outcome = match execute_with_digest(&mut transaction, caller, id, input, digest) {
        Ok(outcome) => outcome,
        Err(error) => {
            transaction.rollback().map_err(|error| {
                ExecuteError::uncertain(sqlite_error(
                    "cannot roll back failed reserved operation",
                    error,
                ))
            })?;
            return Err(error);
        }
    };
    if matches!(&outcome, Outcome::Replayed(_)) {
        return Ok(outcome);
    }
    let uncertain = matches!(&outcome, Outcome::Accepted { .. });
    transaction.commit().map_err(|error| ExecuteError {
        policy_uncertain: uncertain,
        error: sqlite_error("cannot commit reserved operation result", error),
    })?;
    Ok(outcome)
}

/// Execute under a caller-owned transaction using the exact original actor,
/// reservation identity and digest. Terminal replay is read-only and returns
/// no candidate policy. The outer owner must roll back on error; this core
/// neither commits the transaction nor publishes its candidate.
#[cfg(feature = "witness-journal")]
pub(in crate::manage) fn execute_in(
    transaction: &mut rusqlite::Transaction<'_>,
    caller: &Caller,
    id: &str,
    input: Input,
) -> Result<Outcome, ExecuteError> {
    let digest = input.digest().map_err(ExecuteError::before)?;
    if !valid_id(id) {
        return Err(ExecuteError::before(Error::InvalidOperation.error()));
    }
    execute_with_digest(transaction, caller, id, input, digest)
}

fn execute_with_digest(
    transaction: &mut rusqlite::Transaction<'_>,
    caller: &Caller,
    id: &str,
    input: Input,
    digest: [u8; 32],
) -> Result<Outcome, ExecuteError> {
    let authorized = authorize(transaction, caller).map_err(ExecuteError::before)?;
    input
        .require_node(&authorized.node)
        .map_err(ExecuteError::before)?;
    let stored = find(transaction, &authorized, id)
        .map_err(ExecuteError::before)?
        .ok_or_else(|| ExecuteError::before(Error::NotQueryable.error()))?;
    if stored.digest != digest {
        return Err(ExecuteError::before(Error::Conflict.error()));
    }
    if stored.operation.state != State::Reserved {
        // A read-only terminal replay deliberately ends by rolling back this
        // empty transaction; no second commit can obscure its known result.
        return Ok(Outcome::Replayed(stored.operation));
    }
    let rejection = match super::control::require_local(transaction) {
        Ok(()) => {
            if epoch(transaction).map_err(ExecuteError::before)? != input.expected_epoch {
                Some("owner_conflict")
            } else {
                None
            }
        }
        Err(error)
            if error
                .get_ref()
                .and_then(|error| error.downcast_ref::<super::control::ControlError>())
                == Some(&super::control::ControlError::ResourceManaged) =>
        {
            Some("resource_managed")
        }
        Err(error) => return Err(ExecuteError::before(error)),
    };
    let candidate = if let Some(code) = rejection {
        Err(code)
    } else {
        let mut savepoint = transaction.savepoint().map_err(|error| {
            ExecuteError::before(sqlite_error(
                "cannot begin reserved operation candidate",
                error,
            ))
        })?;
        match users::apply_in(
            &savepoint,
            match &authorized.actor {
                ActorKey::Administrator(id) => Actor::Local(id),
                ActorKey::Automation(id) => Actor::Automation {
                    id,
                    generation: authorized
                        .generation
                        .ok_or_else(|| ExecuteError::before(corrupt()))?,
                },
            },
            input.expected_revision,
            input.change.policy(),
        ) {
            Ok(change) => {
                savepoint.commit().map_err(|error| {
                    ExecuteError::uncertain(sqlite_error(
                        "cannot release reserved operation candidate",
                        error,
                    ))
                })?;
                Ok(change)
            }
            Err(error) => {
                let rejection = rejection_code(&error);
                savepoint.rollback().map_err(|error| {
                    ExecuteError::uncertain(sqlite_error(
                        "cannot roll back reserved operation candidate",
                        error,
                    ))
                })?;
                savepoint.commit().map_err(|error| {
                    ExecuteError::uncertain(sqlite_error(
                        "cannot release rejected operation candidate",
                        error,
                    ))
                })?;
                match rejection {
                    Some(code) => Err(code),
                    None => {
                        return Err(ExecuteError::before(error));
                    }
                }
            }
        }
    };
    let saved = candidate.as_ref().ok();
    let saved_revision = saved.map(|change| change.policy.revision);
    let result_user = saved
        .and_then(|change| change.user.as_ref())
        .map(|user| user.id.as_str())
        .or(stored.operation.user_id.as_deref());
    let rejection = candidate.as_ref().err().copied();
    let update = transaction.execute("UPDATE user_operations SET state=?1,user_id=?2,saved_revision=?3,rejection=?4 WHERE id=?5 AND state='reserved'",
        params![if saved.is_some() { "saved" } else { "rejected" }, result_user, saved_revision.map(sql).transpose().map_err(ExecuteError::uncertain)?, rejection, id]);
    let uncertain = saved.is_some();
    exactly_one(update, "cannot save reserved operation result").map_err(|error| ExecuteError {
        policy_uncertain: uncertain,
        error,
    })?;
    let operation = find(transaction, &authorized, id)
        .map_err(|error| ExecuteError {
            policy_uncertain: uncertain,
            error,
        })?
        .ok_or_else(|| ExecuteError {
            policy_uncertain: uncertain,
            error: corrupt(),
        })?
        .operation;
    Ok(match candidate {
        Ok(change) => Outcome::Accepted {
            change: Box::new(change),
            operation,
        },
        Err(_) => Outcome::Rejected(operation),
    })
}

/// Read only this authenticated administrator's result in one snapshot. Current
/// owner changes do not erase the administrator's historical read authority.
pub(in crate::manage) fn get(directory: &Path, actor: &str, id: &str) -> io::Result<Operation> {
    get_as(directory, &Caller::Administrator(actor.to_owned()), id)
}

pub(in crate::manage) fn get_as(
    directory: &Path,
    caller: &Caller,
    id: &str,
) -> io::Result<Operation> {
    if !valid_id(id) {
        return Err(Error::InvalidOperation.error());
    }
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin operation result inspection", error))?;
    let authorized = authorize(&transaction, caller)?;
    find(&transaction, &authorized, id)?
        .map(|stored| stored.operation)
        .ok_or_else(|| Error::NotQueryable.error())
}

/// Newest-first metadata only, at most fifty results. The numeric before cursor
/// is an exclusive sequence boundary, not an authorization capability or proof
/// that an earlier page/row remains retained after concurrent reservations.
pub(in crate::manage) fn list(
    directory: &Path,
    actor: &str,
    before: Option<u64>,
    limit: u32,
) -> io::Result<Page> {
    list_as(
        directory,
        &Caller::Administrator(actor.to_owned()),
        before,
        limit,
    )
}

pub(in crate::manage) fn list_as(
    directory: &Path,
    caller: &Caller,
    before: Option<u64>,
    limit: u32,
) -> io::Result<Page> {
    if !(1..=MAX_PAGE).contains(&limit) {
        return Err(Error::InvalidOperation.error());
    }
    let before = before.map(sql).transpose()?;
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin operation listing", error))?;
    let authorized = authorize(&transaction, caller)?;
    let actor = &authorized.actor;
    let highwater = highwater(&transaction)?;
    let mut statement = transaction.prepare(&format!("SELECT {} FROM user_operations WHERE {}=?1 AND (?2 IS NULL OR sequence<?2) ORDER BY sequence DESC LIMIT ?3", authorized.layout.columns(), actor.column()))
        .map_err(|error| sqlite_error("cannot prepare operation listing", error))?;
    let mut rows = statement
        .query(params![actor.id(), before, i64::from(limit) + 1])
        .map_err(|error| sqlite_error("cannot query operation listing", error))?;
    let mut items = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| sqlite_error("cannot read operation listing", error))?
    {
        let stored = read_operation(row)?;
        if stored.actor != *actor
            || stored.operation.node_id != authorized.node
            || stored.operation.sequence > highwater
        {
            return Err(corrupt());
        }
        items.push(stored.operation);
    }
    let more = items.len() > limit as usize;
    if more {
        items.pop();
    }
    let next_cursor = if more {
        items.last().map(|operation| operation.sequence)
    } else {
        None
    };
    Ok(Page { items, next_cursor })
}

struct Stored {
    operation: Operation,
    actor: ActorKey,
    digest: [u8; 32],
}

fn authorize(connection: &Connection, caller: &Caller) -> io::Result<Authorized> {
    let version = read_overview(connection)?.schema_version;
    if version < 16 {
        return Err(Error::UpgradeRequired.error());
    }
    let (actor, generation) = match caller {
        Caller::Administrator(id) => {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM administrators WHERE id=?1)",
                    [id],
                    |row| row.get(0),
                )
                .map_err(|error| sqlite_error("cannot verify operation administrator", error))?;
            if !valid_id(id) || !exists {
                return Err(Error::Denied.error());
            }
            (ActorKey::Administrator(id.clone()), None)
        }
        Caller::Automation(credential) => {
            let identity = automation::authorize_in(
                connection,
                credential,
                automation::Permission::WriteUsers,
            )?;
            (ActorKey::Automation(identity.id), Some(identity.generation))
        }
    };
    Ok(Authorized {
        node: node_id(connection)?,
        actor,
        generation,
        layout: Layout {
            automation: version >= 18,
        },
    })
}

/// Read the context and caller's current authority in one SQLite snapshot.
pub(in crate::manage) fn context(directory: &Path, caller: &Caller) -> io::Result<Context> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin operation context inspection", error))?;
    let authorized = authorize(&transaction, caller)?;
    let local: bool = transaction
        .query_row(
            "SELECT controller_node_id IS NULL FROM control_ownership WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot inspect operation context ownership", error))?;
    Ok(Context {
        node_id: authorized.node,
        policy_revision: users::read_state(&transaction)?.0,
        expected_epoch: epoch(&transaction)?,
        local,
    })
}

fn node_id(connection: &Connection) -> io::Result<String> {
    let node = connection
        .query_row(
            "SELECT node_id FROM node_identity WHERE singleton=1",
            [],
            |row| bounded_text(row, 0, 22),
        )
        .map_err(|error| sqlite_error("cannot read operation node identity", error))?;
    if !valid_id(&node) {
        return Err(corrupt());
    }
    Ok(node)
}

fn highwater(connection: &Connection) -> io::Result<u64> {
    let (count, sequence): (i64, Option<i64>) = connection
        .query_row(
            "SELECT count(*),max(last_sequence) FROM operations_state WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| sqlite_error("cannot read operation sequence high-water", error))?;
    let total: i64 = connection
        .query_row("SELECT count(*) FROM operations_state", [], |row| {
            row.get(0)
        })
        .map_err(|error| sqlite_error("cannot count operation sequence state", error))?;
    if count != 1 || total != 1 {
        return Err(corrupt());
    }
    sequence
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(corrupt)
}

fn epoch(connection: &Connection) -> io::Result<u64> {
    connection
        .query_row(
            "SELECT epoch FROM control_ownership WHERE singleton=1",
            [],
            |row| users::read_revision(row, 0),
        )
        .map_err(|error| sqlite_error("cannot read reserved operation owner epoch", error))
}

fn find(connection: &Connection, authorized: &Authorized, id: &str) -> io::Result<Option<Stored>> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {} FROM user_operations WHERE id=?1 AND {}=?2 AND node_id=?3",
            authorized.layout.columns(),
            authorized.actor.column()
        ))
        .map_err(|error| sqlite_error("cannot prepare exact operation result", error))?;
    let mut rows = statement
        .query(params![id, authorized.actor.id(), authorized.node])
        .map_err(|error| sqlite_error("cannot query exact operation result", error))?;
    let stored = rows
        .next()
        .map_err(|error| sqlite_error("cannot read exact operation result", error))?
        .map(read_operation)
        .transpose()?;
    let highwater = highwater(connection)?;
    if stored
        .as_ref()
        .is_some_and(|stored| stored.operation.sequence > highwater)
    {
        return Err(corrupt());
    }
    Ok(stored)
}

fn validate_counts(connection: &Connection, actor: &ActorKey) -> io::Result<()> {
    let (total, own): (i64, i64) = connection
        .query_row(
            &format!(
                "SELECT count(*),coalesce(sum({}=?1),0) FROM user_operations",
                actor.column()
            ),
            [actor.id()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| sqlite_error("cannot inspect operation retention capacity", error))?;
    if !(0..=MAX_OPERATIONS as i64).contains(&total)
        || !(0..=MAX_ACTOR_OPERATIONS as i64).contains(&own)
    {
        return Err(corrupt());
    }
    Ok(())
}

fn read_operation(row: &Row<'_>) -> io::Result<Stored> {
    let read = || -> rusqlite::Result<Stored> {
        let id = bounded_text(row, 0, 22)?;
        let node_id = bounded_text(row, 1, 22)?;
        let administrator = optional_text(row, 2, 22)?;
        let principal = optional_text(row, 12, 22)?;
        let actor = match (administrator, principal) {
            (Some(id), None) => ActorKey::Administrator(id),
            (None, Some(id)) => ActorKey::Automation(id),
            _ => return Err(rusqlite::Error::InvalidQuery),
        };
        let sequence = users::read_revision(row, 3)?;
        let expected_revision = users::read_revision(row, 4)?;
        let expected_epoch = users::read_revision(row, 5)?;
        let action = match row.get_ref(6)? {
            ValueRef::Text(b"create_user") => "create_user",
            ValueRef::Text(b"update_user") => "update_user",
            ValueRef::Text(b"set_user_active") => "set_user_active",
            ValueRef::Text(b"delete_user") => "delete_user",
            _ => return Err(rusqlite::Error::InvalidQuery),
        };
        let digest: [u8; 32] = match row.get_ref(7)? {
            ValueRef::Blob(bytes) => bytes
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            _ => return Err(rusqlite::Error::InvalidQuery),
        };
        let user_id = optional_text(row, 8, 22)?;
        let state = match row.get_ref(9)? {
            ValueRef::Text(b"reserved") => State::Reserved,
            ValueRef::Text(b"saved") => State::Saved,
            ValueRef::Text(b"rejected") => State::Rejected,
            _ => return Err(rusqlite::Error::InvalidQuery),
        };
        let saved_revision = if matches!(row.get_ref(10)?, ValueRef::Null) {
            None
        } else {
            Some(users::read_revision(row, 10)?)
        };
        let rejection = match row.get_ref(11)? {
            ValueRef::Null => None,
            ValueRef::Text(b"invalid_policy") => Some("invalid_policy"),
            ValueRef::Text(b"policy_conflict") => Some("policy_conflict"),
            ValueRef::Text(b"resource_not_found") => Some("resource_not_found"),
            ValueRef::Text(b"policy_capacity") => Some("policy_capacity"),
            ValueRef::Text(b"resource_managed") => Some("resource_managed"),
            ValueRef::Text(b"owner_conflict") => Some("owner_conflict"),
            _ => return Err(rusqlite::Error::InvalidQuery),
        };
        Ok(Stored {
            operation: Operation {
                id,
                node_id,
                expected_revision,
                expected_epoch,
                action,
                user_id,
                state,
                saved_revision,
                rejection,
                sequence,
            },
            actor,
            digest,
        })
    };
    let stored = read().map_err(|_| corrupt())?;
    let op = &stored.operation;
    let mut id = [0_u8; 16];
    if !valid_id(&op.id)
        || !valid_id(&op.node_id)
        || !valid_id(stored.actor.id())
        || !matches!(URL_SAFE_NO_PAD.decode_slice(&op.id, &mut id), Ok(16))
        || id[8..] != op.sequence.to_be_bytes()
        || op.user_id.as_ref().is_some_and(|id| !valid_id(id))
        || (op.action == "create_user" && (op.state == State::Saved) != op.user_id.is_some())
        || (op.action != "create_user" && op.user_id.is_none())
        || match op.state {
            State::Reserved => op.saved_revision.is_some() || op.rejection.is_some(),
            State::Saved => {
                op.rejection.is_some() || op.saved_revision != op.expected_revision.checked_add(1)
            }
            State::Rejected => op.saved_revision.is_some() || op.rejection.is_none(),
        }
    {
        return Err(corrupt());
    }
    Ok(stored)
}

fn bounded_text(row: &Row<'_>, column: usize, bound: usize) -> rusqlite::Result<String> {
    match row.get_ref(column)? {
        ValueRef::Text(bytes) if bytes.len() <= bound => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| rusqlite::Error::InvalidQuery),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
fn optional_text(row: &Row<'_>, column: usize, bound: usize) -> rusqlite::Result<Option<String>> {
    if matches!(row.get_ref(column)?, ValueRef::Null) {
        Ok(None)
    } else {
        bounded_text(row, column, bound).map(Some)
    }
}
fn rejection_code(error: &io::Error) -> Option<&'static str> {
    if error
        .get_ref()
        .and_then(|error| error.downcast_ref::<super::control::ControlError>())
        == Some(&super::control::ControlError::PolicyCapacity)
    {
        return Some("policy_capacity");
    }
    match error.kind() {
        io::ErrorKind::InvalidInput => Some("invalid_policy"),
        io::ErrorKind::AlreadyExists => Some("policy_conflict"),
        io::ErrorKind::NotFound => Some("resource_not_found"),
        _ => None,
    }
}
fn exactly_one(result: rusqlite::Result<usize>, context: &'static str) -> io::Result<()> {
    let changed = result.map_err(|error| sqlite_error(context, error))?;
    if changed != 1 {
        return Err(corrupt());
    }
    Ok(())
}
fn sql(value: u64) -> io::Result<i64> {
    users::sql_revision(value).map_err(|_| Error::InvalidOperation.error())
}
fn nonnegative_sql(value: u64) -> io::Result<i64> {
    i64::try_from(value).map_err(|_| corrupt())
}
fn corrupt() -> io::Error {
    invalid_data("local user operation state is malformed")
}

/// Refuse a lossy historical fixture before touching any related namespace.
#[cfg(test)]
pub(in crate::manage) fn require_legacy_for_test(connection: &Connection) -> io::Result<()> {
    let current: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('user_operations') WHERE name='automation_principal_id')", [], |row| row.get(0))
        .map_err(|error| sqlite_error("cannot inspect operation fixture layout", error))?;
    if current {
        let present: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM user_operations WHERE automation_principal_id IS NOT NULL)", [], |row| row.get(0))
            .map_err(|error| sqlite_error("cannot inspect operation fixture actors", error))?;
        if present {
            return Err(corrupt());
        }
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::manage) fn restore_legacy_for_test(connection: &Connection) -> io::Result<()> {
    require_legacy_for_test(connection)?;
    let current: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('user_operations') WHERE name='automation_principal_id')", [], |row| row.get(0))
        .map_err(|error| sqlite_error("cannot inspect operation fixture layout", error))?;
    if !current {
        return Ok(());
    }
    create_table(connection, "user_operations_fixture17", false)?;
    connection.execute_batch(&format!("INSERT INTO user_operations_fixture17({COLUMNS}) SELECT {COLUMNS} FROM user_operations; DROP TABLE user_operations; ALTER TABLE user_operations_fixture17 RENAME TO user_operations;"))
        .map_err(|error| sqlite_error("cannot reconstruct operation fixture actors", error))?;
    create_indexes(connection, false)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;
    use crate::manage::store;

    mod machine {
        //! Transaction-bound machine actors, namespace retention and genuine migration.

        use super::*;
        use zeroize::Zeroizing;

        fn writer(fixture: &Fixture) -> io::Result<(automation::View, Caller)> {
            let mut token = Zeroizing::new(String::new());
            let view = automation::create(
                &fixture.directory,
                "operation writer",
                automation::Scope::UsersWrite,
                3600,
                |value| {
                    token.push_str(value);
                    Ok(())
                },
            )?;
            Ok((
                view,
                Caller::Automation(Arc::new(automation::Credential::parse(&token)?)),
            ))
        }

        fn reserve_for(fixture: &Fixture, caller: &Caller, input: &Input) -> io::Result<Operation> {
            reserve_as(
                &fixture.directory,
                &store::update_lock(&fixture.directory)?,
                caller,
                input,
            )
        }

        #[test]
        fn equal_text_actors_have_separate_results_and_independent_retention() -> io::Result<()> {
            let fixture = Fixture::new()?;
            let (principal, machine) = writer(&fixture)?;
            let mut connection = fixture.writable()?;
            connection
                .execute(
                    "INSERT INTO administrators VALUES(?1,'same-id-administrator',?2)",
                    params![principal.id, PHC],
                )
                .map_err(io::Error::other)?;
            let administrator = Caller::Administrator(principal.id.clone());
            let input = create(1);
            let own = reserve_for(&fixture, &machine, &input)?;
            let other = reserve_for(&fixture, &administrator, &input)?;
            assert_eq!(
                error_code(
                    &get_as(&fixture.directory, &machine, &other.id)
                        .err()
                        .unwrap()
                ),
                Some(Error::NotQueryable)
            );
            assert_eq!(
                error_code(
                    &get_as(&fixture.directory, &administrator, &own.id)
                        .err()
                        .unwrap()
                ),
                Some(Error::NotQueryable)
            );
            assert_eq!(
                list_as(&fixture.directory, &machine, None, 50)?.items,
                vec![own.clone()]
            );
            assert_eq!(
                list_as(&fixture.directory, &administrator, None, 50)?.items,
                vec![other.clone()]
            );

            let transaction = connection.transaction().map_err(io::Error::other)?;
            let digest = input.digest()?;
            for sequence in 3..=512_u64 {
                let (admin, principal_id) = if sequence % 2 == 0 {
                    (Some(principal.id.as_str()), None)
                } else {
                    (None, Some(principal.id.as_str()))
                };
                transaction.execute("INSERT INTO user_operations(id,node_id,administrator_id,sequence,expected_revision,expected_epoch,action,digest,user_id,state,saved_revision,rejection,automation_principal_id) VALUES(?1,?2,?3,?4,1,1,'create_user',?5,NULL,'reserved',NULL,NULL,?6)",
            params![seeded_id(sequence),fixture.node,admin,sequence as i64,digest.as_slice(),principal_id]).map_err(io::Error::other)?;
            }
            transaction
                .execute("UPDATE operations_state SET last_sequence=512", [])
                .map_err(io::Error::other)?;
            transaction.commit().map_err(io::Error::other)?;
            validate_snapshot(&connection)?;
            let next = reserve_for(&fixture, &machine, &input)?;
            assert_eq!(next.sequence, 513);
            assert_eq!(
                error_code(&get_as(&fixture.directory, &machine, &own.id).err().unwrap()),
                Some(Error::NotQueryable)
            );
            assert_eq!(
                get_as(&fixture.directory, &administrator, &other.id)?,
                other
            );
            assert_eq!(reserve_for(&fixture, &administrator, &input)?.sequence, 514);
            validate_snapshot(&connection)?;
            let counts: (i64, i64, i64) = connection.query_row("SELECT count(*),sum(administrator_id IS NOT NULL),sum(automation_principal_id IS NOT NULL) FROM user_operations", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).map_err(io::Error::other)?;
            assert_eq!(counts, (512, 256, 256));
            Ok(())
        }

        #[test]
        fn rotation_and_revocation_are_rechecked_for_execution_and_terminal_reads() -> io::Result<()>
        {
            let fixture = Fixture::new()?;
            let (principal, old) = writer(&fixture)?;
            let input = create(1);
            let reserved = reserve_for(&fixture, &old, &input)?;
            let mut token = Zeroizing::new(String::new());
            automation::rotate(&fixture.directory, &principal.id, 1, 3600, |value| {
                token.push_str(value);
                Ok(())
            })?;
            let gate = store::update_lock(&fixture.directory)?;
            assert!(
                execute_as(&fixture.directory, &gate, &old, &reserved.id, input.clone()).is_err()
            );
            drop(gate);
            assert_eq!(store::load_policy(&fixture.directory)?.revision, 1);
            let current = Caller::Automation(Arc::new(automation::Credential::parse(&token)?));
            assert_eq!(
                get_as(&fixture.directory, &current, &reserved.id)?,
                reserved
            );
            let gate = store::update_lock(&fixture.directory)?;
            let (_, saved) = accepted(
                execute_as(
                    &fixture.directory,
                    &gate,
                    &current,
                    &reserved.id,
                    input.clone(),
                )
                .map_err(ExecuteError::into_error)?,
            );
            assert_eq!(saved.state, State::Saved);
            assert!(matches!(
                execute_as(&fixture.directory, &gate, &current, &reserved.id, input)
                    .map_err(ExecuteError::into_error)?,
                Outcome::Replayed(_)
            ));
            drop(gate);
            let connection = fixture.writable()?;
            let recorded: (String, i64, Option<String>) = connection.query_row("SELECT automation_principal_id,automation_generation,administrator_id FROM proxy_policy_audit WHERE entry='automation_management'", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).map_err(io::Error::other)?;
            assert_eq!(recorded, (principal.id.clone(), 2, None));
            users::validate_operation_audit(&connection)?;
            automation::revoke(&fixture.directory, &principal.id, 2)?;
            assert!(get_as(&fixture.directory, &current, &reserved.id).is_err());
            assert!(list_as(&fixture.directory, &current, None, 50).is_err());
            assert!(context(&fixture.directory, &current).is_err());
            Ok(())
        }

        #[test]
        fn ignored_machine_audit_rolls_back_candidate_and_keeps_reservation() -> io::Result<()> {
            let fixture = Fixture::new()?;
            let (_, machine) = writer(&fixture)?;
            let input = create(1);
            let reserved = reserve_for(&fixture, &machine, &input)?;
            let connection = fixture.writable()?;
            connection.execute_batch("CREATE TRIGGER ignored_machine_audit BEFORE INSERT ON proxy_policy_audit WHEN NEW.entry='automation_management' BEGIN SELECT RAISE(IGNORE); END;").map_err(io::Error::other)?;
            let before = snapshot(&connection)?;
            let gate = store::update_lock(&fixture.directory)?;
            assert!(execute_as(&fixture.directory, &gate, &machine, &reserved.id, input).is_err());
            assert!(snapshot(&connection)? == before);
            assert_eq!(
                get_as(&fixture.directory, &machine, &reserved.id)?.state,
                State::Reserved
            );
            Ok(())
        }

        fn legacy_rows(connection: &Connection) -> io::Result<Vec<Vec<rusqlite::types::Value>>> {
            let mut values = Vec::new();
            for sql in [format!("SELECT {COLUMNS} FROM user_operations ORDER BY sequence"), "SELECT sequence,entry,administrator_id,controller_node_id,controller_epoch,command_id,source_administrator_id,action,user_id,credential_id,policy_revision FROM proxy_policy_audit ORDER BY sequence".into()] {
        let mut statement = connection.prepare(&sql).map_err(io::Error::other)?;
        let count = statement.column_count();
        let rows = statement.query_map([], |row| (0..count).map(|column| row.get(column)).collect()).map_err(io::Error::other)?;
        for row in rows { values.push(row.map_err(io::Error::other)?); }
    }
            Ok(values)
        }

        #[test]
        fn genuine_seventeen_migration_preserves_reserved_digest_audit_and_highwater()
        -> io::Result<()> {
            for collision in [false, true] {
                let fixture = Fixture::new()?;
                let first = fixture.reserve(&create(1))?;
                accepted(
                    fixture
                        .execute(&first.id, create(1))
                        .map_err(ExecuteError::into_error)?,
                );
                let reserved = fixture.reserve(&create(2))?;
                let connection = fixture.writable()?;
                connection
                    .execute("UPDATE operations_state SET last_sequence=100", [])
                    .map_err(io::Error::other)?;
                store::recovery::restore_schema_seventeen_for_test(&connection)?;
                if !collision {
                    let mut token = Zeroizing::new(String::new());
                    let reader = automation::create(
                        &fixture.directory,
                        "legacy operation reader",
                        automation::Scope::UsersRead,
                        3600,
                        |value| {
                            token.push_str(value);
                            Ok(())
                        },
                    )?;
                    let caller =
                        Caller::Automation(Arc::new(automation::Credential::parse(&token)?));
                    let error = context(&fixture.directory, &caller).err().unwrap();
                    assert!(matches!(
                        error
                            .get_ref()
                            .and_then(|source| source.downcast_ref::<automation::Error>()),
                        Some(automation::Error::InsufficientScope)
                    ));
                    let mut wrong = Zeroizing::new(token.to_string());
                    let offset = wrong.rfind('.').unwrap() + 1;
                    let replacement = if wrong.as_bytes()[offset] == b'A' {
                        "B"
                    } else {
                        "A"
                    };
                    wrong.replace_range(offset..offset + 1, replacement);
                    let invalid =
                        Caller::Automation(Arc::new(automation::Credential::parse(&wrong)?));
                    let error = context(&fixture.directory, &invalid).err().unwrap();
                    assert!(matches!(
                        error
                            .get_ref()
                            .and_then(|source| source.downcast_ref::<automation::Error>()),
                        Some(automation::Error::Unauthorized)
                    ));
                    automation::revoke(&fixture.directory, &reader.id, reader.generation)?;
                    let error = context(&fixture.directory, &caller).err().unwrap();
                    assert!(matches!(
                        error
                            .get_ref()
                            .and_then(|source| source.downcast_ref::<automation::Error>()),
                        Some(automation::Error::Unauthorized)
                    ));
                }
                let before = legacy_rows(&connection)?;
                if collision {
                    connection.execute_batch("CREATE TABLE user_operations_v18(value TEXT); INSERT INTO user_operations_v18 VALUES('operator material');").map_err(io::Error::other)?;
                }
                let backup = fixture.directory.join("before-v18.sqlite3");
                let migrated = store::migrate(&fixture.directory, &backup);
                assert_eq!(
                    store::read_overview(&Connection::open(&backup).map_err(io::Error::other)?)?
                        .schema_version,
                    17
                );
                assert!(legacy_rows(&connection)? == before);
                assert_eq!(highwater(&connection)?, 100);
                assert_eq!(fixture.result(&reserved.id)?, reserved);
                if collision {
                    assert!(migrated.is_err());
                    assert_eq!(store::inspect(&fixture.directory)?.schema_version, 17);
                    assert_eq!(
                        connection
                            .query_row("SELECT value FROM user_operations_v18", [], |row| row
                                .get::<_, String>(0))
                            .map_err(io::Error::other)?,
                        "operator material"
                    );
                } else {
                    assert_eq!(migrated?.schema_version, store::SCHEMA_VERSION);
                    assert_eq!(fixture.reserve(&create(2))?.sequence, 101);
                    accepted(
                        fixture
                            .execute(&reserved.id, create(2))
                            .map_err(ExecuteError::into_error)?,
                    );
                }
            }
            Ok(())
        }

        #[test]
        fn write_actor_fixture_downgrades_refuse_before_ddl_changes() -> io::Result<()> {
            for executed in [false, true] {
                let fixture = Fixture::new()?;
                let (_, machine) = writer(&fixture)?;
                if executed {
                    let input = create(1);
                    let reserved = reserve_for(&fixture, &machine, &input)?;
                    let gate = store::update_lock(&fixture.directory)?;
                    accepted(
                        execute_as(&fixture.directory, &gate, &machine, &reserved.id, input)
                            .map_err(ExecuteError::into_error)?,
                    );
                }
                let connection = fixture.writable()?;
                let schema: u32 = connection
                    .pragma_query_value(None, "schema_version", |row| row.get(0))
                    .map_err(io::Error::other)?;
                assert!(store::recovery::restore_schema_seventeen_for_test(&connection).is_err());
                assert!(store::recovery::restore_schema_sixteen_for_test(&connection).is_err());
                assert!(store::remove_operations_schema_for_test(&connection).is_err());
                assert_eq!(
                    connection
                        .pragma_query_value::<u32, _>(None, "schema_version", |row| row.get(0))
                        .map_err(io::Error::other)?,
                    schema
                );
                assert_eq!(
                    store::inspect(&fixture.directory)?.schema_version,
                    store::SCHEMA_VERSION
                );
            }
            Ok(())
        }
    }

    const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$Zml4dHVyZQ";

    struct Fixture {
        directory: std::path::PathBuf,
        actor: String,
        node: String,
    }

    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory =
                std::env::temp_dir().join(format!("vproxy-operations-{}", store::random_id()?));
            let overview = store::initialize(&directory, "operation test", "admin", PHC)?;
            let connection = open_existing(&directory, false)?;
            let actor = connection
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(|error| sqlite_error("cannot read fixture administrator", error))?;
            Ok(Self {
                directory,
                actor,
                node: overview.node_id,
            })
        }

        fn reserve(&self, input: &Input) -> io::Result<Operation> {
            reserve(
                &self.directory,
                &store::update_lock(&self.directory)?,
                &self.actor,
                input,
            )
        }

        fn execute(&self, id: &str, input: Input) -> Result<Outcome, ExecuteError> {
            let guard = store::update_lock(&self.directory).map_err(ExecuteError::before)?;
            execute(&self.directory, &guard, &self.actor, id, input)
        }

        fn result(&self, id: &str) -> io::Result<Operation> {
            get(&self.directory, &self.actor, id)
        }
        fn writable(&self) -> io::Result<Connection> {
            open_existing(&self.directory, true)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn create(revision: u64) -> Input {
        Input {
            expected_node_id: None,
            expected_revision: revision,
            expected_epoch: 1,
            change: UserChange::CreateUser {
                name: "Literal_% user".into(),
                protocols: vec![Protocol::Http, Protocol::Socks5],
                concurrent_limit: 8,
            },
        }
    }

    fn accepted(outcome: Outcome) -> (Box<ChangeResult>, Operation) {
        match outcome {
            Outcome::Accepted { change, operation } => (change, operation),
            _ => panic!("expected first acceptance"),
        }
    }

    fn error_code(error: &io::Error) -> Option<Error> {
        error
            .get_ref()
            .and_then(|error| error.downcast_ref::<Error>())
            .copied()
    }

    fn snapshot(connection: &Connection) -> io::Result<Vec<Vec<Vec<rusqlite::types::Value>>>> {
        [
            "proxy_users",
            "proxy_credentials",
            "proxy_policy_state",
            "proxy_policy_audit",
            "routing_permissions",
            "user_presets",
            "user_operations",
            "operations_state",
        ]
        .into_iter()
        .map(|table| {
            let mut statement = connection
                .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                .map_err(|error| sqlite_error("cannot inspect fixture application state", error))?;
            let columns = statement.column_count();
            let rows = statement
                .query_map([], |row| {
                    (0..columns).map(|column| row.get(column)).collect()
                })
                .map_err(|error| sqlite_error("cannot query fixture application state", error))?;
            rows.map(|row| {
                row.map_err(|error| sqlite_error("cannot read fixture application state", error))
            })
            .collect()
        })
        .collect()
    }

    #[test]
    fn user_actions_save_exact_metadata_and_terminal_replay_never_reapplies() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let _author = store::lock(&fixture.directory)?;
        let input = create(1);
        let reserved = fixture.reserve(&input)?;
        assert_eq!(reserved.state, State::Reserved);
        assert_eq!(store::load_policy(&fixture.directory)?.revision, 1);
        let (change, saved) = accepted(
            fixture
                .execute(&reserved.id, input.clone())
                .map_err(ExecuteError::into_error)?,
        );
        let user = change.user.unwrap();
        assert_eq!(saved.user_id.as_deref(), Some(user.id.as_str()));
        assert_eq!(saved.saved_revision, Some(2));
        assert!(change.secret.is_none() && change.credential.is_none());
        assert_eq!(fixture.result(&saved.id)?, saved);
        let before = snapshot(&fixture.writable()?)?;
        assert!(
            matches!(fixture.execute(&saved.id,input.clone()).map_err(ExecuteError::into_error)?,Outcome::Replayed(operation) if operation==saved)
        );
        assert!(before == snapshot(&fixture.writable()?)?);
        let mut different = input.clone();
        if let UserChange::CreateUser { name, .. } = &mut different.change {
            *name = "different".into();
        }
        let error = fixture.execute(&saved.id, different).err().unwrap();
        assert!(!error.policy_uncertain());
        assert_eq!(error_code(&error.into_error()), Some(Error::Conflict));
        for (revision, change) in [
            (
                2,
                UserChange::UpdateUser {
                    id: user.id.clone(),
                    name: "Updated".into(),
                    protocols: vec![Protocol::Masque],
                    concurrent_limit: 3,
                },
            ),
            (
                3,
                UserChange::SetUserActive {
                    id: user.id.clone(),
                    active: false,
                },
            ),
            (
                4,
                UserChange::DeleteUser {
                    id: user.id.clone(),
                },
            ),
        ] {
            let input = Input {
                expected_node_id: None,
                expected_revision: revision,
                expected_epoch: 1,
                change,
            };
            let reservation = fixture.reserve(&input)?;
            let (_, receipt) = accepted(
                fixture
                    .execute(&reservation.id, input.clone())
                    .map_err(ExecuteError::into_error)?,
            );
            assert_eq!(receipt.saved_revision, Some(revision + 1));
            assert!(matches!(
                fixture
                    .execute(&reservation.id, input)
                    .map_err(ExecuteError::into_error)?,
                Outcome::Replayed(_)
            ));
        }
        let policy = store::load_policy(&fixture.directory)?;
        assert_eq!(policy.revision, 5);
        assert!(policy.users[0].deleted && !policy.users[0].active);
        let page = list(&fixture.directory, &fixture.actor, None, 2)?;
        assert_eq!(
            page.items
                .iter()
                .map(|operation| operation.sequence)
                .collect::<Vec<_>>(),
            [4, 3]
        );
        assert_eq!(page.next_cursor, Some(3));
        assert_eq!(
            list(&fixture.directory, &fixture.actor, page.next_cursor, 2)?
                .items
                .len(),
            2
        );
        validate_snapshot(&fixture.writable()?)?;
        Ok(())
    }

    #[test]
    fn node_assertions_precede_writes_and_terminal_replay_without_changing_legacy_digests()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let _author = store::lock(&fixture.directory)?;
        let connection = fixture.writable()?;
        let mut wrong = create(1);
        wrong.expected_node_id = Some(store::random_id()?);
        let before = snapshot(&connection)?;
        assert_eq!(
            error_code(&fixture.reserve(&wrong).unwrap_err()),
            Some(Error::Conflict)
        );
        assert!(before == snapshot(&connection)?);
        let denied = reserve(
            &fixture.directory,
            &store::update_lock(&fixture.directory)?,
            &store::random_id()?,
            &wrong,
        )
        .unwrap_err();
        assert_eq!(error_code(&denied), Some(Error::Denied));
        assert!(before == snapshot(&connection)?);

        let legacy = create(1);
        let reserved = fixture.reserve(&legacy)?;
        let before = snapshot(&connection)?;
        let error = fixture.execute(&reserved.id, wrong.clone()).err().unwrap();
        assert!(!error.policy_uncertain());
        assert_eq!(error_code(&error.into_error()), Some(Error::Conflict));
        assert!(before == snapshot(&connection)?);
        assert_eq!(fixture.result(&reserved.id)?.state, State::Reserved);
        let mut bound = legacy.clone();
        bound.expected_node_id = Some(fixture.node.clone());
        assert_eq!(legacy.digest()?, bound.digest()?);
        let (change, saved) = accepted(
            fixture
                .execute(&reserved.id, bound.clone())
                .map_err(ExecuteError::into_error)?,
        );
        let user = change.user.unwrap().id;
        let before = snapshot(&connection)?;
        let error = fixture.execute(&saved.id, wrong).err().unwrap();
        assert!(!error.policy_uncertain());
        assert_eq!(error_code(&error.into_error()), Some(Error::Conflict));
        for input in [legacy, bound] {
            assert!(
                matches!(fixture.execute(&saved.id, input).map_err(ExecuteError::into_error)?, Outcome::Replayed(receipt) if receipt == saved)
            );
        }
        assert!(before == snapshot(&connection)?);

        let mut update = Input {
            expected_node_id: Some(store::random_id()?),
            expected_revision: 2,
            expected_epoch: 1,
            change: UserChange::UpdateUser {
                id: user,
                name: "Bound update".into(),
                protocols: vec![Protocol::Http],
                concurrent_limit: 1,
            },
        };
        assert_eq!(
            error_code(&fixture.reserve(&update).unwrap_err()),
            Some(Error::Conflict)
        );
        assert!(before == snapshot(&connection)?);
        update.expected_node_id = Some(fixture.node.clone());
        let reserved = fixture.reserve(&update)?;
        let before = snapshot(&connection)?;
        let mut wrong = update.clone();
        wrong.expected_node_id = Some(store::random_id()?);
        let error = fixture.execute(&reserved.id, wrong).err().unwrap();
        assert!(!error.policy_uncertain());
        assert_eq!(error_code(&error.into_error()), Some(Error::Conflict));
        assert!(before == snapshot(&connection)?);
        let (_, saved) = accepted(
            fixture
                .execute(&reserved.id, update.clone())
                .map_err(ExecuteError::into_error)?,
        );
        let before = snapshot(&connection)?;
        if let UserChange::UpdateUser { name, .. } = &mut update.change {
            *name = "Mismatched payload".into();
        }
        let error = fixture.execute(&saved.id, update).err().unwrap();
        assert!(!error.policy_uncertain());
        assert_eq!(error_code(&error.into_error()), Some(Error::Conflict));
        assert!(before == snapshot(&connection)?);

        let mut rejected = Input {
            expected_node_id: Some(fixture.node.clone()),
            expected_revision: 3,
            expected_epoch: 1,
            change: UserChange::DeleteUser {
                id: store::random_id()?,
            },
        };
        let reservation = fixture.reserve(&rejected)?;
        assert!(matches!(
            fixture
                .execute(&reservation.id, rejected.clone())
                .map_err(ExecuteError::into_error)?,
            Outcome::Rejected(_)
        ));
        let before = snapshot(&connection)?;
        rejected.expected_node_id = Some(store::random_id()?);
        let error = fixture
            .execute(&reservation.id, rejected.clone())
            .err()
            .unwrap();
        assert!(!error.policy_uncertain());
        assert_eq!(error_code(&error.into_error()), Some(Error::Conflict));
        rejected.expected_node_id = None;
        assert!(
            matches!(fixture.execute(&reservation.id, rejected).map_err(ExecuteError::into_error)?, Outcome::Replayed(receipt) if receipt.state == State::Rejected)
        );
        assert!(before == snapshot(&connection)?);
        validate_snapshot(&connection)?;
        Ok(())
    }

    #[test]
    fn business_rejection_is_terminal_and_failed_candidate_writes_are_rolled_back() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        let _author = store::lock(&fixture.directory)?;
        let first = create(1);
        let rejected = fixture.reserve(&first)?;
        let winning = fixture.reserve(&first)?;
        accepted(
            fixture
                .execute(&winning.id, first.clone())
                .map_err(ExecuteError::into_error)?,
        );
        assert!(
            matches!(fixture.execute(&rejected.id,first).map_err(ExecuteError::into_error)?,Outcome::Rejected(operation) if operation.rejection==Some("policy_conflict"))
        );
        assert_eq!(fixture.result(&rejected.id)?.state, State::Rejected);
        let missing = Input {
            expected_node_id: None,
            expected_revision: 2,
            expected_epoch: 1,
            change: UserChange::DeleteUser {
                id: store::random_id()?,
            },
        };
        let reservation = fixture.reserve(&missing)?;
        assert!(
            matches!(fixture.execute(&reservation.id,missing).map_err(ExecuteError::into_error)?,Outcome::Rejected(operation) if operation.rejection==Some("resource_not_found"))
        );
        let input = create(2);
        let reservation = fixture.reserve(&input)?;
        let connection = fixture.writable()?;
        connection.execute_batch("CREATE TRIGGER reject_permission BEFORE INSERT ON routing_permissions BEGIN SELECT RAISE(ABORT,'fixture candidate failure'); END;")
        .map_err(|error|sqlite_error("cannot install candidate failure fixture",error))?;
        let before = snapshot(&connection)?;
        let error = fixture.execute(&reservation.id, input).err().unwrap();
        assert!(
            !error.policy_uncertain(),
            "successful savepoint and outer rollback prove no policy commit"
        );
        assert!(before == snapshot(&connection)?);
        assert_eq!(fixture.result(&reservation.id)?.state, State::Reserved);
        Ok(())
    }

    #[test]
    fn receipt_ignore_commit_failure_and_failed_rollback_never_claim_rejection() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let _author = store::lock(&fixture.directory)?;
        let input = create(1);
        let reservation = fixture.reserve(&input)?;
        let connection = fixture.writable()?;
        let before = snapshot(&connection)?;
        connection.execute_batch("CREATE TRIGGER ignore_receipt BEFORE UPDATE ON user_operations WHEN NEW.state='saved' BEGIN SELECT RAISE(IGNORE); END;")
        .map_err(|error|sqlite_error("cannot install receipt failure fixture",error))?;
        let error = fixture
            .execute(&reservation.id, input.clone())
            .err()
            .unwrap();
        assert!(error.policy_uncertain());
        assert!(before == snapshot(&connection)?);
        connection.execute_batch("DROP TRIGGER ignore_receipt;
        CREATE TABLE fixture_commit_guard(user_id TEXT REFERENCES proxy_users(id) DEFERRABLE INITIALLY DEFERRED);
        CREATE TRIGGER deferred_commit AFTER UPDATE ON user_operations WHEN NEW.state='saved' BEGIN INSERT INTO fixture_commit_guard VALUES('AAAAAAAAAAAAAAAAAAAAAA'); END;")
        .map_err(|error|sqlite_error("cannot install deferred commit fixture",error))?;
        let error = fixture
            .execute(&reservation.id, input.clone())
            .err()
            .unwrap();
        assert!(
            error.policy_uncertain(),
            "a commit failure is not a business rejection"
        );
        assert!(before == snapshot(&connection)?);
        connection.execute_batch("DROP TRIGGER deferred_commit; DROP TABLE fixture_commit_guard;
        CREATE TRIGGER rollback_candidate BEFORE INSERT ON proxy_users BEGIN SELECT RAISE(ROLLBACK,'fixture engine rollback'); END;")
        .map_err(|error|sqlite_error("cannot install rollback failure fixture",error))?;
        let error = fixture.execute(&reservation.id, input).err().unwrap();
        assert!(
            error.policy_uncertain(),
            "failure to confirm savepoint rollback remains conservative"
        );
        assert!(before == snapshot(&connection)?);
        assert_eq!(fixture.result(&reservation.id)?.state, State::Reserved);
        Ok(())
    }

    #[test]
    fn concurrent_same_id_commits_once_and_other_actor_cannot_read_or_execute() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let _author = store::lock(&fixture.directory)?;
        let input = create(1);
        let reserved = fixture.reserve(&input)?;
        let barrier = Arc::new(Barrier::new(2));
        let results = std::thread::scope(|scope| {
            let workers = (0..2)
                .map(|_| {
                    let barrier = barrier.clone();
                    let fixture = &fixture;
                    let id = &reserved.id;
                    let input = input.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        fixture.execute(id, input)
                    })
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        let mut accepted_count = 0;
        let mut replayed_count = 0;
        let mut busy_count = 0;
        for result in results {
            match result {
                Ok(Outcome::Accepted { .. }) => accepted_count += 1,
                Ok(Outcome::Replayed(_)) => replayed_count += 1,
                Ok(Outcome::Rejected(_)) => {
                    panic!("same binding cannot reject after its own success")
                }
                Err(error) => {
                    let error = error.into_error();
                    if error.kind() != io::ErrorKind::WouldBlock {
                        return Err(error);
                    }
                    busy_count += 1;
                }
            }
        }
        // The existing nonblocking update gate may reject the competing writer
        // before SQL starts. Either admission ordering must save exactly once;
        // a busy response does not make a second mutation or an automatic retry.
        assert_eq!(accepted_count, 1);
        assert_eq!(replayed_count + busy_count, 1);
        assert_eq!(fixture.result(&reserved.id)?.state, State::Saved);
        let policy = store::load_policy(&fixture.directory)?;
        assert_eq!((policy.revision, policy.users.len()), (2, 1));
        let connection = fixture.writable()?;
        let other = store::random_id()?;
        connection
            .execute(
                "INSERT INTO administrators VALUES(?1,'other',?2)",
                params![other, PHC],
            )
            .map_err(|error| sqlite_error("cannot create second fixture actor", error))?;
        assert_eq!(
            error_code(&get(&fixture.directory, &other, &reserved.id).unwrap_err()),
            Some(Error::NotQueryable)
        );
        let error = execute(
            &fixture.directory,
            &store::update_lock(&fixture.directory)?,
            &other,
            &reserved.id,
            input,
        )
        .err()
        .unwrap();
        assert_eq!(error_code(&error.into_error()), Some(Error::NotQueryable));
        assert_eq!(
            error_code(&get(&fixture.directory, &store::random_id()?, &reserved.id).unwrap_err()),
            Some(Error::Denied)
        );
        Ok(())
    }

    #[test]
    fn owner_changes_reject_unexecuted_reservations_but_keep_same_actor_history() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        let _author = store::lock(&fixture.directory)?;
        let old = create(1);
        let reservation = fixture.reserve(&old)?;
        store::set_owner(
            &fixture.directory,
            &store::update_lock(&fixture.directory)?,
            &fixture.actor,
            1,
            None,
        )?;
        assert!(
            matches!(fixture.execute(&reservation.id,old).map_err(ExecuteError::into_error)?,Outcome::Rejected(operation) if operation.rejection==Some("owner_conflict"))
        );
        let mut input = create(1);
        input.expected_epoch = 2;
        let reservation = fixture.reserve(&input)?;
        let (_, saved) = accepted(
            fixture
                .execute(&reservation.id, input.clone())
                .map_err(ExecuteError::into_error)?,
        );
        store::set_owner(
            &fixture.directory,
            &store::update_lock(&fixture.directory)?,
            &fixture.actor,
            2,
            None,
        )?;
        assert_eq!(fixture.result(&saved.id)?, saved);
        assert!(
            matches!(fixture.execute(&saved.id,input).map_err(ExecuteError::into_error)?,Outcome::Replayed(operation) if operation==saved)
        );
        assert_eq!(store::load_policy(&fixture.directory)?.revision, 2);
        Ok(())
    }

    fn seeded_id(sequence: u64) -> String {
        let mut bytes = [7_u8; 16];
        bytes[8..].copy_from_slice(&sequence.to_be_bytes());
        URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn retention_is_bounded_ignore_pruning_rolls_back_and_pruned_ids_never_execute()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let _author = store::lock(&fixture.directory)?;
        let input = create(1);
        let digest = input.digest()?;
        let mut connection = fixture.writable()?;
        let transaction = connection
            .transaction()
            .map_err(|error| sqlite_error("cannot begin retention fixture", error))?;
        let mut actors = vec![fixture.actor.clone()];
        for index in 1..17 {
            let actor = store::random_id()?;
            transaction
                .execute(
                    "INSERT INTO administrators VALUES(?1,?2,?3)",
                    params![actor, format!("admin-{index}"), PHC],
                )
                .map_err(|error| sqlite_error("cannot seed retention actors", error))?;
            actors.push(actor);
        }
        {
            let mut insert=transaction.prepare("INSERT INTO user_operations(id,node_id,administrator_id,sequence,expected_revision,expected_epoch,action,digest,user_id,state,saved_revision,rejection) VALUES(?1,?2,?3,?4,1,1,'create_user',?5,NULL,'reserved',NULL,NULL)")
            .map_err(|error|sqlite_error("cannot prepare bounded retention fixture",error))?;
            for sequence in 1..=4_096_u64 {
                insert
                    .execute(params![
                        seeded_id(sequence),
                        fixture.node,
                        actors[(sequence as usize - 1) / 256],
                        sequence as i64,
                        digest.as_slice()
                    ])
                    .map_err(|error| {
                        sqlite_error("cannot seed bounded retention fixture", error)
                    })?;
            }
        }
        transaction
            .execute("UPDATE operations_state SET last_sequence=4096", [])
            .map_err(|error| sqlite_error("cannot seed operation high-water", error))?;
        transaction
            .commit()
            .map_err(|error| sqlite_error("cannot commit retention fixture", error))?;
        validate_snapshot(&connection)?;
        connection.execute_batch("CREATE TRIGGER ignore_pruning BEFORE DELETE ON user_operations BEGIN SELECT RAISE(IGNORE); END;")
        .map_err(|error|sqlite_error("cannot install pruning failure fixture",error))?;
        let error = fixture.reserve(&input).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(highwater(&connection)?, 4096);
        assert_eq!(fixture.result(&seeded_id(1))?.state, State::Reserved);
        connection
            .execute_batch("DROP TRIGGER ignore_pruning;")
            .map_err(|error| sqlite_error("cannot remove pruning failure fixture", error))?;
        let new = fixture.reserve(&input)?;
        assert_eq!(new.sequence, 4097);
        assert_eq!(
            error_code(&fixture.result(&seeded_id(1)).unwrap_err()),
            Some(Error::NotQueryable)
        );
        let error = fixture.execute(&seeded_id(1), input.clone()).err().unwrap();
        assert_eq!(error_code(&error.into_error()), Some(Error::NotQueryable));
        reserve(
            &fixture.directory,
            &store::update_lock(&fixture.directory)?,
            &actors[16],
            &input,
        )?;
        assert_eq!(
            error_code(&fixture.result(&seeded_id(2)).unwrap_err()),
            Some(Error::NotQueryable)
        );
        validate_snapshot(&connection)?;
        assert_eq!(store::load_policy(&fixture.directory)?.revision, 1);
        connection
            .execute("DELETE FROM user_operations", [])
            .map_err(|error| sqlite_error("cannot clear retained fixture rows", error))?;
        assert_eq!(fixture.reserve(&input)?.sequence, 4099);
        connection
            .execute("DELETE FROM user_operations", [])
            .map_err(|error| sqlite_error("cannot reset retained fixture rows", error))?;
        connection
            .execute("UPDATE operations_state SET last_sequence=?1", [i64::MAX])
            .map_err(|error| sqlite_error("cannot seed sequence exhaustion", error))?;
        assert_eq!(
            error_code(&fixture.reserve(&input).unwrap_err()),
            Some(Error::Capacity)
        );
        assert_eq!(highwater(&connection)?, i64::MAX as u64);
        Ok(())
    }

    #[test]
    fn typed_read_rejects_corrupt_receipts_without_unbounded_allocations() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let _author = store::lock(&fixture.directory)?;
        let input = create(1);
        let reservation = fixture.reserve(&input)?;
        let connection = fixture.writable()?;
        connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .map_err(|error| sqlite_error("cannot construct corrupt fixture", error))?;
        connection
            .execute(
                "UPDATE user_operations SET digest=zeroblob(4194304) WHERE id=?1",
                [&reservation.id],
            )
            .map_err(|error| sqlite_error("cannot corrupt fixture digest", error))?;
        assert_eq!(
            fixture.result(&reservation.id).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            validate_snapshot(&connection).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        connection
            .execute(
                "UPDATE user_operations SET digest=?1,state='saved',saved_revision=2 WHERE id=?2",
                params![input.digest()?.as_slice(), reservation.id],
            )
            .map_err(|error| sqlite_error("cannot corrupt fixture result", error))?;
        assert_eq!(
            fixture.result(&reservation.id).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        connection
            .execute(
                "UPDATE user_operations SET state='reserved',saved_revision=NULL,id=?1",
                [store::random_id()?],
            )
            .map_err(|error| sqlite_error("cannot corrupt fixture ID binding", error))?;
        assert_eq!(
            validate_snapshot(&connection).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        Ok(())
    }

    #[test]
    fn strict_typed_inputs_and_genuine_legacy_namespace_require_explicit_upgrade() -> io::Result<()>
    {
        assert!(
            serde_json::from_str::<UserChange>(
                r#"{"action":"create_credential","user_id":"AAAAAAAAAAAAAAAAAAAAAA"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<UserChange>(
                r#"{"action":"delete_user","id":"AAAAAAAAAAAAAAAAAAAAAA","secret":"not-supported"}"#
            )
            .is_err()
        );
        let fixture = Fixture::new()?;
        let _author = store::lock(&fixture.directory)?;
        assert!(list(&fixture.directory, &fixture.actor, None, 51).is_err());
        assert!(list(&fixture.directory, &fixture.actor, Some(0), 1).is_err());
        let connection = fixture.writable()?;
        connection
            .execute_batch("PRAGMA user_version=15")
            .map_err(|error| sqlite_error("cannot lower fixture version", error))?;
        assert_eq!(
            store::inspect(&fixture.directory).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        // Rebuild the genuine historical namespace rather than merely relabelling
        // a current database that still contains the newer automation tables.
        connection
            .pragma_update(None, "user_version", store::SCHEMA_VERSION)
            .map_err(|error| sqlite_error("cannot restore fixture layout version", error))?;
        store::recovery::restore_schema_fifteen_for_test(&connection)?;
        assert_eq!(
            error_code(&fixture.reserve(&create(1)).unwrap_err()),
            Some(Error::UpgradeRequired)
        );
        Ok(())
    }
}
