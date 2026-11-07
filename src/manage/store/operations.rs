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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;
    use crate::manage::store;

    const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$Zml4dHVyZQ";

    struct Fixture {
        directory: std::path::PathBuf,
        actor: String,
    }

    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory =
                std::env::temp_dir().join(format!("vproxy-operations-{}", store::random_id()?));
            store::initialize(&directory, "operation test", "admin", PHC)?;
            let connection = open_existing(&directory, false)?;
            let actor = connection
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(|error| sqlite_error("cannot read fixture administrator", error))?;
            Ok(Self { directory, actor })
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

    fn error_code(error: &io::Error) -> Option<Error> {
        error
            .get_ref()
            .and_then(|error| error.downcast_ref::<Error>())
            .copied()
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
}
