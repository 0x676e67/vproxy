//! Local ownership and at-most-once node commands for the real proxy policy.
//!
//! TLS identity, owner/epoch, command sequence and policy CAS are checked in the
//! same SQLite transaction. The caller retains its update gate through runtime
//! publication; a saved receipt is not evidence that a proxy is running.

pub(in crate::manage) mod endpoints;
mod schema13;
mod schema15;
pub(super) use schema15::upgrade_endpoints;
mod schema6;
mod schema9;
pub(super) use schema6::upgrade_schema;
pub(super) use schema9::upgrade_presets;
pub(super) use schema13::upgrade_owner_audit;

use std::{fmt, io, path::Path, sync::Arc};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params, types::ValueRef};
use sha2::{Digest as _, Sha256};

use super::{
    ChangeResult, CredentialView, Overview, Page, PolicyChange, PolicyStatus, UpdateGuard,
    UserView, peers, read_overview, sqlite_error, users, valid_id,
};
use crate::access::{
    Protocol,
    presets::{PresetData, PresetEntity},
    routing::{RoutingData, RoutingEntity},
};

const MAX_RECEIPTS: u32 = 4096;
const MAX_AUDIT: u32 = 16_384;

/// Stable domain rejection, not a wrapper for arbitrary database/I/O failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::manage) enum ControlError {
    ResourceManaged,
    OwnerConflict,
    PeerNotAuthorized,
    TargetMismatch,
    EpochConflict,
    CommandConflict,
    CommandOutOfOrder,
    ReceiptExpired,
    PolicyCapacity,
}

impl ControlError {
    /// Fixed wire-safe code; diagnostics contain no request or credential data.
    pub(in crate::manage) const fn code(self) -> &'static str {
        match self {
            Self::ResourceManaged => "resource_managed",
            Self::OwnerConflict => "owner_conflict",
            Self::PeerNotAuthorized => "peer_not_authorized",
            Self::TargetMismatch => "target_mismatch",
            Self::EpochConflict => "controller_epoch_changed",
            Self::CommandConflict => "command_conflict",
            Self::CommandOutOfOrder => "command_out_of_order",
            Self::ReceiptExpired => "receipt_expired",
            Self::PolicyCapacity => "policy_capacity",
        }
    }
    pub(super) fn error(self) -> io::Error {
        io::Error::new(
            if self == Self::PeerNotAuthorized {
                io::ErrorKind::PermissionDenied
            } else {
                io::ErrorKind::AlreadyExists
            },
            self,
        )
    }
}
impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for ControlError {}

/// One owner for this node's proxy policy; NULL owner means explicit local control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct Ownership {
    pub(in crate::manage) controller_node_id: Option<String>,
    pub(in crate::manage) epoch: u64,
    /// Never discarded when old receipt rows are pruned within this epoch.
    pub(in crate::manage) last_terminal_command: u64,
}

/// Constructed by the node TLS service, never from JSON/header identity claims.
pub(in crate::manage) struct RemoteAuthorization {
    pub(in crate::manage) node_id: String,
    pub(in crate::manage) authorization_revision: u64,
    pub(in crate::manage) leaf: Arc<[u8]>,
}

/// Typed command vocabulary; machine secrets are generated only on this target.
pub(in crate::manage) struct Command {
    pub(in crate::manage) target_node_id: String,
    pub(in crate::manage) epoch: u64,
    pub(in crate::manage) command_id: u64,
    pub(in crate::manage) expected_policy_revision: u64,
    /// Controller's assertion for audit only, not a local administrator account.
    pub(in crate::manage) source_administrator_id: String,
    pub(in crate::manage) change: PolicyChange,
}

/// Shared durable ordering, but separate access-policy and address metadata CAS.
pub(in crate::manage) enum ControlIntent {
    Policy(Command),
    Endpoint(endpoints::Command),
}
impl ControlIntent {
    pub(in crate::manage) fn target(&self) -> &str {
        match self {
            Self::Policy(value) => &value.target_node_id,
            Self::Endpoint(value) => &value.target_node_id,
        }
    }
    pub(in crate::manage) fn epoch(&self) -> u64 {
        match self {
            Self::Policy(value) => value.epoch,
            Self::Endpoint(value) => value.epoch,
        }
    }
    pub(in crate::manage) fn version(&self) -> u8 {
        match self {
            Self::Policy(value) => value.change.control_version(),
            Self::Endpoint(_) => 4,
        }
    }
}
impl From<Command> for ControlIntent {
    fn from(value: Command) -> Self {
        Self::Policy(value)
    }
}
impl From<endpoints::Command> for ControlIntent {
    fn from(value: endpoints::Command) -> Self {
        Self::Endpoint(value)
    }
}

/// Saved is durable acceptance; Applied is historical actual runtime publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::manage) enum ReceiptStatus {
    Saved,
    Applied,
    Rejected,
}

/// A routing receipt names an immutable identity, never a complete catalog or a
/// fabricated proxy user. Permission references use the actual user's ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum RoutingKind {
    Prefix,
    Address,
    Pool,
    Permission,
}

impl RoutingKind {
    pub(in crate::manage) const fn as_str(self) -> &'static str {
        match self {
            Self::Prefix => "prefix",
            Self::Address => "address",
            Self::Pool => "pool",
            Self::Permission => "permission",
        }
    }
    pub(super) fn parse(value: &str) -> io::Result<Self> {
        match value {
            "prefix" => Ok(Self::Prefix),
            "address" => Ok(Self::Address),
            "pool" => Ok(Self::Pool),
            "permission" => Ok(Self::Permission),
            _ => Err(data("routing receipt kind is malformed")),
        }
    }
}

/// Non-secret terminal routing identity, retained across replay and restart.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct RoutingReceipt {
    pub(in crate::manage) kind: RoutingKind,
    pub(in crate::manage) id: String,
}

/// Stable preset configuration identity. This is separate from routing and
/// proxy users, so a pool update never fabricates a user-based receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum PresetKind {
    User,
    Pool,
}

impl PresetKind {
    pub(in crate::manage) const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Pool => "pool",
        }
    }
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "user" => Ok(Self::User),
            "pool" => Ok(Self::Pool),
            _ => Err(data("preset receipt kind is malformed")),
        }
    }
}

/// Small non-secret metadata retained by replay and the controller outbox.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct PresetReceipt {
    pub(in crate::manage) kind: PresetKind,
    pub(in crate::manage) id: String,
}

impl From<&PresetEntity> for PresetReceipt {
    fn from(value: &PresetEntity) -> Self {
        match value {
            PresetEntity::User(value) => Self {
                kind: PresetKind::User,
                id: value.user_id.clone(),
            },
            PresetEntity::Pool(value) => Self {
                kind: PresetKind::Pool,
                id: value.pool_id.clone(),
            },
        }
    }
}

impl From<&RoutingEntity> for RoutingReceipt {
    fn from(entity: &RoutingEntity) -> Self {
        let (kind, id) = match entity {
            RoutingEntity::Prefix(value) => (RoutingKind::Prefix, &value.id),
            RoutingEntity::Address(value) => (RoutingKind::Address, &value.id),
            RoutingEntity::Pool(value) => (RoutingKind::Pool, &value.id),
            RoutingEntity::Permission(value) => (RoutingKind::Permission, &value.user_id),
        };
        Self {
            kind,
            id: id.clone(),
        }
    }
}

/// Replayable non-secret metadata. Receipts never reconstruct passwords;
/// explicit reads of the current encrypted generation use a separate endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct Receipt {
    /// Stored even for rejection so a v1 endpoint cannot return a v2 command.
    pub(in crate::manage) version: u8,
    pub(in crate::manage) epoch: u64,
    pub(in crate::manage) command_id: u64,
    pub(in crate::manage) status: ReceiptStatus,
    pub(in crate::manage) policy_revision: Option<u64>,
    pub(in crate::manage) rejection: Option<&'static str>,
    pub(in crate::manage) user_id: Option<String>,
    pub(in crate::manage) credential_id: Option<String>,
    pub(in crate::manage) routing: Option<RoutingReceipt>,
    pub(in crate::manage) preset: Option<PresetReceipt>,
}

/// Only first acceptance contains a secret; retries never execute the change again.
pub(in crate::manage) enum CommandOutcome {
    Accepted {
        change: Box<ChangeResult>,
        receipt: Receipt,
    },
    Replayed(Receipt),
    Rejected(Receipt),
}

/// All fields come from the same authorization/ownership/read transaction.
pub(in crate::manage) struct RemotePolicyStatus {
    pub(in crate::manage) node_id: String,
    pub(in crate::manage) ownership: Ownership,
    pub(in crate::manage) policy: PolicyStatus,
}

/// Creates v4 objects and rebuilds the v3 audit CHECKs without losing old actors.
pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection.execute_batch(
        "CREATE TABLE proxy_policy_audit_v4 (
          sequence INTEGER PRIMARY KEY,
          entry TEXT NOT NULL CHECK(entry IN ('local_management','node_management')),
          administrator_id TEXT REFERENCES administrators(id) ON DELETE RESTRICT,
          controller_node_id TEXT REFERENCES peers(node_id) ON DELETE RESTRICT,
          controller_epoch INTEGER CHECK(controller_epoch >= 1),
          command_id INTEGER CHECK(command_id >= 1),
          source_administrator_id TEXT CHECK(length(source_administrator_id) = 22),
          action TEXT NOT NULL CHECK(action IN ('create_user','update_user','enable_user','disable_user','delete_user','create_credential','enable_credential','disable_credential','rotate_credential','revoke_credential')),
          user_id TEXT NOT NULL REFERENCES proxy_users(id) ON DELETE RESTRICT,
          credential_id TEXT REFERENCES proxy_credentials(id) ON DELETE RESTRICT,
          policy_revision INTEGER NOT NULL CHECK(policy_revision >= 1),
          CHECK((entry='local_management' AND administrator_id IS NOT NULL AND controller_node_id IS NULL AND controller_epoch IS NULL AND command_id IS NULL AND source_administrator_id IS NULL)
            OR (entry='node_management' AND administrator_id IS NULL AND controller_node_id IS NOT NULL AND controller_epoch IS NOT NULL AND command_id IS NOT NULL AND source_administrator_id IS NOT NULL))
         ) STRICT;
         INSERT INTO proxy_policy_audit_v4(sequence,entry,administrator_id,action,user_id,credential_id,policy_revision)
          SELECT sequence,entry,administrator_id,action,user_id,credential_id,policy_revision FROM proxy_policy_audit;
         DROP TABLE proxy_policy_audit;
         ALTER TABLE proxy_policy_audit_v4 RENAME TO proxy_policy_audit;
         CREATE TABLE control_ownership (
          singleton INTEGER PRIMARY KEY CHECK(singleton=1),
          controller_node_id TEXT REFERENCES peers(node_id) ON DELETE RESTRICT,
          epoch INTEGER NOT NULL CHECK(epoch >= 1),
          last_terminal_command INTEGER NOT NULL CHECK(last_terminal_command >= 0)
         ) STRICT;
         INSERT INTO control_ownership VALUES(1,NULL,1,0);
         CREATE TABLE control_receipts (
          epoch INTEGER NOT NULL CHECK(epoch >= 1), command_id INTEGER NOT NULL CHECK(command_id >= 1),
          controller_node_id TEXT NOT NULL REFERENCES peers(node_id) ON DELETE RESTRICT,
          digest BLOB NOT NULL CHECK(length(digest)=32),
          status TEXT NOT NULL CHECK(status IN ('saved','applied','rejected')),
          policy_revision INTEGER CHECK(policy_revision >= 1),
          rejection TEXT CHECK(rejection IN ('invalid_policy','policy_conflict','resource_not_found','policy_capacity')),
          user_id TEXT REFERENCES proxy_users(id) ON DELETE RESTRICT,
          credential_id TEXT REFERENCES proxy_credentials(id) ON DELETE RESTRICT,
          PRIMARY KEY(epoch,command_id),
          CHECK((status='rejected' AND rejection IS NOT NULL AND policy_revision IS NULL AND user_id IS NULL AND credential_id IS NULL)
             OR (status IN ('saved','applied') AND rejection IS NULL AND policy_revision IS NOT NULL AND user_id IS NOT NULL))
         ) STRICT;
         CREATE TABLE control_audit (
          sequence INTEGER PRIMARY KEY,
          action TEXT NOT NULL CHECK(action IN ('set_owner','command_rejected')),
          administrator_id TEXT REFERENCES administrators(id) ON DELETE RESTRICT,
          controller_node_id TEXT REFERENCES peers(node_id) ON DELETE RESTRICT,
          epoch INTEGER NOT NULL CHECK(epoch >= 1), command_id INTEGER CHECK(command_id >= 1),
          source_administrator_id TEXT CHECK(length(source_administrator_id)=22),
          rejection TEXT CHECK(rejection IN ('invalid_policy','policy_conflict','resource_not_found','policy_capacity')),
          CHECK((action='set_owner' AND administrator_id IS NOT NULL AND command_id IS NULL AND source_administrator_id IS NULL AND rejection IS NULL)
            OR (action='command_rejected' AND administrator_id IS NULL AND controller_node_id IS NOT NULL AND command_id IS NOT NULL AND source_administrator_id IS NOT NULL AND rejection IS NOT NULL))
         ) STRICT;"
    ).map_err(|error| sqlite_error("cannot create node control schema", error))?;
    super::targets::create_schema(connection)
}

/// Reads local ownership without acquiring or repairing a database. Blocking cold path.
pub(in crate::manage) fn ownership(directory: &Path) -> io::Result<Ownership> {
    read_snapshot(directory, read_ownership)
}

/// Explicit local grant/takeover, serialized with policy apply and peer mutations.
///
/// The real local administrator and selected active peer are rechecked inside
/// the immediate transaction. Every successful grant, even same owner, increments
/// epoch and retires the prior command namespace; existing policy is unchanged.
pub(in crate::manage) fn set_owner(
    directory: &Path,
    guard: &UpdateGuard,
    administrator_id: &str,
    expected_epoch: u64,
    controller: Option<&str>,
) -> io::Result<Ownership> {
    set_owner_as(
        directory,
        guard,
        OwnerActor::Administrator(administrator_id),
        expected_epoch,
        controller,
    )
}

/// Filesystem authority is deliberately not a named browser administrator.
enum OwnerActor<'a> {
    Administrator(&'a str),
    Offline,
}

/// Explicit local grant/takeover while no serve process owns this directory.
/// This never contacts a peer, stops a service, repairs state or retries a write.
/// Both locks fail immediately on contention and outlive the SQL commit. The
/// current offline audit schema is required; older databases need backed-up
/// migration. A commit/output error is not proof that the owner stayed unchanged.
pub(in crate::manage) fn set_owner_offline(
    directory: &Path,
    expected_epoch: u64,
    controller: Option<&str>,
) -> io::Result<Ownership> {
    let _author = super::lock(directory).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            io::Error::new(error.kind(), "management directory is in use; stop manage serve (including managed proxy listeners) or other offline operations explicitly before changing its owner")
        } else {
            error
        }
    })?;
    let gate = super::update_lock(directory)?;
    set_owner_as(
        directory,
        &gate,
        OwnerActor::Offline,
        expected_epoch,
        controller,
    )
}

fn set_owner_as(
    directory: &Path,
    guard: &UpdateGuard,
    actor: OwnerActor<'_>,
    expected_epoch: u64,
    controller: Option<&str>,
) -> io::Result<Ownership> {
    guard.ensure(directory)?;
    positive(expected_epoch)?;
    let mut connection = peers::open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin control ownership update", error))?;
    let result = set_owner_actor_in(&transaction, actor, expected_epoch, controller)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit control ownership", error))?;
    Ok(result)
}

fn set_owner_actor_in(
    transaction: &rusqlite::Transaction<'_>,
    actor: OwnerActor<'_>,
    expected_epoch: u64,
    controller: Option<&str>,
) -> io::Result<Ownership> {
    // A Rust Transaction can outlive raw SQL ROLLBACK/COMMIT. Never let a lost
    // caller transaction turn these two writes into independent autocommits.
    if transaction.is_autocommit() {
        return Err(io::Error::other(
            "ownership transaction is no longer active",
        ));
    }
    positive(expected_epoch)?;
    let (action, administrator) = match actor {
        OwnerActor::Administrator(id) => {
            check_administrator(transaction, id)?;
            ("set_owner", Some(id))
        }
        OwnerActor::Offline => {
            if read_overview(transaction)?.schema_version != super::SCHEMA_VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "offline ownership changes require the current schema; first run manage migrate --backup",
                ));
            }
            ("set_owner_offline", None)
        }
    };
    let before = read_ownership(transaction)?;
    if before.epoch != expected_epoch {
        return Err(ControlError::OwnerConflict.error());
    }
    if let Some(id) = controller {
        if !valid_id(id) {
            return Err(input("invalid controller identity"));
        }
        let active: Option<i64> = transaction
            .query_row("SELECT active FROM peers WHERE node_id=?1", [id], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|error| sqlite_error("cannot inspect selected controller", error))?;
        match active {
            Some(1) => {}
            Some(0) | None => return Err(ControlError::PeerNotAuthorized.error()),
            _ => return Err(data("controller state is malformed")),
        }
        if read_overview(transaction)?.node_id == id {
            return Err(input("a node cannot control itself"));
        }
    }
    let epoch = next(before.epoch)?;
    let changed = transaction.execute("UPDATE control_ownership SET controller_node_id=?1,epoch=?2,last_terminal_command=0 WHERE singleton=1", params![controller, positive(epoch)?]).map_err(|error| sqlite_error("cannot save control ownership", error))?;
    if changed != 1 {
        return Err(data("ownership update did not affect one node"));
    }
    let audited = transaction.execute("INSERT INTO control_audit(action,administrator_id,controller_node_id,epoch) VALUES(?1,?2,?3,?4)", params![action,administrator,controller,positive(epoch)?]).map_err(|error| sqlite_error("cannot audit control ownership", error))?;
    if audited != 1 {
        return Err(data("ownership update audit was not stored"));
    }
    let audit_row = transaction.last_insert_rowid();
    prune_audit(transaction)?;
    let saved = read_ownership(transaction)?;
    if saved.controller_node_id.as_deref() != controller
        || saved.epoch != epoch
        || saved.last_terminal_command != 0
    {
        return Err(data(
            "ownership update readback differs from the selected transition",
        ));
    }
    // Affected-row counts alone cannot prove that an AFTER trigger retained
    // the selected audit. This uses columns shared by legacy admin and current
    // offline schemas, preserving the older administrator ownership API.
    let retained: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM control_audit WHERE rowid=?1 AND action=?2 AND administrator_id IS ?3 AND controller_node_id IS ?4 AND epoch=?5)",
        params![audit_row, action, administrator, controller, positive(epoch)?],
        |row| row.get(0),
    ).map_err(|e| sqlite_error("cannot verify ownership audit readback", e))?;
    if !retained {
        return Err(data(
            "ownership audit readback differs from the selected transition",
        ));
    }
    Ok(saved)
}

/// Enforces explicit schema4/local ownership in the caller's policy transaction.
pub(super) fn require_local(connection: &Connection) -> io::Result<()> {
    if read_ownership(connection)?.controller_node_id.is_some() {
        return Err(ControlError::ResourceManaged.error());
    }
    Ok(())
}

/// Executes one authorized command once, retaining the caller's publication gate.
///
/// Authorization/ownership precede replay, replay precedes policy CAS. Ordinary
/// business rejection rolls back its savepoint and becomes a durable terminal
/// receipt; malformed storage and uncertain SQL/I/O failures roll back the entire
/// transaction, never advance high water and never masquerade as protocol rejection.
/// `can_resume` is the coordinator's serialized listener-lifecycle decision. It
/// rejects only a new enable-admission command; a retained receipt remains the
/// result of its original execution even if this process's lifecycle changed.
pub(in crate::manage) fn apply_command_with_admission(
    directory: &Path,
    guard: &UpdateGuard,
    authorization: &RemoteAuthorization,
    command: Command,
    can_resume: bool,
) -> io::Result<CommandOutcome> {
    guard.ensure(directory)?;
    validate_command(&command)?;
    let mut connection = peers::open_existing(directory, true)?;
    let mut transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin node policy command", error))?;
    let outcome = apply_command_in(&mut transaction, authorization, command, can_resume)?;
    let context = if matches!(&outcome, CommandOutcome::Replayed(_)) {
        "cannot complete node command replay"
    } else {
        "cannot commit node policy command"
    };
    transaction
        .commit()
        .map_err(|error| sqlite_error(context, error))?;
    Ok(outcome)
}

/// Recheck the actual TLS peer, owner/epoch, sequence, digest and policy CAS in
/// a caller-owned write transaction. A terminal replay only reads; the source
/// caller must end that observation without generating another source sequence.
/// Savepoints retain the original durable rejection semantics. No commit,
/// policy publication or secret delivery is performed by this core.
pub(in crate::manage) fn apply_command_in(
    transaction: &mut rusqlite::Transaction<'_>,
    authorization: &RemoteAuthorization,
    command: Command,
    can_resume: bool,
) -> io::Result<CommandOutcome> {
    validate_command(&command)?;
    let version = command.change.control_version();
    let digest = command_digest(&command)?;
    let owner = authorize_in(transaction, authorization)?;
    if version == 5 && read_overview(transaction)?.schema_version < 19 {
        return Err(super::admission::Error::UpgradeRequired.error());
    }
    if read_overview(transaction)?.schema_version < 9 {
        return Err(data("node commands require explicit schema migration"));
    }
    if read_overview(transaction)?.node_id != command.target_node_id {
        return Err(ControlError::TargetMismatch.error());
    }
    if owner.epoch != command.epoch {
        return Err(ControlError::EpochConflict.error());
    }
    if command.command_id <= owner.last_terminal_command {
        if endpoints::receipt_version(transaction, command.epoch, command.command_id)? == Some(4) {
            return Err(ControlError::CommandConflict.error());
        }
        let (receipt, stored_digest) =
            find_receipt(transaction, command.epoch, command.command_id)?
                .ok_or_else(|| ControlError::ReceiptExpired.error())?;
        if stored_digest != digest {
            return Err(ControlError::CommandConflict.error());
        }
        return Ok(CommandOutcome::Replayed(receipt));
    }
    if command.command_id != next(owner.last_terminal_command)? {
        return Err(ControlError::CommandOutOfOrder.error());
    }
    let result = {
        let mut savepoint = transaction
            .savepoint()
            .map_err(|error| sqlite_error("cannot begin command mutation savepoint", error))?;
        let result = if !can_resume
            && matches!(
                &command.change,
                PolicyChange::SetAdmission { accepting: true }
            ) {
            // A known lifecycle refusal is terminal, not a transient delivery
            // error that could enable this old command after a process restart.
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "proxy listeners cannot resume in this lifecycle",
            ))
        } else {
            users::apply_in(
                &savepoint,
                users::Actor::Remote {
                    node_id: &authorization.node_id,
                    epoch: command.epoch,
                    command_id: command.command_id,
                    source_administrator_id: &command.source_administrator_id,
                },
                command.expected_policy_revision,
                command.change,
            )
        };
        match result {
            Ok(change) => {
                savepoint.commit().map_err(|error| {
                    sqlite_error("cannot release command mutation savepoint", error)
                })?;
                Ok(change)
            }
            Err(error) => {
                if let Some(code) = rejection_code(&error) {
                    savepoint.rollback().map_err(|error| {
                        sqlite_error("cannot roll back rejected command", error)
                    })?;
                    Err(code)
                } else {
                    return Err(error);
                }
            }
        }
    };
    let receipt = match &result {
        Ok(change) => Receipt {
            version,
            epoch: command.epoch,
            command_id: command.command_id,
            status: ReceiptStatus::Saved,
            policy_revision: Some(change.policy.revision),
            rejection: None,
            user_id: if version == 1 {
                change.user.as_ref().map(|user| user.id.clone())
            } else {
                None
            },
            credential_id: change
                .credential
                .as_ref()
                .map(|credential| credential.id.clone()),
            routing: change.routing.as_ref().map(RoutingReceipt::from),
            preset: change.presets.as_ref().map(PresetReceipt::from),
        },
        Err(code) => Receipt {
            version,
            epoch: command.epoch,
            command_id: command.command_id,
            status: ReceiptStatus::Rejected,
            policy_revision: None,
            rejection: Some(code),
            user_id: None,
            credential_id: None,
            routing: None,
            preset: None,
        },
    };
    save_receipt(
        transaction,
        authorization,
        &command.source_administrator_id,
        &receipt,
        &digest,
    )?;
    Ok(match result {
        Ok(change) => CommandOutcome::Accepted {
            change: Box::new(change),
            receipt,
        },
        Err(_) => CommandOutcome::Rejected(receipt),
    })
}

/// Store-only fixtures do not own a live listener lifecycle. Production must
/// supply its serialized decision explicitly rather than use this default.
#[cfg(test)]
pub(in crate::manage) fn apply_command(
    directory: &Path,
    guard: &UpdateGuard,
    authorization: &RemoteAuthorization,
    command: Command,
) -> io::Result<CommandOutcome> {
    apply_command_with_admission(directory, guard, authorization, command, true)
}

/// Reads a current owner's receipt with authorization in the same read snapshot.
pub(in crate::manage) fn receipt(
    directory: &Path,
    authorization: &RemoteAuthorization,
    epoch: u64,
    command_id: u64,
) -> io::Result<Receipt> {
    positive(epoch)?;
    positive(command_id)?;
    read_snapshot(directory, |connection| {
        let owner = authorize_in(connection, authorization)?;
        if owner.epoch != epoch {
            return Err(ControlError::EpochConflict.error());
        }
        if let Some((receipt, _)) = find_receipt(connection, epoch, command_id)? {
            return Ok(receipt);
        }
        // A retained metadata receipt belongs to a different resource, not an
        // expired policy result. Classify it only after owner/epoch validation,
        // in this same snapshot; an actually pruned result keeps its old code.
        if endpoints::receipt_version(connection, epoch, command_id)? == Some(4)
            || command_id > owner.last_terminal_command
        {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "node command is not recorded",
            ))
        } else {
            Err(ControlError::ReceiptExpired.error())
        }
    })
}

/// Marks only the current saved candidate after actual publication to a running proxy.
///
/// The coordinator owns the same update gate. Recovery may acknowledge matching
/// current saved receipts, but cannot claim superseded intermediate versions ran.
pub(in crate::manage) fn mark_command_applied(
    directory: &Path,
    guard: &UpdateGuard,
    epoch: u64,
    command_id: u64,
    policy_revision: u64,
) -> io::Result<()> {
    guard.ensure(directory)?;
    positive(epoch)?;
    positive(command_id)?;
    let sql_policy_revision = positive(policy_revision)?;
    let mut connection = peers::open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin node application receipt", error))?;
    read_ownership(&transaction)?;
    if users::status_in(&transaction)?.revision != policy_revision {
        return Err(ControlError::CommandConflict.error());
    }
    let (receipt, _) = find_receipt(&transaction, epoch, command_id)?
        .ok_or_else(|| ControlError::ReceiptExpired.error())?;
    if receipt.status == ReceiptStatus::Rejected || receipt.policy_revision != Some(policy_revision)
    {
        return Err(ControlError::CommandConflict.error());
    }
    transaction
        .execute(
            "UPDATE control_receipts SET status='applied' WHERE epoch=?1 AND command_id=?2",
            params![positive(epoch)?, positive(command_id)?],
        )
        .and_then(|_| {
            transaction.execute(
                "UPDATE proxy_policy_state SET applied_revision=?1 WHERE singleton=1",
                [sql_policy_revision],
            )
        })
        .map_err(|error| sqlite_error("cannot save node application receipt", error))?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit node application receipt", error))
}

/// Returns only this owner's actual target metadata; no independent authorization read.
pub(in crate::manage) fn remote_policy_status(
    directory: &Path,
    authorization: &RemoteAuthorization,
) -> io::Result<RemotePolicyStatus> {
    read_snapshot(directory, |connection| {
        // Peer authorization performed the first complete validation. This
        // read-only transaction cannot change that schema or local identity;
        // retain fresh DER/owner checks and every typed policy-row check.
        let overview = authorize_peer_in(connection, authorization)?;
        let ownership = read_ownership_for_schema(connection, overview.schema_version)?;
        if ownership.controller_node_id.as_deref() == Some(overview.node_id.as_str()) {
            return Err(data("control ownership has an invalid peer binding"));
        }
        if ownership.controller_node_id.as_deref() != Some(authorization.node_id.as_str()) {
            return Err(ControlError::PeerNotAuthorized.error());
        }
        Ok(RemotePolicyStatus {
            ownership,
            node_id: overview.node_id,
            policy: users::status_in_for_schema(connection, overview.schema_version)?,
        })
    })
}

/// Bounded user metadata from the same snapshot as current owner/DER authorization.
pub(in crate::manage) fn remote_list_users(
    directory: &Path,
    authorization: &RemoteAuthorization,
    include_deleted: bool,
    after: Option<&str>,
    limit: u32,
) -> io::Result<Page<UserView>> {
    read_snapshot(directory, |connection| {
        authorize_in(connection, authorization)?;
        users::list_users_in(connection, include_deleted, after, limit)
    })
}

/// Search metadata in the same snapshot as current owner and exact-leaf
/// authorization; a cursor is a consistency check, not delegated authority.
pub(in crate::manage) fn remote_search_users(
    directory: &Path,
    authorization: &RemoteAuthorization,
    query: &crate::manage::user_search::Query,
) -> io::Result<Page<UserView>> {
    read_snapshot(directory, |connection| {
        authorize_in(connection, authorization)?;
        users::search_users_in(connection, query)
    })
}

/// Bounded credential metadata, never a verifier or one-time secret.
pub(in crate::manage) fn remote_list_credentials(
    directory: &Path,
    authorization: &RemoteAuthorization,
    user_id: Option<&str>,
    after: Option<&str>,
    limit: u32,
) -> io::Result<Page<CredentialView>> {
    read_snapshot(directory, |connection| {
        authorize_in(connection, authorization)?;
        users::list_credentials_in(connection, user_id, after, limit)
    })
}

/// Read the bounded non-secret catalog in the very same snapshot that checks
/// exact DER, current peer revision and ownership. Wire callers must paginate.
pub(in crate::manage) fn remote_presets_data(
    directory: &Path,
    authorization: &RemoteAuthorization,
) -> io::Result<(u64, PresetData)> {
    read_snapshot(directory, |connection| {
        authorize_in(connection, authorization)?;
        super::presets::data_in(connection)
    })
}

pub(in crate::manage) fn remote_routing_data(
    directory: &Path,
    authorization: &RemoteAuthorization,
) -> io::Result<(u64, RoutingData)> {
    read_snapshot(directory, |connection| {
        authorize_in(connection, authorization)?;
        if read_overview(connection)?.schema_version < 6 {
            return Err(data("remote routing requires explicit schema migration"));
        }
        super::routing::data_in(connection)
    })
}

/// Sample bounded, nonblocking in-memory metadata while current DER/owner
/// authorization's read transaction remains alive. The callback must not await,
/// mutate SQLite, perform I/O or acquire the policy writer/update gate.
pub(in crate::manage) fn remote_authorized<T>(
    directory: &Path,
    authorization: &RemoteAuthorization,
    sample: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    read_snapshot(directory, |connection| {
        authorize_in(connection, authorization)?;
        if read_overview(connection)?.schema_version < 6 {
            return Err(data(
                "remote observations require explicit schema migration",
            ));
        }
        sample()
    })
}

pub(super) fn read_snapshot<T>(
    directory: &Path,
    work: impl FnOnce(&Connection) -> io::Result<T>,
) -> io::Result<T> {
    let mut connection = peers::open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin node control inspection", error))?;
    let result = work(&transaction)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot complete node control inspection", error))?;
    Ok(result)
}

pub(super) fn read_ownership(connection: &Connection) -> io::Result<Ownership> {
    let owner = read_ownership_for_schema(connection, read_overview(connection)?.schema_version)?;
    if let Some(id) = &owner.controller_node_id
        && read_overview(connection)?.node_id == *id
    {
        return Err(data("control ownership has an invalid peer binding"));
    }
    Ok(owner)
}

/// Reads and validates all owner rows using the version from the caller's
/// current snapshot. The caller must also reject a local-node self binding.
fn read_ownership_for_schema(
    connection: &Connection,
    schema_version: u32,
) -> io::Result<Ownership> {
    if schema_version < 4 {
        return Err(data(
            "node policy control requires explicit schema migration",
        ));
    }
    let count: i64 = connection
        .query_row("SELECT count(*) FROM control_ownership", [], |row| {
            row.get(0)
        })
        .map_err(|error| sqlite_error("cannot count control ownership", error))?;
    if count != 1 {
        return Err(data("control ownership must contain one row"));
    }
    let (controller,epoch,last):(Option<String>,i64,i64)=connection.query_row("SELECT controller_node_id,epoch,last_terminal_command FROM control_ownership WHERE singleton=1",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).map_err(|error|sqlite_error("cannot read control ownership",error))?;
    if controller.as_ref().is_some_and(|id| !valid_id(id)) || epoch < 1 || last < 0 {
        return Err(data("control ownership is malformed"));
    }
    if let Some(id) = &controller {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM peers WHERE node_id=?1)",
                [id],
                |row| row.get(0),
            )
            .map_err(|error| sqlite_error("cannot inspect ownership peer binding", error))?;
        if !exists {
            return Err(data("control ownership has an invalid peer binding"));
        }
    }
    Ok(Ownership {
        controller_node_id: controller,
        epoch: u64::try_from(epoch).map_err(|_| data("control epoch is malformed"))?,
        last_terminal_command: u64::try_from(last)
            .map_err(|_| data("control command high water is malformed"))?,
    })
}

/// Rechecks exact bytes, current permission/SAN and connection binding before owner.
pub(super) fn authorize_in(
    connection: &Connection,
    authorization: &RemoteAuthorization,
) -> io::Result<Ownership> {
    authorize_peer_in(connection, authorization)?;
    let owner = read_ownership(connection)?;
    if owner.controller_node_id.as_deref() != Some(authorization.node_id.as_str()) {
        return Err(ControlError::PeerNotAuthorized.error());
    }
    Ok(owner)
}

/// Preserves certificate-length, schema, exact DER/revision and SAN validation
/// order. The returned overview belongs only to this unchanged transaction;
/// ownership is deliberately still checked by each caller afterwards.
fn authorize_peer_in(
    connection: &Connection,
    authorization: &RemoteAuthorization,
) -> io::Result<Overview> {
    let (overview, peer) = peers::authorize_in_with_overview(connection, &authorization.leaf)?;
    let peer = peer.ok_or_else(|| ControlError::PeerNotAuthorized.error())?;
    if peer.node_id != authorization.node_id
        || peer.authorization_revision != authorization.authorization_revision
        || super::super::tls::verify_peer_name(&authorization.leaf, &peer.expected_san).is_err()
    {
        return Err(ControlError::PeerNotAuthorized.error());
    }
    Ok(overview)
}

pub(super) fn check_administrator(connection: &Connection, id: &str) -> io::Result<()> {
    if !valid_id(id) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "administrator is not authorized",
        ));
    }
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM administrators WHERE id=?1)",
            [id],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot verify ownership administrator", error))?;
    if !exists {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "administrator is not authorized",
        ));
    }
    Ok(())
}

fn validate_command(command: &Command) -> io::Result<()> {
    if !valid_id(&command.target_node_id) || !valid_id(&command.source_administrator_id) {
        return Err(input("invalid node command identity"));
    }
    positive(command.epoch)?;
    positive(command.command_id)?;
    positive(command.expected_policy_revision)?;
    Ok(())
}

/// Versioned length-prefixed encoding; no JSON spelling or caller field order enters it.
pub(super) fn command_digest(command: &Command) -> io::Result<[u8; 32]> {
    fn text(hash: &mut Sha256, value: &str) {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    let mut hash = Sha256::new();
    hash.update(match command.change.control_version() {
        1 => &b"vproxy.proxy-command.v1\0"[..],
        2 => &b"vproxy.proxy-command.v2\0"[..],
        5 => &b"vproxy.proxy-command.v5\0"[..],
        _ => &b"vproxy.proxy-command.v3\0"[..],
    });
    text(&mut hash, &command.target_node_id);
    hash.update(command.epoch.to_be_bytes());
    hash.update(command.command_id.to_be_bytes());
    hash.update(command.expected_policy_revision.to_be_bytes());
    text(&mut hash, &command.source_administrator_id);
    match &command.change {
        PolicyChange::SetAdmission { accepting } => hash.update([u8::from(*accepting)]),
        PolicyChange::CreateUser {
            name,
            protocols,
            concurrent_limit,
        }
        | PolicyChange::UpdateUser {
            id: _,
            name,
            protocols,
            concurrent_limit,
        } => {
            if let PolicyChange::UpdateUser { id, .. } = &command.change {
                hash.update([2]);
                text(&mut hash, id);
            } else {
                hash.update([1]);
            }
            text(&mut hash, name);
            let mut mask = 0u8;
            let mut occurrences = [0u64; 3];
            for protocol in protocols {
                let (bit, index) = match protocol {
                    Protocol::Http => (1, 0),
                    Protocol::Socks5 => (2, 1),
                    Protocol::Masque => (4, 2),
                };
                mask |= bit;
                occurrences[index] = occurrences[index]
                    .checked_add(1)
                    .ok_or_else(|| input("node command protocol count exceeds its bounds"))?;
            }
            hash.update([mask]);
            // Valid permission sets are order-independent. Invalid multisets
            // still need distinct digests: semantic validation below records a
            // terminal rejection instead of leaving the sender's queue stuck.
            for count in occurrences {
                hash.update(count.to_be_bytes());
            }
            hash.update(concurrent_limit.to_be_bytes());
        }
        PolicyChange::SetUserActive { id, active } => {
            hash.update([3]);
            text(&mut hash, id);
            hash.update([u8::from(*active)]);
        }
        PolicyChange::DeleteUser { id } => {
            hash.update([4]);
            text(&mut hash, id);
        }
        PolicyChange::CreateCredential { user_id } => {
            hash.update([5]);
            text(&mut hash, user_id);
        }
        PolicyChange::SetCredentialActive { id, active } => {
            hash.update([6]);
            text(&mut hash, id);
            hash.update([u8::from(*active)]);
        }
        PolicyChange::RotateCredential { id } => {
            hash.update([7]);
            text(&mut hash, id);
        }
        PolicyChange::RevokeCredential { id } => {
            hash.update([8]);
            text(&mut hash, id);
        }
        PolicyChange::CreatePrefix { name, cidr } => {
            hash.update([1]);
            text(&mut hash, name);
            text(&mut hash, &cidr.to_string());
        }
        PolicyChange::RetirePrefix { id } => {
            hash.update([2]);
            text(&mut hash, id);
        }
        PolicyChange::CreateAddress {
            name,
            ip,
            prefix_id,
        } => {
            hash.update([3]);
            text(&mut hash, name);
            match ip {
                std::net::IpAddr::V4(ip) => {
                    hash.update([4]);
                    hash.update(ip.octets());
                }
                std::net::IpAddr::V6(ip) => {
                    hash.update([6]);
                    hash.update(ip.octets());
                }
            }
            hash.update([u8::from(prefix_id.is_some())]);
            if let Some(id) = prefix_id {
                text(&mut hash, id);
            }
        }
        PolicyChange::SetAddressState { id, state } => {
            hash.update([4]);
            text(&mut hash, id);
            text(&mut hash, state.as_str());
        }
        PolicyChange::CreatePool { name, family } => {
            hash.update([5]);
            text(&mut hash, name);
            text(&mut hash, family.as_str());
        }
        PolicyChange::SetPoolState { id, state } => {
            hash.update([6]);
            text(&mut hash, id);
            text(&mut hash, state.as_str());
        }
        PolicyChange::AddPoolMember {
            pool_id,
            address_id,
        }
        | PolicyChange::RemovePoolMember {
            pool_id,
            address_id,
        } => {
            hash.update([
                if matches!(command.change, PolicyChange::AddPoolMember { .. }) {
                    7
                } else {
                    8
                },
            ]);
            text(&mut hash, pool_id);
            text(&mut hash, address_id);
        }
        PolicyChange::SetRoutePermission(permission) => {
            hash.update([9]);
            text(&mut hash, &permission.user_id);
            hash.update([u8::from(permission.legacy_allowed)]);
            // Valid sets are order-independent; retaining every occurrence also
            // distinguishes malformed duplicate multisets before terminal reject.
            for ids in [&permission.exits, &permission.pools] {
                let mut ids: Vec<_> = ids.iter().collect();
                ids.sort_unstable();
                hash.update((ids.len() as u64).to_be_bytes());
                for id in ids {
                    text(&mut hash, id);
                }
            }
        }
        PolicyChange::SetUserPresets { presets } => {
            hash.update([1]);
            text(&mut hash, &presets.user_id);
            hash.update([presets
                .default_preset
                .map_or(0, crate::access::presets::bit)]);
            // A valid set is order-independent; preserve duplicate counts for
            // malformed candidates so terminal rejects cannot alias a replay.
            let mut counts = [0u64; 5];
            for profile in &presets.allowed_presets {
                let index = usize::try_from(crate::access::presets::bit(*profile).trailing_zeros())
                    .map_err(|_| input("preset count is invalid"))?;
                let count = counts
                    .get_mut(index)
                    .ok_or_else(|| input("preset count is invalid"))?;
                *count = count
                    .checked_add(1)
                    .ok_or_else(|| input("preset count exceeds its bounds"))?;
            }
            for count in counts {
                hash.update(count.to_be_bytes());
            }
        }
        PolicyChange::SetPoolPreset { preset } => {
            hash.update([2]);
            text(&mut hash, &preset.pool_id);
            hash.update([preset.default_preset.map_or(0, crate::access::presets::bit)]);
        }
    }
    Ok(hash.finalize().into())
}

fn rejection_code(error: &io::Error) -> Option<&'static str> {
    if error
        .get_ref()
        .and_then(|error| error.downcast_ref::<ControlError>())
        == Some(&ControlError::PolicyCapacity)
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

fn save_receipt(
    connection: &Connection,
    authorization: &RemoteAuthorization,
    source: &str,
    receipt: &Receipt,
    digest: &[u8; 32],
) -> io::Result<()> {
    let status = match receipt.status {
        ReceiptStatus::Saved => "saved",
        ReceiptStatus::Applied => "applied",
        ReceiptStatus::Rejected => "rejected",
    };
    connection
        .execute(
            "INSERT INTO control_receipts(epoch,command_id,controller_node_id,digest,status,policy_revision,rejection,user_id,credential_id,version,routing_kind,routing_id,preset_kind,preset_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                positive(receipt.epoch)?,
                positive(receipt.command_id)?,
                authorization.node_id,
                digest.as_slice(),
                status,
                receipt.policy_revision.map(positive).transpose()?,
                receipt.rejection,
                receipt.user_id,
                receipt.credential_id,
                receipt.version,
                receipt.routing.as_ref().map(|value|value.kind.as_str()),
                receipt.routing.as_ref().map(|value|value.id.as_str()),
                receipt.preset.as_ref().map(|value|value.kind.as_str()),
                receipt.preset.as_ref().map(|value|value.id.as_str())
            ],
        )
        .map_err(|error| sqlite_error("cannot save terminal node command", error))?;
    connection
        .execute(
            "UPDATE control_ownership SET last_terminal_command=?1 WHERE singleton=1",
            [positive(receipt.command_id)?],
        )
        .map_err(|error| sqlite_error("cannot advance node command high water", error))?;
    if receipt.status == ReceiptStatus::Rejected {
        connection.execute("INSERT INTO control_audit(action,controller_node_id,epoch,command_id,source_administrator_id,rejection) VALUES('command_rejected',?1,?2,?3,?4,?5)",params![authorization.node_id,positive(receipt.epoch)?,positive(receipt.command_id)?,source,receipt.rejection]).map_err(|error|sqlite_error("cannot audit rejected node command",error))?;
    }
    // Keep a still-current saved candidate even across an owner epoch change,
    // so activation can acknowledge it. Older saved candidates are superseded.
    connection.execute("DELETE FROM control_receipts WHERE (epoch,command_id) IN (SELECT epoch,command_id FROM control_receipts ORDER BY coalesce(status='saved' AND policy_revision=(SELECT revision FROM proxy_policy_state WHERE singleton=1),0) DESC,epoch DESC,command_id DESC LIMIT -1 OFFSET ?1)",[MAX_RECEIPTS]).map_err(|error|sqlite_error("cannot retain bounded command receipts",error))?;
    prune_audit(connection)
}

fn find_receipt(
    connection: &Connection,
    epoch: u64,
    command_id: u64,
) -> io::Result<Option<(Receipt, [u8; 32])>> {
    if read_overview(connection)?.schema_version >= 15 {
        let mixed: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM control_receipts WHERE epoch=?1 AND command_id=?2 AND version<>4 AND (metadata_revision IS NOT NULL OR endpoint_id IS NOT NULL OR endpoint_generation IS NOT NULL))",
                params![positive(epoch)?, positive(command_id)?],
                |row| row.get(0),
            )
            .map_err(|error| sqlite_error("cannot validate command receipt resource", error))?;
        if mixed {
            return Err(data("command receipt mixes policy and endpoint results"));
        }
    }
    let record=connection.query_row("SELECT status,policy_revision,rejection,user_id,credential_id,digest,version,routing_kind,routing_id,preset_kind,preset_id FROM control_receipts WHERE epoch=?1 AND command_id=?2 AND version<>4",params![positive(epoch)?,positive(command_id)?],|row|{
        let value=row.get_ref(5)?;
        let digest=match value{ValueRef::Blob(bytes)if bytes.len()==32=>{let mut digest=[0;32];digest.copy_from_slice(bytes);digest},_=>return Err(rusqlite::Error::InvalidColumnType(5,"digest".into(),value.data_type()))};
        Ok((row.get::<_,String>(0)?,row.get::<_,Option<i64>>(1)?,row.get::<_,Option<String>>(2)?,row.get::<_,Option<String>>(3)?,row.get::<_,Option<String>>(4)?,digest,row.get::<_,i64>(6)?,row.get::<_,Option<String>>(7)?,row.get::<_,Option<String>>(8)?,row.get::<_,Option<String>>(9)?,row.get::<_,Option<String>>(10)?))
    }).optional().map_err(|error|sqlite_error("cannot read command receipt",error))?;
    record
        .map(
            |(
                status,
                revision,
                rejection,
                user_id,
                credential_id,
                digest,
                version,
                kind,
                id,
                preset_kind,
                preset_id,
            )| {
                let routing = read_routing(kind, id)?;
                let preset = read_preset(preset_kind, preset_id)?;
                if let Some(value) = &preset {
                    let (table, key) = match value.kind {
                        PresetKind::User => ("user_presets", "user_id"),
                        PresetKind::Pool => ("pool_presets", "pool_id"),
                    };
                    let present: bool = connection
                        .query_row(
                            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {key}=?1)"),
                            [&value.id],
                            |row| row.get(0),
                        )
                        .map_err(|error| {
                            sqlite_error("cannot inspect preset receipt binding", error)
                        })?;
                    if !present {
                        return Err(data("preset receipt resource is missing"));
                    }
                }
                if let Some(reference) = &routing {
                    let table = match reference.kind {
                        RoutingKind::Prefix => "routing_prefixes",
                        RoutingKind::Address => "routing_addresses",
                        RoutingKind::Pool => "routing_pools",
                        RoutingKind::Permission => "routing_permissions",
                    };
                    let key = if reference.kind == RoutingKind::Permission {
                        "user_id"
                    } else {
                        "id"
                    };
                    let present: bool = connection
                        .query_row(
                            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {key}=?1)"),
                            [&reference.id],
                            |row| row.get(0),
                        )
                        .map_err(|error| {
                            sqlite_error("cannot inspect receipt routing binding", error)
                        })?;
                    if !present {
                        return Err(data("routing receipt resource is missing"));
                    }
                }
                let status = match status.as_str() {
                    "saved" => ReceiptStatus::Saved,
                    "applied" => ReceiptStatus::Applied,
                    "rejected" => ReceiptStatus::Rejected,
                    _ => return Err(data("command receipt status is malformed")),
                };
                let rejection = match rejection.as_deref() {
                    None => None,
                    Some("invalid_policy") => Some("invalid_policy"),
                    Some("policy_conflict") => Some("policy_conflict"),
                    Some("resource_not_found") => Some("resource_not_found"),
                    Some("policy_capacity") => Some("policy_capacity"),
                    _ => return Err(data("command receipt rejection is malformed")),
                };
                if !matches!(version, 1..=3 | 5)
                    || revision.is_some_and(|value| value < 1)
                    || user_id.as_ref().is_some_and(|id| !valid_id(id))
                    || credential_id.as_ref().is_some_and(|id| !valid_id(id))
                    || (status == ReceiptStatus::Rejected) != (rejection.is_some())
                    || (status == ReceiptStatus::Rejected)
                        && (revision.is_some()
                            || user_id.is_some()
                            || credential_id.is_some()
                            || routing.is_some()
                            || preset.is_some())
                    || (status != ReceiptStatus::Rejected)
                        && (revision.is_none()
                            || match version {
                                1 => user_id.is_none() || routing.is_some() || preset.is_some(),
                                2 => {
                                    user_id.is_some()
                                        || credential_id.is_some()
                                        || routing.is_none()
                                        || preset.is_some()
                                }
                                3 => {
                                    user_id.is_some()
                                        || credential_id.is_some()
                                        || routing.is_some()
                                        || preset.is_none()
                                }
                                _ => {
                                    user_id.is_some()
                                        || credential_id.is_some()
                                        || routing.is_some()
                                        || preset.is_some()
                                }
                            })
                {
                    return Err(data("command receipt is malformed"));
                }
                Ok((
                    Receipt {
                        version: u8::try_from(version)
                            .map_err(|_| data("receipt version is malformed"))?,
                        epoch,
                        command_id,
                        status,
                        policy_revision: revision
                            .map(|value| {
                                u64::try_from(value)
                                    .map_err(|_| data("receipt revision is malformed"))
                            })
                            .transpose()?,
                        rejection,
                        user_id,
                        credential_id,
                        routing,
                        preset,
                    },
                    digest,
                ))
            },
        )
        .transpose()
}

/// A preset kind/identity is one atomic pair, not a permissive partial record.
pub(super) fn read_preset(
    kind: Option<String>,
    id: Option<String>,
) -> io::Result<Option<PresetReceipt>> {
    match (kind, id) {
        (None, None) => Ok(None),
        (Some(kind), Some(id)) if valid_id(&id) => Ok(Some(PresetReceipt {
            kind: PresetKind::parse(&kind)?,
            id,
        })),
        _ => Err(data("preset receipt identity is malformed")),
    }
}

/// Polymorphic routing keys are validated as an atomic pair after SQL decoding.
pub(super) fn read_routing(
    kind: Option<String>,
    id: Option<String>,
) -> io::Result<Option<RoutingReceipt>> {
    match (kind, id) {
        (None, None) => Ok(None),
        (Some(kind), Some(id)) if valid_id(&id) => Ok(Some(RoutingReceipt {
            kind: RoutingKind::parse(&kind)?,
            id,
        })),
        _ => Err(data("routing receipt identity is malformed")),
    }
}

fn prune_audit(connection: &Connection) -> io::Result<()> {
    connection.execute("DELETE FROM control_audit WHERE sequence IN (SELECT sequence FROM control_audit ORDER BY sequence DESC LIMIT -1 OFFSET ?1)",[MAX_AUDIT]).map_err(|error|sqlite_error("cannot retain bounded control audit",error))?;
    Ok(())
}
fn positive(value: u64) -> io::Result<i64> {
    if value == 0 {
        return Err(input("control revision must be positive"));
    }
    i64::try_from(value).map_err(|_| input("control revision exceeds storage range"))
}
fn next(value: u64) -> io::Result<u64> {
    value
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| data("control revision is exhausted"))
}
fn input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::store::{
        self, initialize, load_policy, random_id, register_peer, update_lock,
    };

    mod admission {
        use super::*;

        #[test]
        fn schema_nineteen_copies_legacy_receipts_and_pending_endpoint_bytes_or_rolls_back()
        -> io::Result<()> {
            for collision in [false, true] {
                let fixture = Fixture::new()?;
                fixture.grant()?;
                fixture.run(fixture.command(1, 1, create()))?;
                let connection = fixture.writable()?;
                // Issue the pending command as a real legacy writer, not as schema20
                // work whose permanent history identity a downgrade must reject.
                store::recovery::restore_schema_eighteen_for_test(&connection)?;
                connection.execute("INSERT INTO control_receipts(epoch,command_id,controller_node_id,digest,status,version,metadata_revision,endpoint_id,endpoint_generation) VALUES(2,2,?1,?2,'saved',4,2,?3,?4)",params![fixture.peer,[9_u8;32].as_slice(),random_id()?,"a".repeat(64)]).map_err(io::Error::other)?;
                connection
                    .execute("UPDATE control_ownership SET last_terminal_command=2", [])
                    .map_err(io::Error::other)?;
                store::targets::configure(
                    &fixture.directory,
                    &fixture.administrator,
                    &fixture.peer,
                    None,
                    "https://controller.example",
                    true,
                    None,
                )?;
                store::targets::observe(&fixture.directory, &fixture.peer, 1, 2, 0, 1)?;
                let pending = store::targets::enqueue_intent(
                    &fixture.directory,
                    &fixture.administrator,
                    1,
                    ControlIntent::Endpoint(store::endpoint_control::Command {
                        target_node_id: fixture.peer.clone(),
                        epoch: 2,
                        command_id: 1,
                        expected_metadata_revision: 2,
                        source_administrator_id: fixture.administrator.clone(),
                        generation: "b".repeat(64),
                        change: store::endpoints::Change {
                            listener_id: random_id()?,
                            selection: store::endpoints::AddressSelection::Hidden,
                        },
                    }),
                )?;
                let blob: Vec<u8> = connection
                    .query_row("SELECT command FROM control_outbox", [], |row| row.get(0))
                    .map_err(io::Error::other)?;
                let digests: Vec<(u8, Vec<u8>)> = {
                    let mut statement = connection
                        .prepare("SELECT version,digest FROM control_receipts ORDER BY command_id")
                        .map_err(io::Error::other)?;
                    statement
                        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                        .map_err(io::Error::other)?
                        .collect::<rusqlite::Result<_>>()
                        .map_err(io::Error::other)?
                };
                if collision {
                    connection.execute_batch("CREATE TABLE control_receipts_admission_rebuild(sentinel TEXT); INSERT INTO control_receipts_admission_rebuild VALUES('operator fixture');").map_err(io::Error::other)?;
                }
                let backup = fixture.directory.join("before19.sqlite3");
                let migrated = store::migrate(&fixture.directory, &backup);
                let copied = Connection::open(&backup).map_err(io::Error::other)?;
                assert_eq!(store::read_overview(&copied)?.schema_version, 18);
                let after_blob: Vec<u8> = connection
                    .query_row("SELECT command FROM control_outbox", [], |row| row.get(0))
                    .map_err(io::Error::other)?;
                assert_eq!(blob, after_blob);
                let after_digests: Vec<(u8, Vec<u8>)> = {
                    let mut statement = connection
                        .prepare("SELECT version,digest FROM control_receipts ORDER BY command_id")
                        .map_err(io::Error::other)?;
                    statement
                        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                        .map_err(io::Error::other)?
                        .collect::<rusqlite::Result<_>>()
                        .map_err(io::Error::other)?
                };
                assert_eq!(digests, after_digests);
                assert_eq!(
                    store::targets::job(&fixture.directory, &fixture.peer)?
                        .unwrap()
                        .job_id,
                    pending.job_id
                );
                assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 2);
                if collision {
                    assert!(migrated.is_err());
                    assert_eq!(store::inspect(&fixture.directory)?.schema_version, 18);
                    let sentinel: String = connection
                        .query_row(
                            "SELECT sentinel FROM control_receipts_admission_rebuild",
                            [],
                            |row| row.get(0),
                        )
                        .map_err(io::Error::other)?;
                    assert_eq!(sentinel, "operator fixture");
                } else {
                    assert_eq!(migrated?.schema_version, store::SCHEMA_VERSION);
                    let history = store::targets::history::get(
                        &fixture.directory,
                        &fixture.administrator,
                        &fixture.peer,
                        &pending.job_id,
                    )?
                    .unwrap();
                    assert!(history.imported);
                    assert_eq!((history.sequence, history.protocol_version), (1, 4));
                    assert_eq!(history.job, pending);
                    assert!(history.recorded_at_unix_s.is_none());
                    assert!(history.updated_at_unix_s.is_none());
                    assert!(matches!(
                        fixture.run(fixture.command(1, 1, create()))?,
                        CommandOutcome::Replayed(Receipt { version: 1, .. })
                    ));
                    assert_eq!(
                        store::endpoint_control::receipt(
                            &fixture.directory,
                            &fixture.authorize(),
                            2,
                            2
                        )?
                        .metadata_revision,
                        Some(2)
                    );
                    fixture.run(fixture.command(
                        3,
                        2,
                        PolicyChange::SetAdmission { accepting: false },
                    ))?;
                    assert!(!store::load_policy(&fixture.directory)?.accepting);
                }
            }
            Ok(())
        }

        #[test]
        fn lifecycle_resume_rejection_is_durable_and_does_not_block_the_next_pause()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            fixture.grant()?;
            fixture.run(fixture.command(1, 1, PolicyChange::SetAdmission { accepting: false }))?;
            let execute = |command, can_resume| {
                apply_command_with_admission(
                    &fixture.directory,
                    &update_lock(&fixture.directory)?,
                    &fixture.authorize(),
                    command,
                    can_resume,
                )
            };
            let command = || fixture.command(2, 2, PolicyChange::SetAdmission { accepting: true });
            let digest = command_digest(&command())?;
            let CommandOutcome::Rejected(rejected) = execute(command(), false)? else {
                panic!("quiesced listener accepted resume")
            };
            assert_eq!(
                (rejected.version, rejected.status, rejected.rejection),
                (5, ReceiptStatus::Rejected, Some("policy_conflict"))
            );
            assert!(rejected.policy_revision.is_none());
            assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 2);
            let policy = load_policy(&fixture.directory)?;
            assert_eq!(policy.revision, 2);
            assert!(!policy.accepting);

            // Reopen the store without carrying any in-memory lifecycle decision. A
            // later resumable runtime must still replay this exact durable rejection.
            let connection = fixture.writable()?;
            let (retained, retained_digest) = find_receipt(&connection, 2, 2)?.unwrap();
            assert_eq!(retained, rejected);
            assert_eq!(retained_digest, digest);
            let audits: (i64, i64) = connection
                .query_row(
                    "SELECT (SELECT count(*) FROM proxy_admission_audit),
                (SELECT count(*) FROM control_audit WHERE action='command_rejected'
                 AND epoch=2 AND command_id=2 AND controller_node_id=?1
                 AND source_administrator_id=?2 AND rejection='policy_conflict')",
                    params![fixture.peer, fixture.administrator],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(io::Error::other)?;
            assert_eq!(
                audits,
                (1, 1),
                "rejection adds terminal audit, not a policy mutation"
            );
            drop(connection);
            let CommandOutcome::Replayed(replayed) = execute(command(), true)? else {
                panic!("durable rejection was executed again")
            };
            assert_eq!(replayed, rejected);
            assert_eq!(
                code(
                    execute(
                        fixture.command(2, 2, PolicyChange::SetAdmission { accepting: false }),
                        false
                    )
                    .err()
                    .unwrap()
                ),
                Some("command_conflict")
            );
            let CommandOutcome::Accepted { change, receipt } = execute(
                fixture.command(3, 2, PolicyChange::SetAdmission { accepting: false }),
                false,
            )?
            else {
                panic!("lifecycle guard blocked the next pause")
            };
            assert_eq!((receipt.command_id, receipt.policy_revision), (3, Some(3)));
            assert!(!change.policy.accepting);
            assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 3);
            Ok(())
        }
    }

    #[test]
    fn fixed_v1_digest_bytes_survive_routing_extension_and_v2_grants_are_multiset_safe()
    -> io::Result<()> {
        let user = "AgICAgICAgICAgICAgICAg".to_owned();
        let credential = "AwMDAwMDAwMDAwMDAwMDAw".to_owned();
        let changes = [
            PolicyChange::CreateUser {
                name: "golden user".into(),
                protocols: vec![Protocol::Http, Protocol::Socks5],
                concurrent_limit: 2,
            },
            PolicyChange::RotateCredential {
                id: credential.clone(),
            },
        ];
        let expected = [
            "6d3405ca772fcaab7b2ce01cb65fed9f39cee8b3ef361e15e4552286b2799539",
            "30620f4fa3af820ff41ff5013f2185584c16e7e1e7e15b74bf2c519ee9829151",
        ];
        let command = |change| Command {
            target_node_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            epoch: 2,
            command_id: 1,
            expected_policy_revision: 1,
            source_administrator_id: "AQEBAQEBAQEBAQEBAQEBAQ".into(),
            change,
        };
        for (change, expected) in changes.into_iter().zip(expected) {
            let actual = command_digest(&command(change))?
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(actual, expected);
        }
        let grant = |exits| {
            command(PolicyChange::SetRoutePermission(
                crate::access::routing::RoutePermission {
                    user_id: user.clone(),
                    legacy_allowed: false,
                    exits,
                    pools: vec![],
                },
            ))
        };
        assert_eq!(
            command_digest(&grant(vec![user.clone(), credential.clone()]))?,
            command_digest(&grant(vec![credential.clone(), user.clone()]))?
        );
        assert_ne!(
            command_digest(&grant(vec![user.clone(), credential.clone()]))?,
            command_digest(&grant(vec![user.clone(), user.clone()]))?
        );
        Ok(())
    }

    /// Owns one private store and a SAN-valid public leaf; transport trust is tested by node.
    struct Fixture {
        directory: std::path::PathBuf,
        administrator: String,
        target: String,
        peer: String,
        leaf: Arc<[u8]>,
    }
    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory = std::env::temp_dir().join(format!("vproxy-control-{}", random_id()?));
            let overview = initialize(&directory, "target", "admin", "fixture PHC bytes")?;
            let connection = peers::open_existing(&directory, false)?;
            let administrator = connection
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(|error| {
                    sqlite_error("cannot read control fixture administrator", error)
                })?;
            let peer = random_id()?;
            let cert = rcgen::generate_simple_self_signed(vec!["controller.example".into()])
                .map_err(io::Error::other)?;
            let leaf: Arc<[u8]> = cert.cert.der().to_vec().into();
            register_peer(
                &directory,
                &peer,
                "controller",
                &leaf,
                "controller.example",
                None,
            )?;
            Ok(Self {
                directory,
                administrator,
                target: overview.node_id,
                peer,
                leaf,
            })
        }
        fn authorize(&self) -> RemoteAuthorization {
            RemoteAuthorization {
                node_id: self.peer.clone(),
                authorization_revision: 1,
                leaf: self.leaf.clone(),
            }
        }
        fn grant(&self) -> io::Result<Ownership> {
            set_owner(
                &self.directory,
                &update_lock(&self.directory)?,
                &self.administrator,
                1,
                Some(&self.peer),
            )
        }
        fn command(&self, id: u64, revision: u64, change: PolicyChange) -> Command {
            Command {
                target_node_id: self.target.clone(),
                epoch: 2,
                command_id: id,
                expected_policy_revision: revision,
                source_administrator_id: self.administrator.clone(),
                change,
            }
        }
        fn run(&self, command: Command) -> io::Result<CommandOutcome> {
            apply_command(
                &self.directory,
                &update_lock(&self.directory)?,
                &self.authorize(),
                command,
            )
        }
        fn writable(&self) -> io::Result<Connection> {
            peers::open_existing(&self.directory, true)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
    fn create() -> PolicyChange {
        PolicyChange::CreateUser {
            name: "proxy user".into(),
            protocols: vec![Protocol::Http, Protocol::Socks5],
            concurrent_limit: 3,
        }
    }

    fn code(error: io::Error) -> Option<&'static str> {
        error
            .get_ref()
            .and_then(|error| error.downcast_ref::<ControlError>())
            .map(|error| error.code())
    }
}
