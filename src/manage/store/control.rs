//! Local ownership and at-most-once node commands for the real proxy policy.
//!
//! TLS identity, owner/epoch, command sequence and policy CAS are checked in the
//! same SQLite transaction. The caller retains its update gate through runtime
//! publication; a saved receipt is not evidence that a proxy is running.

pub(in crate::manage) mod endpoints;
mod schema13;
mod schema15;
#[cfg(test)]
pub(in crate::manage::store) use schema15::remove_endpoints_schema_for_test;
pub(super) use schema15::upgrade_endpoints;
mod schema6;
mod schema9;
#[cfg(test)]
pub(super) use schema6::legacy::reconstruct_v5;
pub(super) use schema6::upgrade_schema;
#[cfg(test)]
pub(super) use schema9::legacy::reconstruct_v8;
pub(super) use schema9::upgrade_presets;
#[cfg(test)]
pub(in crate::manage) use schema13::restore_legacy_owner_audit;
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

/// Local-session ownership CAS inside the caller's transaction. Filesystem
/// authority remains a separate offline path; no commit/publication occurs.
#[cfg(feature = "witness-journal")]
pub(in crate::manage) fn set_owner_in(
    transaction: &rusqlite::Transaction<'_>,
    administrator: &str,
    expected_epoch: u64,
    controller: Option<&str>,
) -> io::Result<Ownership> {
    set_owner_actor_in(
        transaction,
        OwnerActor::Administrator(administrator),
        expected_epoch,
        controller,
    )
}

/// File-author CAS in the already-held Source transaction. The outer caller
/// must hold the original offline author/update guards; this grants no browser
/// or peer authority. The same audit vocabulary/schema as the Native CLI is
/// retained, and no COMMIT, network wait or publication occurs here.
#[cfg(feature = "witness-journal")]
pub(super) fn set_owner_offline_in(
    transaction: &rusqlite::Transaction<'_>,
    expected_epoch: u64,
    controller: Option<&str>,
) -> io::Result<Ownership> {
    set_owner_actor_in(transaction, OwnerActor::Offline, expected_epoch, controller)
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
        PolicyChange::SetRoutePermission { permission } => {
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
        self, initialize, load_policy, random_id, register_peer, revoke_certificate, update_lock,
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
        fn version_five_is_userless_replayed_by_original_digest_and_reauthorized() -> io::Result<()>
        {
            let fixture = Fixture::new()?;
            fixture.grant()?;
            let command = || fixture.command(1, 1, PolicyChange::SetAdmission { accepting: false });
            let digest = command_digest(&command())?;
            assert_ne!(
                digest,
                command_digest(&fixture.command(
                    1,
                    1,
                    PolicyChange::SetAdmission { accepting: true }
                ))?
            );
            let CommandOutcome::Accepted { change, receipt } = fixture.run(command())? else {
                panic!("admission rejected")
            };
            assert_eq!(receipt.version, 5);
            assert_eq!(receipt.policy_revision, Some(2));
            assert_eq!(receipt.status, ReceiptStatus::Saved);
            assert!(
                receipt.user_id.is_none()
                    && receipt.credential_id.is_none()
                    && receipt.routing.is_none()
                    && receipt.preset.is_none()
            );
            assert!(!change.policy.accepting);
            assert!(matches!(
                fixture.run(command())?,
                CommandOutcome::Replayed(Receipt { version: 5, .. })
            ));
            assert!(
                fixture
                    .run(fixture.command(1, 1, PolicyChange::SetAdmission { accepting: true }))
                    .is_err()
            );
            assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 1);
            assert!(
                !store::admission::remote_snapshot(&fixture.directory, &fixture.authorize())?
                    .accepting
            );
            mark_command_applied(
                &fixture.directory,
                &update_lock(&fixture.directory)?,
                2,
                1,
                2,
            )?;
            assert_eq!(
                super::super::receipt(&fixture.directory, &fixture.authorize(), 2, 1)?.status,
                ReceiptStatus::Applied
            );
            let CommandOutcome::Rejected(rejected) = fixture.run(fixture.command(
                2,
                1,
                PolicyChange::SetAdmission { accepting: true },
            ))?
            else {
                panic!("stale CAS accepted")
            };
            assert_eq!(
                (rejected.version, rejected.rejection),
                (5, Some("policy_conflict"))
            );
            assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 2);
            assert!(!store::load_policy(&fixture.directory)?.accepting);
            revoke_certificate(&fixture.directory, &fixture.leaf, 1)?;
            assert!(
                store::admission::remote_snapshot(&fixture.directory, &fixture.authorize())
                    .is_err()
            );
            assert!(fixture.run(command()).is_err());
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
            // The lifecycle decision is not authority and cannot bypass target, epoch
            // or sequence checks to manufacture a terminal receipt for another intent.
            let mut wrong_target =
                fixture.command(2, 2, PolicyChange::SetAdmission { accepting: true });
            wrong_target.target_node_id = random_id()?;
            assert_eq!(
                code(execute(wrong_target, false).err().unwrap()),
                Some("target_mismatch")
            );
            let mut wrong_epoch =
                fixture.command(2, 2, PolicyChange::SetAdmission { accepting: true });
            wrong_epoch.epoch = 3;
            assert_eq!(
                code(execute(wrong_epoch, false).err().unwrap()),
                Some("controller_epoch_changed")
            );
            assert_eq!(
                code(
                    execute(
                        fixture.command(3, 2, PolicyChange::SetAdmission { accepting: true }),
                        false
                    )
                    .err()
                    .unwrap()
                ),
                Some("command_out_of_order")
            );
            assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 1);

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

        #[test]
        fn accepted_resume_replay_precedes_lifecycle_guard_and_still_reauthorizes() -> io::Result<()>
        {
            let fixture = Fixture::new()?;
            fixture.grant()?;
            let execute = |command, can_resume| {
                apply_command_with_admission(
                    &fixture.directory,
                    &update_lock(&fixture.directory)?,
                    &fixture.authorize(),
                    command,
                    can_resume,
                )
            };
            let command = || fixture.command(1, 1, PolicyChange::SetAdmission { accepting: true });
            let CommandOutcome::Accepted { receipt, .. } = execute(command(), true)? else {
                panic!("resumable listener refused admission")
            };
            let CommandOutcome::Replayed(replayed) = execute(command(), false)? else {
                panic!("lifecycle guard replaced an existing accepted receipt")
            };
            assert_eq!(replayed, receipt);
            assert_eq!(load_policy(&fixture.directory)?.revision, 2);
            assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 1);
            revoke_certificate(&fixture.directory, &fixture.leaf, 1)?;
            assert_eq!(
                code(execute(command(), false).err().unwrap()),
                Some("peer_not_authorized")
            );
            Ok(())
        }
    }
    mod endpoints {
        //! Public-address commands share the terminal ordering ledger, not access
        //! policy revision or publication. Every fixture is a new private local DB.

        use super::*;
        use crate::manage::{
            proxy::{Protocol as ListenerProtocol, endpoint_id},
            store::{endpoint_control as metadata_control, endpoints as metadata},
        };
        use rusqlite::types::Value;

        fn inventory(fixture: &Fixture) -> io::Result<metadata::Inventory> {
            let bind = "127.0.0.1:18080".parse().map_err(io::Error::other)?;
            let value = metadata::Inventory::new(
                &fixture.target,
                vec![metadata::ListenerKey {
                    id: endpoint_id(&fixture.target, ListenerProtocol::Http, bind),
                    protocol: ListenerProtocol::Http,
                    bind,
                    configured_public_address: Some("startup.example:1080".into()),
                }],
            )?;
            metadata::configure(
                &fixture.directory,
                &update_lock(&fixture.directory)?,
                &value,
            )?;
            Ok(value)
        }

        fn command(
            fixture: &Fixture,
            inventory: &metadata::Inventory,
            command_id: u64,
            revision: u64,
        ) -> metadata_control::Command {
            metadata_control::Command {
                target_node_id: fixture.target.clone(),
                epoch: 2,
                command_id,
                expected_metadata_revision: revision,
                source_administrator_id: fixture.administrator.clone(),
                generation: inventory.digest.clone(),
                change: metadata::Change {
                    listener_id: inventory.listeners[0].id.clone(),
                    selection: metadata::AddressSelection::Hidden,
                },
            }
        }

        fn apply(
            fixture: &Fixture,
            inventory: &metadata::Inventory,
            command: metadata_control::Command,
        ) -> io::Result<metadata_control::Outcome> {
            metadata_control::apply(
                &fixture.directory,
                &update_lock(&fixture.directory)?,
                &fixture.authorize(),
                inventory,
                command,
            )
        }

        /// Compare the actual durable values relevant to either kind of command. No
        /// plaintext credential or administrator verifier is read by this helper.
        fn protected_rows(connection: &Connection) -> io::Result<Vec<Vec<Vec<Value>>>> {
            [
                "control_ownership",
                "control_receipts",
                "control_audit",
                "endpoint_state",
                "endpoint_overrides",
                "endpoint_audit",
                "proxy_policy_state",
                "proxy_users",
                "proxy_policy_audit",
            ]
            .into_iter()
            .map(|table| {
                let mut statement = connection
                    .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                    .map_err(io::Error::other)?;
                let columns = statement.column_count();
                statement
                    .query_map([], |row| {
                        (0..columns)
                            .map(|column| row.get(column))
                            .collect::<rusqlite::Result<Vec<Value>>>()
                    })
                    .map_err(io::Error::other)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(io::Error::other)
            })
            .collect()
        }

        #[test]
        fn policy_metadata_policy_share_command_order_not_policy_revision_or_receipt_resource()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            fixture.grant()?;
            let inventory = inventory(&fixture)?;
            let state = metadata::read(&fixture.directory)?;
            let user = accepted(fixture.run(fixture.command(1, 1, create()))?)
                .user
                .unwrap();
            let request = command(&fixture, &inventory, 2, state.revision);
            let saved = apply(&fixture, &inventory, request.clone())?;
            assert!(!saved.replayed);
            assert_eq!(saved.receipt.metadata_revision, Some(state.revision + 1));
            assert_eq!(load_policy(&fixture.directory)?.revision, 2);
            assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 2);
            let before = protected_rows(&fixture.writable()?)?;
            // Known cross-resource records are not expired. Reading one namespace must
            // neither expose the other receipt nor remove its recoverable result.
            assert_eq!(
                receipt(&fixture.directory, &fixture.authorize(), 2, 2)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::NotFound
            );
            assert_eq!(
                metadata_control::receipt(&fixture.directory, &fixture.authorize(), 2, 1)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::NotFound
            );
            assert_eq!(
                metadata_control::receipt(&fixture.directory, &fixture.authorize(), 2, 2)?,
                saved.receipt
            );
            let mut stale_authorization = fixture.authorize();
            stale_authorization.authorization_revision = 2;
            for id in [1, 2, 99] {
                assert_eq!(
                    code(
                        receipt(&fixture.directory, &stale_authorization, 2, id)
                            .err()
                            .unwrap()
                    ),
                    Some("peer_not_authorized")
                );
                assert_eq!(
                    code(
                        metadata_control::receipt(&fixture.directory, &stale_authorization, 2, id)
                            .err()
                            .unwrap()
                    ),
                    Some("peer_not_authorized")
                );
                assert_eq!(
                    code(
                        receipt(&fixture.directory, &fixture.authorize(), 3, id)
                            .err()
                            .unwrap()
                    ),
                    Some("controller_epoch_changed")
                );
                assert_eq!(
                    code(
                        metadata_control::receipt(&fixture.directory, &fixture.authorize(), 3, id)
                            .err()
                            .unwrap()
                    ),
                    Some("controller_epoch_changed")
                );
            }
            assert_eq!(protected_rows(&fixture.writable()?)?, before);
            let replayed = apply(&fixture, &inventory, request.clone())?;
            assert!(replayed.replayed);
            assert_eq!(replayed.receipt, saved.receipt);
            assert_eq!(protected_rows(&fixture.writable()?)?, before);

            assert_eq!(
                code(
                    apply(
                        &fixture,
                        &inventory,
                        command(&fixture, &inventory, 1, state.revision)
                    )
                    .err()
                    .unwrap()
                ),
                Some("command_conflict")
            );
            assert_eq!(
                code(fixture.run(fixture.command(2, 2, create())).err().unwrap()),
                Some("command_conflict")
            );
            let mut changed = request;
            changed.change.selection = metadata::AddressSelection::Inherit;
            assert_eq!(
                code(apply(&fixture, &inventory, changed).err().unwrap()),
                Some("command_conflict")
            );
            assert_eq!(protected_rows(&fixture.writable()?)?, before);

            let changed = accepted(fixture.run(fixture.command(
                3,
                2,
                PolicyChange::SetUserActive {
                    id: user.id,
                    active: false,
                },
            ))?);
            assert_eq!(changed.policy.revision, 3);
            assert_eq!(
                metadata::read(&fixture.directory)?.revision,
                state.revision + 1
            );
            let rejected = apply(
                &fixture,
                &inventory,
                command(&fixture, &inventory, 4, state.revision),
            )?;
            assert_eq!(
                rejected.receipt.rejection,
                Some("endpoint_revision_changed")
            );
            assert!(rejected.receipt.metadata_revision.is_none());
            assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 4);
            assert_eq!(load_policy(&fixture.directory)?.revision, 3);
            // Revoking this otherwise valid peer's ownership takes precedence even
            // over an old epoch and known cross-resource receipt identities.
            set_owner(
                &fixture.directory,
                &update_lock(&fixture.directory)?,
                &fixture.administrator,
                2,
                None,
            )?;
            let revoked = protected_rows(&fixture.writable()?)?;
            for id in [1, 2] {
                assert_eq!(
                    code(
                        receipt(&fixture.directory, &fixture.authorize(), 2, id)
                            .err()
                            .unwrap()
                    ),
                    Some("peer_not_authorized")
                );
                assert_eq!(
                    code(
                        metadata_control::receipt(&fixture.directory, &fixture.authorize(), 2, id)
                            .err()
                            .unwrap()
                    ),
                    Some("peer_not_authorized")
                );
            }
            assert_eq!(protected_rows(&fixture.writable()?)?, revoked);
            Ok(())
        }

        #[test]
        fn both_receipt_pruners_keep_new_metadata_with_full_old_policy_window() -> io::Result<()> {
            let fixture = Fixture::new()?;
            fixture.grant()?;
            let inventory = inventory(&fixture)?;
            accepted(fixture.run(fixture.command(1, 1, create()))?);
            let connection = fixture.writable()?;
            // One real current saved policy receipt and 4095 structurally valid old
            // rejections fill the window. Raw seeding tests retention, not historical
            // command deserialization or 4095 network deliveries.
            connection
        .execute(
            "WITH RECURSIVE numbers(n) AS (VALUES(2) UNION ALL SELECT n+1 FROM numbers WHERE n<?1)
         INSERT INTO control_receipts(epoch,command_id,controller_node_id,digest,status,rejection)
         SELECT 2,n,?2,zeroblob(32),'rejected','policy_conflict' FROM numbers",
            params![MAX_RECEIPTS, fixture.peer],
        )
        .map_err(io::Error::other)?;
            connection
                .execute(
                    "UPDATE control_ownership SET last_terminal_command=?1",
                    [MAX_RECEIPTS],
                )
                .map_err(io::Error::other)?;
            let state = metadata::read(&fixture.directory)?;
            let id = u64::from(MAX_RECEIPTS) + 1;
            let request = command(&fixture, &inventory, id, state.revision);
            let saved = apply(&fixture, &inventory, request.clone())?;
            assert_eq!(saved.receipt.metadata_revision, Some(state.revision + 1));
            let count: i64 = connection
                .query_row("SELECT count(*) FROM control_receipts", [], |row| {
                    row.get(0)
                })
                .map_err(io::Error::other)?;
            assert_eq!(count, i64::from(MAX_RECEIPTS));
            assert!(find_receipt(&connection, 2, 1)?.is_some());
            assert!(find_receipt(&connection, 2, 2)?.is_none());
            assert_eq!(
                code(
                    receipt(&fixture.directory, &fixture.authorize(), 2, 2)
                        .err()
                        .unwrap()
                ),
                Some("receipt_expired")
            );
            assert_eq!(
                receipt(&fixture.directory, &fixture.authorize(), 2, id)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::NotFound
            );
            assert_eq!(
                receipt(&fixture.directory, &fixture.authorize(), 2, id + 1)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::NotFound
            );
            assert_eq!(
                metadata_control::receipt(&fixture.directory, &fixture.authorize(), 2, id)?,
                saved.receipt
            );

            // A policy-side rejection invokes the other pruner without changing the
            // priority of the still-current saved policy receipt.
            assert!(matches!(
                fixture.run(fixture.command(id + 1, 999, create()))?,
                CommandOutcome::Rejected(_)
            ));
            let count: i64 = connection
                .query_row("SELECT count(*) FROM control_receipts", [], |row| {
                    row.get(0)
                })
                .map_err(io::Error::other)?;
            assert_eq!(count, i64::from(MAX_RECEIPTS));
            assert!(find_receipt(&connection, 2, 1)?.is_some());
            assert!(find_receipt(&connection, 2, 3)?.is_none());
            assert!(find_receipt(&connection, 2, id + 1)?.is_some());
            assert_eq!(
                code(
                    receipt(&fixture.directory, &fixture.authorize(), 2, 3)
                        .err()
                        .unwrap()
                ),
                Some("receipt_expired")
            );
            assert_eq!(
                receipt(&fixture.directory, &fixture.authorize(), 2, id)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::NotFound
            );
            assert_eq!(
                metadata_control::receipt(&fixture.directory, &fixture.authorize(), 2, id)?,
                saved.receipt
            );
            let replay = apply(&fixture, &inventory, request)?;
            assert!(replay.replayed);
            assert_eq!(replay.receipt, saved.receipt);
            Ok(())
        }

        #[test]
        fn ignored_rejection_audit_rolls_back_receipt_high_water_and_metadata() -> io::Result<()> {
            let fixture = Fixture::new()?;
            fixture.grant()?;
            let inventory = inventory(&fixture)?;
            let connection = fixture.writable()?;
            connection.execute_batch("CREATE TRIGGER fixture_ignored_endpoint_rejection BEFORE INSERT ON control_audit WHEN NEW.action='command_rejected' BEGIN SELECT RAISE(IGNORE); END;")
        .map_err(io::Error::other)?;
            let before = protected_rows(&connection)?;
            // Positive but stale metadata CAS normally becomes a durable rejection.
            let error = apply(&fixture, &inventory, command(&fixture, &inventory, 1, 1))
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(protected_rows(&connection)?, before);
            assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 0);
            assert!(
                metadata_control::receipt(&fixture.directory, &fixture.authorize(), 2, 1).is_err()
            );
            Ok(())
        }

        #[test]
        fn corrupt_metadata_receipt_policy_fields_are_rejected_by_read_and_replay() -> io::Result<()>
        {
            let fixture = Fixture::new()?;
            fixture.grant()?;
            let inventory = inventory(&fixture)?;
            let state = metadata::read(&fixture.directory)?;
            let request = command(&fixture, &inventory, 1, state.revision);
            apply(&fixture, &inventory, request.clone())?;
            let connection = fixture.writable()?;
            connection.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE control_receipts SET policy_revision=99 WHERE epoch=2 AND command_id=1;")
        .map_err(io::Error::other)?;
            let before = protected_rows(&connection)?;
            assert_eq!(
                metadata_control::receipt(&fixture.directory, &fixture.authorize(), 2, 1)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(
                apply(&fixture, &inventory, request).err().unwrap().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(protected_rows(&connection)?, before);
            Ok(())
        }
    }
    mod offline_owner {
        use super::*;
        use rusqlite::types::Value;

        type Rows = Vec<(String, Vec<Vec<Value>>)>;

        #[test]
        fn owner_kernel_refuses_a_lost_transaction_without_autocommitting_state_or_audit()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let connection = fixture.writable()?;
            let before = rows(&connection, false)?;
            for actor in [
                OwnerActor::Offline,
                OwnerActor::Administrator(&fixture.administrator),
            ] {
                let tx = rusqlite::Transaction::new_unchecked(
                    &connection,
                    TransactionBehavior::Immediate,
                )
                .map_err(io::Error::other)?;
                tx.execute_batch("ROLLBACK").map_err(io::Error::other)?;
                let error = set_owner_actor_in(&tx, actor, 1, Some(&fixture.peer))
                    .err()
                    .ok_or_else(|| io::Error::other("lost transaction unexpectedly accepted"))?;
                assert_eq!(error.kind(), io::ErrorKind::Other);
                assert!(
                    error
                        .get_ref()
                        .and_then(|e| e.downcast_ref::<ControlError>())
                        .is_none()
                );
                drop(tx);
                assert_eq!(rows(&connection, false)?, before);
            }
            Ok(())
        }

        #[test]
        fn owner_readback_refuses_rewritten_state_or_missing_audit_and_rolls_back() -> io::Result<()>
        {
            for trigger in [
                "CREATE TEMP TRIGGER rewrite_epoch AFTER UPDATE ON main.control_ownership WHEN new.epoch=old.epoch+1 BEGIN UPDATE control_ownership SET epoch=old.epoch WHERE singleton=1; END;",
                "CREATE TEMP TRIGGER erase_owner_audit AFTER INSERT ON main.control_audit BEGIN DELETE FROM control_audit WHERE rowid=new.rowid; END;",
            ] {
                let fixture = Fixture::new()?;
                let mut connection = fixture.writable()?;
                let before = rows(&connection, false)?;
                connection
                    .execute_batch(trigger)
                    .map_err(io::Error::other)?;
                let tx = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(io::Error::other)?;
                let error = set_owner_actor_in(&tx, OwnerActor::Offline, 1, Some(&fixture.peer))
                    .err()
                    .ok_or_else(|| {
                        io::Error::other("rewritten owner transition unexpectedly accepted")
                    })?;
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                tx.rollback().map_err(io::Error::other)?;
                assert_eq!(rows(&connection, false)?, before);
            }
            Ok(())
        }

        /// Compare stored values, not re-encoded policy DTOs that could omit history.
        fn rows(connection: &Connection, omit_owner: bool) -> io::Result<Rows> {
            let names = connection
                .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
                .map_err(io::Error::other)?
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(io::Error::other)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(io::Error::other)?;
            names
                .into_iter()
                .filter(|name| !omit_owner || name != "control_ownership")
                .map(|name| {
                    let quoted = name.replace('"', "\"\"");
                    let filter = if omit_owner && name == "control_audit" {
                        " WHERE action<>'set_owner_offline'"
                    } else {
                        ""
                    };
                    let mut statement = connection
                        .prepare(&format!(
                            "SELECT * FROM \"{quoted}\"{filter} ORDER BY rowid"
                        ))
                        .map_err(io::Error::other)?;
                    let columns = statement.column_count();
                    let values = statement
                        .query_map([], |row| {
                            (0..columns)
                                .map(|index| row.get(index))
                                .collect::<rusqlite::Result<Vec<Value>>>()
                        })
                        .map_err(io::Error::other)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(io::Error::other)?;
                    Ok((name, values))
                })
                .collect()
        }

        #[test]
        fn offline_owner_preserves_policy_credentials_receipts_and_peer_tombstones()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            store::apply_policy(
                &fixture.directory,
                &fixture.administrator,
                1,
                PolicyChange::CreatePrefix {
                    name: "retained prefix".into(),
                    cidr: "192.0.2.0/24".parse().unwrap(),
                },
                &update_lock(&fixture.directory)?,
            )?;
            fixture.grant()?;
            let user = accepted(fixture.run(fixture.command(1, 2, create()))?)
                .user
                .unwrap()
                .id;
            fixture.run(fixture.command(2, 3, PolicyChange::CreateCredential { user_id: user }))?;
            fixture.run(fixture.command(
                3,
                4,
                PolicyChange::CreateUser {
                    name: "rejected".into(),
                    protocols: vec![],
                    concurrent_limit: 0,
                },
            ))?;
            let revoked = random_id()?;
            register_peer(
                &fixture.directory,
                &revoked,
                "revoked",
                b"retained revoked fixture",
                "revoked.example",
                None,
            )?;
            revoke_certificate(&fixture.directory, b"retained revoked fixture", 1)?;
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
            store::targets::enqueue(
                &fixture.directory,
                &fixture.administrator,
                1,
                Command {
                    target_node_id: fixture.peer.clone(),
                    epoch: 2,
                    command_id: 1,
                    expected_policy_revision: 1,
                    source_administrator_id: fixture.administrator.clone(),
                    change: create(),
                },
            )?;
            let connection = fixture.writable()?;
            let before = rows(&connection, true)?;
            let takeover = set_owner_offline(&fixture.directory, 2, None)?;
            assert_eq!(
                takeover,
                Ownership {
                    controller_node_id: None,
                    epoch: 3,
                    last_terminal_command: 0
                }
            );
            assert_eq!(rows(&connection, true)?, before);
            let grant = set_owner_offline(&fixture.directory, 3, Some(&fixture.peer))?;
            assert_eq!(grant.epoch, 4);
            assert_eq!(
                grant.controller_node_id.as_deref(),
                Some(fixture.peer.as_str())
            );
            assert_eq!(
                set_owner_offline(&fixture.directory, 4, Some(&fixture.peer))?.epoch,
                5
            );
            assert_eq!(rows(&connection, true)?, before);
            let offline: i64 = connection.query_row("SELECT count(*) FROM control_audit WHERE action='set_owner_offline' AND administrator_id IS NULL AND source_administrator_id IS NULL AND command_id IS NULL AND rejection IS NULL", [], |row| row.get(0)).map_err(io::Error::other)?;
            assert_eq!(offline, 3);
            assert!(connection.execute("INSERT INTO control_audit(action,administrator_id,epoch) VALUES('set_owner_offline',?1,6)", [&fixture.administrator]).is_err());
            assert!(
                connection
                    .execute(
                        "INSERT INTO control_audit(action,epoch) VALUES('set_owner',6)",
                        []
                    )
                    .is_err()
            );
            Ok(())
        }

        #[test]
        fn offline_owner_requires_idle_directory_active_peer_and_exact_epoch() -> io::Result<()> {
            let fixture = Fixture::new()?;
            let connection = fixture.writable()?;
            let before = rows(&connection, false)?;
            let author = store::lock(&fixture.directory)?;
            assert_eq!(
                ownership(&fixture.directory)?.epoch,
                1,
                "read-only status may run with an author"
            );
            assert_eq!(
                set_owner_offline(&fixture.directory, 1, Some(&fixture.peer))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            drop(author);
            let gate = update_lock(&fixture.directory)?;
            assert_eq!(
                set_owner_offline(&fixture.directory, 1, None)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            drop(gate);
            for (epoch, controller) in [
                (0, Some(fixture.peer.as_str())),
                (2, Some(fixture.peer.as_str())),
                (1, Some(fixture.target.as_str())),
                (1, Some("invalid")),
            ] {
                assert!(set_owner_offline(&fixture.directory, epoch, controller).is_err());
            }
            assert!(set_owner_offline(&fixture.directory, 1, Some(&random_id()?)).is_err());
            assert_eq!(rows(&connection, false)?, before);
            store::set_peer_active(&fixture.directory, &fixture.peer, 1, false)?;
            let inactive = rows(&connection, false)?;
            assert!(set_owner_offline(&fixture.directory, 1, Some(&fixture.peer)).is_err());
            assert_eq!(rows(&connection, false)?, inactive);
            connection
                .execute("UPDATE control_ownership SET epoch=?1", [i64::MAX])
                .map_err(io::Error::other)?;
            let exhausted = rows(&connection, false)?;
            assert!(set_owner_offline(&fixture.directory, i64::MAX as u64, None).is_err());
            assert_eq!(rows(&connection, false)?, exhausted);
            let _released = store::lock(&fixture.directory)?;
            let missing = fixture.directory.join("uninitialized");
            store::prepare_directory(&missing)?;
            assert_eq!(
                set_owner_offline(&missing, 1, None).unwrap_err().kind(),
                io::ErrorKind::NotFound
            );
            assert!(!missing.join("management.sqlite3").exists());
            Ok(())
        }

        #[test]
        fn offline_owner_audit_and_deferred_commit_failures_leave_the_old_snapshot()
        -> io::Result<()> {
            for (index, trigger) in [
        "CREATE TRIGGER failed_audit BEFORE INSERT ON control_audit BEGIN SELECT RAISE(ABORT,'fixture'); END;",
        "CREATE TRIGGER failed_audit BEFORE INSERT ON control_audit BEGIN SELECT RAISE(IGNORE); END;",
        "CREATE TRIGGER failed_update BEFORE UPDATE ON control_ownership BEGIN SELECT RAISE(IGNORE); END;",
        "CREATE TABLE deferred_guard (id TEXT REFERENCES administrators(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER failed_commit AFTER UPDATE ON control_ownership BEGIN INSERT INTO deferred_guard VALUES ('missing'); END;",
    ].iter().enumerate() {
        let fixture = Fixture::new()?;
        let connection = fixture.writable()?;
        connection.execute_batch(trigger).map_err(io::Error::other)?;
        let before = rows(&connection, false)?;
        assert!(set_owner_offline(&fixture.directory, 1, Some(&fixture.peer)).is_err(), "fault {index}");
        assert_eq!(rows(&connection, false)?, before, "fault {index}");
        let _released = store::lock(&fixture.directory)?;
    }
            Ok(())
        }

        #[test]
        fn schema_thirteen_migrates_real_old_owner_audits_and_retains_private_backup()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            fixture.grant()?;
            fixture.run(fixture.command(
                1,
                1,
                PolicyChange::CreateUser {
                    name: "rejected".into(),
                    protocols: vec![],
                    concurrent_limit: 0,
                },
            ))?;
            let connection = fixture.writable()?;
            restore_legacy_owner_audit(&connection)?;
            connection
                .pragma_update(None, "user_version", 12)
                .map_err(io::Error::other)?;
            assert!(
                connection
                    .execute(
                        "INSERT INTO control_audit(action,epoch) VALUES('set_owner_offline',3)",
                        []
                    )
                    .is_err()
            );
            let before = rows(&connection, false)?;
            assert_eq!(
                set_owner_offline(&fixture.directory, 2, None)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Unsupported
            );
            assert_eq!(rows(&connection, false)?, before);
            let backup = fixture.directory.join("schema12.sqlite3");
            store::migrate(&fixture.directory, &backup)?;
            store::proxy_service::require_unused_for_test(&connection)?;
            assert_eq!(
                store::inspect(&fixture.directory)?.schema_version,
                store::SCHEMA_VERSION
            );
            // Only this migration comparison projects the historical command columns.
            // Other owner tests still compare every column with the unmodified rows().
            store::notifications::ensure_unused_for_test(&connection)?;
            let mut migrated = rows(&connection, false)?
                .into_iter()
                .filter(|(name, _)| {
                    ![
                        "recovery_state",
                        "endpoint_state",
                        "endpoint_overrides",
                        "endpoint_audit",
                        "operations_state",
                        "user_operations",
                        "automation_state",
                        "automation_principals",
                        "automation_audit",
                        "proxy_admission_state",
                        "proxy_admission_audit",
                        "controller_history_state",
                        "controller_history",
                        "alert_history_state",
                        "alert_episodes",
                        "alert_events",
                        "webhook_state",
                        "recovery_witness",
                        "recovery_source",
                        "proxy_service_state",
                        "proxy_service_operations",
                        "proxy_credential_secrets",
                    ]
                    .contains(&name.as_str())
                })
                .collect::<Rows>();
            for (name, values) in &mut migrated {
                let columns = match name.as_str() {
                    "control_receipts" => Some(
                        "epoch,command_id,controller_node_id,digest,status,policy_revision,rejection,user_id,credential_id,version,routing_kind,routing_id,preset_kind,preset_id",
                    ),
                    "control_outbox" => Some(
                        "peer_id,job_id,administrator_id,controller_epoch,command_id,expected_policy_revision,command,state,policy_revision,outcome_code,attempts,next_attempt,routing_kind,routing_id,preset_kind,preset_id",
                    ),
                    _ => None,
                };
                if let Some(columns) = columns {
                    let mut statement = connection
                        .prepare(&format!("SELECT {columns} FROM {name} ORDER BY rowid"))
                        .map_err(io::Error::other)?;
                    let width = statement.column_count();
                    *values = statement
                        .query_map([], |row| {
                            (0..width)
                                .map(|column| row.get(column))
                                .collect::<rusqlite::Result<Vec<Value>>>()
                        })
                        .map_err(io::Error::other)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(io::Error::other)?;
                }
            }
            assert_eq!(migrated, before);
            let policy_only:bool=connection.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM control_receipts WHERE metadata_revision IS NOT NULL OR endpoint_id IS NOT NULL OR endpoint_generation IS NOT NULL)
          AND NOT EXISTS(SELECT 1 FROM control_outbox WHERE resource<>'proxy_policy' OR expected_metadata_revision IS NOT NULL OR metadata_revision IS NOT NULL)",
        [],|row|row.get(0),
    ).map_err(io::Error::other)?;
            assert!(policy_only);
            let automation: (i64, i64, i64, i64) = connection
                .query_row(
                    "SELECT (SELECT count(*) FROM automation_state),
                    (SELECT last_sequence FROM automation_state WHERE singleton=1),
                    (SELECT count(*) FROM automation_principals),
                    (SELECT count(*) FROM automation_audit)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(io::Error::other)?;
            assert_eq!(automation, (1, 0, 0, 0));
            let admission: (i64, i64, i64, i64) = connection
                .query_row(
                    "SELECT (SELECT count(*) FROM proxy_admission_state),
                    (SELECT singleton FROM proxy_admission_state),
                    (SELECT accepting FROM proxy_admission_state),
                    (SELECT count(*) FROM proxy_admission_audit)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(io::Error::other)?;
            assert_eq!(admission, (1, 1, 1, 0));
            store::targets::history::validate_snapshot(&connection)?;
            let history: (i64, i64, i64, i64) = connection
                .query_row(
                    "SELECT (SELECT count(*) FROM controller_history_state),
                    (SELECT singleton FROM controller_history_state),
                    (SELECT last_sequence FROM controller_history_state),
                    (SELECT count(*) FROM controller_history)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(io::Error::other)?;
            assert_eq!(history, (1, 1, 0, 0));
            store::alerts::history::validate_snapshot(&connection)?;
            // The new journal must remain unstarted and empty after migration.
            store::alerts::history::require_empty(&connection)?;
            assert!(
                store::recovery::status(&fixture.directory)?
                    .recovery
                    .is_none()
            );
            assert!(
                store::endpoints::read(&fixture.directory)?
                    .digest
                    .is_empty()
            );
            let copied = Connection::open(backup).map_err(io::Error::other)?;
            assert_eq!(store::read_overview(&copied)?.schema_version, 12);
            assert_eq!(rows(&copied, false)?, before);
            assert!(
                copied
                    .execute(
                        "INSERT INTO control_audit(action,epoch) VALUES('set_owner_offline',3)",
                        []
                    )
                    .is_err()
            );
            assert_eq!(set_owner_offline(&fixture.directory, 2, None)?.epoch, 3);
            Ok(())
        }

        #[test]
        fn schema_thirteen_failure_retains_owner_version_old_rows_and_backup() -> io::Result<()> {
            let fixture = Fixture::new()?;
            fixture.grant()?;
            let connection = fixture.writable()?;
            restore_legacy_owner_audit(&connection)?;
            connection
                .pragma_update(None, "user_version", 12)
                .map_err(io::Error::other)?;
            connection.execute_batch("CREATE TABLE control_audit_v13(sentinel TEXT); INSERT INTO control_audit_v13 VALUES('operator data');").map_err(io::Error::other)?;
            let before = rows(&connection, false)?;
            let backup = fixture.directory.join("failed13.sqlite3");
            assert!(store::migrate(&fixture.directory, &backup).is_err());
            assert_eq!(store::inspect(&fixture.directory)?.schema_version, 12);
            assert_eq!(rows(&connection, false)?, before);
            let copied = Connection::open(backup).map_err(io::Error::other)?;
            assert_eq!(rows(&copied, false)?, before);
            assert_eq!(store::read_overview(&copied)?.schema_version, 12);
            Ok(())
        }
    }
    mod presets {
        use super::*;
        use crate::{
            access::{
                presets::{PoolPreset, PresetEntity, UserPreset},
                traffic::{PoolSnapshot, SeriesSnapshot},
            },
            ebpf::Profile,
            traffic::Snapshot,
        };

        #[test]
        fn version_three_presets_are_actor_bound_terminal_and_replay_without_configuration()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            fixture.grant()?;
            let user = accepted(fixture.run(fixture.command(1, 1, create()))?)
                .user
                .unwrap()
                .id;
            let value = UserPreset {
                user_id: user.clone(),
                default_preset: Some(Profile::Linux),
                allowed_presets: vec![Profile::Windows, Profile::Linux],
            };
            let change = || PolicyChange::SetUserPresets {
                presets: value.clone(),
            };
            let CommandOutcome::Accepted {
                receipt,
                change: result,
            } = fixture.run(fixture.command(2, 2, change()))?
            else {
                panic!("preset change rejected")
            };
            assert_eq!(receipt.version, 3);
            assert!(
                receipt.user_id.is_none()
                    && receipt.credential_id.is_none()
                    && receipt.routing.is_none()
            );
            assert_eq!(
                receipt.preset,
                Some(PresetReceipt {
                    kind: PresetKind::User,
                    id: user.clone()
                })
            );
            assert!(
                matches!(result.presets,Some(PresetEntity::User(ref actual)) if actual==&value)
            );
            assert!(
                matches!(fixture.run(fixture.command(2,2,change()))?,CommandOutcome::Replayed(ref replay) if replay==&receipt)
            );
            let mut reordered = value.clone();
            reordered.allowed_presets.reverse();
            assert_eq!(
                command_digest(&fixture.command(2, 2, change()))?,
                command_digest(&fixture.command(
                    2,
                    2,
                    PolicyChange::SetUserPresets { presets: reordered }
                ))?
            );
            let invalid = || PolicyChange::SetUserPresets {
                presets: UserPreset {
                    allowed_presets: vec![Profile::Linux, Profile::Linux],
                    ..value.clone()
                },
            };
            let CommandOutcome::Rejected(rejected) =
                fixture.run(fixture.command(3, 3, invalid()))?
            else {
                panic!("duplicate preset grant accepted")
            };
            assert_eq!(
                (rejected.version, rejected.rejection),
                (3, Some("invalid_policy"))
            );
            assert!(rejected.preset.is_none());
            assert!(matches!(
                fixture.run(fixture.command(3, 3, invalid()))?,
                CommandOutcome::Replayed(_)
            ));
            assert_eq!(store::load_policy(&fixture.directory)?.revision, 3);
            let (revision, policies) =
                remote_presets_data(&fixture.directory, &fixture.authorize())?;
            assert_eq!(revision, 3);
            assert_eq!(policies.users, vec![value]);
            let connection = fixture.writable()?;
            let actor_count:i64=connection.query_row("SELECT count(*) FROM preset_audit WHERE entry='node_management' AND controller_node_id=?1 AND administrator_id IS NULL AND controller_epoch=2 AND command_id=2",[&fixture.peer],|row|row.get(0)).map_err(io::Error::other)?;
            assert_eq!(actor_count, 1);
            assert!(
                connection
                    .execute(
                        "UPDATE control_receipts SET user_id=?1 WHERE version=3",
                        [&user]
                    )
                    .is_err()
            );
            revoke_certificate(&fixture.directory, &fixture.leaf, 1)?;
            assert_eq!(
                remote_presets_data(&fixture.directory, &fixture.authorize())
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            Ok(())
        }

        #[test]
        fn schema_eight_migration_preserves_identity_statistics_and_old_pending_bytes()
        -> io::Result<()> {
            migration_preserves_identity_statistics_and_old_pending_bytes(8)
        }

        #[test]
        fn schema_nine_server_ip_migration_preserves_every_existing_row() -> io::Result<()> {
            migration_preserves_identity_statistics_and_old_pending_bytes(9)
        }

        fn migration_preserves_identity_statistics_and_old_pending_bytes(
            version: u32,
        ) -> io::Result<()> {
            let fixture = Fixture::new()?;
            fixture.grant()?;
            let user = accepted(fixture.run(fixture.command(1, 1, create()))?)
                .user
                .unwrap()
                .id;
            let credential = accepted(fixture.run(fixture.command(
                2,
                2,
                PolicyChange::CreateCredential {
                    user_id: user.clone(),
                },
            ))?)
            .credential
            .unwrap()
            .id;
            assert!(matches!(
                fixture.run(fixture.command(
                    3,
                    3,
                    PolicyChange::CreateUser {
                        name: "".into(),
                        protocols: vec![],
                        concurrent_limit: 1
                    }
                ))?,
                CommandOutcome::Rejected(_)
            ));
            let pool = match accepted(fixture.run(fixture.command(
                4,
                3,
                PolicyChange::CreatePool {
                    name: "legacy pool".into(),
                    family: crate::access::routing::AddressFamily::V4,
                },
            ))?)
            .routing
            .unwrap()
            {
                RoutingEntity::Pool(value) => value.id,
                _ => panic!("pool creation returned another entity"),
            };
            let gate = update_lock(&fixture.directory)?;
            let before = store::traffic::restore(&fixture.directory)?.status;
            let run = store::traffic::start_run(
                &fixture.directory,
                &gate,
                &before.meter_epoch,
                before.cursor,
                Some(60_000),
            )?
            .status;
            let observed = store::traffic::checkpoint(
                &fixture.directory,
                &gate,
                run.run_id.as_deref().unwrap(),
                Some(65_000),
                &[SeriesSnapshot {
                    user_id: Arc::from(user.as_str()),
                    credential_id: Arc::from(credential.as_str()),
                    protocol: crate::access::traffic::Protocol::Http,
                    value: Snapshot {
                        upload: 101,
                        download: 55,
                        saturated: false,
                    },
                }],
                &[PoolSnapshot {
                    pool_id: Arc::from(pool.as_str()),
                    protocol: crate::access::traffic::Protocol::Http,
                    value: Snapshot {
                        upload: 31,
                        download: 17,
                        saturated: false,
                    },
                }],
            )?;
            drop(gate);
            let connection = fixture.writable()?;
            // Legacy writers have no permanent history namespace to erase when the
            // remaining pre-v10 columns are reconstructed below.
            store::recovery::restore_schema_nineteen_for_test(&connection)?;
            let target = store::targets::configure(
                &fixture.directory,
                &fixture.administrator,
                &fixture.peer,
                None,
                "https://localhost:18843",
                true,
                None,
            )?;
            store::targets::observe(&fixture.directory, &fixture.peer, target.revision, 5, 0, 4)?;
            let pending = store::targets::enqueue(
                &fixture.directory,
                &fixture.administrator,
                target.revision,
                Command {
                    target_node_id: fixture.peer.clone(),
                    epoch: 5,
                    command_id: 1,
                    expected_policy_revision: 4,
                    source_administrator_id: fixture.administrator.clone(),
                    change: PolicyChange::SetUserActive {
                        id: user.clone(),
                        active: false,
                    },
                },
            )?;
            let blob: Vec<u8> = connection
                .query_row("SELECT command FROM control_outbox", [], |row| row.get(0))
                .map_err(io::Error::other)?;
            let before_policy = store::load_policy(&fixture.directory)?;
            let before_owner = ownership(&fixture.directory)?;
            let before_node = store::inspect(&fixture.directory)?.node_id;
            if version == 8 {
                reconstruct_v8(&connection)?;
            } else {
                store::restore_legacy_owner_audit(&connection)?;
                store::administrators::remove_schema_for_test(&connection)?;
                connection
                    .execute_batch(
                        "ALTER TABLE managed_targets DROP COLUMN server_ip; PRAGMA user_version=9;",
                    )
                    .map_err(io::Error::other)?;
            }
            let all_rows_before = if version == 9 {
                Some(existing_rows(&connection)?)
            } else {
                None
            };
            let receipts: Vec<(i64, i64, Vec<u8>)> = {
                let mut statement = connection
            .prepare("SELECT command_id,version,digest FROM control_receipts ORDER BY command_id")
            .map_err(io::Error::other)?;
                statement
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                    .map_err(io::Error::other)?
                    .collect::<Result<_, _>>()
                    .map_err(io::Error::other)?
            };
            let backup = fixture
                .directory
                .join(format!("schema{version}-before-upgrade.sqlite3"));
            assert_eq!(
                store::migrate(&fixture.directory, &backup)?.schema_version,
                store::SCHEMA_VERSION
            );
            assert!(
                store::recovery::status(&fixture.directory)?
                    .recovery
                    .is_none()
            );
            assert!(
                store::endpoints::read(&fixture.directory)?
                    .digest
                    .is_empty()
            );
            assert_eq!(store::inspect(&fixture.directory)?.node_id, before_node);
            assert_eq!(ownership(&fixture.directory)?, before_owner);
            let after_policy = store::load_policy(&fixture.directory)?;
            assert_eq!(after_policy.revision, before_policy.revision);
            assert_eq!(
                after_policy.credentials[0].secret_digest,
                before_policy.credentials[0].secret_digest
            );
            assert_eq!(after_policy.presets.users, vec![UserPreset::native(user)]);
            assert_eq!(after_policy.presets.pools, vec![PoolPreset::native(pool)]);
            let after_stats = store::traffic::restore(&fixture.directory)?;
            assert_eq!(
                (
                    after_stats.status.meter_epoch,
                    after_stats.status.cursor,
                    after_stats.status.run_id
                ),
                (observed.meter_epoch, observed.cursor, observed.run_id)
            );
            assert_eq!(after_stats.credential_seeds[0].value.upload, 101);
            assert_eq!(after_stats.pool_seeds[0].value.upload, 31);
            let restored = store::targets::job(&fixture.directory, &fixture.peer)?.unwrap();
            assert_eq!(restored.job_id, pending.job_id);
            assert_eq!(restored.command_id, pending.command_id);
            let history = store::targets::history::get(
                &fixture.directory,
                &fixture.administrator,
                &fixture.peer,
                &pending.job_id,
            )?
            .unwrap();
            assert!(history.imported);
            assert_eq!(history.sequence, 1);
            assert_eq!(history.job, restored);
            assert!(history.recorded_at_unix_s.is_none());
            assert!(history.updated_at_unix_s.is_none());
            let current_blob: Vec<u8> = connection
                .query_row("SELECT command FROM control_outbox", [], |row| row.get(0))
                .map_err(io::Error::other)?;
            assert_eq!(current_blob, blob);
            let after_receipts: Vec<(i64, i64, Vec<u8>)> = {
                let mut statement = connection
            .prepare("SELECT command_id,version,digest FROM control_receipts ORDER BY command_id")
            .map_err(io::Error::other)?;
                statement
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                    .map_err(io::Error::other)?
                    .collect::<Result<_, _>>()
                    .map_err(io::Error::other)?
            };
            assert_eq!(after_receipts, receipts);
            assert!(
                store::targets::get(&fixture.directory, &fixture.peer)?
                    .server_ip
                    .is_none()
            );
            if let Some(before) = &all_rows_before {
                store::proxy_service::require_unused_for_test(&connection)?;
                assert_eq!(&existing_rows(&connection)?, before);
            }
            let no_automation_actor: bool = connection.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM proxy_policy_audit WHERE automation_principal_id IS NOT NULL OR automation_generation IS NOT NULL)",
        [], |row| row.get(0),
    ).map_err(io::Error::other)?;
            assert!(no_automation_actor);
            // New v15 columns describe the old rows as policy-only; they are excluded
            // from the historical projection below, not left unverified.
            let policy_only:bool=connection.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM control_outbox WHERE resource<>'proxy_policy' OR expected_metadata_revision IS NOT NULL OR metadata_revision IS NOT NULL)
          AND NOT EXISTS(SELECT 1 FROM control_receipts WHERE metadata_revision IS NOT NULL OR endpoint_id IS NOT NULL OR endpoint_generation IS NOT NULL)",
        [],|row|row.get(0),
    ).map_err(io::Error::other)?;
            assert!(policy_only);
            let automation: (i64, i64, i64, i64) = connection
                .query_row(
                    "SELECT (SELECT count(*) FROM automation_state),
                    (SELECT last_sequence FROM automation_state WHERE singleton=1),
                    (SELECT count(*) FROM automation_principals),
                    (SELECT count(*) FROM automation_audit)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(io::Error::other)?;
            assert_eq!(automation, (1, 0, 0, 0));
            let admission: (i64, i64, i64, i64) = connection
                .query_row(
                    "SELECT (SELECT count(*) FROM proxy_admission_state),
                    (SELECT singleton FROM proxy_admission_state),
                    (SELECT accepting FROM proxy_admission_state),
                    (SELECT count(*) FROM proxy_admission_audit)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(io::Error::other)?;
            assert_eq!(admission, (1, 1, 1, 0));
            store::alerts::history::validate_snapshot(&connection)?;
            // Namespace creation cannot fabricate a monitor boot or historical events.
            store::alerts::history::require_empty(&connection)?;
            let copied = Connection::open(&backup).map_err(io::Error::other)?;
            assert_eq!(store::read_overview(&copied)?.schema_version, version);
            if let Some(before) = &all_rows_before {
                assert_eq!(&existing_rows(&copied)?, before);
            }
            assert!(
                copied
                    .prepare("SELECT server_ip FROM managed_targets")
                    .is_err()
            );
            if version == 8 {
                assert!(copied.prepare("SELECT * FROM user_presets").is_err());
            }
            Ok(())
        }

        /// Compare all pre-existing SQL values, including identities, hashes, ownership,
        /// IPAM, preset, outbox and metering rows. Schema-ten metadata, newly created
        /// schema-eleven audit tables, recovery/endpoint/operation/automation/admission/history namespaces
        /// (including the new alert journal)
        /// and v15 command/v18 actor columns are omitted, not any historical rows. Migration
        /// separately verifies the new namespaces and policy-only defaults.
        type DatabaseRows = Vec<(String, Vec<Vec<rusqlite::types::Value>>)>;

        fn existing_rows(connection: &Connection) -> io::Result<DatabaseRows> {
            store::notifications::ensure_unused_for_test(connection)?;
            let names = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT IN ('administrator_audit', 'administrator_audit_state', 'recovery_state', 'endpoint_state', 'endpoint_overrides', 'endpoint_audit', 'operations_state', 'user_operations', 'automation_state', 'automation_principals', 'automation_audit', 'proxy_admission_state', 'proxy_admission_audit', 'controller_history_state', 'controller_history', 'alert_history_state', 'alert_episodes', 'alert_events', 'webhook_state', 'recovery_witness', 'recovery_source', 'proxy_service_state', 'proxy_service_operations', 'proxy_credential_secrets') ORDER BY name")
        .map_err(io::Error::other)?
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(io::Error::other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
            let mut snapshot = Vec::new();
            for name in names {
                let quoted = format!("\"{}\"", name.replace('"', "\"\""));
                let columns = if name == "proxy_policy_audit" {
                    // All eleven original audit fields remain in the exact comparison;
                    // the two new actor fields have a separate NULL-default assertion.
                    [
                        "sequence",
                        "entry",
                        "administrator_id",
                        "controller_node_id",
                        "controller_epoch",
                        "command_id",
                        "source_administrator_id",
                        "action",
                        "user_id",
                        "credential_id",
                        "policy_revision",
                    ]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
                } else {
                    connection
                        .prepare(&format!("PRAGMA table_info({quoted})"))
                        .map_err(io::Error::other)?
                        .query_map([], |row| row.get::<_, String>(1))
                        .map_err(io::Error::other)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(io::Error::other)?
                };
                let columns = columns
                    .into_iter()
                    .filter(|column| match name.as_str() {
                        "managed_targets" => column != "server_ip",
                        "control_outbox" => ![
                            "resource",
                            "expected_metadata_revision",
                            "metadata_revision",
                        ]
                        .contains(&column.as_str()),
                        "control_receipts" => {
                            !["metadata_revision", "endpoint_id", "endpoint_generation"]
                                .contains(&column.as_str())
                        }
                        _ => true,
                    })
                    .map(|column| format!("\"{}\"", column.replace('"', "\"\"")))
                    .collect::<Vec<_>>();
                let mut statement = connection
                    .prepare(&format!(
                        "SELECT {} FROM {quoted} ORDER BY {}",
                        columns.join(","),
                        columns.join(",")
                    ))
                    .map_err(io::Error::other)?;
                let rows = statement
                    .query_map([], |row| {
                        (0..columns.len())
                            .map(|index| row.get(index))
                            .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
                    })
                    .map_err(io::Error::other)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(io::Error::other)?;
                snapshot.push((name, rows));
            }
            Ok(snapshot)
        }
    }

    #[test]
    fn corrupt_policy_receipt_metadata_fields_are_rejected_by_read_and_replay() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.grant()?;
        fixture.run(fixture.command(1, 1, create()))?;
        let connection = fixture.writable()?;
        connection.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE control_receipts SET metadata_revision=99 WHERE epoch=2 AND command_id=1;")
        .map_err(io::Error::other)?;
        assert_eq!(
            find_receipt(&connection, 2, 1).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            fixture
                .run(fixture.command(1, 1, create()))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(store::policy_status(&fixture.directory)?.revision, 2);
        assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 1);
        Ok(())
    }

    #[test]
    fn version_two_routing_is_userless_terminal_and_authorized_in_one_snapshot() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.grant()?;
        let create = || PolicyChange::CreatePrefix {
            name: "owned prefix".into(),
            cidr: "192.0.2.0/24".parse().unwrap(),
        };
        let CommandOutcome::Accepted { receipt, change } =
            fixture.run(fixture.command(1, 1, create()))?
        else {
            panic!("routing creation rejected")
        };
        assert_eq!(receipt.version, 2);
        assert!(
            receipt.user_id.is_none() && receipt.credential_id.is_none() && change.user.is_none()
        );
        let reference = receipt.routing.unwrap();
        assert_eq!(reference.kind, RoutingKind::Prefix);
        assert!(matches!(
            fixture.run(fixture.command(1, 1, create()))?,
            CommandOutcome::Replayed(Receipt { version: 2, .. })
        ));
        let CommandOutcome::Rejected(rejected) = fixture.run(fixture.command(
            2,
            2,
            PolicyChange::CreateAddress {
                name: "outside".into(),
                ip: "198.51.100.1".parse().unwrap(),
                prefix_id: Some(reference.id.clone()),
            },
        ))?
        else {
            panic!("outside-prefix address accepted")
        };
        assert_eq!(rejected.version, 2);
        assert_eq!(rejected.rejection, Some("invalid_policy"));
        assert!(rejected.routing.is_none() && rejected.user_id.is_none());
        let CommandOutcome::Accepted { receipt, .. } = fixture.run(fixture.command(
            3,
            2,
            PolicyChange::CreateAddress {
                name: "owned address".into(),
                ip: "192.0.2.1".parse().unwrap(),
                prefix_id: Some(reference.id),
            },
        ))?
        else {
            panic!("address creation rejected")
        };
        assert_eq!(receipt.routing.as_ref().unwrap().kind, RoutingKind::Address);
        let (revision, data) = remote_routing_data(&fixture.directory, &fixture.authorize())?;
        assert_eq!((revision, data.addresses.len()), (3, 1));
        let actors:i64=fixture.writable()?.query_row("SELECT count(*) FROM routing_audit WHERE entry='node_management' AND controller_node_id=?1 AND administrator_id IS NULL",[&fixture.peer],|row|row.get(0)).map_err(io::Error::other)?;
        assert_eq!(actors, 2);
        revoke_certificate(&fixture.directory, &fixture.leaf, 1)?;
        assert_eq!(
            remote_routing_data(&fixture.directory, &fixture.authorize())
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut sampled = false;
        assert!(
            remote_authorized(&fixture.directory, &fixture.authorize(), || {
                sampled = true;
                Ok(())
            })
            .is_err()
        );
        assert!(!sampled);
        Ok(())
    }

    #[test]
    fn permission_receipt_uses_routing_user_identity_without_fabricating_a_user_group()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.grant()?;
        let CommandOutcome::Accepted { change, .. } =
            fixture.run(fixture.command(1, 1, create()))?
        else {
            panic!("user creation rejected")
        };
        let user = change.user.unwrap().id;
        let change = || PolicyChange::SetRoutePermission {
            permission: crate::access::routing::RoutePermission {
                user_id: user.clone(),
                legacy_allowed: false,
                exits: vec![],
                pools: vec![],
            },
        };
        let CommandOutcome::Accepted { receipt, .. } =
            fixture.run(fixture.command(2, 2, change()))?
        else {
            panic!("deny-all routing rejected")
        };
        assert_eq!(
            receipt.routing,
            Some(RoutingReceipt {
                kind: RoutingKind::Permission,
                id: user.clone()
            })
        );
        assert!(receipt.user_id.is_none() && receipt.credential_id.is_none());
        assert!(matches!(
            fixture.run(fixture.command(2, 2, change()))?,
            CommandOutcome::Replayed(Receipt { version: 2, .. })
        ));
        let connection = fixture.writable()?;
        for sql in [
            "UPDATE control_receipts SET version=1 WHERE command_id=2",
            "UPDATE control_receipts SET user_id=routing_id WHERE command_id=2",
            "UPDATE control_receipts SET routing_id=NULL WHERE command_id=2",
        ] {
            assert!(connection.execute(sql, []).is_err());
        }
        connection
            .pragma_update(None, "ignore_check_constraints", true)
            .map_err(io::Error::other)?;
        connection
            .execute(
                "UPDATE control_receipts SET version=7 WHERE command_id=2",
                [],
            )
            .map_err(io::Error::other)?;
        assert!(super::receipt(&fixture.directory, &fixture.authorize(), 2, 2).is_err());
        Ok(())
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
            PolicyChange::UpdateUser {
                id: user.clone(),
                name: "golden user".into(),
                protocols: vec![Protocol::Http, Protocol::Socks5],
                concurrent_limit: 2,
            },
            PolicyChange::SetUserActive {
                id: user.clone(),
                active: false,
            },
            PolicyChange::DeleteUser { id: user.clone() },
            PolicyChange::CreateCredential {
                user_id: user.clone(),
            },
            PolicyChange::SetCredentialActive {
                id: credential.clone(),
                active: false,
            },
            PolicyChange::RotateCredential {
                id: credential.clone(),
            },
            PolicyChange::RevokeCredential {
                id: credential.clone(),
            },
        ];
        let expected = [
            "6d3405ca772fcaab7b2ce01cb65fed9f39cee8b3ef361e15e4552286b2799539",
            "944094014729299ee3612b3414be7fca05e8380e82f1d843bba4ad5d31ee8de5",
            "16cb392daca74a952d6ca84d9fae76d6404059880aa5108cdf6bf01d65bc099a",
            "13c37210dfe1caa1364da6e499cfb6f90c20b45cf53acf30d25e8f17663aaca4",
            "cfafd6909b658566874c3374fdaa6df500d5c23d64bc5b8f071fe1b39a1b4042",
            "35ff8f6b6569b2d780c2a54495bd9e1b1d2b28ecd8478703cb7fa7f7d9285cee",
            "30620f4fa3af820ff41ff5013f2185584c16e7e1e7e15b74bf2c519ee9829151",
            "7662212432d755ce249fbe519e5d326ad746fc20f657ae2e0239f4acacd6d9cf",
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
            command(PolicyChange::SetRoutePermission {
                permission: crate::access::routing::RoutePermission {
                    user_id: user.clone(),
                    legacy_allowed: false,
                    exits,
                    pools: vec![],
                },
            })
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

    #[test]
    fn host_prefix_v2_digest_bytes_and_input_aliases_are_unchanged() -> io::Result<()> {
        let command = |cidr| Command {
            target_node_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            epoch: 2,
            command_id: 1,
            expected_policy_revision: 1,
            source_administrator_id: "AQEBAQEBAQEBAQEBAQEBAQ".into(),
            change: PolicyChange::CreatePrefix {
                name: "golden host prefix".into(),
                cidr,
            },
        };
        // Fixed v2 digests include the historical bare-host Display spelling.
        for (bare, masked, expected) in [
            (
                "192.0.2.1",
                "192.0.2.1/32",
                "4a6ef1a73b32d48d4991ed0186c1b60d86e835ebad952398255940fd6bee2a96",
            ),
            (
                "2001:db8::1",
                "2001:db8::1/128",
                "0f864b0a2c7bf8f4d1551679c56169d022c2155c4109a891fbb09767ee6d338a",
            ),
        ] {
            let bare = command(bare.parse().map_err(io::Error::other)?);
            let masked = command(masked.parse().map_err(io::Error::other)?);
            let digest = command_digest(&bare)?;
            assert_eq!(command_digest(&masked)?, digest);
            assert_eq!(
                digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn host_prefix_input_alias_replays_the_original_receipt_without_advancing_policy()
    -> io::Result<()> {
        for (bare, masked) in [
            ("192.0.2.1", "192.0.2.1/32"),
            ("2001:db8::1", "2001:db8::1/128"),
        ] {
            let fixture = Fixture::new()?;
            fixture.grant()?;
            let create = |text: &str| -> io::Result<PolicyChange> {
                Ok(PolicyChange::CreatePrefix {
                    name: "host prefix".into(),
                    cidr: text.parse().map_err(io::Error::other)?,
                })
            };
            let CommandOutcome::Accepted { receipt, .. } =
                fixture.run(fixture.command(1, 1, create(bare)?))?
            else {
                panic!("host prefix creation rejected")
            };
            assert_eq!(receipt.policy_revision, Some(2));
            let CommandOutcome::Replayed(replayed) =
                fixture.run(fixture.command(1, 1, create(masked)?))?
            else {
                panic!("host prefix alias did not replay")
            };
            assert_eq!(replayed, receipt);
            let policy = load_policy(&fixture.directory)?;
            assert_eq!(policy.revision, 2);
            assert_eq!(policy.routing.prefixes.len(), 1);
            assert_eq!(policy.routing.prefixes[0].cidr.to_string(), bare);
            assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 1);
        }
        Ok(())
    }

    /// Reconstruct old columns while retaining the real v5 row bytes. Upgrade must
    /// copy those rows instead of replacing identities or intent.
    fn old_five_layout(connection: &Connection) -> io::Result<()> {
        reconstruct_v5(connection)
    }

    #[test]
    fn schema_five_migration_keeps_receipts_route_assets_phc_and_exact_pending_bytes()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let prefix = store::apply_policy(
            &fixture.directory,
            &fixture.administrator,
            1,
            PolicyChange::CreatePrefix {
                name: "existing prefix".into(),
                cidr: "192.0.2.0/24".parse().unwrap(),
            },
            &update_lock(&fixture.directory)?,
        )?;
        let prefix_id = prefix
            .routing
            .as_ref()
            .map(RoutingReceipt::from)
            .unwrap()
            .id;
        fixture.grant()?;
        let CommandOutcome::Accepted { change, .. } =
            fixture.run(fixture.command(1, 2, create()))?
        else {
            panic!("user creation rejected")
        };
        let user = change.user.unwrap().id;
        fixture.run(fixture.command(
            2,
            3,
            PolicyChange::CreateCredential {
                user_id: user.clone(),
            },
        ))?;
        let rejected = fixture.run(fixture.command(
            3,
            4,
            PolicyChange::CreateUser {
                name: "business reject".into(),
                protocols: vec![],
                concurrent_limit: 0,
            },
        ))?;
        assert!(matches!(
            rejected,
            CommandOutcome::Rejected(Receipt { version: 1, .. })
        ));
        let revoked = random_id()?;
        register_peer(
            &fixture.directory,
            &revoked,
            "retired peer",
            b"permanent public fixture",
            "revoked.example",
            None,
        )?;
        revoke_certificate(&fixture.directory, b"permanent public fixture", 1)?;
        let connection = fixture.writable()?;
        // Preserve a legacy command's raw bytes without first allocating a
        // schema20 history identity that cannot legally be downgraded.
        store::recovery::restore_schema_nineteen_for_test(&connection)?;
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
        let pending = store::targets::enqueue(
            &fixture.directory,
            &fixture.administrator,
            1,
            Command {
                target_node_id: fixture.peer.clone(),
                epoch: 2,
                command_id: 1,
                expected_policy_revision: 1,
                source_administrator_id: fixture.administrator.clone(),
                change: create(),
            },
        )?;
        let bytes: Vec<u8> = connection
            .query_row("SELECT command FROM control_outbox", [], |row| row.get(0))
            .map_err(io::Error::other)?;
        let digest: Vec<u8> = connection
            .query_row(
                "SELECT digest FROM control_receipts WHERE command_id=2",
                [],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        let before = load_policy(&fixture.directory)?;
        old_five_layout(&connection)?;
        let backup = fixture.directory.join("schema5-consistent.sqlite3");
        store::migrate(&fixture.directory, &backup)?;
        assert_eq!(
            store::inspect(&fixture.directory)?.schema_version,
            store::SCHEMA_VERSION
        );
        assert_eq!(store::inspect(&fixture.directory)?.node_id, fixture.target);
        let after = load_policy(&fixture.directory)?;
        assert_eq!(
            (after.revision, after.users[0].id.as_str()),
            (before.revision, user.as_str())
        );
        assert_eq!(
            after.credentials[0].secret_digest,
            before.credentials[0].secret_digest
        );
        assert_eq!(after.routing.prefixes[0].id, prefix_id);
        assert_eq!(
            store::ownership(&fixture.directory)?.last_terminal_command,
            3
        );
        let restored = store::targets::job(&fixture.directory, &fixture.peer)?.unwrap();
        assert_eq!(restored.job_id, pending.job_id);
        let history = store::targets::history::get(
            &fixture.directory,
            &fixture.administrator,
            &fixture.peer,
            &pending.job_id,
        )?
        .unwrap();
        assert!(history.imported);
        assert_eq!(history.sequence, 1);
        assert_eq!(history.job, restored);
        assert!(history.recorded_at_unix_s.is_none());
        assert!(history.updated_at_unix_s.is_none());
        let copied_bytes: Vec<u8> = connection
            .query_row("SELECT command FROM control_outbox", [], |row| row.get(0))
            .map_err(io::Error::other)?;
        let copied_digest: Vec<u8> = connection
            .query_row(
                "SELECT digest FROM control_receipts WHERE command_id=2",
                [],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        assert_eq!(copied_bytes, bytes);
        assert_eq!(copied_digest, digest);
        assert_eq!(
            after.routing.permissions.len(),
            before.routing.permissions.len()
        );
        assert_eq!(
            after.routing.permissions[0].legacy_allowed,
            before.routing.permissions[0].legacy_allowed
        );
        let rejected = super::receipt(&fixture.directory, &fixture.authorize(), 2, 3)?;
        assert_eq!(
            (rejected.version, rejected.rejection),
            (1, Some("invalid_policy"))
        );
        for (table, expected) in [
            ("proxy_policy_audit", 2_i64),
            ("routing_audit", 1),
            ("control_audit", 2),
            ("controller_audit", 2),
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .map_err(io::Error::other)?;
            assert_eq!(count, expected, "preserve {table}");
        }
        assert_eq!(
            super::receipt(&fixture.directory, &fixture.authorize(), 2, 2)?.version,
            1
        );
        let revoked_flag: i64 = connection
            .query_row(
                "SELECT revoked FROM peer_certificates WHERE der=?1",
                [b"permanent public fixture".as_slice()],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        assert_eq!(revoked_flag, 1);
        let backup = Connection::open(backup).map_err(io::Error::other)?;
        assert_eq!(store::read_overview(&backup)?.schema_version, 5);
        let phc: String = backup
            .query_row("SELECT password_hash FROM administrators", [], |row| {
                row.get(0)
            })
            .map_err(io::Error::other)?;
        assert_eq!(phc, "fixture PHC bytes");
        Ok(())
    }

    #[test]
    fn schema_six_failure_rolls_back_and_retains_old_snapshot_backup() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let connection = fixture.writable()?;
        old_five_layout(&connection)?;
        connection
            .execute("CREATE TABLE controller_audit_v6(fixture INTEGER)", [])
            .map_err(io::Error::other)?;
        let backup = fixture.directory.join("schema5-failure.sqlite3");
        assert!(store::migrate(&fixture.directory, &backup).is_err());
        assert_eq!(store::inspect(&fixture.directory)?.schema_version, 5);
        assert_eq!(load_policy(&fixture.directory)?.revision, 1);
        let added: i64 = connection
            .query_row(
                "SELECT count(*) FROM pragma_table_info('control_receipts') WHERE name='version'",
                [],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        assert_eq!(added, 0);
        assert_eq!(
            store::read_overview(&Connection::open(backup).map_err(io::Error::other)?)?
                .schema_version,
            5
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
    fn accepted(outcome: CommandOutcome) -> ChangeResult {
        match outcome {
            CommandOutcome::Accepted { change, .. } => *change,
            _ => panic!("fixture command was not newly accepted"),
        }
    }
    fn code(error: io::Error) -> Option<&'static str> {
        error
            .get_ref()
            .and_then(|error| error.downcast_ref::<ControlError>())
            .map(|error| error.code())
    }

    #[test]
    fn ownership_cas_and_update_gate_exclude_local_and_other_directory_writers() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let other = Fixture::new()?;
        let guard = update_lock(&fixture.directory)?;
        assert!(
            matches!(update_lock(&fixture.directory),Err(error)if error.kind()==io::ErrorKind::WouldBlock)
        );
        assert!(
            matches!(store::set_peer_active(&fixture.directory,&fixture.peer,1,false),Err(error)if error.kind()==io::ErrorKind::WouldBlock)
        );
        assert!(
            matches!(revoke_certificate(&fixture.directory,&fixture.leaf,1),Err(error)if error.kind()==io::ErrorKind::WouldBlock)
        );
        assert!(
            matches!(store::apply_policy(&other.directory,&other.administrator,1,create(),&guard),Err(error)if error.kind()==io::ErrorKind::PermissionDenied)
        );
        let owner = set_owner(
            &fixture.directory,
            &guard,
            &fixture.administrator,
            1,
            Some(&fixture.peer),
        )?;
        assert_eq!((owner.epoch, owner.last_terminal_command), (2, 0));
        assert_eq!(
            code(
                store::apply_policy(
                    &fixture.directory,
                    &fixture.administrator,
                    1,
                    create(),
                    &guard
                )
                .err()
                .unwrap()
            ),
            Some("resource_managed")
        );
        assert_eq!(
            code(
                set_owner(&fixture.directory, &guard, &fixture.administrator, 1, None)
                    .err()
                    .unwrap()
            ),
            Some("owner_conflict")
        );
        let local = set_owner(&fixture.directory, &guard, &fixture.administrator, 2, None)?;
        assert_eq!(local.epoch, 3);
        let result = store::apply_policy(
            &fixture.directory,
            &fixture.administrator,
            1,
            create(),
            &guard,
        )?;
        assert_eq!(result.policy.revision, 2);
        let owner = set_owner(
            &fixture.directory,
            &guard,
            &fixture.administrator,
            3,
            Some(&fixture.peer),
        )?;
        assert_eq!(owner.epoch, 4);
        assert_eq!(
            code(
                apply_command(
                    &fixture.directory,
                    &guard,
                    &fixture.authorize(),
                    fixture.command(1, 2, create())
                )
                .err()
                .unwrap()
            ),
            Some("controller_epoch_changed")
        );
        assert_eq!(
            set_owner(
                &fixture.directory,
                &guard,
                &fixture.administrator,
                4,
                Some(&fixture.peer)
            )?
            .epoch,
            5
        );
        Ok(())
    }

    #[test]
    fn commands_replay_before_cas_without_generating_or_restoring_secrets() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.grant()?;
        let mut first_command = fixture.command(1, 1, create());
        first_command.source_administrator_id = fixture.peer.clone();
        let user = accepted(fixture.run(first_command)?).user.unwrap();
        let first = accepted(fixture.run(fixture.command(
            2,
            2,
            PolicyChange::CreateCredential {
                user_id: user.id.clone(),
            },
        ))?);
        let credential = first.credential.unwrap();
        let secret = first.secret.unwrap();
        assert_eq!(secret.len(), 43);
        let saved_digest = load_policy(&fixture.directory)?.credentials[0].secret_digest;
        let replay = fixture.run(fixture.command(
            2,
            2,
            PolicyChange::CreateCredential {
                user_id: user.id.clone(),
            },
        ))?;
        assert!(matches!(
            replay,
            CommandOutcome::Replayed(Receipt {
                status: ReceiptStatus::Saved,
                policy_revision: Some(3),
                ..
            })
        ));
        assert_eq!(
            load_policy(&fixture.directory)?.credentials[0].secret_digest,
            saved_digest
        );
        assert_eq!(
            store::policy_status(&fixture.directory)?.credential_count,
            1
        );
        assert_eq!(
            code(
                fixture
                    .run(fixture.command(
                        2,
                        3,
                        PolicyChange::CreateCredential {
                            user_id: user.id.clone()
                        }
                    ))
                    .err()
                    .unwrap()
            ),
            Some("command_conflict")
        );
        let rotated = accepted(fixture.run(fixture.command(
            3,
            3,
            PolicyChange::RotateCredential {
                id: credential.id.clone(),
            },
        ))?);
        assert_ne!(rotated.secret.unwrap().as_str(), secret.as_str());
        assert!(matches!(
            fixture.run(fixture.command(
                3,
                3,
                PolicyChange::RotateCredential {
                    id: credential.id.clone()
                }
            ))?,
            CommandOutcome::Replayed(_)
        ));
        let revoked = accepted(fixture.run(fixture.command(
            4,
            4,
            PolicyChange::RevokeCredential {
                id: credential.id.clone(),
            },
        ))?);
        assert!(revoked.credential.unwrap().revoked);
        assert!(matches!(
            fixture.run(fixture.command(
                5,
                5,
                PolicyChange::RotateCredential { id: credential.id }
            ))?,
            CommandOutcome::Rejected(Receipt {
                rejection: Some("policy_conflict"),
                ..
            })
        ));
        assert_eq!(load_policy(&fixture.directory)?.revision, 5);
        assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 5);
        let connection = fixture.writable()?;
        let actor:(String,Option<String>,String,String)=connection.query_row("SELECT entry,administrator_id,controller_node_id,source_administrator_id FROM proxy_policy_audit ORDER BY sequence LIMIT 1",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).map_err(|error|sqlite_error("cannot inspect remote fixture actor",error))?;
        assert_eq!(
            actor,
            (
                "node_management".into(),
                None,
                fixture.peer.clone(),
                fixture.peer.clone()
            )
        );
        Ok(())
    }

    #[test]
    #[ignore = "local segmented snapshot measurement; no performance SLO"]
    fn remote_policy_status_segmented_read_cost() -> io::Result<()> {
        use std::time::Instant;

        let fixture = Fixture::new()?;
        fixture.grant()?;
        assert!(
            accepted(fixture.run(fixture.command(1, 1, create()))?)
                .user
                .is_some()
        );
        let authorization = fixture.authorize();
        let expected_owner = Ownership {
            controller_node_id: Some(fixture.peer.clone()),
            epoch: 2,
            last_terminal_command: 1,
        };
        let check = |status: &RemotePolicyStatus| {
            assert!(
                status.node_id == fixture.target,
                "remote policy snapshot node differs",
            );
            assert!(
                status.ownership == expected_owner,
                "remote policy snapshot ownership differs",
            );
            assert_eq!(
                (
                    status.policy.revision,
                    status.policy.applied_revision,
                    status.policy.user_count,
                    status.policy.credential_count,
                ),
                (2, None, 1, 0),
            );
        };
        const PHASES: [&str; 7] = [
            "full", "open", "begin", "auth", "overview", "status", "commit",
        ];
        let mut totals = [0_u128; PHASES.len()];
        for sample in 1..=16 {
            let full_started = Instant::now();
            let full = remote_policy_status(&fixture.directory, &authorization)?;
            let full_returned = Instant::now();
            check(&full);

            // Mirror read_snapshot and its closure without skipping repeated schema,
            // owner or SAN validation. These wall intervals include preemption and
            // timestamp overhead; the complete call remains the production path.
            let started = Instant::now();
            let mut connection = peers::open_existing(&fixture.directory, false)?;
            let opened = Instant::now();
            let transaction = connection
                .transaction()
                .map_err(|error| sqlite_error("cannot begin node control inspection", error))?;
            let begun = Instant::now();
            let ownership = authorize_in(&transaction, &authorization)?;
            let authorized = Instant::now();
            let node_id = read_overview(&transaction)?.node_id;
            let overview_read = Instant::now();
            let policy = users::status_in(&transaction)?;
            let status_read = Instant::now();
            let segmented = RemotePolicyStatus {
                ownership,
                node_id,
                policy,
            };
            transaction
                .commit()
                .map_err(|error| sqlite_error("cannot complete node control inspection", error))?;
            let committed = Instant::now();
            drop(connection);
            check(&segmented);

            // Assertions, conversion, aggregation and output do not enter any phase.
            // Connection close is outside the segments but inside the full call.
            let elapsed = [
                full_returned.duration_since(full_started).as_micros(),
                opened.duration_since(started).as_micros(),
                begun.duration_since(opened).as_micros(),
                authorized.duration_since(begun).as_micros(),
                overview_read.duration_since(authorized).as_micros(),
                status_read.duration_since(overview_read).as_micros(),
                committed.duration_since(status_read).as_micros(),
            ];
            for (index, phase) in PHASES.iter().enumerate() {
                totals[index] = totals[index]
                    .checked_add(elapsed[index])
                    .ok_or_else(|| io::Error::other("segmented measurement duration overflow"))?;
                eprintln!(
                    "remote_policy_status_read phase={phase},sample={sample},elapsed_us={}",
                    elapsed[index],
                );
            }
        }
        for (phase, elapsed) in PHASES.iter().zip(totals) {
            eprintln!("remote_policy_status_read phase={phase},samples=16,total_us={elapsed}");
        }
        Ok(())
    }

    #[test]
    fn remote_policy_status_rechecks_peer_revision_owner_and_revocation_per_read() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        fixture.grant()?;
        accepted(fixture.run(fixture.command(1, 1, create()))?);
        let authorization = fixture.authorize();
        let initial = remote_policy_status(&fixture.directory, &authorization)?;
        assert_eq!(initial.node_id, fixture.target);
        assert_eq!((initial.policy.revision, initial.policy.user_count), (2, 1));

        register_peer(
            &fixture.directory,
            &fixture.peer,
            "updated controller",
            &fixture.leaf,
            "controller.example",
            Some(1),
        )?;
        assert_eq!(
            code(
                remote_policy_status(&fixture.directory, &authorization)
                    .err()
                    .unwrap()
            ),
            Some("peer_not_authorized"),
        );
        let mut current = fixture.authorize();
        current.authorization_revision = 2;
        assert_eq!(
            remote_policy_status(&fixture.directory, &current)?
                .ownership
                .epoch,
            2,
        );

        set_owner(
            &fixture.directory,
            &update_lock(&fixture.directory)?,
            &fixture.administrator,
            2,
            None,
        )?;
        assert_eq!(
            code(
                remote_policy_status(&fixture.directory, &current)
                    .err()
                    .unwrap()
            ),
            Some("peer_not_authorized"),
        );
        set_owner(
            &fixture.directory,
            &update_lock(&fixture.directory)?,
            &fixture.administrator,
            3,
            Some(&fixture.peer),
        )?;
        let restored = remote_policy_status(&fixture.directory, &current)?;
        assert_eq!(restored.ownership.epoch, 4);
        assert_eq!(restored.ownership.last_terminal_command, 0);
        assert_eq!(restored.policy.revision, initial.policy.revision);
        assert_eq!(restored.policy.user_count, initial.policy.user_count);

        revoke_certificate(&fixture.directory, &fixture.leaf, 2)?;
        current.authorization_revision = 3;
        assert_eq!(
            code(
                remote_policy_status(&fixture.directory, &current)
                    .err()
                    .unwrap()
            ),
            Some("peer_not_authorized"),
        );
        Ok(())
    }

    #[test]
    fn remote_policy_status_preserves_certificate_and_schema_error_precedence() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.grant()?;
        let connection = fixture.writable()?;
        let application_id: i32 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .map_err(io::Error::other)?;
        let schema_version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(io::Error::other)?;
        connection
            .pragma_update(None, "application_id", 0)
            .map_err(io::Error::other)?;
        // Input length was checked before namespace inspection. Reusing a snapshot
        // must not turn malformed input into a different database failure first.
        for leaf in [Vec::new(), vec![0; 16 * 1024 + 1]] {
            let mut invalid = fixture.authorize();
            invalid.leaf = leaf.into();
            assert!(
                matches!(remote_policy_status(&fixture.directory, &invalid), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
            );
        }
        assert!(
            matches!(remote_policy_status(&fixture.directory, &fixture.authorize()), Err(error) if error.kind() == io::ErrorKind::InvalidData)
        );
        connection
            .pragma_update(None, "application_id", application_id)
            .map_err(io::Error::other)?;
        remote_policy_status(&fixture.directory, &fixture.authorize())?;

        let mut unknown = fixture.authorize();
        unknown.leaf = b"unregistered public fixture".as_slice().into();
        connection
            .pragma_update(None, "user_version", 0)
            .map_err(io::Error::other)?;
        // A bounded unknown leaf still reaches schema validation before lookup can
        // classify it as unauthorized; storage corruption must not become denial.
        assert!(
            matches!(remote_policy_status(&fixture.directory, &unknown), Err(error) if error.kind() == io::ErrorKind::InvalidData)
        );
        connection
            .pragma_update(None, "user_version", schema_version)
            .map_err(io::Error::other)?;
        assert_eq!(
            code(
                remote_policy_status(&fixture.directory, &unknown)
                    .err()
                    .unwrap()
            ),
            Some("peer_not_authorized"),
        );
        remote_policy_status(&fixture.directory, &fixture.authorize())?;
        Ok(())
    }

    #[test]
    fn remote_policy_status_revalidates_overview_owner_and_policy_after_each_snapshot()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.grant()?;
        accepted(fixture.run(fixture.command(1, 1, create()))?);
        let authorization = fixture.authorize();
        let connection = fixture.writable()?;
        let check = || -> io::Result<()> {
            let status = remote_policy_status(&fixture.directory, &authorization)?;
            assert_eq!(status.node_id, fixture.target);
            assert_eq!(
                status.ownership.controller_node_id.as_ref(),
                Some(&fixture.peer)
            );
            assert_eq!(
                (
                    status.ownership.epoch,
                    status.ownership.last_terminal_command
                ),
                (2, 1)
            );
            assert_eq!(
                (
                    status.policy.revision,
                    status.policy.applied_revision,
                    status.policy.user_count,
                    status.policy.credential_count,
                ),
                (2, None, 1, 0),
            );
            Ok(())
        };
        check()?;

        // This fixture has no automation identities. A valid-looking peer/owner
        // must not bypass an independent namespace's highwater invariant.
        connection
            .execute("UPDATE automation_state SET last_sequence=1", [])
            .map_err(io::Error::other)?;
        assert!(
            matches!(remote_policy_status(&fixture.directory, &authorization), Err(error) if error.kind() == io::ErrorKind::InvalidData)
        );
        connection
            .execute("UPDATE automation_state SET last_sequence=0", [])
            .map_err(io::Error::other)?;
        check()?;

        connection
        .execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE control_ownership SET epoch=0 WHERE singleton=1; PRAGMA ignore_check_constraints=OFF;")
        .map_err(io::Error::other)?;
        assert!(
            matches!(remote_policy_status(&fixture.directory, &authorization), Err(error) if error.kind() == io::ErrorKind::InvalidData)
        );
        connection
            .execute("UPDATE control_ownership SET epoch=2 WHERE singleton=1", [])
            .map_err(io::Error::other)?;
        check()?;

        connection
        .execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE proxy_policy_state SET applied_revision=3 WHERE singleton=1; PRAGMA ignore_check_constraints=OFF;")
        .map_err(io::Error::other)?;
        assert!(
            matches!(remote_policy_status(&fixture.directory, &authorization), Err(error) if error.kind() == io::ErrorKind::InvalidData)
        );
        connection
            .execute(
                "UPDATE proxy_policy_state SET applied_revision=NULL WHERE singleton=1",
                [],
            )
            .map_err(io::Error::other)?;
        check()?;
        Ok(())
    }

    #[test]
    fn authorization_and_epoch_are_rechecked_before_reads_and_replay() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.grant()?;
        let user = accepted(fixture.run(fixture.command(1, 1, create()))?)
            .user
            .unwrap();
        let status = remote_policy_status(&fixture.directory, &fixture.authorize())?;
        assert_eq!(status.node_id, fixture.target);
        assert_eq!(status.policy.revision, 2);
        assert_eq!(
            remote_list_users(&fixture.directory, &fixture.authorize(), false, None, 25)?.items[0]
                .id,
            user.id
        );
        assert!(
            remote_list_credentials(&fixture.directory, &fixture.authorize(), None, None, 25)?
                .items
                .is_empty()
        );
        let mut impostor = fixture.authorize();
        impostor.node_id = random_id()?;
        assert_eq!(
            code(
                remote_policy_status(&fixture.directory, &impostor)
                    .err()
                    .unwrap()
            ),
            Some("peer_not_authorized")
        );
        let mut wrong = fixture.command(2, 2, create());
        wrong.target_node_id = random_id()?;
        assert_eq!(
            code(fixture.run(wrong).err().unwrap()),
            Some("target_mismatch")
        );
        revoke_certificate(&fixture.directory, &fixture.leaf, 1)?;
        assert_eq!(
            code(fixture.run(fixture.command(1, 1, create())).err().unwrap()),
            Some("peer_not_authorized")
        );
        assert_eq!(
            code(
                receipt(&fixture.directory, &fixture.authorize(), 2, 1)
                    .err()
                    .unwrap()
            ),
            Some("peer_not_authorized")
        );
        assert_eq!(
            code(
                remote_list_users(&fixture.directory, &fixture.authorize(), false, None, 25)
                    .err()
                    .unwrap()
            ),
            Some("peer_not_authorized")
        );
        let guard = update_lock(&fixture.directory)?;
        set_owner(&fixture.directory, &guard, &fixture.administrator, 2, None)?;
        assert_eq!(ownership(&fixture.directory)?.epoch, 3);
        Ok(())
    }

    #[test]
    fn rejected_sequence_is_terminal_unknown_storage_is_not_and_expired_never_reexecutes()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.grant()?;
        assert_eq!(
            code(fixture.run(fixture.command(2, 1, create())).err().unwrap()),
            Some("command_out_of_order")
        );
        assert!(matches!(
            fixture.run(fixture.command(1, 2, create()))?,
            CommandOutcome::Rejected(Receipt {
                rejection: Some("policy_conflict"),
                policy_revision: None,
                ..
            })
        ));
        assert_eq!(load_policy(&fixture.directory)?.revision, 1);
        assert!(matches!(
            fixture.run(fixture.command(1, 2, create()))?,
            CommandOutcome::Replayed(Receipt {
                status: ReceiptStatus::Rejected,
                ..
            })
        ));
        accepted(fixture.run(fixture.command(2, 1, create()))?);
        let connection = fixture.writable()?;
        connection
            .execute("DELETE FROM control_receipts WHERE command_id=1", [])
            .map_err(|error| sqlite_error("cannot expire fixture receipt", error))?;
        assert_eq!(
            code(fixture.run(fixture.command(1, 2, create())).err().unwrap()),
            Some("receipt_expired")
        );
        connection.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE proxy_users SET active=2; PRAGMA ignore_check_constraints=OFF;").map_err(|error|sqlite_error("cannot corrupt fixture policy",error))?;
        assert!(
            matches!(fixture.run(fixture.command(3,2,create())),Err(error)if error.kind()==io::ErrorKind::InvalidData)
        );
        assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 2);
        Ok(())
    }

    #[test]
    fn recovery_marks_only_exact_actual_revision_and_can_recover_old_epoch() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.grant()?;
        accepted(fixture.run(fixture.command(1, 1, create()))?);
        accepted(fixture.run(fixture.command(2, 2, create()))?);
        let guard = update_lock(&fixture.directory)?;
        assert_eq!(
            code(
                mark_command_applied(&fixture.directory, &guard, 2, 1, 2)
                    .err()
                    .unwrap()
            ),
            Some("command_conflict")
        );
        set_owner(&fixture.directory, &guard, &fixture.administrator, 2, None)?;
        store::record_applied(&fixture.directory, 3)?;
        let connection = fixture.writable()?;
        let statuses:(String,String)=connection.query_row("SELECT (SELECT status FROM control_receipts WHERE command_id=1),(SELECT status FROM control_receipts WHERE command_id=2)",[],|row|Ok((row.get(0)?,row.get(1)?))).map_err(|error|sqlite_error("cannot inspect recovered fixture receipt",error))?;
        assert_eq!(statuses, ("saved".into(), "applied".into()));
        mark_command_applied(&fixture.directory, &guard, 2, 2, 3)?;
        assert_eq!(
            store::policy_status(&fixture.directory)?.applied_revision,
            Some(3)
        );
        Ok(())
    }

    /// Reconstructs the actual D1 schema, including its stricter local-only audit table.
    fn make_v3(connection: &Connection) -> io::Result<()> {
        store::traffic::remove_schema_for_test(connection)?;
        connection.execute_batch("DROP TABLE routing_audit; DROP TABLE routing_exit_grants; DROP TABLE routing_pool_grants; DROP TABLE routing_permissions; DROP TABLE routing_pool_members; DROP TABLE routing_pools; DROP TABLE routing_addresses; DROP TABLE routing_prefixes; DROP TABLE controller_audit; DROP TABLE control_outbox; DROP TABLE managed_targets;
      DROP TABLE control_audit; DROP TABLE control_receipts; DROP TABLE control_ownership;
      ALTER TABLE proxy_policy_audit RENAME TO audit_new;
      CREATE TABLE proxy_policy_audit(sequence INTEGER PRIMARY KEY,entry TEXT NOT NULL CHECK(entry='local_management'),administrator_id TEXT NOT NULL REFERENCES administrators(id),action TEXT NOT NULL CHECK(action IN ('create_user','update_user','enable_user','disable_user','delete_user','create_credential','enable_credential','disable_credential','rotate_credential','revoke_credential')),user_id TEXT NOT NULL REFERENCES proxy_users(id),credential_id TEXT REFERENCES proxy_credentials(id),policy_revision INTEGER NOT NULL CHECK(policy_revision>=1)) STRICT;
      INSERT INTO proxy_policy_audit SELECT sequence,entry,administrator_id,action,user_id,credential_id,policy_revision FROM audit_new;
      DROP TABLE audit_new; PRAGMA user_version=3;")
      .map_err(|error|sqlite_error("cannot build D1 migration fixture",error))
    }

    #[test]
    fn v3_migration_preserves_all_identifiers_hashes_tombstones_and_local_audits() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        let guard = update_lock(&fixture.directory)?;
        let user = store::apply_policy(
            &fixture.directory,
            &fixture.administrator,
            1,
            create(),
            &guard,
        )?
        .user
        .unwrap();
        let credential = store::apply_policy(
            &fixture.directory,
            &fixture.administrator,
            2,
            PolicyChange::CreateCredential { user_id: user.id },
            &guard,
        )?
        .credential
        .unwrap();
        store::apply_policy(
            &fixture.directory,
            &fixture.administrator,
            3,
            PolicyChange::RevokeCredential {
                id: credential.id.clone(),
            },
            &guard,
        )?;
        drop(guard);
        revoke_certificate(&fixture.directory, &fixture.leaf, 1)?;
        let connection = fixture.writable()?;
        make_v3(&connection)?;
        let before = load_policy(&fixture.directory)?;
        let backup = fixture.directory.join("schema3-backup.sqlite3");
        store::migrate(&fixture.directory, &backup)?;
        let after = load_policy(&fixture.directory)?;
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.credentials[0].id, credential.id);
        assert_eq!(
            after.credentials[0].secret_digest,
            before.credentials[0].secret_digest
        );
        assert!(after.credentials[0].revoked);
        assert!(store::authorize_peer(&fixture.directory, &fixture.leaf)?.is_none());
        assert_eq!(
            store::list_peers(&fixture.directory)?[0].authorization_revision,
            2
        );
        assert_eq!(store::inspect(&fixture.directory)?.node_id, fixture.target);
        let hash: String = connection
            .query_row(
                "SELECT password_hash FROM administrators WHERE id=?1",
                [&fixture.administrator],
                |row| row.get(0),
            )
            .map_err(|error| sqlite_error("cannot inspect preserved fixture PHC", error))?;
        assert_eq!(hash, "fixture PHC bytes");
        let audits:i64=connection.query_row("SELECT count(*) FROM proxy_policy_audit WHERE entry='local_management' AND administrator_id=?1 AND controller_node_id IS NULL",[&fixture.administrator],|row|row.get(0)).map_err(|error|sqlite_error("cannot inspect migrated local audit",error))?;
        assert_eq!(audits, 3);
        assert_eq!(
            ownership(&fixture.directory)?,
            Ownership {
                controller_node_id: None,
                epoch: 1,
                last_terminal_command: 0
            }
        );
        assert_eq!(
            store::read_overview(&store::open(
                &backup,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            )?)?
            .schema_version,
            3
        );
        Ok(())
    }

    #[test]
    fn failed_v3_migration_rolls_back_audit_rebuild_and_keeps_consistent_backup() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        let connection = fixture.writable()?;
        make_v3(&connection)?;
        connection
            .execute("CREATE TABLE control_ownership (operator_fixture TEXT)", [])
            .map_err(|error| sqlite_error("cannot seed conflicting migration fixture", error))?;
        let backup = fixture.directory.join("failed-schema4.sqlite3");
        assert!(store::migrate(&fixture.directory, &backup).is_err());
        assert_eq!(store::inspect(&fixture.directory)?.schema_version, 3);
        let new_columns:i64=connection.query_row("SELECT count(*) FROM pragma_table_info('proxy_policy_audit') WHERE name='controller_node_id'",[],|row|row.get(0)).map_err(|error|sqlite_error("cannot inspect rolled back audit",error))?;
        assert_eq!(new_columns, 0);
        assert_eq!(
            store::read_overview(&store::open(
                &backup,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            )?)?
            .schema_version,
            3
        );
        Ok(())
    }

    #[test]
    fn unknown_sql_failure_rolls_back_partial_change_without_terminal_receipt() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.grant()?;
        let connection = fixture.writable()?;
        connection.execute_batch("CREATE TRIGGER fixture_audit_failure BEFORE INSERT ON proxy_policy_audit BEGIN SELECT RAISE(ABORT,'fixture'); END;")
        .map_err(|error|sqlite_error("cannot install failing audit fixture",error))?;
        let error = fixture.run(fixture.command(1, 1, create())).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(code(error).is_none());
        assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 0);
        let policy = load_policy(&fixture.directory)?;
        assert_eq!(policy.revision, 1);
        assert!(policy.users.is_empty());
        let count: i64 = connection
            .query_row("SELECT count(*) FROM control_receipts", [], |row| {
                row.get(0)
            })
            .map_err(|error| sqlite_error("cannot inspect rolled back command fixture", error))?;
        assert_eq!(count, 0);
        connection
            .execute("DROP TRIGGER fixture_audit_failure", [])
            .map_err(|error| sqlite_error("cannot remove failing audit fixture", error))?;
        accepted(fixture.run(fixture.command(1, 1, create()))?);
        Ok(())
    }

    #[test]
    fn receipts_remain_bounded_without_discarding_current_saved_candidate() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.grant()?;
        accepted(fixture.run(fixture.command(1, 1, create()))?);
        set_owner(
            &fixture.directory,
            &update_lock(&fixture.directory)?,
            &fixture.administrator,
            2,
            Some(&fixture.peer),
        )?;
        let connection = fixture.writable()?;
        connection
        .execute(
            "WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n < ?1)
      INSERT INTO control_receipts(epoch,command_id,controller_node_id,digest,status,rejection)
      SELECT 3,n,?2,zeroblob(32),'rejected','policy_conflict' FROM numbers",
            params![MAX_RECEIPTS, fixture.peer],
        )
        .and_then(|_| {
            connection.execute(
                "UPDATE control_ownership SET last_terminal_command=?1",
                [MAX_RECEIPTS],
            )
        })
        .map_err(|error| sqlite_error("cannot seed bounded receipt fixture", error))?;
        let mut command = fixture.command(u64::from(MAX_RECEIPTS) + 1, 999, create());
        command.epoch = 3;
        assert!(matches!(fixture.run(command)?, CommandOutcome::Rejected(_)));
        let count: i64 = connection
            .query_row("SELECT count(*) FROM control_receipts", [], |row| {
                row.get(0)
            })
            .map_err(|error| sqlite_error("cannot inspect receipt bound fixture", error))?;
        assert_eq!(count, i64::from(MAX_RECEIPTS));
        assert_eq!(
            find_receipt(&connection, 2, 1)?.unwrap().0.status,
            ReceiptStatus::Saved
        );
        assert_eq!(
            code(
                receipt(&fixture.directory, &fixture.authorize(), 3, 1)
                    .err()
                    .unwrap()
            ),
            Some("receipt_expired")
        );
        store::record_applied(&fixture.directory, 2)?;
        assert_eq!(
            find_receipt(&connection, 2, 1)?.unwrap().0.status,
            ReceiptStatus::Applied
        );
        Ok(())
    }

    #[test]
    fn capacity_rejection_is_terminal_and_changed_peer_revision_never_replays() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.grant()?;
        let mut connection = fixture.writable()?;
        let transaction = connection
            .transaction()
            .map_err(|error| sqlite_error("cannot begin policy capacity fixture", error))?;
        for _ in 0..crate::access::MAX_USERS {
            transaction
                .execute(
                    "INSERT INTO proxy_users VALUES(?1,'retired',0,1,0,1,1)",
                    [random_id()?],
                )
                .map_err(|error| sqlite_error("cannot fill policy history fixture", error))?;
        }
        transaction
            .execute(
                "INSERT INTO routing_permissions SELECT id,1 FROM proxy_users",
                [],
            )
            .map_err(|error| sqlite_error("cannot seed explicit policy history routes", error))?;
        transaction
            .execute(
                "INSERT INTO user_presets SELECT id,NULL,0 FROM proxy_users",
                [],
            )
            .map_err(|error| sqlite_error("cannot seed explicit policy history presets", error))?;
        transaction
            .commit()
            .map_err(|error| sqlite_error("cannot commit policy capacity fixture", error))?;
        assert!(matches!(
            fixture.run(fixture.command(1, 1, create()))?,
            CommandOutcome::Rejected(Receipt {
                rejection: Some("policy_capacity"),
                ..
            })
        ));
        assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 1);
        assert_eq!(load_policy(&fixture.directory)?.revision, 1);
        register_peer(
            &fixture.directory,
            &fixture.peer,
            "rotated metadata",
            &fixture.leaf,
            "controller.example",
            Some(1),
        )?;
        assert_eq!(
            code(fixture.run(fixture.command(1, 1, create())).err().unwrap()),
            Some("peer_not_authorized")
        );
        let mut fresh = fixture.authorize();
        fresh.authorization_revision = 2;
        assert!(matches!(
            apply_command(
                &fixture.directory,
                &update_lock(&fixture.directory)?,
                &fresh,
                fixture.command(1, 1, create())
            )?,
            CommandOutcome::Replayed(_)
        ));
        Ok(())
    }

    #[test]
    fn duplicate_protocols_are_terminal_but_canonical_permission_sets_ignore_order()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.grant()?;
        let change = |protocols| PolicyChange::CreateUser {
            name: "permissions".into(),
            protocols,
            concurrent_limit: 1,
        };
        let duplicate = || change(vec![Protocol::Http, Protocol::Http, Protocol::Socks5]);
        assert!(matches!(
            fixture.run(fixture.command(1, 1, duplicate()))?,
            CommandOutcome::Rejected(Receipt {
                rejection: Some("invalid_policy"),
                ..
            })
        ));
        assert!(matches!(
            fixture.run(fixture.command(1, 1, duplicate()))?,
            CommandOutcome::Replayed(Receipt {
                status: ReceiptStatus::Rejected,
                ..
            })
        ));
        assert_eq!(ownership(&fixture.directory)?.last_terminal_command, 1);
        assert_eq!(load_policy(&fixture.directory)?.revision, 1);
        assert_eq!(
            code(
                fixture
                    .run(fixture.command(
                        1,
                        1,
                        change(vec![Protocol::Http, Protocol::Socks5, Protocol::Socks5])
                    ))
                    .err()
                    .unwrap()
            ),
            Some("command_conflict")
        );
        accepted(fixture.run(fixture.command(
            2,
            1,
            change(vec![Protocol::Http, Protocol::Socks5]),
        ))?);
        assert!(matches!(
            fixture.run(fixture.command(2, 1, change(vec![Protocol::Socks5, Protocol::Http])))?,
            CommandOutcome::Replayed(Receipt {
                policy_revision: Some(2),
                ..
            })
        ));
        assert_eq!(load_policy(&fixture.directory)?.users.len(), 1);
        Ok(())
    }
}
