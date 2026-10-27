//! Complete, versioned local proxy access policy and non-secret management views.
//!
//! Live writes belong to the managed runner's single apply coordinator. SQLite
//! commit is the durable saved revision, not proof that a runtime published it.

use std::{collections::HashSet, io, path::Path};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{Connection, Row, TransactionBehavior, params, types::ValueRef};
use zeroize::Zeroizing;

use super::{peers::open_existing, random_id, read_overview, sqlite_error, valid_id};
use crate::access::presets::{PoolPreset, PresetData, PresetEntity, UserPreset};
use crate::access::routing::{AddressFamily, ResourceState, RoutePermission, RoutingEntity};
use crate::access::{
    self, CredentialRecord, MAX_CREDENTIALS, MAX_USERS, PolicyData, Protocol, UserRecord,
};

const MAX_AUDIT_RECORDS: u32 = 16_384;
const MAX_PAGE_SIZE: u32 = 50;

mod operation_audit;
mod search;
#[cfg(test)]
pub(super) use operation_audit::{
    require_legacy_for_test as require_legacy_audit_for_test,
    restore_legacy_for_test as restore_legacy_audit_for_test,
};
pub(super) use operation_audit::{
    upgrade_schema as upgrade_operation_audit, validate_snapshot as validate_operation_audit,
};
pub(in crate::manage) use search::search_users;
pub(super) use search::search_users_in;

/// An explicit local policy mutation; no variant accepts a human-selected secret.
#[derive(Clone)]
pub(in crate::manage) enum PolicyChange {
    /// Node-wide admission only; existing authorized operations keep their lease.
    SetAdmission {
        accepting: bool,
    },
    /// Creates an active identity; empty protocols intentionally grant no access.
    CreateUser {
        name: String,
        protocols: Vec<Protocol>,
        concurrent_limit: u32,
    },
    /// Replaces mutable user fields without changing its stable ID or credentials.
    UpdateUser {
        id: String,
        name: String,
        protocols: Vec<Protocol>,
        concurrent_limit: u32,
    },
    /// Changes admission only; already admitted flows retain their existing lease.
    SetUserActive {
        id: String,
        active: bool,
    },
    /// Irreversibly retires the user and all of its credential identities.
    DeleteUser {
        id: String,
    },
    /// Generates a new random login identity and high-entropy proxy password.
    CreateCredential {
        user_id: String,
    },
    /// Changes admission without advancing the secret's verifier generation.
    SetCredentialActive {
        id: String,
        active: bool,
    },
    /// Keeps ID/login stable, replaces the secret and advances its verifier generation.
    RotateCredential {
        id: String,
    },
    /// Leaves a permanent tombstone; neither enabling nor rotation may restore it.
    RevokeCredential {
        id: String,
    },
    CreatePrefix {
        name: String,
        cidr: cidr::IpCidr,
    },
    RetirePrefix {
        id: String,
    },
    CreateAddress {
        name: String,
        ip: std::net::IpAddr,
        prefix_id: Option<String>,
    },
    SetAddressState {
        id: String,
        state: ResourceState,
    },
    CreatePool {
        name: String,
        family: AddressFamily,
    },
    SetPoolState {
        id: String,
        state: ResourceState,
    },
    AddPoolMember {
        pool_id: String,
        address_id: String,
    },
    RemovePoolMember {
        pool_id: String,
        address_id: String,
    },
    SetRoutePermission {
        permission: RoutePermission,
    },
    /// Replace one user's complete built-in preset grant and TCP default.
    SetUserPresets {
        presets: UserPreset,
    },
    /// Replace a pool's suggestion without granting it to any user.
    SetPoolPreset {
        preset: PoolPreset,
    },
}

impl PolicyChange {
    /// Select the fixed command contract from its typed action. Existing eight
    /// actions always remain version one, including after a schema upgrade.
    pub(in crate::manage) const fn control_version(&self) -> u8 {
        match self {
            Self::SetAdmission { .. } => 5,
            Self::CreateUser { .. }
            | Self::UpdateUser { .. }
            | Self::SetUserActive { .. }
            | Self::DeleteUser { .. }
            | Self::CreateCredential { .. }
            | Self::SetCredentialActive { .. }
            | Self::RotateCredential { .. }
            | Self::RevokeCredential { .. } => 1,
            Self::CreatePrefix { .. }
            | Self::RetirePrefix { .. }
            | Self::CreateAddress { .. }
            | Self::SetAddressState { .. }
            | Self::CreatePool { .. }
            | Self::SetPoolState { .. }
            | Self::AddPoolMember { .. }
            | Self::RemovePoolMember { .. }
            | Self::SetRoutePermission { .. } => 2,
            Self::SetUserPresets { .. } | Self::SetPoolPreset { .. } => 3,
        }
    }
}

/// User metadata only; this contains neither a verifier nor a machine secret.
#[derive(Clone)]
pub(in crate::manage) struct UserView {
    pub(in crate::manage) id: String,
    pub(in crate::manage) name: String,
    pub(in crate::manage) active: bool,
    pub(in crate::manage) deleted: bool,
    pub(in crate::manage) protocols: Vec<Protocol>,
    pub(in crate::manage) concurrent_limit: u32,
    /// This user's metadata generation, not the complete policy's global CAS.
    pub(in crate::manage) revision: u64,
}

/// Public connection identity/status; digest and algorithm state stay internal.
#[derive(Clone)]
pub(in crate::manage) struct CredentialView {
    pub(in crate::manage) id: String,
    pub(in crate::manage) user_id: String,
    /// Public proxy wire identity; passwords never enter metadata views.
    pub(in crate::manage) login: String,
    pub(in crate::manage) syntax_version: u8,
    pub(in crate::manage) active: bool,
    pub(in crate::manage) revoked: bool,
    /// Changes only when rotating the secret, not when toggling admission.
    pub(in crate::manage) verifier_revision: u64,
}

/// One bounded page from a consistent read snapshot; cursors are stable IDs.
pub(in crate::manage) struct Page<T> {
    pub(in crate::manage) revision: u64,
    pub(in crate::manage) items: Vec<T>,
    pub(in crate::manage) next_cursor: Option<String>,
}

/// Saved policy metadata and historical receipt, not a live runtime observation.
pub(in crate::manage) struct PolicyStatus {
    pub(in crate::manage) revision: u64,
    pub(in crate::manage) applied_revision: Option<u64>,
    /// All durable identities, including soft-deleted history counted for capacity.
    pub(in crate::manage) user_count: u32,
    /// All credentials, including permanent revocation tombstones.
    pub(in crate::manage) credential_count: u32,
}

/// A committed candidate for the coordinator to publish, not an applied receipt.
///
/// `user` identifies the affected/owning user. `secret` is returned once for
/// creation/rotation only; this intentionally has no Debug/Serialize impl.
pub(in crate::manage) struct ChangeResult {
    pub(in crate::manage) policy: PolicyData,
    pub(in crate::manage) user: Option<UserView>,
    pub(in crate::manage) credential: Option<CredentialView>,
    pub(in crate::manage) secret: Option<Zeroizing<String>>,
    pub(in crate::manage) routing: Option<RoutingEntity>,
    pub(in crate::manage) presets: Option<PresetEntity>,
}

/// Cold-path mutation metadata, never serialized or included in diagnostics.
struct Mutation {
    user_id: Option<String>,
    credential_id: Option<String>,
    action: &'static str,
    secret: Option<Zeroizing<String>>,
    routing: Option<RoutingEntity>,
    presets: Option<PresetEntity>,
}

/// Adds the v3 policy objects inside the caller's initialization/migration transaction.
pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection
        .execute_batch(
            "CREATE TABLE proxy_policy_state (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            revision INTEGER NOT NULL CHECK (revision >= 1),
            applied_revision INTEGER CHECK (applied_revision >= 1 AND applied_revision <= revision)
         ) STRICT;
         INSERT INTO proxy_policy_state VALUES (1, 1, NULL);
         CREATE TABLE proxy_users (
            id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 22),
            name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
            active INTEGER NOT NULL CHECK (active IN (0, 1)),
            deleted INTEGER NOT NULL CHECK (deleted IN (0, 1)),
            protocols INTEGER NOT NULL CHECK (protocols BETWEEN 0 AND 7),
            concurrent_limit INTEGER NOT NULL CHECK (concurrent_limit BETWEEN 1 AND 1000000),
            revision INTEGER NOT NULL CHECK (revision >= 1),
            CHECK (deleted = 0 OR active = 0)
         ) STRICT;
         CREATE TABLE proxy_credentials (
            id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 22),
            user_id TEXT NOT NULL REFERENCES proxy_users(id) ON DELETE RESTRICT,
            login TEXT NOT NULL UNIQUE CHECK (length(login) = 36 AND substr(login, 1, 4) = 'vp2_'
                AND substr(login, 5) NOT GLOB '*[^0-9a-f]*'),
            syntax_version INTEGER NOT NULL CHECK (syntax_version = 2),
            verifier_version INTEGER NOT NULL CHECK (verifier_version = 1),
            secret_digest BLOB NOT NULL CHECK (length(secret_digest) = 32),
            active INTEGER NOT NULL CHECK (active IN (0, 1)),
            revoked INTEGER NOT NULL CHECK (revoked IN (0, 1)),
            verifier_revision INTEGER NOT NULL CHECK (verifier_revision >= 1),
            CHECK (revoked = 0 OR active = 0)
         ) STRICT;
         CREATE INDEX proxy_credentials_user ON proxy_credentials(user_id, id);
         CREATE TABLE proxy_policy_audit (
            sequence INTEGER PRIMARY KEY,
            entry TEXT NOT NULL CHECK (entry = 'local_management'),
            administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
            action TEXT NOT NULL CHECK (action IN ('create_user', 'update_user', 'enable_user',
                'disable_user', 'delete_user', 'create_credential', 'enable_credential',
                'disable_credential', 'rotate_credential', 'revoke_credential')),
            user_id TEXT NOT NULL REFERENCES proxy_users(id) ON DELETE RESTRICT,
            credential_id TEXT REFERENCES proxy_credentials(id) ON DELETE RESTRICT,
            policy_revision INTEGER NOT NULL CHECK (policy_revision >= 1)
         ) STRICT;",
        )
        .map_err(|error| sqlite_error("cannot create proxy access policy schema", error))
}

/// Loads and validates one complete policy without creating or migrating storage.
///
/// Schema v1/v2, malformed fields/relationships and capacity violations return
/// InvalidData, never anonymous/empty policy. This performs bounded blocking
/// SQLite reads; async callers must use their bounded blocking executor.
pub(in crate::manage) fn load_policy(directory: &Path) -> io::Result<PolicyData> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin proxy policy inspection", error))?;
    let policy = read_policy(&transaction)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot complete proxy policy inspection", error))?;
    Ok(policy)
}

/// Commits one complete policy change using a global revision CAS.
///
/// Only the live coordinator may call this while retaining its directory Guard
/// and apply admission permit through blocking work. Commit precedes runtime
/// publish; the returned policy is validated but not claimed applied. Invalid
/// input, stale CAS, exhausted revisions/capacity and tombstone resurrection
/// fail atomically. Writes use an immediate FULL-durable transaction. Secrets
/// are OS-random 256-bit values returned in zeroizing text. Schema28 saves an
/// encrypted copy in this same transaction; plaintext is never stored in SQL.
/// `administrator_id` must come from the verified session; its durable identity
/// is rechecked in this same transaction before any policy or audit write.
pub(in crate::manage) fn apply_policy(
    directory: &Path,
    administrator_id: &str,
    expected_revision: u64,
    change: PolicyChange,
    guard: &super::UpdateGuard,
) -> io::Result<ChangeResult> {
    apply_policy_inner(
        directory,
        administrator_id,
        expected_revision,
        change,
        guard,
        None,
    )
}

/// Node-wide admission requires an explicit node/epoch assertion, validated in
/// the same transaction as administrator, local owner and policy CAS.
pub(in crate::manage) fn apply_policy_asserted(
    directory: &Path,
    administrator_id: &str,
    expected_revision: u64,
    change: PolicyChange,
    guard: &super::UpdateGuard,
    assertion: &super::admission::Assertion,
) -> io::Result<ChangeResult> {
    apply_policy_inner(
        directory,
        administrator_id,
        expected_revision,
        change,
        guard,
        Some(assertion),
    )
}

fn apply_policy_inner(
    directory: &Path,
    administrator_id: &str,
    expected_revision: u64,
    change: PolicyChange,
    guard: &super::UpdateGuard,
    assertion: Option<&super::admission::Assertion>,
) -> io::Result<ChangeResult> {
    guard.ensure(directory)?;
    sql_revision(expected_revision)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin proxy policy mutation", error))?;
    let result = apply_local_in(
        &transaction,
        administrator_id,
        expected_revision,
        change,
        assertion,
    )?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit proxy policy mutation", error))?;
    Ok(result)
}

/// Apply the original local-session checks and CAS within a caller-owned write
/// transaction. Native and witnessed writers share this exact business path;
/// this function neither commits nor publishes the returned policy/secret.
/// The caller must own directory author/update admission and only deliver the
/// result after its durable transaction and any witness confirmation succeed.
pub(in crate::manage) fn apply_local_in(
    transaction: &rusqlite::Transaction<'_>,
    administrator_id: &str,
    expected_revision: u64,
    change: PolicyChange,
    assertion: Option<&super::admission::Assertion>,
) -> io::Result<ChangeResult> {
    sql_revision(expected_revision)?;
    read_overview(transaction)?;
    let administrator_exists: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM administrators WHERE id = ?1)",
            [administrator_id],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot verify proxy policy administrator", error))?;
    if !valid_id(administrator_id) || !administrator_exists {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy policy administrator is not authorized",
        ));
    }
    super::control::require_local(transaction)?;
    if let Some(assertion) = assertion {
        super::admission::assert_local_in(transaction, assertion)?;
    } else if matches!(&change, PolicyChange::SetAdmission { .. }) {
        return Err(invalid_input(
            "proxy admission requires an explicit node and epoch assertion",
        ));
    }
    apply_in(
        transaction,
        Actor::Local(administrator_id),
        expected_revision,
        change,
    )
}

/// A verified local or TLS actor; never constructed by deserializing request JSON.
pub(super) enum Actor<'a> {
    Local(&'a str),
    Automation {
        id: &'a str,
        generation: u64,
    },
    Remote {
        node_id: &'a str,
        epoch: u64,
        command_id: u64,
        source_administrator_id: &'a str,
    },
}

/// Applies one candidate in an already-authorized immediate transaction/savepoint.
///
/// The caller owns commit/rollback and must validate the actor and owner in the
/// same transaction. This returns only a candidate, not a live applied receipt.
pub(super) fn apply_in(
    connection: &Connection,
    actor: Actor<'_>,
    expected_revision: u64,
    change: PolicyChange,
) -> io::Result<ChangeResult> {
    if matches!(&actor, Actor::Automation { .. })
        && !matches!(
            &change,
            PolicyChange::CreateUser { .. }
                | PolicyChange::UpdateUser { .. }
                | PolicyChange::SetUserActive { .. }
                | PolicyChange::DeleteUser { .. }
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "automation change is outside user scope",
        ));
    }
    if read_overview(connection)?.schema_version < 9 {
        return Err(invalid_data(
            "proxy policy writes require explicit schema migration",
        ));
    }
    let mut policy = read_policy(connection)?;
    if policy.revision != expected_revision {
        return Err(conflict("proxy policy revision changed"));
    }
    let next = increment(policy.revision)?;
    let admission = matches!(&change, PolicyChange::SetAdmission { .. });
    let mutation = mutate(connection, &mut policy, change)?;
    if let (Some(id), Some(secret)) = (&mutation.credential_id, &mutation.secret) {
        let credential = policy
            .credentials
            .iter()
            .find(|item| item.id == *id)
            .ok_or_else(|| invalid_data("generated credential is missing"))?;
        let node_id = read_overview(connection)?.node_id;
        super::secrets::save(connection, &node_id, credential, secret)?;
    }
    policy.revision = next;
    access::validate_policy(&policy)?;
    connection
        .execute(
            "UPDATE proxy_policy_state SET revision = ?1 WHERE singleton = 1",
            [sql_revision(next)?],
        )
        .map_err(|error| sqlite_error("cannot save proxy policy revision", error))?;
    if admission {
        super::admission::audit(connection, actor, policy.accepting, next)?;
    } else if let Some(entity) = &mutation.presets {
        super::presets::audit(connection, actor, entity, next)?;
    } else if let Some(entity) = &mutation.routing {
        super::routing::audit(connection, actor, mutation.action, entity, next)?;
    } else {
        audit(connection, actor, &mutation, next)?;
    }
    let user = policy
        .users
        .iter()
        .find(|user| Some(user.id.as_str()) == mutation.user_id.as_deref())
        .map(UserView::from);
    let credential = mutation
        .credential_id
        .as_ref()
        .and_then(|id| {
            policy
                .credentials
                .iter()
                .find(|credential| credential.id == *id)
        })
        .map(CredentialView::from);
    Ok(ChangeResult {
        policy,
        user,
        credential,
        secret: mutation.secret,
        routing: mutation.routing,
        presets: mutation.presets,
    })
}

/// Reads a bounded user page without fetching credential digests.
///
/// `limit` is 1..=50 and `after` is a canonical ID cursor; deleted tombstones
/// are excluded unless explicitly requested. The revision and rows share one
/// read transaction. This blocks on SQLite and never changes policy or receipts.
pub(in crate::manage) fn list_users(
    directory: &Path,
    include_deleted: bool,
    after: Option<&str>,
    limit: u32,
) -> io::Result<Page<UserView>> {
    validate_page(after, limit)?;
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin user listing", error))?;
    let page = list_users_in(&transaction, include_deleted, after, limit)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot complete user listing", error))?;
    Ok(page)
}

/// Reads only user metadata in the caller's authorization snapshot.
pub(super) fn list_users_in(
    connection: &Connection,
    include_deleted: bool,
    after: Option<&str>,
    limit: u32,
) -> io::Result<Page<UserView>> {
    validate_page(after, limit)?;
    let revision = read_state(connection)?.0;
    let mut items = {
        let mut statement = connection.prepare(
            "SELECT id, name, active, deleted, protocols, concurrent_limit, revision FROM proxy_users
             WHERE (?1 OR deleted = 0) AND id > ?2 ORDER BY id LIMIT ?3"
        ).map_err(|error| sqlite_error("cannot prepare user listing", error))?;
        let rows = statement
            .query_map(
                params![include_deleted, after.unwrap_or(""), i64::from(limit) + 1],
                read_user,
            )
            .map_err(|error| sqlite_error("cannot query user listing", error))?;
        let mut items = Vec::new();
        for row in rows {
            let user = row.map_err(|error| sqlite_error("cannot read user listing", error))?;
            validate_user(&user, revision)?;
            items.push(UserView::from(&user));
        }
        items
    };
    let more = items.len() > limit as usize;
    if more {
        items.pop();
    }
    let next_cursor = if more {
        items.last().map(|user| user.id.clone())
    } else {
        None
    };
    Ok(Page {
        revision,
        items,
        next_cursor,
    })
}

/// Reads public credential metadata, optionally limited to one stable owner ID.
///
/// Revoked tombstones remain visible. Cursor/limit have the same bounds as user
/// pages; SQL deliberately omits digest bytes. Invalid storage is an error,
/// not an empty/anonymous result. Calls perform blocking read-only SQLite work.
pub(in crate::manage) fn list_credentials(
    directory: &Path,
    user_id: Option<&str>,
    after: Option<&str>,
    limit: u32,
) -> io::Result<Page<CredentialView>> {
    validate_page(after, limit)?;
    if let Some(id) = user_id {
        validate_id(id)?;
    }
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin credential listing", error))?;
    let page = list_credentials_in(&transaction, user_id, after, limit)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot complete credential listing", error))?;
    Ok(page)
}

/// Reads non-secret credential columns in the caller's authorization snapshot.
pub(super) fn list_credentials_in(
    connection: &Connection,
    user_id: Option<&str>,
    after: Option<&str>,
    limit: u32,
) -> io::Result<Page<CredentialView>> {
    validate_page(after, limit)?;
    if let Some(id) = user_id {
        validate_id(id)?;
    }
    let revision = read_state(connection)?.0;
    let mut items = {
        let mut statement = connection.prepare(
            "SELECT id, user_id, login, syntax_version, active, revoked, verifier_revision, verifier_version
             FROM proxy_credentials WHERE (?1 IS NULL OR user_id = ?1) AND id > ?2 ORDER BY id LIMIT ?3"
        ).map_err(|error| sqlite_error("cannot prepare credential listing", error))?;
        let rows = statement
            .query_map(
                params![user_id, after.unwrap_or(""), i64::from(limit) + 1],
                |row| {
                    let verifier_version: i64 = row.get(7)?;
                    if verifier_version != 1 {
                        return Err(rusqlite::Error::IntegralValueOutOfRange(
                            7,
                            verifier_version,
                        ));
                    }
                    Ok(CredentialView {
                        id: row.get(0)?,
                        user_id: row.get(1)?,
                        login: row.get(2)?,
                        syntax_version: row.get(3)?,
                        active: read_bool(row, 4)?,
                        revoked: read_bool(row, 5)?,
                        verifier_revision: read_revision(row, 6)?,
                    })
                },
            )
            .map_err(|error| sqlite_error("cannot query credential listing", error))?;
        let mut items = Vec::new();
        for row in rows {
            let credential =
                row.map_err(|error| sqlite_error("cannot read credential listing", error))?;
            validate_credential_view(&credential, revision)?;
            items.push(credential);
        }
        items
    };
    let more = items.len() > limit as usize;
    if more {
        items.pop();
    }
    let next_cursor = if more {
        items.last().map(|credential| credential.id.clone())
    } else {
        None
    };
    Ok(Page {
        revision,
        items,
        next_cursor,
    })
}

/// Reads bounded counts/receipt in one read-only snapshot without reading digests.
///
/// Counts include tombstones. Invalid schema, overflow and over-capacity storage
/// are errors. This is blocking SQLite work for the management executor, and
/// an old receipt never proves a currently running proxy has applied policy.
pub(in crate::manage) fn policy_status(directory: &Path) -> io::Result<PolicyStatus> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin proxy policy status", error))?;
    let status = status_in(&transaction)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot complete proxy policy status", error))?;
    Ok(status)
}

/// Aggregates counts without loading verifier rows in the caller's snapshot.
pub(super) fn status_in(connection: &Connection) -> io::Result<PolicyStatus> {
    status_in_for_schema(connection, read_overview(connection)?.schema_version)
}

/// Aggregates typed policy state after full validation in this same, unchanged
/// snapshot. The version must come from read_overview, not an external caller.
pub(super) fn status_in_for_schema(
    connection: &Connection,
    schema_version: u32,
) -> io::Result<PolicyStatus> {
    let (revision, applied_revision) = read_state_for_schema(connection, schema_version)?;
    let (users, credentials): (i64, i64) = connection
        .query_row(
            "SELECT (SELECT count(*) FROM proxy_users), (SELECT count(*) FROM proxy_credentials)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| sqlite_error("cannot count proxy policy identities", error))?;
    let user_count =
        u32::try_from(users).map_err(|_| invalid_data("proxy user count is malformed"))?;
    let credential_count = u32::try_from(credentials)
        .map_err(|_| invalid_data("proxy credential count is malformed"))?;
    if user_count as usize > MAX_USERS || credential_count as usize > MAX_CREDENTIALS {
        return Err(invalid_data("proxy policy exceeds identity capacity"));
    }
    Ok(PolicyStatus {
        revision,
        applied_revision,
        user_count,
        credential_count,
    })
}

/// Records only the current saved revision after the coordinator really publishes it.
///
/// This does not advance policy revision. Stale writes conflict; repeating the
/// same receipt is idempotent. Callers retain their apply/Guard ownership until
/// this blocking FULL-durable transaction completes, including request cancellation.
pub(in crate::manage) fn record_applied(directory: &Path, revision: u64) -> io::Result<()> {
    sql_revision(revision)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin applied receipt update", error))?;
    record_applied_in(&transaction, revision)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit applied proxy policy receipt", error))
}

/// Save an actual publication receipt inside the caller's durable transaction.
/// This does not publish policy or advance its revision. Witnessed callers must
/// retain their suspended Reader and confirm this separate metadata write too.
pub(super) fn record_applied_in(connection: &Connection, revision: u64) -> io::Result<()> {
    if read_state(connection)?.0 != revision {
        return Err(conflict("cannot acknowledge a stale proxy policy"));
    }
    connection
        .execute(
            "UPDATE proxy_policy_state SET applied_revision = ?1 WHERE singleton = 1",
            [sql_revision(revision)?],
        )
        .map_err(|error| sqlite_error("cannot record applied proxy policy receipt", error))?;
    if read_overview(connection)?.schema_version >= 4 {
        // Only this exact candidate really ran; earlier saved-only versions may
        // have been superseded without ever being published to a live proxy.
        connection.execute("UPDATE control_receipts SET status='applied' WHERE status='saved' AND policy_revision=?1", [sql_revision(revision)?])
            .map_err(|error| sqlite_error("cannot recover matching node application receipt", error))?;
        let remaining: i64 = connection
            .query_row(
                "SELECT count(*) FROM control_receipts WHERE status='saved' AND policy_revision=?1",
                [sql_revision(revision)?],
                |row| row.get(0),
            )
            .map_err(|error| {
                sqlite_error("cannot verify matching node application receipts", error)
            })?;
        if remaining != 0 {
            return Err(invalid_data("applied command receipt was not stored"));
        }
    }
    if read_state(connection)? != (revision, Some(revision)) {
        return Err(invalid_data("applied policy receipt was not stored"));
    }
    Ok(())
}

/// Reads the policy in the caller's snapshot, including revoked/deleted history.
pub(super) fn read_policy(connection: &Connection) -> io::Result<PolicyData> {
    let revision = read_state(connection)?.0;
    let users = {
        let mut statement = connection.prepare("SELECT id, name, active, deleted, protocols, concurrent_limit, revision FROM proxy_users ORDER BY id LIMIT 1025")
            .map_err(|error| sqlite_error("cannot prepare complete proxy users", error))?;
        let rows = statement
            .query_map([], read_user)
            .map_err(|error| sqlite_error("cannot query complete proxy users", error))?;
        let mut users = Vec::new();
        for row in rows {
            let user =
                row.map_err(|error| sqlite_error("cannot read complete proxy users", error))?;
            validate_user(&user, revision)?;
            users.push(user);
        }
        users
    };
    let credentials = {
        let mut statement = connection.prepare("SELECT id, user_id, login, syntax_version, verifier_version, secret_digest, active, revoked, verifier_revision FROM proxy_credentials ORDER BY id LIMIT 8193")
            .map_err(|error| sqlite_error("cannot prepare complete proxy credentials", error))?;
        let rows = statement
            .query_map([], |row| {
                let value = row.get_ref(5)?;
                let secret_digest = match value {
                    ValueRef::Blob(bytes) if bytes.len() == 32 => {
                        let mut digest = [0; 32];
                        digest.copy_from_slice(bytes);
                        digest
                    }
                    _ => {
                        return Err(rusqlite::Error::InvalidColumnType(
                            5,
                            "secret_digest".into(),
                            value.data_type(),
                        ));
                    }
                };
                Ok(CredentialRecord {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    login: row.get(2)?,
                    syntax_version: row.get(3)?,
                    verifier_version: row.get(4)?,
                    secret_digest,
                    active: read_bool(row, 6)?,
                    revoked: read_bool(row, 7)?,
                    verifier_revision: read_revision(row, 8)?,
                })
            })
            .map_err(|error| sqlite_error("cannot query complete proxy credentials", error))?;
        let mut credentials = Vec::new();
        for row in rows {
            let credential =
                row.map_err(|error| sqlite_error("cannot read complete proxy credentials", error))?;
            validate_credential_view(&CredentialView::from(&credential), revision)?;
            credentials.push(credential);
        }
        credentials
    };
    let schema = read_overview(connection)?.schema_version;
    let routing = if schema >= 5 {
        super::routing::read(connection)?
    } else {
        crate::access::routing::RoutingData {
            permissions: users
                .iter()
                .map(|user| RoutePermission::legacy(user.id.clone()))
                .collect(),
            ..Default::default()
        }
    };
    let presets = if schema >= 9 {
        super::presets::read(connection)?
    } else {
        PresetData {
            users: users
                .iter()
                .map(|user| UserPreset::native(user.id.clone()))
                .collect(),
            pools: routing
                .pools
                .iter()
                .map(|pool| PoolPreset::native(pool.id.clone()))
                .collect(),
        }
    };
    let policy = PolicyData {
        accepting: super::admission::read_in(connection, schema)?,
        revision,
        routing,
        presets,
        users,
        credentials,
    };
    access::validate_policy(&policy)?;
    let deleted: HashSet<&str> = policy
        .users
        .iter()
        .filter(|user| user.deleted)
        .map(|user| user.id.as_str())
        .collect();
    if policy
        .credentials
        .iter()
        .any(|credential| !credential.revoked && deleted.contains(credential.user_id.as_str()))
    {
        return Err(invalid_data("deleted user retains an unrevoked credential"));
    }
    Ok(policy)
}

/// Requires schema3 and a single valid saved/applied state row.
pub(super) fn read_state(connection: &Connection) -> io::Result<(u64, Option<u64>)> {
    read_state_for_schema(connection, read_overview(connection)?.schema_version)
}

/// The caller has already validated the complete schema in this same snapshot.
/// Keep row count, revision and applied-state checks even when avoiding a second
/// overview; none of these values are supplied by the remote request.
fn read_state_for_schema(
    connection: &Connection,
    schema_version: u32,
) -> io::Result<(u64, Option<u64>)> {
    if schema_version < 3 {
        return Err(invalid_data(
            "proxy users require explicit management schema migration",
        ));
    }
    let count: i64 = connection
        .query_row("SELECT count(*) FROM proxy_policy_state", [], |row| {
            row.get(0)
        })
        .map_err(|error| sqlite_error("cannot inspect proxy policy state", error))?;
    if count != 1 {
        return Err(invalid_data("proxy policy must contain one state row"));
    }
    let (revision, applied): (i64, Option<i64>) = connection
        .query_row(
            "SELECT revision, applied_revision FROM proxy_policy_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| sqlite_error("cannot read proxy policy state", error))?;
    if revision < 1 || applied.is_some_and(|value| value < 1 || value > revision) {
        return Err(invalid_data("proxy policy revision is malformed"));
    }
    let revision =
        u64::try_from(revision).map_err(|_| invalid_data("proxy policy revision is malformed"))?;
    let applied = applied
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| invalid_data("applied proxy policy revision is malformed"))
        })
        .transpose()?;
    Ok((revision, applied))
}

/// Applies fixed SQL to a validated in-memory snapshot while the writer lock is held.
fn mutate(
    connection: &Connection,
    policy: &mut PolicyData,
    change: PolicyChange,
) -> io::Result<Mutation> {
    match change {
        PolicyChange::SetAdmission { accepting } => {
            super::admission::write_in(connection, accepting)?;
            policy.accepting = accepting;
            Ok(Mutation {
                user_id: None,
                credential_id: None,
                action: "set_admission",
                secret: None,
                routing: None,
                presets: None,
            })
        }
        PolicyChange::CreateUser {
            name,
            protocols,
            concurrent_limit,
        } => {
            validate_user_input(&name, &protocols, concurrent_limit)?;
            if policy.users.len() >= MAX_USERS {
                return Err(super::control::ControlError::PolicyCapacity.error());
            }
            let user = UserRecord {
                id: random_id()?,
                name,
                active: true,
                deleted: false,
                protocols,
                concurrent_limit,
                revision: 1,
            };
            connection
                .execute(
                    "INSERT INTO proxy_users VALUES (?1, ?2, 1, 0, ?3, ?4, 1)",
                    params![
                        user.id,
                        user.name,
                        protocols_mask(&user.protocols)?,
                        user.concurrent_limit
                    ],
                )
                .map_err(|error| sqlite_error("cannot create proxy user", error))?;
            let mutation = Mutation {
                user_id: Some(user.id.clone()),
                credential_id: None,
                action: "create_user",
                secret: None,
                routing: None,
                presets: None,
            };
            let permission = RoutePermission::legacy(user.id.clone());
            super::routing::write_permission(connection, &permission)?;
            policy.routing.permissions.push(permission);
            let presets = UserPreset::native(user.id.clone());
            super::presets::write_user(connection, &presets)?;
            policy.presets.users.push(presets);
            policy.users.push(user);
            Ok(mutation)
        }
        PolicyChange::UpdateUser {
            id,
            name,
            protocols,
            concurrent_limit,
        } => {
            validate_user_input(&name, &protocols, concurrent_limit)?;
            let user = editable_user(policy, &id)?;
            user.revision = increment(user.revision)?;
            user.name = name;
            user.protocols = protocols;
            user.concurrent_limit = concurrent_limit;
            connection.execute("UPDATE proxy_users SET name = ?1, protocols = ?2, concurrent_limit = ?3, revision = ?4 WHERE id = ?5",
                params![user.name, protocols_mask(&user.protocols)?, user.concurrent_limit, sql_revision(user.revision)?, id])
                .map_err(|error| sqlite_error("cannot update proxy user", error))?;
            Ok(Mutation {
                user_id: Some(id),
                credential_id: None,
                action: "update_user",
                secret: None,
                routing: None,
                presets: None,
            })
        }
        PolicyChange::SetUserActive { id, active } => {
            let user = editable_user(policy, &id)?;
            user.revision = increment(user.revision)?;
            user.active = active;
            connection
                .execute(
                    "UPDATE proxy_users SET active = ?1, revision = ?2 WHERE id = ?3",
                    params![active, sql_revision(user.revision)?, id],
                )
                .map_err(|error| sqlite_error("cannot change proxy user status", error))?;
            Ok(Mutation {
                user_id: Some(id),
                credential_id: None,
                action: if active {
                    "enable_user"
                } else {
                    "disable_user"
                },
                secret: None,
                routing: None,
                presets: None,
            })
        }
        PolicyChange::DeleteUser { id } => {
            let user = editable_user(policy, &id)?;
            user.revision = increment(user.revision)?;
            user.active = false;
            user.deleted = true;
            connection
                .execute(
                    "UPDATE proxy_users SET active = 0, deleted = 1, revision = ?1 WHERE id = ?2",
                    params![sql_revision(user.revision)?, id],
                )
                .and_then(|_| {
                    connection.execute(
                        "UPDATE proxy_credentials SET active = 0, revoked = 1 WHERE user_id = ?1",
                        [&id],
                    )
                })
                .map_err(|error| sqlite_error("cannot retire proxy user and credentials", error))?;
            for credential in &mut policy.credentials {
                if credential.user_id == id {
                    credential.active = false;
                    credential.revoked = true;
                }
            }
            Ok(Mutation {
                user_id: Some(id),
                credential_id: None,
                action: "delete_user",
                secret: None,
                routing: None,
                presets: None,
            })
        }
        PolicyChange::CreateCredential { user_id } => {
            editable_user(policy, &user_id)?;
            if policy.credentials.len() >= MAX_CREDENTIALS {
                return Err(super::control::ControlError::PolicyCapacity.error());
            }
            let id = random_id()?;
            let login = login_for_id(&id)?;
            let secret = generate_secret()?;
            let secret_digest = access::digest_secret(&id, secret.as_bytes());
            let credential = CredentialRecord {
                id,
                user_id: user_id.clone(),
                login,
                syntax_version: 2,
                verifier_version: 1,
                secret_digest,
                active: true,
                revoked: false,
                verifier_revision: 1,
            };
            connection
                .execute(
                    "INSERT INTO proxy_credentials VALUES (?1, ?2, ?3, 2, 1, ?4, 1, 0, 1)",
                    params![
                        credential.id,
                        user_id,
                        credential.login,
                        credential.secret_digest.as_slice()
                    ],
                )
                .map_err(|error| sqlite_error("cannot create proxy credential", error))?;
            let mutation = Mutation {
                user_id: Some(user_id),
                credential_id: Some(credential.id.clone()),
                action: "create_credential",
                secret: Some(secret),
                routing: None,
                presets: None,
            };
            policy.credentials.push(credential);
            Ok(mutation)
        }
        PolicyChange::SetCredentialActive { id, active } => {
            let credential = editable_credential(policy, &id)?;
            credential.active = active;
            connection
                .execute(
                    "UPDATE proxy_credentials SET active = ?1 WHERE id = ?2",
                    params![active, id],
                )
                .map_err(|error| sqlite_error("cannot change proxy credential status", error))?;
            Ok(Mutation {
                user_id: Some(credential.user_id.clone()),
                credential_id: Some(id),
                action: if active {
                    "enable_credential"
                } else {
                    "disable_credential"
                },
                secret: None,
                routing: None,
                presets: None,
            })
        }
        PolicyChange::RotateCredential { id } => {
            let credential = editable_credential(policy, &id)?;
            credential.verifier_revision = increment(credential.verifier_revision)?;
            let secret = generate_secret()?;
            credential.secret_digest = access::digest_secret(&credential.id, secret.as_bytes());
            connection.execute("UPDATE proxy_credentials SET secret_digest = ?1, verifier_revision = ?2 WHERE id = ?3",
                params![credential.secret_digest.as_slice(), sql_revision(credential.verifier_revision)?, id])
                .map_err(|error| sqlite_error("cannot rotate proxy credential", error))?;
            Ok(Mutation {
                user_id: Some(credential.user_id.clone()),
                credential_id: Some(id),
                action: "rotate_credential",
                secret: Some(secret),
                routing: None,
                presets: None,
            })
        }
        PolicyChange::RevokeCredential { id } => {
            let credential = editable_credential(policy, &id)?;
            credential.active = false;
            credential.revoked = true;
            connection
                .execute(
                    "UPDATE proxy_credentials SET active = 0, revoked = 1 WHERE id = ?1",
                    [&id],
                )
                .map_err(|error| sqlite_error("cannot revoke proxy credential", error))?;
            Ok(Mutation {
                user_id: Some(credential.user_id.clone()),
                credential_id: Some(id),
                action: "revoke_credential",
                secret: None,
                routing: None,
                presets: None,
            })
        }
        change @ (PolicyChange::CreatePrefix { .. }
        | PolicyChange::RetirePrefix { .. }
        | PolicyChange::CreateAddress { .. }
        | PolicyChange::SetAddressState { .. }
        | PolicyChange::CreatePool { .. }
        | PolicyChange::SetPoolState { .. }
        | PolicyChange::AddPoolMember { .. }
        | PolicyChange::RemovePoolMember { .. }
        | PolicyChange::SetRoutePermission { .. }) => {
            let changed = super::routing::mutate(policy, change)?;
            super::routing::write_entity(connection, &changed.0)?;
            if let RoutingEntity::Pool(pool) = &changed.0
                && !policy
                    .presets
                    .pools
                    .iter()
                    .any(|value| value.pool_id == pool.id)
            {
                let preset = PoolPreset::native(pool.id.clone());
                super::presets::write_pool(connection, &preset)?;
                policy.presets.pools.push(preset);
            }
            let user_id = if let RoutingEntity::Permission(permission) = &changed.0 {
                Some(permission.user_id.clone())
            } else {
                None
            };
            Ok(Mutation {
                user_id,
                credential_id: None,
                action: changed.1,
                secret: None,
                routing: Some(changed.0),
                presets: None,
            })
        }
        change @ (PolicyChange::SetUserPresets { .. } | PolicyChange::SetPoolPreset { .. }) => {
            let presets = super::presets::mutate(connection, policy, change)?;
            Ok(Mutation {
                user_id: None,
                credential_id: None,
                action: match &presets {
                    PresetEntity::User(_) => "set_user_presets",
                    PresetEntity::Pool(_) => "set_pool_preset",
                },
                secret: None,
                routing: None,
                presets: Some(presets),
            })
        }
    }
}

/// Finds only live users; soft-deleted IDs cannot be reused or restored.
fn editable_user<'a>(policy: &'a mut PolicyData, id: &str) -> io::Result<&'a mut UserRecord> {
    validate_id(id)?;
    let user = policy
        .users
        .iter_mut()
        .find(|user| user.id == id)
        .ok_or_else(|| missing("proxy user is not registered"))?;
    if user.deleted {
        return Err(conflict("proxy user is permanently deleted"));
    }
    Ok(user)
}

/// Rejects revoked credentials and those owned by a deleted/missing user.
fn editable_credential<'a>(
    policy: &'a mut PolicyData,
    id: &str,
) -> io::Result<&'a mut CredentialRecord> {
    validate_id(id)?;
    let index = policy
        .credentials
        .iter()
        .position(|credential| credential.id == id)
        .ok_or_else(|| missing("proxy credential is not registered"))?;
    let owner = policy.credentials[index].user_id.clone();
    editable_user(policy, &owner)?;
    let credential = &mut policy.credentials[index];
    if credential.revoked {
        return Err(conflict("proxy credential is permanently revoked"));
    }
    Ok(credential)
}

/// Converts database fields without allowing nonzero corrupt integers to become true.
fn read_user(row: &Row<'_>) -> rusqlite::Result<UserRecord> {
    let mask: u8 = row.get(4)?;
    if mask > 7 {
        return Err(rusqlite::Error::IntegralValueOutOfRange(4, i64::from(mask)));
    }
    Ok(UserRecord {
        id: row.get(0)?,
        name: row.get(1)?,
        active: read_bool(row, 2)?,
        deleted: read_bool(row, 3)?,
        protocols: [Protocol::Http, Protocol::Socks5, Protocol::Masque]
            .into_iter()
            .filter(|protocol| mask & protocol_bit(*protocol) != 0)
            .collect(),
        concurrent_limit: row.get(5)?,
        revision: read_revision(row, 6)?,
    })
}

pub(super) fn read_bool(row: &Row<'_>, column: usize) -> rusqlite::Result<bool> {
    match row.get::<_, i64>(column)? {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(rusqlite::Error::IntegralValueOutOfRange(column, value)),
    }
}

pub(super) fn read_revision(row: &Row<'_>, column: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(column)?;
    if value < 1 {
        return Err(rusqlite::Error::IntegralValueOutOfRange(column, value));
    }
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}

fn protocol_bit(protocol: Protocol) -> u8 {
    match protocol {
        Protocol::Http => 1,
        Protocol::Socks5 => 2,
        Protocol::Masque => 4,
    }
}

/// Canonical mask storage avoids JSON parsing and duplicate protocol permissions.
fn protocols_mask(protocols: &[Protocol]) -> io::Result<u8> {
    let mut mask = 0;
    for protocol in protocols {
        let bit = protocol_bit(*protocol);
        if mask & bit != 0 {
            return Err(invalid_input("proxy protocols contain duplicates"));
        }
        mask |= bit;
    }
    Ok(mask)
}

pub(super) fn validate_user_input(
    name: &str,
    protocols: &[Protocol],
    limit: u32,
) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 128
        || name.trim() != name
        || name.chars().any(char::is_control)
        || !(1..=1_000_000).contains(&limit)
    {
        return Err(invalid_input(
            "proxy user name or concurrency limit is invalid",
        ));
    }
    protocols_mask(protocols)?;
    Ok(())
}

fn validate_user(user: &UserRecord, revision: u64) -> io::Result<()> {
    if !valid_id(&user.id)
        || user.revision == 0
        || user.revision > revision
        || (user.deleted && user.active)
        || validate_user_input(&user.name, &user.protocols, user.concurrent_limit).is_err()
    {
        return Err(invalid_data("proxy user record is malformed"));
    }
    Ok(())
}

fn validate_credential_view(credential: &CredentialView, revision: u64) -> io::Result<()> {
    if !valid_id(&credential.id)
        || !valid_id(&credential.user_id)
        || credential.syntax_version != 2
        || credential.verifier_revision == 0
        || credential.verifier_revision > revision
        || (credential.revoked && credential.active)
        || login_for_id(&credential.id)? != credential.login
    {
        return Err(invalid_data("proxy credential record is malformed"));
    }
    Ok(())
}

fn validate_page(after: Option<&str>, limit: u32) -> io::Result<()> {
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(invalid_input("proxy page size must be 1 to 50"));
    }
    if let Some(id) = after {
        validate_id(id)?;
    }
    Ok(())
}

fn validate_id(id: &str) -> io::Result<()> {
    if !valid_id(id) {
        return Err(invalid_input(
            "proxy identity must use the canonical 128-bit encoding",
        ));
    }
    Ok(())
}

/// Generates the wire secret without retaining its unencoded random bytes.
fn generate_secret() -> io::Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0; 32]);
    getrandom::fill(&mut *bytes)
        .map_err(|_| io::Error::other("cannot obtain randomness for proxy credential"))?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice())))
}

/// Uses hex for the wire ID because base64url IDs may contain the '-' delimiter.
fn login_for_id(id: &str) -> io::Result<String> {
    let mut bytes = [0; 16];
    if !valid_id(id) || URL_SAFE_NO_PAD.decode_slice(id, &mut bytes).is_err() {
        return Err(invalid_data("proxy credential ID is malformed"));
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut login = String::with_capacity(36);
    login.push_str("vp2_");
    for byte in bytes {
        login.push(char::from(HEX[usize::from(byte >> 4)]));
        login.push(char::from(HEX[usize::from(byte & 15)]));
    }
    Ok(login)
}

fn increment(value: u64) -> io::Result<u64> {
    value
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| invalid_data("proxy policy revision is exhausted"))
}
pub(super) fn sql_revision(value: u64) -> io::Result<i64> {
    if value == 0 {
        return Err(invalid_input("proxy policy revision must be positive"));
    }
    i64::try_from(value)
        .map_err(|_| invalid_input("proxy policy revision exceeds SQLite integer range"))
}

/// Prunes only old non-secret audit rows, never IDs, users or credential tombstones.
fn audit(
    connection: &Connection,
    actor: Actor<'_>,
    mutation: &Mutation,
    revision: u64,
) -> io::Result<()> {
    let changed = match actor {
        Actor::Local(administrator_id) => connection.execute("INSERT INTO proxy_policy_audit (entry, administrator_id, action, user_id, credential_id, policy_revision) VALUES ('local_management', ?1, ?2, ?3, ?4, ?5)",
            params![administrator_id, mutation.action, mutation.user_id, mutation.credential_id, sql_revision(revision)?]),
        Actor::Remote { node_id, epoch, command_id, source_administrator_id } => connection.execute(
            "INSERT INTO proxy_policy_audit (entry, controller_node_id, controller_epoch, command_id, source_administrator_id, action, user_id, credential_id, policy_revision) VALUES ('node_management', ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![node_id, sql_revision(epoch)?, sql_revision(command_id)?, source_administrator_id, mutation.action, mutation.user_id, mutation.credential_id, sql_revision(revision)?]),
        Actor::Automation { id, generation } => connection.execute(
            "INSERT INTO proxy_policy_audit(entry,automation_principal_id,automation_generation,action,user_id,policy_revision) VALUES('automation_management',?1,?2,?3,?4,?5)",
            params![id,sql_revision(generation)?,mutation.action,mutation.user_id,sql_revision(revision)?]),
    }.map_err(|error| sqlite_error("cannot record proxy policy audit", error))?;
    if changed != 1 {
        return Err(super::invalid_data("proxy policy audit was not recorded"));
    }
    connection.execute("DELETE FROM proxy_policy_audit WHERE sequence IN (SELECT sequence FROM proxy_policy_audit ORDER BY sequence DESC LIMIT -1 OFFSET ?1)", [MAX_AUDIT_RECORDS])
        .map_err(|error| sqlite_error("cannot retain bounded proxy policy audit", error))?;
    Ok(())
}

impl From<&UserRecord> for UserView {
    fn from(user: &UserRecord) -> Self {
        Self {
            id: user.id.clone(),
            name: user.name.clone(),
            active: user.active,
            deleted: user.deleted,
            protocols: user.protocols.clone(),
            concurrent_limit: user.concurrent_limit,
            revision: user.revision,
        }
    }
}

impl From<&CredentialRecord> for CredentialView {
    fn from(credential: &CredentialRecord) -> Self {
        Self {
            id: credential.id.clone(),
            user_id: credential.user_id.clone(),
            login: credential.login.clone(),
            syntax_version: credential.syntax_version,
            active: credential.active,
            revoked: credential.revoked,
            verifier_revision: credential.verifier_revision,
        }
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn conflict(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, message)
}
fn missing(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, message)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;
    use crate::manage::store::{
        self, DATABASE_NAME, Guard, SCHEMA_VERSION, initialize, inspect, lock, migrate,
        register_peer, revoke_certificate,
    };

    mod search {
        use super::*;
        use crate::manage::user_search::{Error as SearchError, Mode, Query};

        fn seed(fixture: &Fixture, count: usize) -> io::Result<Vec<String>> {
            let mut ids: Vec<_> = (0..count)
                .map(|index| URL_SAFE_NO_PAD.encode((index as u128).to_be_bytes()))
                .collect();
            ids.sort();
            let mut connection = fixture.writable()?;
            let transaction = connection
                .transaction()
                .map_err(|error| sqlite_error("cannot begin search fixture", error))?;
            for id in &ids {
                transaction.execute("INSERT INTO proxy_users(id,name,active,deleted,protocols,concurrent_limit,revision) VALUES(?1,'unmatched',1,0,1,8,1)", [id])
            .map_err(|error| sqlite_error("cannot seed search fixture", error))?;
            }
            transaction
                .commit()
                .map_err(|error| sqlite_error("cannot commit search fixture", error))?;
            Ok(ids)
        }

        fn name_query(
            q: &str,
            deleted: bool,
            limit: u32,
            after: Option<String>,
        ) -> io::Result<Query> {
            Query::new(Mode::Name, q.into(), deleted, limit, after)
        }

        #[test]
        fn literal_name_search_filters_before_pages_and_includes_tombstones_only_explicitly()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let _guard = fixture.guard()?;
            let ids = seed(&fixture, 32)?;
            let connection = fixture.writable()?;
            for (id, name, deleted) in [
                (&ids[28], "Prefix AlPhA%_界", false),
                (&ids[29], "alpha%_界 second", false),
                (&ids[30], "ALPHA%_界 deleted", true),
                (&ids[31], "alphabet is not a wildcard match", false),
            ] {
                connection
                    .execute(
                        "UPDATE proxy_users SET name=?1,deleted=?2,active=?3 WHERE id=?4",
                        params![name, deleted, !deleted, id],
                    )
                    .map_err(|error| sqlite_error("cannot name search fixture", error))?;
            }
            assert!(
                list_users(&fixture.directory, false, None, 25)?
                    .items
                    .iter()
                    .all(|user| !user.name.contains('%'))
            );
            let first = search_users(
                &fixture.directory,
                &name_query("ALPHA%_界", false, 1, None)?,
            )?;
            assert_eq!(first.revision, 1);
            assert_eq!(first.items.len(), 1);
            assert_eq!(first.items[0].id, ids[28]);
            let second = search_users(
                &fixture.directory,
                &name_query("alpha%_界", false, 1, first.next_cursor)?,
            )?;
            assert_eq!(second.items.len(), 1);
            assert_eq!(second.items[0].id, ids[29]);
            assert!(second.next_cursor.is_none());
            let history = search_users(
                &fixture.directory,
                &name_query("alpha%_界", true, 50, None)?,
            )?;
            assert_eq!(history.items.len(), 3);
            assert!(history.items[2].deleted && !history.items[2].active);
            assert_eq!(policy_status(&fixture.directory)?.revision, 1);
            Ok(())
        }

        #[test]
        fn explicit_id_mode_does_not_match_an_id_shaped_name_or_resurrect_a_tombstone()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let _guard = fixture.guard()?;
            let ids = seed(&fixture, 2)?;
            fixture
                .writable()?
                .execute(
                    "UPDATE proxy_users SET name=?1 WHERE id=?2",
                    params![ids[0], ids[1]],
                )
                .map_err(|error| sqlite_error("cannot name identity fixture", error))?;
            let exact = Query::new(Mode::Id, ids[0].clone(), false, 1, None)?;
            let found = search_users(&fixture.directory, &exact)?;
            assert_eq!(found.items[0].id, ids[0]);
            assert!(found.next_cursor.is_none());
            let name = search_users(&fixture.directory, &name_query(&ids[0], false, 1, None)?)?;
            assert_eq!(name.items[0].id, ids[1]);
            fixture
                .writable()?
                .execute(
                    "UPDATE proxy_users SET active=0,deleted=1 WHERE id=?1",
                    [&ids[0]],
                )
                .map_err(|error| sqlite_error("cannot retire identity fixture", error))?;
            assert!(search_users(&fixture.directory, &exact)?.items.is_empty());
            let history = Query::new(Mode::Id, ids[0].clone(), true, 1, None)?;
            assert!(search_users(&fixture.directory, &history)?.items[0].deleted);
            Ok(())
        }

        #[test]
        fn search_cursor_rejects_another_node_and_a_new_policy_snapshot() -> io::Result<()> {
            let fixture = Fixture::new()?;
            let _guard = fixture.guard()?;
            seed(&fixture, 3)?;
            let first = search_users(
                &fixture.directory,
                &name_query("unmatched", false, 1, None)?,
            )?;
            let next = name_query("unmatched", false, 1, first.next_cursor)?;
            let other = Fixture::new()?;
            let error = search_users(&other.directory, &next).err().unwrap();
            assert!(matches!(
                error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<SearchError>()),
                Some(SearchError::InvalidCursor)
            ));
            // The fixture intentionally seeds only the searched metadata, not routing
            // or preset policy. HTTP coverage below uses a real policy mutation.
            fixture
                .writable()?
                .execute("UPDATE proxy_policy_state SET revision=2", [])
                .map_err(|error| sqlite_error("cannot advance search fixture revision", error))?;
            let error = search_users(&fixture.directory, &next).err().unwrap();
            assert!(matches!(
                error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<SearchError>()),
                Some(SearchError::Changed)
            ));
            assert_eq!(policy_status(&fixture.directory)?.revision, 2);
            Ok(())
        }

        #[test]
        fn name_scan_counts_deleted_rows_and_rejects_capacity_before_reading_the_extra_row()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let _guard = fixture.guard()?;
            let ids = seed(&fixture, MAX_USERS + 1)?;
            let connection = fixture.writable()?;
            connection
                .execute("DELETE FROM proxy_users WHERE id=?1", [&ids[MAX_USERS]])
                .map_err(|error| sqlite_error("cannot set capacity fixture", error))?;
            connection
                .execute("UPDATE proxy_users SET active=0,deleted=1", [])
                .map_err(|error| sqlite_error("cannot set deleted fixture", error))?;
            for id in &ids[..2] {
                connection
                    .execute(
                        "UPDATE proxy_users SET name='hit',active=1,deleted=0 WHERE id=?1",
                        [id],
                    )
                    .map_err(|error| sqlite_error("cannot set matching fixture", error))?;
            }
            let query = name_query("hit", false, 1, None)?;
            let full = search_users(&fixture.directory, &query)?;
            assert_eq!(full.items.len(), 1);
            assert!(full.next_cursor.is_some());
            connection
                .pragma_update(None, "ignore_check_constraints", true)
                .map_err(|error| sqlite_error("cannot construct capacity fault", error))?;
            connection.execute("INSERT INTO proxy_users(id,name,active,deleted,protocols,concurrent_limit,revision) VALUES(?1,?2,0,1,1,8,1)", params![ids[MAX_USERS], "x".repeat(1_048_576)])
        .map_err(|error| sqlite_error("cannot insert over-capacity fixture", error))?;
            let error = search_users(&fixture.directory, &query).err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "user search exceeds policy capacity");
            Ok(())
        }

        #[test]
        fn bounded_metadata_validation_continues_after_the_retained_page_and_covers_id_lookup()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let _guard = fixture.guard()?;
            let ids = seed(&fixture, 3)?;
            let connection = fixture.writable()?;
            connection
                .pragma_update(None, "ignore_check_constraints", true)
                .map_err(|error| sqlite_error("cannot construct metadata fault", error))?;
            let query = name_query("unmatched", false, 1, None)?;
            connection
                .execute(
                    "UPDATE proxy_users SET name=?1 WHERE id=?2",
                    params!["x".repeat(1_048_576), ids[2]],
                )
                .map_err(|error| sqlite_error("cannot set oversized metadata", error))?;
            assert_eq!(
                search_users(&fixture.directory, &query)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            let exact = Query::new(Mode::Id, ids[2].clone(), false, 1, None)?;
            assert_eq!(
                search_users(&fixture.directory, &exact)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            connection
                .execute(
                    "UPDATE proxy_users SET name=CAST(x'ff' AS TEXT) WHERE id=?1",
                    [&ids[2]],
                )
                .map_err(|error| sqlite_error("cannot set malformed UTF-8 metadata", error))?;
            assert_eq!(
                search_users(&fixture.directory, &query)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            connection
                .execute(
                    "UPDATE proxy_users SET name='unmatched',active=7 WHERE id=?1",
                    [&ids[2]],
                )
                .map_err(|error| sqlite_error("cannot set malformed numeric metadata", error))?;
            assert_eq!(
                search_users(&fixture.directory, &query)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            Ok(())
        }
    }

    const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$Zml4dHVyZQ";

    /// Owns a fresh private directory; admin IDs come from its initialized database.
    struct Fixture {
        directory: std::path::PathBuf,
        administrator: String,
    }

    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory =
                std::env::temp_dir().join(format!("vproxy-user-store-{}", random_id()?));
            initialize(&directory, "local node", "admin", PHC)?;
            let connection = open_existing(&directory, false)?;
            let administrator = connection
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(|error| sqlite_error("cannot read fixture administrator", error))?;
            Ok(Self {
                directory,
                administrator,
            })
        }

        fn guard(&self) -> io::Result<Guard> {
            lock(&self.directory)
        }

        fn apply(&self, revision: u64, change: PolicyChange) -> io::Result<ChangeResult> {
            apply_policy(
                &self.directory,
                &self.administrator,
                revision,
                change,
                &store::update_lock(&self.directory)?,
            )
        }

        fn create_user(&self, revision: u64, name: &str) -> io::Result<ChangeResult> {
            self.apply(
                revision,
                PolicyChange::CreateUser {
                    name: name.into(),
                    protocols: vec![Protocol::Http, Protocol::Socks5, Protocol::Masque],
                    concurrent_limit: 8,
                },
            )
        }

        fn writable(&self) -> io::Result<Connection> {
            open_existing(&self.directory, true)
        }

        fn make_v2(&self) -> io::Result<()> {
            store::traffic::remove_schema_for_test(&self.writable()?)?;
            self.writable()?.execute_batch(
            "DROP TABLE routing_audit; DROP TABLE routing_exit_grants; DROP TABLE routing_pool_grants; DROP TABLE routing_permissions; DROP TABLE routing_pool_members; DROP TABLE routing_pools; DROP TABLE routing_addresses; DROP TABLE routing_prefixes; DROP TABLE controller_audit; DROP TABLE control_outbox; DROP TABLE managed_targets; DROP TABLE control_audit; DROP TABLE control_receipts; DROP TABLE control_ownership; DROP TABLE proxy_policy_audit; DROP TABLE proxy_credentials; DROP TABLE proxy_users; DROP TABLE proxy_policy_state; PRAGMA user_version = 2;"
        ).map_err(|error| sqlite_error("cannot construct v2 fixture", error))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn generated_credentials_rotate_and_retire_without_reusing_history() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let _guard = fixture.guard()?;
        let initial = load_policy(&fixture.directory)?;
        assert_eq!(initial.revision, 1);
        assert!(initial.users.is_empty() && initial.credentials.is_empty());
        let created = fixture.create_user(1, "First user")?;
        let user = created.user.unwrap();
        assert!(user.active && !user.deleted);
        assert_eq!(user.revision, 1);
        assert!(created.secret.is_none());
        let created = fixture.apply(
            2,
            PolicyChange::CreateCredential {
                user_id: user.id.clone(),
            },
        )?;
        let credential = created.credential.unwrap();
        let old_secret = created.secret.unwrap();
        assert_eq!(old_secret.len(), 43);
        assert_eq!(credential.login.len(), 36);
        assert!(!credential.login.contains('-'));
        assert_eq!(credential.verifier_revision, 1);
        assert!(
            access::Reader::new(created.policy)?
                .authenticate(&credential.login, old_secret.as_bytes(), Protocol::Http)
                .is_ok()
        );
        let stored = load_policy(&fixture.directory)?;
        assert_eq!(
            stored.credentials[0].secret_digest,
            access::digest_secret(&credential.id, old_secret.as_bytes())
        );

        let rotated = fixture.apply(
            3,
            PolicyChange::RotateCredential {
                id: credential.id.clone(),
            },
        )?;
        let new_secret = rotated.secret.unwrap();
        assert_ne!(old_secret.as_str(), new_secret.as_str());
        assert_eq!(rotated.credential.as_ref().unwrap().id, credential.id);
        assert_eq!(rotated.credential.as_ref().unwrap().login, credential.login);
        assert_eq!(rotated.credential.as_ref().unwrap().verifier_revision, 2);
        let reader = access::Reader::new(rotated.policy)?;
        assert!(
            reader
                .authenticate(&credential.login, old_secret.as_bytes(), Protocol::Http)
                .is_err()
        );
        assert!(
            reader
                .authenticate(&credential.login, new_secret.as_bytes(), Protocol::Http)
                .is_ok()
        );
        let disabled = fixture.apply(
            4,
            PolicyChange::SetCredentialActive {
                id: credential.id.clone(),
                active: false,
            },
        )?;
        assert_eq!(disabled.credential.unwrap().verifier_revision, 2);
        reader.publish(disabled.policy)?;
        assert!(
            reader
                .authenticate(&credential.login, new_secret.as_bytes(), Protocol::Http)
                .is_err()
        );
        let enabled = fixture.apply(
            5,
            PolicyChange::SetCredentialActive {
                id: credential.id.clone(),
                active: true,
            },
        )?;
        assert_eq!(enabled.credential.unwrap().verifier_revision, 2);
        reader.publish(enabled.policy)?;
        assert!(
            reader
                .authenticate(&credential.login, new_secret.as_bytes(), Protocol::Http)
                .is_ok()
        );
        let deleted = fixture.apply(
            6,
            PolicyChange::DeleteUser {
                id: user.id.clone(),
            },
        )?;
        assert!(deleted.user.as_ref().unwrap().deleted);
        assert_eq!(deleted.user.as_ref().unwrap().revision, 2);
        assert!(deleted.policy.credentials[0].revoked);
        assert_eq!(deleted.policy.credentials[0].verifier_revision, 2);
        reader.publish(deleted.policy)?;
        assert!(
            reader
                .authenticate(&credential.login, new_secret.as_bytes(), Protocol::Http)
                .is_err()
        );
        for change in [
            PolicyChange::SetUserActive {
                id: user.id.clone(),
                active: true,
            },
            PolicyChange::CreateCredential {
                user_id: user.id.clone(),
            },
            PolicyChange::RotateCredential {
                id: credential.id.clone(),
            },
            PolicyChange::SetCredentialActive {
                id: credential.id.clone(),
                active: true,
            },
        ] {
            assert!(
                matches!(fixture.apply(7, change), Err(error) if error.kind() == io::ErrorKind::AlreadyExists)
            );
        }
        assert_eq!(policy_status(&fixture.directory)?.revision, 7);
        assert!(
            list_users(&fixture.directory, false, None, 50)?
                .items
                .is_empty()
        );
        assert_eq!(
            list_users(&fixture.directory, true, None, 50)?.items.len(),
            1
        );
        assert!(list_credentials(&fixture.directory, Some(&user.id), None, 50)?.items[0].revoked);
        let connection = fixture.writable()?;
        let (actor, action): (String, String) = connection.query_row("SELECT administrator_id, action FROM proxy_policy_audit ORDER BY sequence DESC LIMIT 1", [], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|error| sqlite_error("cannot inspect fixture audit", error))?;
        assert_eq!(actor, fixture.administrator);
        assert_eq!(action, "delete_user");
        Ok(())
    }

    #[test]
    fn unknown_actor_bad_input_and_cas_failure_do_not_consume_revision() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let _guard = fixture.guard()?;
        let change = || PolicyChange::CreateUser {
            name: "user".into(),
            protocols: vec![Protocol::Http],
            concurrent_limit: 1,
        };
        for id in ["invalid".to_owned(), random_id()?] {
            assert!(
                matches!(apply_policy(&fixture.directory, &id, 1, change(), &store::update_lock(&fixture.directory)?), Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
            );
        }
        assert!(
            matches!(fixture.apply(2, change()), Err(error) if error.kind() == io::ErrorKind::AlreadyExists)
        );
        assert!(
            matches!(fixture.apply(1, PolicyChange::CreateUser { name: "bad\nname".into(), protocols: vec![], concurrent_limit: 1 }), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
        );
        assert!(
            matches!(fixture.apply(1, PolicyChange::CreateUser { name: "user".into(), protocols: vec![Protocol::Http, Protocol::Http], concurrent_limit: 1 }), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
        );
        assert!(
            matches!(fixture.apply(1, PolicyChange::CreateUser { name: "user".into(), protocols: vec![], concurrent_limit: 0 }), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
        );
        assert_eq!(policy_status(&fixture.directory)?.revision, 1);
        assert_eq!(policy_status(&fixture.directory)?.user_count, 0);
        let user = fixture.create_user(1, "initial")?.user.unwrap();
        let updated = fixture.apply(
            2,
            PolicyChange::UpdateUser {
                id: user.id.clone(),
                name: "renamed".into(),
                protocols: vec![Protocol::Socks5],
                concurrent_limit: 2,
            },
        )?;
        assert_eq!(updated.user.unwrap().revision, 2);
        let disabled = fixture.apply(
            3,
            PolicyChange::SetUserActive {
                id: user.id,
                active: false,
            },
        )?;
        assert_eq!(disabled.user.unwrap().revision, 3);
        Ok(())
    }

    #[test]
    fn global_cas_serializes_writers_and_receipts_never_claim_new_policy() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let guard = Arc::new(fixture.guard()?);
        assert_eq!(policy_status(&fixture.directory)?.applied_revision, None);
        record_applied(&fixture.directory, 1)?;
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for name in ["first", "second"] {
            let directory = fixture.directory.clone();
            let administrator = fixture.administrator.clone();
            let barrier = Arc::clone(&barrier);
            let owner = Arc::clone(&guard);
            handles.push(std::thread::spawn(move || {
                let _owner = owner;
                barrier.wait();
                let update = store::update_lock(&directory)?;
                apply_policy(
                    &directory,
                    &administrator,
                    1,
                    PolicyChange::CreateUser {
                        name: name.into(),
                        protocols: vec![Protocol::Http],
                        concurrent_limit: 1,
                    },
                    &update,
                )
            }));
        }
        barrier.wait();
        let mut successes = 0;
        let mut conflicts = 0;
        for handle in handles {
            match handle
                .join()
                .map_err(|_| io::Error::other("policy writer fixture panicked"))?
            {
                Ok(result) => {
                    assert_eq!(result.policy.revision, 2);
                    successes += 1;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::AlreadyExists | io::ErrorKind::WouldBlock
                    ) =>
                {
                    conflicts += 1
                }
                Err(error) => return Err(error),
            }
        }
        assert_eq!((successes, conflicts), (1, 1));
        let status = policy_status(&fixture.directory)?;
        assert_eq!(
            (status.revision, status.applied_revision, status.user_count),
            (2, Some(1), 1)
        );
        assert!(
            matches!(record_applied(&fixture.directory, 1), Err(error) if error.kind() == io::ErrorKind::AlreadyExists)
        );
        record_applied(&fixture.directory, 2)?;
        record_applied(&fixture.directory, 2)?;
        assert_eq!(policy_status(&fixture.directory)?.applied_revision, Some(2));
        Ok(())
    }

    #[test]
    fn pages_are_stable_bounded_and_omit_secret_material() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let _guard = fixture.guard()?;
        for index in 0..5 {
            fixture.create_user(index + 1, "user")?;
        }
        assert!(list_users(&fixture.directory, false, None, 0).is_err());
        assert!(list_users(&fixture.directory, false, None, 51).is_err());
        assert!(list_users(&fixture.directory, false, Some("bad cursor"), 2).is_err());
        let first = list_users(&fixture.directory, false, None, 2)?;
        let second = list_users(&fixture.directory, false, first.next_cursor.as_deref(), 2)?;
        let third = list_users(&fixture.directory, false, second.next_cursor.as_deref(), 2)?;
        assert_eq!(
            (first.items.len(), second.items.len(), third.items.len()),
            (2, 2, 1)
        );
        assert!(third.next_cursor.is_none());
        let ids: std::collections::HashSet<_> = first
            .items
            .iter()
            .chain(&second.items)
            .chain(&third.items)
            .map(|user| &user.id)
            .collect();
        assert_eq!(ids.len(), 5);
        let user_id = first.items[0].id.clone();
        let credential = fixture
            .apply(
                6,
                PolicyChange::CreateCredential {
                    user_id: user_id.clone(),
                },
            )?
            .credential
            .unwrap();
        let page = list_credentials(&fixture.directory, Some(&user_id), None, 50)?;
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].id, credential.id);
        let revoked = fixture.apply(
            7,
            PolicyChange::RevokeCredential {
                id: credential.id.clone(),
            },
        )?;
        assert_eq!(revoked.credential.unwrap().verifier_revision, 1);
        assert!(
            matches!(fixture.apply(8, PolicyChange::RotateCredential { id: credential.id }), Err(error) if error.kind() == io::ErrorKind::AlreadyExists)
        );
        assert_eq!(policy_status(&fixture.directory)?.credential_count, 1);
        Ok(())
    }

    #[test]
    fn malformed_storage_and_revision_exhaustion_fail_closed() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let _guard = fixture.guard()?;
        let id = fixture.create_user(1, "user")?.user.unwrap().id;
        let connection = fixture.writable()?;
        connection.execute_batch("PRAGMA ignore_check_constraints = ON; UPDATE proxy_users SET active = 2; PRAGMA ignore_check_constraints = OFF;")
        .map_err(|error| sqlite_error("cannot corrupt fixture user flag", error))?;
        assert!(
            matches!(load_policy(&fixture.directory), Err(error) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert!(
            matches!(list_users(&fixture.directory, true, None, 50), Err(error) if error.kind() == io::ErrorKind::InvalidData)
        );
        connection
            .execute("UPDATE proxy_users SET active = 1", [])
            .map_err(|error| sqlite_error("cannot restore fixture user flag", error))?;
        fixture.apply(
            2,
            PolicyChange::CreateCredential {
                user_id: id.clone(),
            },
        )?;
        connection.execute_batch("PRAGMA ignore_check_constraints = ON; UPDATE proxy_credentials SET verifier_version = 2; PRAGMA ignore_check_constraints = OFF;")
        .map_err(|error| sqlite_error("cannot corrupt fixture verifier version", error))?;
        assert!(
            matches!(list_credentials(&fixture.directory, None, None, 50), Err(error) if error.kind() == io::ErrorKind::InvalidData)
        );
        connection
            .execute("UPDATE proxy_credentials SET verifier_version = 1", [])
            .and_then(|_| {
                connection.execute("UPDATE proxy_policy_state SET revision = ?1", [i64::MAX])
            })
            .map_err(|error| sqlite_error("cannot exhaust fixture policy revision", error))?;
        assert!(
            matches!(fixture.apply(i64::MAX as u64, PolicyChange::DeleteUser { id }), Err(error) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert_eq!(policy_status(&fixture.directory)?.revision, i64::MAX as u64);
        Ok(())
    }

    #[test]
    fn migration_from_v2_preserves_peer_tombstones_revisions_and_administrator() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.make_v2()?;
        let node = inspect(&fixture.directory)?.node_id;
        let peer_id = random_id()?;
        register_peer(
            &fixture.directory,
            &peer_id,
            "peer",
            b"old certificate",
            "peer.example",
            None,
        )?;
        revoke_certificate(&fixture.directory, b"old certificate", 1)?;
        let connection = fixture.writable()?;
        let before: (String, String) = connection
            .query_row("SELECT id, password_hash FROM administrators", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(|error| sqlite_error("cannot inspect v2 fixture administrator", error))?;
        assert!(load_policy(&fixture.directory).is_err());
        let active = fixture.guard()?;
        let backup = fixture.directory.join("before-v3.sqlite3");
        assert!(
            matches!(migrate(&fixture.directory, &backup), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert!(!backup.exists());
        drop(active);
        let overview = migrate(&fixture.directory, &backup)?;
        assert_eq!(overview.schema_version, SCHEMA_VERSION);
        assert_eq!(overview.node_id, node);
        assert_eq!(load_policy(&fixture.directory)?.revision, 1);
        assert_eq!(
            store::list_peers(&fixture.directory)?[0].authorization_revision,
            2
        );
        assert!(store::authorize_peer(&fixture.directory, b"old certificate")?.is_none());
        let after: (String, String) = connection
            .query_row("SELECT id, password_hash FROM administrators", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(|error| {
                sqlite_error("cannot inspect migrated fixture administrator", error)
            })?;
        assert_eq!(before, after);
        let copied = store::open(&backup, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        assert_eq!(store::read_overview(&copied)?.schema_version, 2);
        let revoked: i64 = copied
            .query_row("SELECT revoked FROM peer_certificates", [], |row| {
                row.get(0)
            })
            .map_err(|error| sqlite_error("cannot inspect copied certificate tombstone", error))?;
        assert_eq!(revoked, 1);
        assert!(fixture.directory.join(DATABASE_NAME).is_file());
        Ok(())
    }

    #[test]
    fn tombstones_keep_capacity_and_audit_retention_is_bounded() -> io::Result<()> {
        let users = Fixture::new()?;
        let _users_guard = users.guard()?;
        let mut connection = users.writable()?;
        {
            let transaction = connection
                .transaction()
                .map_err(|error| sqlite_error("cannot begin capacity fixture", error))?;
            for _ in 0..MAX_USERS {
                transaction
                    .execute(
                        "INSERT INTO proxy_users VALUES (?1, 'retired', 0, 1, 0, 1, 1)",
                        [random_id()?],
                    )
                    .map_err(|error| sqlite_error("cannot seed retired user capacity", error))?;
            }
            transaction
                .execute(
                    "INSERT INTO routing_permissions SELECT id,1 FROM proxy_users",
                    [],
                )
                .map_err(|error| sqlite_error("cannot seed explicit retired user routes", error))?;
            transaction
                .commit()
                .map_err(|error| sqlite_error("cannot commit capacity fixture", error))?;
        }
        assert!(users.create_user(1, "new").is_err());
        let status = policy_status(&users.directory)?;
        assert_eq!((status.revision, status.user_count), (1, MAX_USERS as u32));

        let credentials = Fixture::new()?;
        let _credential_guard = credentials.guard()?;
        let user = credentials.create_user(1, "owner")?.user.unwrap();
        let mut connection = credentials.writable()?;
        {
            let transaction = connection
                .transaction()
                .map_err(|error| sqlite_error("cannot begin credential capacity fixture", error))?;
            for _ in 0..MAX_CREDENTIALS {
                let id = random_id()?;
                transaction
                    .execute(
                        "INSERT INTO proxy_credentials VALUES (?1, ?2, ?3, 2, 1, ?4, 0, 1, 1)",
                        params![id, user.id, login_for_id(&id)?, [0u8; 32].as_slice()],
                    )
                    .map_err(|error| {
                        sqlite_error("cannot seed credential tombstone capacity", error)
                    })?;
            }
            transaction.execute("DELETE FROM proxy_policy_audit", [])
            .and_then(|_| transaction.execute(
                "WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM numbers WHERE n < ?1)
                 INSERT INTO proxy_policy_audit (sequence, entry, administrator_id, action, user_id, policy_revision)
                 SELECT n, 'local_management', ?2, 'create_user', ?3, 2 FROM numbers",
                params![MAX_AUDIT_RECORDS, credentials.administrator, user.id]))
            .map_err(|error| sqlite_error("cannot seed audit retention fixture", error))?;
            transaction.commit().map_err(|error| {
                sqlite_error("cannot commit credential capacity fixture", error)
            })?;
        }
        assert!(
            credentials
                .apply(
                    2,
                    PolicyChange::CreateCredential {
                        user_id: user.id.clone()
                    }
                )
                .is_err()
        );
        assert_eq!(
            policy_status(&credentials.directory)?.credential_count,
            MAX_CREDENTIALS as u32
        );
        credentials.apply(
            2,
            PolicyChange::SetUserActive {
                id: user.id,
                active: false,
            },
        )?;
        let (count, first, last): (i64, i64, i64) = connection
            .query_row(
                "SELECT count(*), min(sequence), max(sequence) FROM proxy_policy_audit",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| sqlite_error("cannot inspect bounded audit fixture", error))?;
        assert_eq!(
            (count, first, last),
            (
                i64::from(MAX_AUDIT_RECORDS),
                2,
                i64::from(MAX_AUDIT_RECORDS) + 1
            )
        );
        Ok(())
    }

    #[test]
    fn failed_v2_migration_keeps_source_identity_and_consistent_backup() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.make_v2()?;
        let before = inspect(&fixture.directory)?;
        let connection = fixture.writable()?;
        connection
            .execute("CREATE TABLE proxy_users (conflicting_object TEXT)", [])
            .map_err(|error| sqlite_error("cannot create migration collision fixture", error))?;
        let backup = fixture.directory.join("failed-v3.sqlite3");
        assert!(migrate(&fixture.directory, &backup).is_err());
        let after = inspect(&fixture.directory)?;
        assert_eq!(after.schema_version, 2);
        assert_eq!(after.node_id, before.node_id);
        assert_eq!(after.administrator_count, before.administrator_count);
        let new_tables: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name IN ('proxy_policy_state', 'proxy_credentials', 'proxy_policy_audit')", [], |row| row.get(0)
    ).map_err(|error| sqlite_error("cannot inspect migration rollback fixture", error))?;
        assert_eq!(new_tables, 0);
        let copied = store::open(&backup, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        assert_eq!(store::read_overview(&copied)?.schema_version, 2);
        assert_eq!(store::read_overview(&copied)?.node_id, before.node_id);
        Ok(())
    }
}
