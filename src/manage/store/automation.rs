//! Local-file-managed, node-bound automation identities for user management.
//!
//! Secrets are delivered once. Read identities inspect metadata; explicitly
//! issued write identities may use their own local user operations. Neither is
//! an administrator or remote peer.
//! Key rotation preserves scope and permanent revocation serializes through the
//! existing update gate, without taking the serve author or publishing policy.

use std::{io, path::Path, time::SystemTime};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{Connection, TransactionBehavior, params, types::ValueRef};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{invalid_data, peers::open_existing, read_overview, sqlite_error, valid_id};
use crate::manage::user_search::Query;

const MAX_PRINCIPALS: i64 = 64;
const MAX_AUDIT: i64 = 16_384;
const MAX_VALID_SECONDS: u64 = 90 * 24 * 60 * 60;
const COLUMNS: &str =
    "id,name,generation,created_at,issued_at,expires_at,revoked,secret_digest,scope";

/// Business capability fixed at creation; write includes user metadata reads.
/// Rotation cannot broaden it, and the verifier's distinct digest domain binds
/// the key to this stored capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::manage) enum Scope {
    UsersRead,
    UsersWrite,
}

impl Scope {
    pub(in crate::manage) const fn as_str(self) -> &'static str {
        match self {
            Self::UsersRead => "users:read",
            Self::UsersWrite => "users:write",
        }
    }

    const fn permits(self, permission: Permission) -> bool {
        matches!(permission, Permission::ReadUsers) || matches!(self, Self::UsersWrite)
    }

    const fn digest_domain(self) -> &'static [u8] {
        match self {
            // This historical domain must stay byte-for-byte compatible with
            // schema17 keys, including its final NUL separator.
            Self::UsersRead => b"vproxy:automation:users-read:v1\0",
            Self::UsersWrite => b"vproxy:automation:users-write:v1\0",
        }
    }
}

/// The action checked inside the consuming transaction, not at HTTP arrival.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::manage) enum Permission {
    ReadUsers,
    WriteUsers,
}

/// Non-secret identity of the key verified in the current transaction. This is
/// audit attribution, not a reusable authorization for a later transaction.
pub(in crate::manage) struct Authorized {
    pub(in crate::manage) id: String,
    pub(in crate::manage) generation: u64,
}

/// Fixed failures distinguish rejected credentials from unavailable/corrupt
/// storage. The latter retain their I/O error and must not become HTTP 401.
#[derive(Debug, thiserror::Error)]
pub(in crate::manage) enum Error {
    #[error("automation identity requires explicit schema migration")]
    UpgradeRequired,
    #[error("automation credential is not authorized")]
    Unauthorized,
    #[error("automation credential lacks the required scope")]
    InsufficientScope,
    #[error("invalid automation identity input")]
    InvalidInput,
    #[error("automation identity generation or state changed")]
    Conflict,
    #[error("automation identity capacity is exhausted")]
    Capacity,
}

impl Error {
    pub(in crate::manage) const fn code(&self) -> &'static str {
        match self {
            Self::UpgradeRequired => "management_upgrade_required",
            Self::Unauthorized => "automation_unauthorized",
            Self::InsufficientScope => "automation_insufficient_scope",
            Self::InvalidInput => "invalid_automation_identity",
            Self::Conflict => "automation_conflict",
            Self::Capacity => "automation_capacity",
        }
    }

    fn error(self) -> io::Error {
        let kind = match self {
            Self::Unauthorized | Self::InsufficientScope => io::ErrorKind::PermissionDenied,
            Self::InvalidInput => io::ErrorKind::InvalidInput,
            Self::Conflict => io::ErrorKind::AlreadyExists,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }
}

/// Parsed secret material has no Debug/Serialize/Clone implementation. A request
/// may share one `Arc<Credential>` with its owned blocking read, not log it.
pub(in crate::manage) struct Credential {
    id: String,
    generation: u64,
    secret: Zeroizing<[u8; 32]>,
}

impl Credential {
    /// Accept only the canonical vpa1.ID.GENERATION.SECRET representation (73 to
    /// 91 ASCII bytes). A malformed token has the same fixed unauthorized error
    /// as a wrong, expired, revoked or previous-generation credential.
    pub(in crate::manage) fn parse(value: &str) -> io::Result<Self> {
        let invalid = || {
            // Tests need a stage marker because all credential rejections share
            // one public error. Never print the input or add production logs.
            #[cfg(test)]
            eprintln!("automation_test_rejection stage=parse");
            Error::Unauthorized.error()
        };
        if !(73..=91).contains(&value.len()) {
            return Err(invalid());
        }
        let mut fields = value.split('.');
        let (Some("vpa1"), Some(id), Some(generation), Some(encoded), None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(invalid());
        };
        if !valid_id(id)
            || generation.starts_with('0')
            || generation.is_empty()
            || generation.len() > 19
            || !generation.bytes().all(|byte| byte.is_ascii_digit())
            || encoded.len() != 43
        {
            return Err(invalid());
        }
        let generation = generation
            .parse::<u64>()
            .ok()
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or_else(invalid)?;
        let mut secret = Zeroizing::new([0; 32]);
        if !matches!(URL_SAFE_NO_PAD.decode_slice(encoded, &mut *secret), Ok(32)) {
            return Err(invalid());
        }
        let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret.as_slice()));
        if canonical.as_str() != encoded {
            return Err(invalid());
        }
        Ok(Self {
            id: id.to_owned(),
            generation,
            secret,
        })
    }
}

/// Public local-file metadata; names are not identities and no verifier or token
/// is reconstructed. Millisecond times describe this principal/current key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct View {
    pub(in crate::manage) id: String,
    pub(in crate::manage) name: String,
    pub(in crate::manage) generation: u64,
    pub(in crate::manage) scope: &'static str,
    pub(in crate::manage) created_at_unix_ms: u64,
    pub(in crate::manage) expires_at_unix_ms: u64,
    pub(in crate::manage) revoked: bool,
}

struct Stored {
    view: View,
    scope: Scope,
    issued_at: u64,
    digest: Option<[u8; 32]>,
}

/// Only initialization/backed-up migration may create this namespace. Principal
/// rows, including revoked tombstones, are never pruned or reused. Audit rows
/// are bounded independently and their permanent highwater cannot move back.
pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    if connection.is_autocommit() {
        return Err(invalid_data("automation schema requires a transaction"));
    }
    connection
        .execute_batch(
            "CREATE TABLE automation_state(
           singleton INTEGER PRIMARY KEY CHECK(singleton=1),
           last_sequence INTEGER NOT NULL CHECK(last_sequence>=0)
         ) STRICT;
         INSERT INTO automation_state VALUES(1,0);",
        )
        .map_err(|error| sqlite_error("cannot create automation identity state", error))?;
    create_identity_tables(connection, true)
}

fn create_identity_tables(connection: &Connection, allow_write: bool) -> io::Result<()> {
    // These are fixed SQL literals, never caller-controlled identifiers/input.
    let scopes = if allow_write {
        "'users:read','users:write'"
    } else {
        "'users:read'"
    };
    connection
        .execute_batch(&format!(
            "CREATE TABLE automation_principals(
           id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=22),
           name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
           generation INTEGER NOT NULL CHECK(generation>=1),
           scope TEXT NOT NULL CHECK(scope IN({scopes})),
           created_at INTEGER NOT NULL CHECK(created_at>=1),
           issued_at INTEGER NOT NULL CHECK(issued_at>=created_at),
           expires_at INTEGER NOT NULL CHECK(expires_at-issued_at BETWEEN 60000 AND 7776000000),
           revoked INTEGER NOT NULL CHECK(revoked IN(0,1)),
           secret_digest BLOB,
           CHECK((revoked=0 AND secret_digest IS NOT NULL AND length(secret_digest)=32)
              OR (revoked=1 AND secret_digest IS NULL))
         ) STRICT;
         CREATE TABLE automation_audit(
           sequence INTEGER PRIMARY KEY CHECK(sequence>=1),
           entry TEXT NOT NULL CHECK(entry='local_file'),
           action TEXT NOT NULL CHECK(action IN('create','rotate','revoke')),
           principal_id TEXT NOT NULL REFERENCES automation_principals(id) ON DELETE RESTRICT,
           generation INTEGER NOT NULL CHECK(generation>=1),
           observed_at INTEGER NOT NULL CHECK(observed_at>=1),
           expires_at INTEGER NOT NULL CHECK(expires_at>=1),
           CHECK(action='revoke' OR expires_at-observed_at BETWEEN 60000 AND 7776000000)
         ) STRICT;"
        ))
        .map_err(|error| sqlite_error("cannot create automation identity namespace", error))
}

/// Widen schema17's capability CHECK inside the caller's backed-up migration.
/// Its only principal child is the old automation audit: move that child with
/// its parent, copy both into the new namespace, then remove the old child
/// before its parent. The audit highwater and every original column are kept.
/// Call this before schema18 operations/audits add further principal FKs.
pub(super) fn migrate_to_18(connection: &Connection) -> io::Result<()> {
    if connection.is_autocommit() {
        return Err(invalid_data("automation migration requires a transaction"));
    }
    validate_schema(connection, 17)?;
    validate_snapshot(connection, 17)?;
    rebuild_identity_tables(connection, true)?;
    validate_schema(connection, 18)?;
    validate_snapshot(connection, 18)
}

fn rebuild_identity_tables(connection: &Connection, allow_write: bool) -> io::Result<()> {
    connection
        .execute_batch(
            "ALTER TABLE automation_audit RENAME TO automation_audit_previous;
             ALTER TABLE automation_principals RENAME TO automation_principals_previous;",
        )
        .map_err(|error| sqlite_error("cannot retain legacy automation identity tables", error))?;
    create_identity_tables(connection, allow_write)?;
    connection
        .execute_batch(
            "INSERT INTO automation_principals(id,name,generation,created_at,issued_at,expires_at,revoked,secret_digest,scope)
             SELECT id,name,generation,created_at,issued_at,expires_at,revoked,secret_digest,scope FROM automation_principals_previous;
             INSERT INTO automation_audit(sequence,entry,action,principal_id,generation,observed_at,expires_at)
             SELECT sequence,entry,action,principal_id,generation,observed_at,expires_at FROM automation_audit_previous;",
        )
        .map_err(|error| sqlite_error("cannot preserve legacy automation identities", error))?;
    let identical: bool = connection.query_row(
        "SELECT NOT EXISTS(SELECT * FROM automation_principals EXCEPT SELECT * FROM automation_principals_previous)
            AND NOT EXISTS(SELECT * FROM automation_principals_previous EXCEPT SELECT * FROM automation_principals)
            AND NOT EXISTS(SELECT * FROM automation_audit EXCEPT SELECT * FROM automation_audit_previous)
            AND NOT EXISTS(SELECT * FROM automation_audit_previous EXCEPT SELECT * FROM automation_audit)",
        [], |row| row.get(0),
    ).map_err(|error| sqlite_error("cannot verify preserved automation identities", error))?;
    if !identical {
        return Err(corrupt());
    }
    connection
        .execute_batch(
            "DROP TABLE automation_audit_previous; DROP TABLE automation_principals_previous;",
        )
        .map_err(|error| sqlite_error("cannot finish automation capability migration", error))
}

/// Bounded namespace/highwater checks for ordinary opens, not a scan of retained
/// audit rows. At most 65 principal metadata entries are counted; typed live
/// reads validate only the rows they consume.
pub(super) fn validate_schema(connection: &Connection, version: u32) -> io::Result<()> {
    let (all, tables): (i64, i64) = connection
        .query_row(
            "SELECT count(*),coalesce(sum(type='table'),0) FROM sqlite_schema
         WHERE name IN('automation_state','automation_principals','automation_audit')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| sqlite_error("cannot inspect automation namespace", error))?;
    if version < 17 {
        return if all == 0 { Ok(()) } else { Err(corrupt()) };
    }
    if all != 3 || tables != 3 {
        return Err(corrupt());
    }
    let highwater = highwater(connection)?;
    let principals: i64 = connection
        .query_row(
            "SELECT count(*) FROM(SELECT 1 FROM automation_principals LIMIT 65)",
            [],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot inspect automation principal bound", error))?;
    if principals > MAX_PRINCIPALS || (highwater == 0) != (principals == 0) {
        return Err(corrupt());
    }
    let maximum: Option<i64> = connection
        .query_row("SELECT max(sequence) FROM automation_audit", [], |row| {
            row.get(0)
        })
        .map_err(|error| sqlite_error("cannot inspect automation audit highwater", error))?;
    let expected = if highwater == 0 {
        None
    } else {
        Some(highwater as i64)
    };
    if maximum != expected {
        return Err(corrupt());
    }
    Ok(())
}

/// Explicit immutable-backup validation supplements SQLite's read-only checks;
/// it does not authenticate wall time, freshness or an old restored authority.
pub(super) fn validate_snapshot(connection: &Connection, version: u32) -> io::Result<()> {
    let principals = read_all(connection, version)?;
    let highwater = highwater(connection)?;
    // Every successful mutation consumes exactly one sequence, and retention
    // removes only an old prefix. Unlike ordinary opens, explicit snapshots
    // verify the entire retained tail rather than accepting its maximum alone.
    let expected_count = highwater.min(MAX_AUDIT as u64);
    let mut expected_sequence = highwater - expected_count;
    let mut statement = connection.prepare("SELECT sequence,entry,action,principal_id,generation,observed_at,expires_at FROM automation_audit ORDER BY sequence LIMIT 16385")
        .map_err(|error| sqlite_error("cannot prepare automation audit validation", error))?;
    let mut rows = statement
        .query([])
        .map_err(|error| sqlite_error("cannot query automation audit validation", error))?;
    let mut count = 0;
    while let Some(row) = rows
        .next()
        .map_err(|error| sqlite_error("cannot read automation audit validation", error))?
    {
        count += 1;
        if count > MAX_AUDIT {
            return Err(corrupt());
        }
        let sequence = positive(row, 0)?;
        expected_sequence = expected_sequence.checked_add(1).ok_or_else(corrupt)?;
        let entry = text(row, 1, 10)?;
        let action = text(row, 2, 6)?;
        let id = text(row, 3, 22)?;
        let generation = positive(row, 4)?;
        let observed = positive(row, 5)?;
        let expires = positive(row, 6)?;
        let principal = principals
            .iter()
            .find(|principal| principal.view.id == id)
            .ok_or_else(corrupt)?;
        if sequence != expected_sequence
            || entry != "local_file"
            || !matches!(action.as_str(), "create" | "rotate" | "revoke")
            || generation > principal.view.generation
            || (action == "create" && generation != 1)
            || (action != "revoke" && !valid_duration(observed, expires))
        {
            return Err(corrupt());
        }
    }
    if count as u64 != expected_count || expected_sequence != highwater {
        return Err(corrupt());
    }
    Ok(())
}

/// File authority may inspect bounded metadata while serve is running. This does
/// not authenticate as an administrator and never returns secret material.
pub(in crate::manage) fn list(directory: &Path) -> io::Result<Vec<View>> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin automation listing", error))?;
    let overview = require_current(&transaction)?;
    Ok(read_all(&transaction, overview.schema_version)?
        .into_iter()
        .map(|stored| stored.view)
        .collect())
}

/// Reserve no permanent effect until `deliver` succeeds inside the immediate
/// transaction. The callback receives a single 73..91 byte raw token, not a log
/// message. A later COMMIT error is uncertain: inspect metadata, never replay.
/// Read identities remain available on schema17; write identities require schema18.
pub(in crate::manage) fn create(
    directory: &Path,
    name: &str,
    scope: Scope,
    valid_for_seconds: u64,
    deliver: impl FnOnce(&str) -> io::Result<()>,
) -> io::Result<View> {
    validate_name(name)?;
    validate_seconds(valid_for_seconds)?;
    let _gate = super::update_lock(directory)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin automation creation", error))?;
    let issued = stage_create(&transaction, name, scope, valid_for_seconds)?;
    deliver(issued.token.as_str())?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit automation creation", error))?;
    Ok(issued.view)
}

/// One-time owned output, never serialized, logged, cloned or reconstructed.
/// Source retains it privately until confirmation; an unknown result drops it.
pub(in crate::manage) struct Issued {
    view: View,
    token: Zeroizing<String>,
}

/// SQL is already confirmed; a failed private output must not be mistaken for
/// pre-commit permission rejection. Display stays fixed and the I/O cause remains
/// available to a trusted local diagnostic without exposing the token.
#[cfg(feature = "witness-journal")]
#[derive(Debug, thiserror::Error)]
#[error(
    "automation identity confirmed, but private output failed; inspect metadata before issuing another key"
)]
pub(in crate::manage) struct OutputError(#[source] io::Error);

impl Issued {
    /// The Source owner's post-confirmation continuation may deliver once.
    /// Output failure cannot roll back confirmed SQL; retain the private output
    /// and inspect metadata rather than silently issuing another generation.
    #[cfg(feature = "witness-journal")]
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "Source one-time output awaits fixed file-author CLI admission"
        )
    )]
    pub(in crate::manage) fn deliver(
        self,
        output: impl FnOnce(&str) -> io::Result<()>,
    ) -> io::Result<View> {
        output(self.token.as_str()).map_err(|error| io::Error::other(OutputError(error)))?;
        Ok(self.view)
    }
}

#[cfg(feature = "witness-journal")]
pub(super) fn create_in(
    transaction: &rusqlite::Transaction<'_>,
    name: &str,
    scope: Scope,
    valid_for_seconds: u64,
) -> io::Result<Issued> {
    validate_name(name)?;
    validate_seconds(valid_for_seconds)?;
    stage_create(transaction, name, scope, valid_for_seconds)
}

fn stage_create(
    transaction: &Connection,
    name: &str,
    scope: Scope,
    valid_for_seconds: u64,
) -> io::Result<Issued> {
    require_transaction(transaction)?;
    let overview = require_current(transaction)?;
    if scope == Scope::UsersWrite && overview.schema_version < 18 {
        return Err(Error::UpgradeRequired.error());
    }
    let principals = read_all(transaction, overview.schema_version)?;
    if principals.len() >= MAX_PRINCIPALS as usize {
        return Err(Error::Capacity.error());
    }
    let now = now()?;
    let expires = expiration(now, valid_for_seconds)?;
    let id = super::random_id()?;
    let (token, digest) = new_key(&overview.node_id, &id, 1, scope)?;
    exactly_one(transaction.execute(
        "INSERT INTO automation_principals(id,name,generation,scope,created_at,issued_at,expires_at,revoked,secret_digest)
         VALUES(?1,?2,1,?6,?3,?3,?4,0,?5)", params![id,name,sql(now)?,sql(expires)?,digest.as_slice(),scope.as_str()],
    ), "cannot store automation principal")?;
    audit(transaction, "create", &id, 1, now, expires)?;
    let count: i64 = transaction
        .query_row("SELECT count(*) FROM automation_principals", [], |row| {
            row.get(0)
        })
        .map_err(|error| sqlite_error("cannot inspect automation principal capacity", error))?;
    if !(1..=MAX_PRINCIPALS).contains(&count) {
        return Err(corrupt());
    }
    let view = find(transaction, &id, overview.schema_version)?
        .ok_or_else(corrupt)?
        .view;
    Ok(Issued { view, token })
}

/// Replace only an active principal's current key. The stable identity survives
/// rotation; old generations fail on the next snapshot. Delivery precedes the
/// commit, so a private output may remain even when commit is unknown/failed.
/// The previous scope is retained and cannot be changed through this operation.
pub(in crate::manage) fn rotate(
    directory: &Path,
    id: &str,
    expected_generation: u64,
    valid_for_seconds: u64,
    deliver: impl FnOnce(&str) -> io::Result<()>,
) -> io::Result<View> {
    validate_id(id)?;
    sql(expected_generation)?;
    validate_seconds(valid_for_seconds)?;
    let _gate = super::update_lock(directory)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin automation rotation", error))?;
    let issued = stage_rotate(&transaction, id, expected_generation, valid_for_seconds)?;
    deliver(issued.token.as_str())?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit automation rotation", error))?;
    Ok(issued.view)
}

#[cfg(feature = "witness-journal")]
pub(super) fn rotate_in(
    transaction: &rusqlite::Transaction<'_>,
    id: &str,
    expected_generation: u64,
    valid_for_seconds: u64,
) -> io::Result<Issued> {
    validate_id(id)?;
    sql(expected_generation)?;
    validate_seconds(valid_for_seconds)?;
    stage_rotate(transaction, id, expected_generation, valid_for_seconds)
}

fn stage_rotate(
    transaction: &Connection,
    id: &str,
    expected_generation: u64,
    valid_for_seconds: u64,
) -> io::Result<Issued> {
    require_transaction(transaction)?;
    let overview = require_current(transaction)?;
    let previous =
        find(transaction, id, overview.schema_version)?.ok_or_else(|| Error::Conflict.error())?;
    if previous.view.generation != expected_generation || previous.view.revoked {
        return Err(Error::Conflict.error());
    }
    let generation = expected_generation
        .checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or_else(|| Error::Capacity.error())?;
    let now = now()?;
    if now < previous.issued_at {
        return Err(invalid_data("automation issue clock moved backwards"));
    }
    let expires = expiration(now, valid_for_seconds)?;
    let (token, digest) = new_key(&overview.node_id, id, generation, previous.scope)?;
    exactly_one(transaction.execute(
        "UPDATE automation_principals SET generation=?1,issued_at=?2,expires_at=?3,secret_digest=?4 WHERE id=?5 AND generation=?6 AND revoked=0",
        params![sql(generation)?,sql(now)?,sql(expires)?,digest.as_slice(),id,sql(expected_generation)?],
    ), "cannot rotate automation credential")?;
    audit(transaction, "rotate", id, generation, now, expires)?;
    let view = find(transaction, id, overview.schema_version)?
        .ok_or_else(corrupt)?
        .view;
    Ok(Issued { view, token })
}

/// Revocation is permanent. It deliberately does not increment key generation,
/// so even i64::MAX can be revoked; an exact same-generation repeat is read-only
/// and emits no duplicate audit. Authorization is linearized at transaction
/// commit; a read snapshot begun before that commit may still finish its read.
pub(in crate::manage) fn revoke(
    directory: &Path,
    id: &str,
    expected_generation: u64,
) -> io::Result<View> {
    validate_id(id)?;
    sql(expected_generation)?;
    let _gate = super::update_lock(directory)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin automation revocation", error))?;
    let (view, changed) = stage_revoke(&transaction, id, expected_generation)?;
    if changed {
        transaction
            .commit()
            .map_err(|error| sqlite_error("cannot commit automation revocation", error))?;
    }
    Ok(view)
}

#[cfg(feature = "witness-journal")]
pub(super) fn revoke_in(
    transaction: &rusqlite::Transaction<'_>,
    id: &str,
    expected_generation: u64,
) -> io::Result<View> {
    validate_id(id)?;
    sql(expected_generation)?;
    stage_revoke(transaction, id, expected_generation).map(|(value, _)| value)
}

fn stage_revoke(
    transaction: &Connection,
    id: &str,
    expected_generation: u64,
) -> io::Result<(View, bool)> {
    require_transaction(transaction)?;
    let overview = require_current(transaction)?;
    let previous =
        find(transaction, id, overview.schema_version)?.ok_or_else(|| Error::Conflict.error())?;
    if previous.view.generation != expected_generation {
        return Err(Error::Conflict.error());
    }
    if previous.view.revoked {
        return Ok((previous.view, false));
    }
    exactly_one(transaction.execute("UPDATE automation_principals SET revoked=1,secret_digest=NULL WHERE id=?1 AND generation=?2 AND revoked=0",
        params![id,sql(expected_generation)?]), "cannot revoke automation credential")?;
    audit(
        transaction,
        "revoke",
        id,
        expected_generation,
        now()?,
        previous.view.expires_at_unix_ms,
    )?;
    let view = find(transaction, id, overview.schema_version)?
        .ok_or_else(corrupt)?
        .view;
    Ok((view, true))
}

fn require_transaction(transaction: &Connection) -> io::Result<()> {
    if transaction.is_autocommit() {
        return Err(Error::InvalidInput.error());
    }
    Ok(())
}

/// Authorize and read one page in the same read-only SQLite snapshot. The clock
/// is sampled after its first database read, not at HTTP arrival or before a
/// deferred BEGIN establishes a snapshot. No secret/verifier enters the page.
pub(in crate::manage) fn list_users(
    directory: &Path,
    credential: &Credential,
    include_deleted: bool,
    after: Option<&str>,
    limit: u32,
) -> io::Result<super::Page<super::UserView>> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin automation user listing", error))?;
    authorize_in(&transaction, credential, Permission::ReadUsers)?;
    super::users::list_users_in(&transaction, include_deleted, after, limit)
}

/// Search shares the normal typed query/cursor rules but cannot escape this node
/// or authenticate as the administrator that originally provisioned the key.
pub(in crate::manage) fn search_users(
    directory: &Path,
    credential: &Credential,
    query: &Query,
) -> io::Result<super::Page<super::UserView>> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin automation user search", error))?;
    authorize_in(&transaction, credential, Permission::ReadUsers)?;
    super::users::search_users_in(&transaction, query)
}

/// Revalidate the key and then its scope in the consuming SQLite transaction.
/// The first database read establishes its snapshot before sampling wall time.
/// Invalid keys retain the same unauthorized error even when write scope is
/// required; storage failures are not converted into credential rejections.
pub(in crate::manage) fn authorize_in(
    connection: &Connection,
    credential: &Credential,
    permission: Permission,
) -> io::Result<Authorized> {
    if connection.is_autocommit() {
        return Err(invalid_data(
            "automation authorization requires a transaction",
        ));
    }
    let overview = require_current(connection)?;
    let now = now()?;
    let stored = find(connection, &credential.id, overview.schema_version)?.ok_or_else(|| {
        #[cfg(test)]
        eprintln!("automation_test_rejection stage=missing");
        Error::Unauthorized.error()
    })?;
    if stored.view.revoked
        || stored.view.generation != credential.generation
        || now < stored.issued_at
        || now >= stored.view.expires_at_unix_ms
    {
        // Diagnose only the original decision's booleans: a fresh clock read
        // here could hide the wall-clock movement that rejected this snapshot.
        #[cfg(test)]
        eprintln!(
            "automation_test_rejection stage=metadata revoked={} generation_mismatch={} before_issued={} expired={}",
            stored.view.revoked,
            stored.view.generation != credential.generation,
            now < stored.issued_at,
            now >= stored.view.expires_at_unix_ms,
        );
        return Err(Error::Unauthorized.error());
    }
    let digest = key_digest(
        &overview.node_id,
        &credential.id,
        credential.generation,
        &credential.secret,
        stored.scope,
    );
    if !stored
        .digest
        .is_some_and(|expected| bool::from(expected.ct_eq(&digest)))
    {
        #[cfg(test)]
        eprintln!("automation_test_rejection stage=digest");
        return Err(Error::Unauthorized.error());
    }
    if !stored.scope.permits(permission) {
        return Err(Error::InsufficientScope.error());
    }
    if permission == Permission::WriteUsers && overview.schema_version < 18 {
        return Err(Error::UpgradeRequired.error());
    }
    Ok(Authorized {
        id: stored.view.id,
        generation: credential.generation,
    })
}

fn require_current(connection: &Connection) -> io::Result<super::Overview> {
    let overview = read_overview(connection)?;
    if overview.schema_version < 17 {
        return Err(Error::UpgradeRequired.error());
    }
    Ok(overview)
}

fn find(connection: &Connection, id: &str, version: u32) -> io::Result<Option<Stored>> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {COLUMNS} FROM automation_principals WHERE id=?1"
        ))
        .map_err(|error| sqlite_error("cannot prepare automation identity", error))?;
    let mut rows = statement
        .query([id])
        .map_err(|error| sqlite_error("cannot query automation identity", error))?;
    rows.next()
        .map_err(|error| sqlite_error("cannot read automation identity", error))?
        .map(|row| read_stored(row, version))
        .transpose()
}

fn read_all(connection: &Connection, version: u32) -> io::Result<Vec<Stored>> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {COLUMNS} FROM automation_principals ORDER BY id LIMIT 65"
        ))
        .map_err(|error| sqlite_error("cannot prepare automation listing", error))?;
    let mut rows = statement
        .query([])
        .map_err(|error| sqlite_error("cannot query automation listing", error))?;
    let mut values = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| sqlite_error("cannot read automation listing", error))?
    {
        if values.len() == MAX_PRINCIPALS as usize {
            return Err(corrupt());
        }
        values.push(read_stored(row, version)?);
    }
    Ok(values)
}

fn read_stored(row: &rusqlite::Row<'_>, version: u32) -> io::Result<Stored> {
    let id = text(row, 0, 22)?;
    let name = text(row, 1, 128)?;
    let generation = positive(row, 2)?;
    let created_at = positive(row, 3)?;
    let issued_at = positive(row, 4)?;
    let expires_at = positive(row, 5)?;
    let revoked = match row
        .get_ref(6)
        .map_err(|error| sqlite_error("cannot decode automation revocation", error))?
    {
        ValueRef::Integer(0) => false,
        ValueRef::Integer(1) => true,
        _ => return Err(corrupt()),
    };
    let digest = match row
        .get_ref(7)
        .map_err(|error| sqlite_error("cannot decode automation verifier", error))?
    {
        ValueRef::Null if revoked => None,
        ValueRef::Blob(bytes) if !revoked && bytes.len() == 32 => {
            Some(bytes.try_into().map_err(|_| corrupt())?)
        }
        _ => return Err(corrupt()),
    };
    let scope = match text(row, 8, 11)?.as_str() {
        "users:read" => Scope::UsersRead,
        "users:write" if version >= 18 => Scope::UsersWrite,
        _ => return Err(corrupt()),
    };
    if !valid_id(&id)
        || validate_name(&name).is_err()
        || issued_at < created_at
        || !valid_duration(issued_at, expires_at)
    {
        return Err(corrupt());
    }
    Ok(Stored {
        view: View {
            id,
            name,
            generation,
            scope: scope.as_str(),
            created_at_unix_ms: created_at,
            expires_at_unix_ms: expires_at,
            revoked,
        },
        scope,
        issued_at,
        digest,
    })
}

fn new_key(
    node: &str,
    id: &str,
    generation: u64,
    scope: Scope,
) -> io::Result<(Zeroizing<String>, [u8; 32])> {
    let mut secret = Zeroizing::new([0; 32]);
    getrandom::fill(&mut *secret)
        .map_err(|_| io::Error::other("cannot obtain automation key randomness"))?;
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret.as_slice()));
    let token = Zeroizing::new(format!("vpa1.{id}.{generation}.{}", encoded.as_str()));
    Ok((token, key_digest(node, id, generation, &secret, scope)))
}

fn key_digest(node: &str, id: &str, generation: u64, secret: &[u8; 32], scope: Scope) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(scope.digest_domain());
    hash.update(node.as_bytes());
    hash.update(id.as_bytes());
    hash.update(generation.to_be_bytes());
    hash.update(secret);
    hash.finalize().into()
}

fn audit(
    connection: &Connection,
    action: &str,
    id: &str,
    generation: u64,
    observed: u64,
    expires: u64,
) -> io::Result<()> {
    let previous = highwater(connection)?;
    let next = previous
        .checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or_else(|| Error::Capacity.error())?;
    exactly_one(connection.execute("INSERT INTO automation_audit(sequence,entry,action,principal_id,generation,observed_at,expires_at) VALUES(?1,'local_file',?2,?3,?4,?5,?6)",
        params![sql(next)?,action,id,sql(generation)?,sql(observed)?,sql(expires)?]), "cannot audit automation identity")?;
    exactly_one(
        connection.execute(
            "UPDATE automation_state SET last_sequence=?1 WHERE singleton=1 AND last_sequence=?2",
            params![sql(next)?, i64::try_from(previous).map_err(|_| corrupt())?],
        ),
        "cannot advance automation audit sequence",
    )?;
    connection.execute("DELETE FROM automation_audit WHERE sequence IN(SELECT sequence FROM automation_audit ORDER BY sequence DESC LIMIT -1 OFFSET ?1)", [MAX_AUDIT])
        .map_err(|error| sqlite_error("cannot retain automation audit", error))?;
    let count: i64 = connection
        .query_row("SELECT count(*) FROM automation_audit", [], |row| {
            row.get(0)
        })
        .map_err(|error| sqlite_error("cannot inspect automation audit capacity", error))?;
    if !(1..=MAX_AUDIT).contains(&count) {
        return Err(corrupt());
    }
    Ok(())
}

fn highwater(connection: &Connection) -> io::Result<u64> {
    let (count, sequence): (i64, Option<i64>) = connection.query_row("SELECT count(*),max(CASE WHEN singleton=1 THEN last_sequence END) FROM automation_state", [], |row| Ok((row.get(0)?,row.get(1)?)))
        .map_err(|error| sqlite_error("cannot read automation audit sequence", error))?;
    if count != 1 {
        return Err(corrupt());
    }
    sequence
        .and_then(|n| u64::try_from(n).ok())
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or_else(corrupt)
}

fn text(row: &rusqlite::Row<'_>, column: usize, maximum: usize) -> io::Result<String> {
    match row
        .get_ref(column)
        .map_err(|error| sqlite_error("cannot decode automation text", error))?
    {
        ValueRef::Text(bytes) if bytes.len() <= maximum => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| corrupt()),
        _ => Err(corrupt()),
    }
}

fn positive(row: &rusqlite::Row<'_>, column: usize) -> io::Result<u64> {
    match row
        .get_ref(column)
        .map_err(|error| sqlite_error("cannot decode automation integer", error))?
    {
        ValueRef::Integer(value) if value >= 1 => Ok(value as u64),
        _ => Err(corrupt()),
    }
}

fn validate_name(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(Error::InvalidInput.error());
    }
    Ok(())
}

fn validate_id(value: &str) -> io::Result<()> {
    if !valid_id(value) {
        return Err(Error::InvalidInput.error());
    }
    Ok(())
}

fn validate_seconds(value: u64) -> io::Result<()> {
    if !(60..=MAX_VALID_SECONDS).contains(&value) {
        return Err(Error::InvalidInput.error());
    }
    Ok(())
}

fn valid_duration(issued: u64, expires: u64) -> bool {
    expires
        .checked_sub(issued)
        .is_some_and(|duration| (60_000..=MAX_VALID_SECONDS * 1000).contains(&duration))
}

fn expiration(now: u64, seconds: u64) -> io::Result<u64> {
    now.checked_add(
        seconds
            .checked_mul(1000)
            .ok_or_else(|| Error::InvalidInput.error())?,
    )
    .filter(|n| *n <= i64::MAX as u64)
    .ok_or_else(|| Error::InvalidInput.error())
}

fn sql(value: u64) -> io::Result<i64> {
    i64::try_from(value)
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| Error::InvalidInput.error())
}

fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .filter(|value| *value > 0 && *value <= i64::MAX as u64)
        .ok_or_else(|| io::Error::other("automation clock is unavailable"))
}

fn exactly_one(result: rusqlite::Result<usize>, context: &'static str) -> io::Result<()> {
    if result.map_err(|error| sqlite_error(context, error))? != 1 {
        return Err(corrupt());
    }
    Ok(())
}

fn corrupt() -> io::Error {
    invalid_data("automation identity storage is malformed")
}

/// Legacy test fixtures may remove only a genuinely unused namespace. Production
/// migration never deletes identities or resets an issued audit highwater.
#[cfg(test)]
pub(in crate::manage) fn ensure_unused_for_test(connection: &Connection) -> io::Result<()> {
    let exists: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name IN('automation_state','automation_principals','automation_audit'))", [], |row| row.get(0))
        .map_err(|error| sqlite_error("cannot inspect automation fixture namespace", error))?;
    if !exists {
        return Ok(());
    }
    validate_schema(connection, 18)?;
    if highwater(connection)? != 0 || !read_all(connection, 18)?.is_empty() {
        return Err(corrupt());
    }
    let count: i64 = connection
        .query_row("SELECT count(*) FROM automation_audit", [], |row| {
            row.get(0)
        })
        .map_err(|error| sqlite_error("cannot inspect automation fixture audit", error))?;
    if count != 0 {
        return Err(corrupt());
    }
    Ok(())
}

/// Reject write identities before any caller starts a reverse-fixture DDL.
#[cfg(test)]
pub(in crate::manage) fn require_legacy_for_test(connection: &Connection) -> io::Result<()> {
    validate_schema(connection, 18)?;
    if read_all(connection, 18)?
        .iter()
        .any(|stored| stored.scope != Scope::UsersRead)
    {
        return Err(corrupt());
    }
    validate_snapshot(connection, 18)
}

/// The caller first removes schema18's external principal FK children. Only
/// read identities can be represented as genuine17, preserving their raw rows.
#[cfg(test)]
pub(in crate::manage) fn restore_schema_seventeen_for_test(
    connection: &Connection,
) -> io::Result<()> {
    require_legacy_for_test(connection)?;
    if connection.is_autocommit() {
        let transaction = connection
            .unchecked_transaction()
            .map_err(|error| sqlite_error("cannot begin legacy automation fixture", error))?;
        rebuild_identity_tables(&transaction, false)?;
        transaction
            .commit()
            .map_err(|error| sqlite_error("cannot commit legacy automation fixture", error))?;
    } else {
        rebuild_identity_tables(connection, false)?;
    }
    validate_schema(connection, 17)?;
    validate_snapshot(connection, 17)
}

#[cfg(test)]
pub(in crate::manage) fn remove_schema_for_test(connection: &Connection) -> io::Result<()> {
    ensure_unused_for_test(connection)?;
    connection.execute_batch("DROP TABLE IF EXISTS automation_audit; DROP TABLE IF EXISTS automation_principals; DROP TABLE IF EXISTS automation_state;")
        .map_err(|error| sqlite_error("cannot reconstruct pre-automation fixture", error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::Protocol;
    use crate::manage::{store, user_search::Mode};

    const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$Zml4dHVyZQ";

    struct Fixture {
        directory: std::path::PathBuf,
    }

    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory =
                std::env::temp_dir().join(format!("vproxy-automation-{}", store::random_id()?));
            #[cfg(windows)]
            crate::manage::files::create_directory(&directory)?;
            store::initialize(&directory, "automation test", "admin", PHC)?;
            Ok(Self { directory })
        }

        fn raw(&self) -> io::Result<Connection> {
            open_existing(&self.directory, true)
        }

        fn issue(&self, name: &str) -> io::Result<(View, Zeroizing<String>)> {
            self.issue_with_scope(name, Scope::UsersRead)
        }

        fn issue_with_scope(
            &self,
            name: &str,
            scope: Scope,
        ) -> io::Result<(View, Zeroizing<String>)> {
            let mut token = Zeroizing::new(String::new());
            let view = create(&self.directory, name, scope, 3600, |value| {
                token.push_str(value);
                Ok(())
            })?;
            Ok((view, token))
        }

        fn add_user(&self) -> io::Result<String> {
            let connection = self.raw()?;
            let actor: String = connection
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)?;
            let gate = store::update_lock(&self.directory)?;
            let result = store::apply_policy(
                &self.directory,
                &actor,
                1,
                store::PolicyChange::CreateUser {
                    name: "Literal_% user".into(),
                    protocols: vec![Protocol::Http],
                    concurrent_limit: 4,
                },
                &gate,
            )?;
            Ok(result.user.ok_or_else(corrupt)?.id)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn code(error: &io::Error) -> Option<&'static str> {
        error
            .get_ref()
            .and_then(|value| value.downcast_ref::<Error>())
            .map(Error::code)
    }

    fn rejected_read(fixture: &Fixture, token: &str) {
        let credential = Credential::parse(token).unwrap();
        let error = list_users(&fixture.directory, &credential, false, None, 25)
            .err()
            .unwrap();
        assert_eq!(code(&error), Some("automation_unauthorized"));
    }

    fn metadata(connection: &Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
        [
            "automation_state",
            "automation_principals",
            "automation_audit",
            "proxy_policy_state",
            "proxy_users",
        ]
        .into_iter()
        .map(|table| {
            let mut statement = connection
                .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
                .unwrap();
            let columns = statement.column_count();
            statement
                .query_map([], |row| {
                    (0..columns).map(|column| row.get(column)).collect()
                })
                .unwrap()
                .map(Result::unwrap)
                .collect()
        })
        .collect()
    }

    #[test]
    fn issued_key_reads_literal_user_metadata_without_becoming_an_administrator() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        let user = fixture.add_user()?;
        let _serve_author = store::lock(&fixture.directory)?;
        let before = store::policy_status(&fixture.directory)?.revision;
        let (view, token) = fixture.issue("nightly inventory")?;
        assert_eq!(view.scope, "users:read");
        assert_eq!(view.generation, 1);
        assert!(!view.revoked);
        assert!((73..=91).contains(&token.len()));
        assert_eq!(view.expires_at_unix_ms - view.created_at_unix_ms, 3_600_000);
        let credential = Credential::parse(token.as_str())?;
        let page = list_users(&fixture.directory, &credential, false, None, 25)?;
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].id, user);
        let query = Query::new(Mode::Name, "_%".into(), false, 25, None)?;
        let result = search_users(&fixture.directory, &credential, &query)?;
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].id, user);
        assert_eq!(list(&fixture.directory)?, vec![view]);
        assert_eq!(store::policy_status(&fixture.directory)?.revision, before);
        let connection = fixture.raw()?;
        let (entry, action): (String, String) = connection
            .query_row("SELECT entry,action FROM automation_audit", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(io::Error::other)?;
        assert_eq!((entry.as_str(), action.as_str()), ("local_file", "create"));
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM administrators", [], |row| row
                    .get::<_, i64>(0))
                .map_err(io::Error::other)?,
            1
        );
        validate_snapshot(&connection, 18)?;
        Ok(())
    }

    #[test]
    fn rotation_is_generation_cas_and_revocation_is_permanent_even_at_max_generation()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (view, old) = fixture.issue("reader")?;
        let mut renewed = Zeroizing::new(String::new());
        let rotated = rotate(&fixture.directory, &view.id, 1, 3600, |value| {
            renewed.push_str(value);
            Ok(())
        })?;
        assert_eq!(rotated.generation, 2);
        assert_eq!(rotated.created_at_unix_ms, view.created_at_unix_ms);
        rejected_read(&fixture, &old);
        list_users(
            &fixture.directory,
            &Credential::parse(&renewed)?,
            false,
            None,
            25,
        )?;
        let error = rotate(&fixture.directory, &view.id, 1, 3600, |_| {
            panic!("stale rotation must not deliver")
        })
        .err()
        .unwrap();
        assert_eq!(code(&error), Some("automation_conflict"));
        let node = store::inspect(&fixture.directory)?.node_id;
        let (maximum_key, digest) = new_key(&node, &view.id, i64::MAX as u64, Scope::UsersRead)?;
        fixture
            .raw()?
            .execute(
                "UPDATE automation_principals SET generation=?1,secret_digest=?2 WHERE id=?3",
                params![i64::MAX, digest.as_slice(), view.id],
            )
            .map_err(io::Error::other)?;
        list_users(
            &fixture.directory,
            &Credential::parse(&maximum_key)?,
            false,
            None,
            25,
        )?;
        let revoked = revoke(&fixture.directory, &view.id, i64::MAX as u64)?;
        assert!(revoked.revoked);
        assert_eq!(revoked.generation, i64::MAX as u64);
        rejected_read(&fixture, &maximum_key);
        let before = metadata(&fixture.raw()?);
        assert_eq!(
            revoke(&fixture.directory, &view.id, i64::MAX as u64)?,
            revoked
        );
        assert!(metadata(&fixture.raw()?) == before);
        let error = rotate(&fixture.directory, &view.id, i64::MAX as u64, 3600, |_| {
            panic!("revocation cannot be reversed")
        })
        .err()
        .unwrap();
        assert_eq!(code(&error), Some("automation_conflict"));
        Ok(())
    }

    #[test]
    fn delivery_failures_roll_back_creation_and_rotation_without_policy_changes() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        let before = metadata(&fixture.raw()?);
        let error = create(
            &fixture.directory,
            "not delivered",
            Scope::UsersRead,
            60,
            |_| Err(io::Error::other("fixture output failure")),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(metadata(&fixture.raw()?) == before);
        let (view, token) = fixture.issue("existing")?;
        let before = metadata(&fixture.raw()?);
        assert!(
            rotate(&fixture.directory, &view.id, 1, 60, |_| Err(
                io::Error::other("fixture output failure")
            ))
            .is_err()
        );
        assert!(metadata(&fixture.raw()?) == before);
        list_users(
            &fixture.directory,
            &Credential::parse(&token)?,
            false,
            None,
            25,
        )?;
        Ok(())
    }

    #[test]
    fn malformed_wrong_node_expired_and_wrong_secret_keys_fail_without_exposing_storage_errors()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (view, token) = fixture.issue("reader")?;
        for invalid in [
            "",
            "vpa1",
            " vpa1.key",
            "Bearer token",
            "vpa1.AAECAwQFBgcICQoLDA0ODw.0.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert_eq!(
                code(&Credential::parse(invalid).err().unwrap()),
                Some("automation_unauthorized")
            );
        }
        let node = store::inspect(&fixture.directory)?.node_id;
        let (wrong, _) = new_key(&node, &view.id, 1, Scope::UsersRead)?;
        rejected_read(&fixture, &wrong);
        fixture
            .raw()?
            .execute(
                "UPDATE node_identity SET node_id=?1 WHERE singleton=1",
                [store::random_id()?],
            )
            .map_err(io::Error::other)?;
        rejected_read(&fixture, &token);
        fixture
            .raw()?
            .execute(
                "UPDATE node_identity SET node_id=?1 WHERE singleton=1",
                [&node],
            )
            .map_err(io::Error::other)?;
        let past = now()? - 120_000;
        fixture
        .raw()?
        .execute(
            "UPDATE automation_principals SET created_at=?1,issued_at=?1,expires_at=?2 WHERE id=?3",
            params![sql(past)?, sql(past + 60_000)?, view.id],
        )
        .map_err(io::Error::other)?;
        rejected_read(&fixture, &token);
        let connection = fixture.raw()?;
        connection.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE automation_principals SET secret_digest=zeroblob(1048576);").map_err(io::Error::other)?;
        let error = list_users(
            &fixture.directory,
            &Credential::parse(&token)?,
            false,
            None,
            25,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(code(&error).is_none());
        Ok(())
    }

    #[test]
    fn revocation_orders_at_commit_without_retroactively_cancelling_an_existing_read_snapshot()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.add_user()?;
        let (view, token) = fixture.issue("snapshot reader")?;
        let credential = Credential::parse(&token)?;
        let mut connection = open_existing(&fixture.directory, false)?;
        let snapshot = connection.transaction().map_err(io::Error::other)?;
        // This real data read establishes the WAL snapshot before revocation.
        require_current(&snapshot)?;
        revoke(&fixture.directory, &view.id, 1)?;
        authorize_in(&snapshot, &credential, Permission::ReadUsers)?;
        assert_eq!(
            super::super::users::list_users_in(&snapshot, false, None, 25)?
                .items
                .len(),
            1
        );
        rejected_read(&fixture, &token);
        Ok(())
    }

    #[test]
    fn audit_ignore_and_post_delivery_commit_failures_never_leave_half_rotations() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        let (view, token) = fixture.issue("reader")?;
        let connection = fixture.raw()?;
        connection.execute_batch("CREATE TRIGGER ignore_automation_audit BEFORE INSERT ON automation_audit BEGIN SELECT RAISE(IGNORE); END;").map_err(io::Error::other)?;
        let before = metadata(&connection);
        assert!(
            rotate(&fixture.directory, &view.id, 1, 60, |_| panic!(
                "failed audit must not deliver"
            ))
            .is_err()
        );
        assert!(metadata(&connection) == before);
        connection.execute_batch("DROP TRIGGER ignore_automation_audit;
        CREATE TABLE automation_deferred_fault(parent TEXT REFERENCES automation_principals(id) DEFERRABLE INITIALLY DEFERRED);
        CREATE TRIGGER deferred_automation_failure AFTER INSERT ON automation_audit WHEN NEW.action='rotate'
        BEGIN INSERT INTO automation_deferred_fault VALUES('AAECAwQFBgcICQoLDA0ODw'); END;").map_err(io::Error::other)?;
        let mut delivered = Zeroizing::new(String::new());
        let error = rotate(&fixture.directory, &view.id, 1, 60, |value| {
            delivered.push_str(value);
            Ok(())
        })
        .err()
        .unwrap();
        assert!(code(&error).is_none());
        assert!(!delivered.is_empty());
        assert!(metadata(&connection) == before);
        list_users(
            &fixture.directory,
            &Credential::parse(&token)?,
            false,
            None,
            25,
        )?;
        rejected_read(&fixture, &delivered);
        Ok(())
    }

    #[test]
    fn tombstones_keep_capacity_and_ignored_audit_pruning_rolls_back_the_new_generation()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (first, token) = fixture.issue("first")?;
        for index in 1..MAX_PRINCIPALS {
            let view = create(
                &fixture.directory,
                &format!("reader {index}"),
                Scope::UsersRead,
                60,
                |_| Ok(()),
            )?;
            revoke(&fixture.directory, &view.id, 1)?;
        }
        assert_eq!(list(&fixture.directory)?.len(), MAX_PRINCIPALS as usize);
        let error = create(&fixture.directory, "overflow", Scope::UsersRead, 60, |_| {
            panic!("full lifetime capacity must not deliver")
        })
        .err()
        .unwrap();
        assert_eq!(code(&error), Some("automation_capacity"));
        let connection = fixture.raw()?;
        // A bounded synthetic audit window exercises retention, not API history.
        connection
            .execute_batch("DELETE FROM automation_audit;")
            .map_err(io::Error::other)?;
        connection.execute("WITH RECURSIVE n(value) AS(VALUES(1) UNION ALL SELECT value+1 FROM n WHERE value<16384)
        INSERT INTO automation_audit(sequence,entry,action,principal_id,generation,observed_at,expires_at)
        SELECT value,'local_file','create',?1,1,?2,?3 FROM n", params![first.id,sql(first.created_at_unix_ms)?,sql(first.expires_at_unix_ms)?]).map_err(io::Error::other)?;
        connection.execute_batch("UPDATE automation_state SET last_sequence=16384;
        CREATE TRIGGER ignore_automation_prune BEFORE DELETE ON automation_audit BEGIN SELECT RAISE(IGNORE); END;").map_err(io::Error::other)?;
        let before = metadata(&connection);
        assert!(
            rotate(&fixture.directory, &first.id, 1, 60, |_| panic!(
                "over-cap audit must not deliver"
            ))
            .is_err()
        );
        assert!(metadata(&connection) == before);
        list_users(
            &fixture.directory,
            &Credential::parse(&token)?,
            false,
            None,
            25,
        )?;
        connection
            .execute_batch("DROP TRIGGER ignore_automation_prune;")
            .map_err(io::Error::other)?;
        rotate(&fixture.directory, &first.id, 1, 60, |_| Ok(()))?;
        assert_eq!(highwater(&connection)?, 16385);
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM automation_audit", [], |row| row
                    .get::<_, i64>(0))
                .map_err(io::Error::other)?,
            MAX_AUDIT
        );
        assert_eq!(
            connection
                .query_row("SELECT min(sequence) FROM automation_audit", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .map_err(io::Error::other)?,
            2
        );
        validate_snapshot(&connection, 18)?;
        Ok(())
    }

    #[test]
    fn matching_hash_packages_with_missing_audit_rows_are_rejected_without_repair() -> io::Result<()>
    {
        for missing in [1, 2] {
            let source = Fixture::new()?;
            let owner = Fixture::new()?;
            let package = owner.directory.join("package");
            let (first, _) = source.issue("first reader")?;
            rotate(&source.directory, &first.id, 1, 3600, |_| Ok(()))?;
            let (second, _) = source.issue("second reader")?;
            revoke(&source.directory, &second.id, 1)?;
            store::create_backup(&source.directory, &package)?;
            store::verify_backup(&package)?;

            let database = package.join("management.sqlite3");
            let manifest_path = package.join("manifest.json");
            let connection = Connection::open(&database).map_err(io::Error::other)?;
            connection
                .execute("DELETE FROM automation_audit WHERE sequence=?1", [missing])
                .map_err(io::Error::other)?;
            // Both mutations retain the true maximum/highwater; rejection must
            // reach the explicit typed window check, not a hash or MAX mismatch.
            validate_schema(&connection, 18)?;
            assert_eq!(highwater(&connection)?, 4);
            drop(connection);
            let database_bytes = std::fs::read(&database)?;
            let mut manifest: store::BackupManifest =
                serde_json::from_slice(&std::fs::read(&manifest_path)?)
                    .map_err(io::Error::other)?;
            manifest.database_bytes =
                u64::try_from(database_bytes.len()).map_err(io::Error::other)?;
            manifest.database_sha256 = Sha256::digest(&database_bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            std::fs::write(
                &manifest_path,
                serde_json::to_vec(&manifest).map_err(io::Error::other)?,
            )?;
            let manifest_bytes = std::fs::read(&manifest_path)?;
            let error = store::verify_backup(&package)
                .err()
                .ok_or_else(|| io::Error::other("audit gap was accepted"))?;
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(std::fs::read(&database)? == database_bytes);
            assert!(std::fs::read(&manifest_path)? == manifest_bytes);
            assert_eq!(std::fs::read_dir(&package)?.count(), 2);
        }
        Ok(())
    }

    #[test]
    fn genuine_schema_sixteen_requires_explicit_migration_and_legacy_namespace_smuggling_fails()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let connection = fixture.raw()?;
        super::super::recovery::restore_schema_sixteen_for_test(&connection)?;
        assert_eq!(store::inspect(&fixture.directory)?.schema_version, 16);
        assert_eq!(
            code(&list(&fixture.directory).err().unwrap()),
            Some("management_upgrade_required")
        );
        let backup = fixture.directory.join("before-v18.sqlite3");
        assert_eq!(
            store::migrate(&fixture.directory, &backup)?.schema_version,
            store::SCHEMA_VERSION
        );
        assert!(list(&fixture.directory)?.is_empty());
        create(
            &fixture.directory,
            "new reader",
            Scope::UsersRead,
            60,
            |_| Ok(()),
        )?;
        connection
            .pragma_update(None, "user_version", 16)
            .map_err(io::Error::other)?;
        assert_eq!(
            store::inspect(&fixture.directory).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        Ok(())
    }

    fn authorize_for(
        fixture: &Fixture,
        token: &str,
        permission: Permission,
    ) -> io::Result<Authorized> {
        let credential = Credential::parse(token)?;
        let mut connection = open_existing(&fixture.directory, false)?;
        let transaction = connection.transaction().map_err(io::Error::other)?;
        authorize_in(&transaction, &credential, permission)
    }

    #[test]
    fn permission_is_checked_only_after_the_current_key_is_verified() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (view, token) = fixture.issue("reader")?;
        let authorized = authorize_for(&fixture, &token, Permission::ReadUsers)?;
        assert_eq!(authorized.id, view.id);
        assert_eq!(authorized.generation, 1);
        assert_eq!(
            code(
                &authorize_for(&fixture, &token, Permission::WriteUsers)
                    .err()
                    .unwrap()
            ),
            Some("automation_insufficient_scope")
        );
        let node = store::inspect(&fixture.directory)?.node_id;
        let (wrong, _) = new_key(&node, &view.id, 1, Scope::UsersRead)?;
        assert_eq!(
            code(
                &authorize_for(&fixture, &wrong, Permission::WriteUsers)
                    .err()
                    .unwrap()
            ),
            Some("automation_unauthorized")
        );
        // Parsing is not authorization: a key parsed before a subsequent rotation
        // must be checked against the new snapshot, not its old HTTP-arrival state.
        let parsed = Credential::parse(&token)?;
        rotate(&fixture.directory, &view.id, 1, 3600, |_| Ok(()))?;
        let mut connection = open_existing(&fixture.directory, false)?;
        let transaction = connection.transaction().map_err(io::Error::other)?;
        assert_eq!(
            code(
                &authorize_in(&transaction, &parsed, Permission::WriteUsers)
                    .err()
                    .unwrap()
            ),
            Some("automation_unauthorized")
        );
        Ok(())
    }

    #[test]
    fn write_scope_includes_reads_but_rotation_and_stored_scope_cannot_escalate_a_key()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.add_user()?;
        let (view, token) = fixture.issue_with_scope("writer", Scope::UsersWrite)?;
        assert_eq!(view.scope, "users:write");
        assert_eq!(
            authorize_for(&fixture, &token, Permission::WriteUsers)?.id,
            view.id
        );
        assert_eq!(
            list_users(
                &fixture.directory,
                &Credential::parse(&token)?,
                false,
                None,
                25
            )?
            .items
            .len(),
            1
        );
        let mut renewed = Zeroizing::new(String::new());
        let rotated = rotate(&fixture.directory, &view.id, 1, 3600, |value| {
            renewed.push_str(value);
            Ok(())
        })?;
        assert_eq!(rotated.scope, "users:write");
        assert_eq!(rotated.id, view.id);
        assert_eq!(rotated.generation, 2);
        assert_eq!(
            code(
                &authorize_for(&fixture, &token, Permission::WriteUsers)
                    .err()
                    .unwrap()
            ),
            Some("automation_unauthorized")
        );
        authorize_for(&fixture, &renewed, Permission::WriteUsers)?;
        // Changing only the stored capability invalidates the verifier, rather
        // than making a read-domain key capable of using the write-domain row.
        let (reader, read_token) = fixture.issue("reader")?;
        let connection = fixture.raw()?;
        connection
            .execute(
                "UPDATE automation_principals SET scope='users:write' WHERE id=?1",
                [&reader.id],
            )
            .map_err(io::Error::other)?;
        assert_eq!(
            code(
                &authorize_for(&fixture, &read_token, Permission::WriteUsers)
                    .err()
                    .unwrap()
            ),
            Some("automation_unauthorized")
        );
        connection
            .execute(
                "UPDATE automation_principals SET scope='users:read' WHERE id=?1",
                [&reader.id],
            )
            .map_err(io::Error::other)?;
        let mut read_renewed = Zeroizing::new(String::new());
        assert_eq!(
            rotate(&fixture.directory, &reader.id, 1, 3600, |value| {
                read_renewed.push_str(value);
                Ok(())
            })?
            .scope,
            "users:read"
        );
        assert_eq!(
            code(
                &authorize_for(&fixture, &read_renewed, Permission::WriteUsers)
                    .err()
                    .unwrap()
            ),
            Some("automation_insufficient_scope")
        );
        revoke(&fixture.directory, &view.id, 2)?;
        assert_eq!(
            code(
                &authorize_for(&fixture, &renewed, Permission::WriteUsers)
                    .err()
                    .unwrap()
            ),
            Some("automation_unauthorized")
        );
        Ok(())
    }

    #[test]
    fn read_digest_keeps_the_historical_bytes_and_write_uses_a_distinct_domain() {
        let node = "AAECAwQFBgcICQoLDA0ODw";
        let id = "EBESExQVFhcYGRobHB0eHw";
        let secret = [0x42; 32];
        for (scope, expected) in [
            (
                Scope::UsersRead,
                "4d08c0294d8239bad4513f7e58ad8050b8fdae7fbb40b58dfa8c21caa319cf5d",
            ),
            (
                Scope::UsersWrite,
                "fc207b5d2b7e6d1a6b51733cd65391606ac0f0145a77fec20cd3c5988c98e153",
            ),
        ] {
            let actual: String = key_digest(node, id, 7, &secret, scope)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn genuine_seventeen_keeps_read_lifecycle_and_raw_verifiers_across_migration() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        super::super::recovery::restore_schema_seventeen_for_test(&fixture.raw()?)?;
        assert_eq!(store::inspect(&fixture.directory)?.schema_version, 17);
        let (view, token) = fixture.issue("legacy reader")?;
        let connection = fixture.raw()?;
        // This is the actual historical CHECK, not just a relabelled user_version.
        assert!(
            connection
                .execute(
                    "UPDATE automation_principals SET scope='users:write' WHERE id=?1",
                    [&view.id]
                )
                .is_err()
        );
        let error = create(
            &fixture.directory,
            "cannot create writer",
            Scope::UsersWrite,
            60,
            |_| panic!("schema17 must not deliver a write key"),
        )
        .err()
        .unwrap();
        assert_eq!(code(&error), Some("management_upgrade_required"));
        let mut renewed = Zeroizing::new(String::new());
        assert_eq!(
            rotate(&fixture.directory, &view.id, 1, 3600, |value| {
                renewed.push_str(value);
                Ok(())
            })?
            .scope,
            "users:read"
        );
        rejected_read(&fixture, &token);
        let (revoked, _) = fixture.issue("legacy revoked")?;
        revoke(&fixture.directory, &revoked.id, 1)?;
        authorize_for(&fixture, &renewed, Permission::ReadUsers)?;
        let before = metadata(&connection);
        // Capture every original table's exact column projection before migration,
        // including raw verifiers and command BLOBs. New actor columns and the
        // admission namespace must not exclude any historical table from this check.
        let names = connection
            .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
            .map_err(io::Error::other)?
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(io::Error::other)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(io::Error::other)?;
        let mut projections = Vec::new();
        for name in names {
            let table = format!("\"{}\"", name.replace('"', "\"\""));
            let columns = connection
                .prepare(&format!("PRAGMA table_info({table})"))
                .map_err(io::Error::other)?
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(io::Error::other)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(io::Error::other)?
                .into_iter()
                .map(|column| format!("\"{}\"", column.replace('"', "\"\"")))
                .collect::<Vec<_>>()
                .join(",");
            projections.push(format!("SELECT {columns} FROM {table} ORDER BY {columns}"));
        }
        let original_rows =
            |database: &Connection| -> io::Result<Vec<Vec<Vec<rusqlite::types::Value>>>> {
                projections
                    .iter()
                    .map(|query| {
                        let mut statement = database.prepare(query).map_err(io::Error::other)?;
                        let width = statement.column_count();
                        statement
                            .query_map([], |row| (0..width).map(|column| row.get(column)).collect())
                            .map_err(io::Error::other)?
                            .collect::<rusqlite::Result<_>>()
                            .map_err(io::Error::other)
                    })
                    .collect()
            };
        let before_rows = original_rows(&connection)?;
        let backup = fixture.directory.join("before-v18.sqlite3");
        assert_eq!(
            store::migrate(&fixture.directory, &backup)?.schema_version,
            store::SCHEMA_VERSION
        );
        assert!(metadata(&connection) == before);
        assert!(original_rows(&connection)? == before_rows);
        let copied = Connection::open(&backup).map_err(io::Error::other)?;
        assert_eq!(store::read_overview(&copied)?.schema_version, 17);
        assert!(original_rows(&copied)? == before_rows);
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
        assert_eq!(
            authorize_for(&fixture, &renewed, Permission::ReadUsers)?.generation,
            2
        );
        assert_eq!(
            code(
                &authorize_for(&fixture, &renewed, Permission::WriteUsers)
                    .err()
                    .unwrap()
            ),
            Some("automation_insufficient_scope")
        );
        let (writer, write_token) = fixture.issue_with_scope("new writer", Scope::UsersWrite)?;
        assert_eq!(
            authorize_for(&fixture, &write_token, Permission::WriteUsers)?.id,
            writer.id
        );
        Ok(())
    }

    #[test]
    fn migration_collision_rolls_back_renamed_tables_without_losing_legacy_keys() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        let mut connection = fixture.raw()?;
        super::super::recovery::restore_schema_seventeen_for_test(&connection)?;
        let (_, token) = fixture.issue("preserved reader")?;
        connection.execute_batch("CREATE TABLE automation_principals_previous(value TEXT); INSERT INTO automation_principals_previous VALUES('collision');")
        .map_err(io::Error::other)?;
        let before = metadata(&connection);
        {
            let transaction = connection.transaction().map_err(io::Error::other)?;
            assert!(migrate_to_18(&transaction).is_err());
        }
        assert!(metadata(&connection) == before);
        assert_eq!(
            connection
                .query_row(
                    "SELECT value FROM automation_principals_previous",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .map_err(io::Error::other)?,
            "collision"
        );
        assert_eq!(store::inspect(&fixture.directory)?.schema_version, 17);
        authorize_for(&fixture, &token, Permission::ReadUsers)?;
        Ok(())
    }
}
