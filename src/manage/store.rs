//! Durable management identity, peer authorization and proxy access storage.
//!
//! The database is durable node state, not a cache: an unreadable or partially
//! initialized file must never cause this module to generate a replacement node
//! identity. Schema migration is explicit; proxy policy writes belong to the
//! live management coordinator, while peer authorization is rechecked per request.

pub(super) mod administrators;
pub(super) mod admission;
pub(super) mod alerts;
mod author;
pub(super) mod automation;
mod backup;
mod content;
mod control;
pub(super) mod diagnostics;
pub(super) mod endpoints;
#[cfg(feature = "witness-journal")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "Source file-author identity methods await fixed CLI configuration admission"
    )
)]
pub(super) mod identities;
#[cfg(feature = "witness-journal")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "Source activation waits for whole-writer and restart admission coverage"
    )
)]
pub(super) mod journal;
pub(super) mod notifications;
pub(super) mod operations;
mod peers;
pub(super) mod presets;
pub(super) mod proxy_service;
pub(super) mod recovery;
pub(super) mod remote_traffic;
pub(super) mod routing;
pub(super) mod secrets;
mod source;
pub(super) mod targets;
pub(super) mod traffic;
mod users;
pub(super) mod witness;

#[cfg(feature = "witness-journal")]
pub(super) use control::{apply_command_in, set_owner_in};
#[cfg(feature = "witness-journal")]
pub(super) use users::apply_local_in as apply_local_policy_in;

pub(super) use administrators::reset_password;
pub(super) use author::{Guard, UpdateGuard, lock, update_lock};
#[cfg(feature = "witness-journal")]
pub(super) use backup::read_verified as read_backup_verified;
pub(super) use backup::{BackupManifest, create_backup, create_identity_snapshot, verify_backup};
pub(super) use control::endpoints as endpoint_control;
#[cfg(test)]
pub(super) use control::restore_legacy_owner_audit;
pub(super) use control::{
    Command, CommandOutcome, ControlError, ControlIntent, Ownership, PresetKind, PresetReceipt,
    Receipt, ReceiptStatus, RemoteAuthorization, RoutingKind, RoutingReceipt,
    apply_command_with_admission, mark_command_applied, ownership, receipt, remote_authorized,
    remote_list_credentials, remote_list_users, remote_policy_status, remote_presets_data,
    remote_routing_data, remote_search_users, set_owner, set_owner_offline,
};
pub(super) use routing::routing_data;

pub(super) use peers::{
    PeerAuthorization, PeerSummary, authorize_peer, list_peers, migrate, register_peer,
    revoke_certificate, set_peer_active,
};
pub(super) use users::{
    ChangeResult, CredentialView, Page, PolicyChange, PolicyStatus, UserView, apply_policy,
    apply_policy_asserted, list_credentials, list_users, load_policy, policy_status,
    record_applied, search_users,
};

use std::{
    fs::{self, DirBuilder, OpenOptions},
    io,
    path::Path,
    time::Duration,
};

use argon2::{
    Argon2, Params, PasswordVerifier,
    password_hash::{self, phc::PasswordHash},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use zeroize::Zeroizing;

const DATABASE_NAME: &str = "management.sqlite3";
// SQLite reserves application_id for distinguishing unrelated file formats.
// The big-endian ASCII namespace "VPXY" is independent of the schema version.
const APPLICATION_ID: i32 = i32::from_be_bytes(*b"VPXY");
pub(super) const SCHEMA_VERSION: u32 = 29;
const BUSY_TIMEOUT: Duration = Duration::from_secs(2);

/// Reconstructs a pre-operation fixture without discarding issued identities.
/// Only an unused, canonical singleton may be removed; historical command and
/// recovery helpers call this before lowering the database's user_version.
#[cfg(test)]
pub(in crate::manage) fn remove_operations_schema_for_test(
    connection: &Connection,
) -> io::Result<()> {
    alerts::history::ensure_unused_for_test(connection)?;
    notifications::ensure_unused_for_test(connection)?;
    targets::history::ensure_unused_for_test(connection)?;
    let tables: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name IN('operations_state','user_operations')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot inspect operation fixture namespace", error))?;
    if tables == 0 {
        recovery::restore_schema_eighteen_for_test(connection)?;
        return automation::remove_schema_for_test(connection);
    }
    if tables != 2 {
        return Err(invalid_data("operation fixture namespace is incomplete"));
    }
    let version = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| sqlite_error("cannot inspect operation fixture version", error))?;
    operations::validate_schema(connection, version)?;
    let unused: bool = connection
        .query_row(
            "SELECT (SELECT last_sequence=0 FROM operations_state WHERE singleton=1)
              AND NOT EXISTS(SELECT 1 FROM user_operations)",
            [],
            |row| row.get(0),
        )
        .map_err(|error| {
            sqlite_error("cannot inspect issued operation fixture identities", error)
        })?;
    if !unused {
        return Err(invalid_data(
            "issued operation identities cannot become a legacy fixture",
        ));
    }
    // Reject issued operation history before removing any newer namespace;
    // callers may deliberately test this failure and continue using the store.
    automation::ensure_unused_for_test(connection)?;
    users::require_legacy_audit_for_test(connection)?;
    recovery::restore_schema_eighteen_for_test(connection)?;
    users::restore_legacy_audit_for_test(connection)?;
    connection
        .execute_batch("DROP TABLE user_operations; DROP TABLE operations_state;")
        .map_err(|error| sqlite_error("cannot reconstruct pre-operation fixture", error))?;
    automation::remove_schema_for_test(connection)
}

/// Non-secret, locally observed facts for offline initialization and inspection.
///
/// This deliberately omits administrator identities and password hashes, so a
/// caller can display status without accidentally disclosing credential data.
pub(super) struct Overview {
    /// Persistent, random node identifier; changing the display name does not change it.
    pub(super) node_id: String,
    /// User-selected local display name, not an authentication or routing identity.
    pub(super) name: String,
    /// Number of stored management administrators, checked before narrowing to `u32`.
    pub(super) administrator_count: u32,
    /// Validated storage schema version; unknown versions are not opened for writes.
    pub(super) schema_version: u32,
    /// SQLite library version used by this process, not the file's schema version.
    pub(super) sqlite_version: String,
}

/// Authenticated management identity; never a proxy user or a password container.
pub(super) struct Administrator {
    /// Stable random identity used for session ownership rather than display text.
    pub(super) id: String,
    /// Login name for presentation after successful authentication.
    pub(super) username: String,
}

/// Verifies a local administrator without exposing stored PHC values to the API.
///
/// Missing usernames still run Argon2 against the caller's same-cost dummy PHC.
/// A password mismatch returns `None`; malformed storage, unsupported hash costs,
/// filesystem failures and database contention return an error, not a false
/// credential rejection. Calls perform blocking DB/CPU work and must be bounded
/// and moved off async workers by the caller.
pub(super) fn authenticate(
    directory: &Path,
    username: &str,
    password: &[u8],
    dummy_phc: &str,
) -> io::Result<Option<Administrator>> {
    validate_directory(directory)?;
    let path = directory.join(DATABASE_NAME);
    validate_database(&path)?;
    let mut connection = open(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    configure(&connection)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin management credential inspection", error))?;
    read_overview(&transaction)?;
    let record = transaction
        .query_row(
            "SELECT id, username, password_hash FROM administrators WHERE username = ?1",
            [username],
            |row| {
                Ok((
                    Administrator {
                        id: row.get(0)?,
                        username: row.get(1)?,
                    },
                    Zeroizing::new(row.get::<_, String>(2)?),
                ))
            },
        )
        .optional()
        .map_err(|error| sqlite_error("cannot read management credential", error))?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot complete management credential inspection", error))?;
    let phc = record.as_ref().map_or(dummy_phc, |(_, hash)| hash.as_str());
    if verify_password(phc, password)? {
        Ok(record.map(|(administrator, _)| administrator))
    } else {
        Ok(None)
    }
}

/// Apply the same bounded Argon2id policy to login and authenticated revalidation.
fn verify_password(phc: &str, password: &[u8]) -> io::Result<bool> {
    // PHC parameters come from durable state, not request JSON. Still cap them
    // before the verifier allocates memory so corrupt state cannot bypass the
    // API's concurrent hashing budget. Initialization uses 19 MiB / 2 / 1.
    if phc.len() > 512 {
        return Err(invalid_data("management password hash is malformed"));
    }
    let hash = PasswordHash::new(phc)
        .map_err(|_| invalid_data("management password hash is malformed"))?;
    let parameters = Params::try_from(&hash)
        .map_err(|_| invalid_data("management password hash parameters are invalid"))?;
    if hash.algorithm.as_str() != "argon2id"
        || hash.version != Some(19)
        || hash.salt.is_none()
        || hash.hash.as_ref().is_none_or(|output| output.len() != 32)
        || !(19 * 1024..=64 * 1024).contains(&parameters.m_cost())
        || !(2..=4).contains(&parameters.t_cost())
        || !(1..=2).contains(&parameters.p_cost())
    {
        return Err(invalid_data("unsupported management password hash policy"));
    }
    match Argon2::default().verify_password(password, &hash) {
        Ok(()) => Ok(true),
        Err(password_hash::Error::PasswordInvalid) => Ok(false),
        Err(_) => Err(invalid_data("cannot verify management password hash")),
    }
}

/// Initializes a new node and its first administrator in one SQLite transaction.
///
/// The caller validates names and supplies an already-derived Argon2 PHC string;
/// plaintext passwords do not enter this layer. A new private directory is
/// created when needed, but existing directory permissions are never changed.
/// The directory's ancestors must be controlled by the operator. On Windows,
/// new files inherit the directory's ACL; Unix mode checks are not an ACL audit.
///
/// Existing database files, including empty or corrupt files, return
/// `AlreadyExists` without opening or resetting them. Database sidecars left
/// without a database also require explicit operator recovery. Symlink leaves,
/// non-directory data paths and non-private Unix permissions are rejected.
/// SQLite lock waits are bounded by [`BUSY_TIMEOUT`]. Failures leave any newly
/// created files in place for diagnosis, including a failed first transaction.
pub(super) fn initialize(
    directory: &Path,
    name: &str,
    administrator: &str,
    password_hash: &str,
) -> io::Result<Overview> {
    initialize_with(directory, name, administrator, password_hash, |_, _, _| {
        Ok(())
    })
}

/// Share the exclusively claimed fresh database transaction with offline restore.
/// The callback runs only after the database file exists and before any schema,
/// native/recovery state or identity becomes visible to another connection.
fn initialize_with(
    directory: &Path,
    name: &str,
    administrator: &str,
    password_hash: &str,
    before_commit: impl FnOnce(&Connection, &str, &str) -> io::Result<()>,
) -> io::Result<Overview> {
    prepare_directory(directory)?;
    reject_snapshot_directory(directory)?;
    let _guard = lock(directory)?;
    let _update = update_lock(directory)?;
    let path = directory.join(DATABASE_NAME);
    // Check first for a useful diagnostic; create_new is the actual exclusive
    // claim and also rejects a dangling symlink created before the open.
    if fs::symlink_metadata(&path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "management database already exists; initialization never replaces it",
        ));
    }
    reject_orphan_sidecars(directory)?;

    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let database_file = options.open(&path)?;
    // No CREATE flag here: SQLite must use the file claimed exclusively above,
    // and NOFOLLOW rejects a substituted symlink rather than following it.
    let mut connection = open(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    configure(&connection)?;
    let mode: String = connection
        .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
        .map_err(|error| sqlite_error("cannot enable management WAL journal", error))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(io::Error::other("management database requires WAL mode"));
    }
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|error| sqlite_error("cannot configure management durability", error))?;

    let node_id = random_id()?;
    let administrator_id = random_id()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin management initialization", error))?;
    transaction
        .execute_batch(
            "CREATE TABLE node_identity (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                node_id TEXT NOT NULL UNIQUE CHECK (length(node_id) = 22),
                name TEXT NOT NULL CHECK (length(name) > 0)
             ) STRICT;
             CREATE TABLE administrators (
                id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 22),
                username TEXT NOT NULL UNIQUE CHECK (length(username) > 0),
                password_hash TEXT NOT NULL CHECK (length(password_hash) > 0)
             ) STRICT;",
        )
        .map_err(|error| sqlite_error("cannot create management schema", error))?;
    peers::create_schema(&transaction)?;
    users::create_schema(&transaction)?;
    control::create_schema(&transaction)?;
    routing::create_schema(&transaction)?;
    control::upgrade_schema(&transaction)?;
    traffic::create_schema(&transaction)?;
    remote_traffic::create_schema(&transaction)?;
    presets::create_schema(&transaction)?;
    control::upgrade_presets(&transaction)?;
    targets::upgrade_metadata(&transaction)?;
    administrators::create_schema(&transaction)?;
    administrators::upgrade_schema(&transaction)?;
    control::upgrade_owner_audit(&transaction)?;
    recovery::create_schema(&transaction)?;
    endpoints::create_schema(&transaction)?;
    control::upgrade_endpoints(&transaction)?;
    automation::create_schema(&transaction)?;
    operations::create_schema(&transaction)?;
    users::upgrade_operation_audit(&transaction)?;
    admission::create_schema(&transaction)?;
    targets::history::create_schema(&transaction)?;
    alerts::history::create_schema(&transaction)?;
    notifications::create_schema(&transaction)?;
    witness::create_schema(&transaction)?;
    source::create_schema(&transaction)?;
    proxy_service::create_schema(&transaction)?;
    secrets::create_schema(&transaction)?;
    traffic::upgrade_protocols(&transaction)?;
    remote_traffic::upgrade_protocols(&transaction)?;
    transaction
        .execute(
            "INSERT INTO node_identity (singleton, node_id, name) VALUES (1, ?1, ?2)",
            params![node_id, name],
        )
        .map_err(|error| sqlite_error("cannot store management node identity", error))?;
    transaction
        .execute(
            "INSERT INTO administrators (id, username, password_hash) VALUES (?1, ?2, ?3)",
            params![administrator_id, administrator, password_hash],
        )
        .map_err(|error| sqlite_error("cannot store management administrator", error))?;
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(|error| sqlite_error("cannot identify management database", error))?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(|error| sqlite_error("cannot version management schema", error))?;
    before_commit(&transaction, &node_id, &administrator_id)?;
    let overview = read_overview(&transaction)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit management initialization", error))?;
    connection
        .close()
        .map_err(|(_, error)| sqlite_error("cannot close management database", error))?;
    database_file.sync_all()?;
    #[cfg(unix)]
    // Persist the new directory entry as well as SQLite's FULL-synchronized
    // transaction. This does not turn filesystem or hardware failures into a
    // guarantee that an operator never needs a backup.
    fs::File::open(directory)?.sync_all()?;
    Ok(overview)
}

/// Reads existing local identity metadata without creating a database.
///
/// A missing file returns `NotFound`; incompatible, incomplete or malformed
/// storage returns `InvalidData` instead of silently regenerating identity.
/// This uses a read-only SQLite connection and a single read transaction, so
/// schema, identity and administrator count belong to the same snapshot.
/// SQLite may access its WAL/SHM sidecars as part of read-only WAL operation;
/// this is not an immutable-file or forensic inspection mode. Lock waits are
/// bounded by [`BUSY_TIMEOUT`], and no migration or repair is attempted.
pub(super) fn inspect(directory: &Path) -> io::Result<Overview> {
    validate_directory(directory)?;
    let path = directory.join(DATABASE_NAME);
    validate_database(&path)?;
    let mut connection = open(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    configure(&connection)?;
    connection
        .pragma_update(None, "query_only", true)
        .map_err(|error| sqlite_error("cannot configure read-only management inspection", error))?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin management inspection", error))?;
    let overview = read_overview(&transaction)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot complete management inspection", error))?;
    Ok(overview)
}

/// Creates private directories only when absent; never chmods user-owned paths.
fn prepare_directory(directory: &Path) -> io::Result<()> {
    match fs::symlink_metadata(directory) {
        Ok(_) => validate_directory(directory),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut missing = Vec::new();
            let mut path = directory;
            loop {
                match fs::metadata(path) {
                    Ok(metadata) if metadata.is_dir() => break,
                    Ok(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::NotADirectory,
                            "management data path has a non-directory ancestor",
                        ));
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        missing.push(path.to_owned());
                        path = path
                            .parent()
                            .filter(|path| !path.as_os_str().is_empty())
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "management data directory requires an existing ancestor",
                                )
                            })?;
                    }
                    Err(error) => return Err(error),
                }
            }
            for path in missing.iter().rev() {
                let builder = DirBuilder::new();
                #[cfg(unix)]
                let builder = {
                    use std::os::unix::fs::DirBuilderExt;
                    let mut builder = builder;
                    builder.mode(0o700);
                    builder
                };
                match builder.create(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        validate_directory(path)?;
                    }
                    Err(error) => return Err(error),
                }
                #[cfg(unix)]
                if let Some(parent) = path.parent() {
                    // fsync of a new directory does not persist its entry in
                    // the parent. Sync each newly created level before an
                    // initialized identity can be reported as durable.
                    fs::File::open(parent)?.sync_all()?;
                }
            }
            validate_directory(directory)
        }
        Err(error) => Err(error),
    }
}

/// Rejects redirected or non-private leaves before database or sidecar access.
///
/// A snapshot marker is tested by writers/startup separately: readonly typed
/// inspection must remain possible without turning the artifact into live state.
fn validate_directory(directory: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "management data path must be a dedicated real directory, not a symlink",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "management data directory is accessible to other users; choose a dedicated private directory (0700)",
            ));
        }
    }
    Ok(())
}

/// The private marker is persisted before the first database page is copied.
/// Any existing object at this reserved leaf fences partial outputs, even when
/// its contents or the still-incomplete SQL file cannot be decoded. Complete
/// snapshots retain an additional SQL fence if an operator removes the marker.
fn reject_snapshot_directory(directory: &Path) -> io::Result<()> {
    match fs::symlink_metadata(directory.join(backup::SNAPSHOT_FILE)) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "identity snapshot is not live state; witnessed takeover or an as-new restore is required",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Checks existing database leaves without following symlinks or changing modes.
fn validate_database(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "management database must be a regular file, not a symlink",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "management database is accessible to other users; require private file permissions (0600)",
            ));
        }
    }
    Ok(())
}

/// Never reuse sidecars of a lost database as the seed of a different identity.
fn reject_orphan_sidecars(directory: &Path) -> io::Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        match fs::symlink_metadata(directory.join(format!("{DATABASE_NAME}{suffix}"))) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "management database sidecars already exist; recover them before initialization",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Opens only the previously checked leaf, without URI interpretation or CREATE.
fn open(path: &Path, access: OpenFlags) -> io::Result<Connection> {
    if access.contains(OpenFlags::SQLITE_OPEN_READ_WRITE) {
        source::reject_marker(
            path.parent()
                .ok_or_else(|| invalid_data("database parent is missing"))?,
        )?;
    }
    let connection = connect(path, access)?;
    if access.contains(OpenFlags::SQLITE_OPEN_READ_WRITE) {
        source::require_unprotected(&connection)?;
    }
    Ok(connection)
}

/// Low-level flags only. The source journal supplies its own retained author,
/// gate, directory/recovery/schema checks. Offline backup uses this only on its
/// private unpublished CreateNew copy to install quarantine. Ordinary callers
/// must use open; this function alone grants no startup or write permission.
fn connect(path: &Path, access: OpenFlags) -> io::Result<Connection> {
    Connection::open_with_flags(
        path,
        access | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| sqlite_error("cannot open management database", error))
}

/// Bounds contention and disables trust in schema-defined SQL extensions.
fn configure(connection: &Connection) -> io::Result<()> {
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(|error| sqlite_error("cannot configure management lock timeout", error))?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|error| sqlite_error("cannot enable management foreign keys", error))?;
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(|error| sqlite_error("cannot restrict management schema trust", error))
}

/// Validates the namespace, schema and required records within the caller's snapshot.
fn read_overview(connection: &Connection) -> io::Result<Overview> {
    let application_id: i32 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|error| sqlite_error("cannot read management database namespace", error))?;
    if application_id != APPLICATION_ID {
        return Err(invalid_data("file is not a vproxy management database"));
    }
    let schema_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| sqlite_error("cannot read management schema version", error))?;
    let schema_version = u32::try_from(schema_version)
        .map_err(|_| invalid_data("management schema version is out of range"))?;
    if !(1..=SCHEMA_VERSION).contains(&schema_version) {
        return Err(invalid_data("unsupported management schema version"));
    }
    recovery::validate_schema(connection, schema_version)?;
    endpoints::validate_schema(connection, schema_version)?;
    operations::validate_schema(connection, schema_version)?;
    automation::validate_schema(connection, schema_version)?;
    admission::validate_schema(connection, schema_version)?;
    targets::history::validate_schema(connection, schema_version)?;
    alerts::history::validate_schema(connection, schema_version)?;
    notifications::validate_schema(connection, schema_version)?;
    witness::validate_schema(connection, schema_version)?;
    source::validate_schema(connection, schema_version)?;
    proxy_service::validate_schema(connection, schema_version)?;
    secrets::validate_schema(connection, schema_version)?;
    let identity_count: i64 = connection
        .query_row("SELECT count(*) FROM node_identity", [], |row| row.get(0))
        .map_err(|error| sqlite_error("cannot validate management identity", error))?;
    if identity_count != 1 {
        return Err(invalid_data(
            "management database must contain exactly one node identity",
        ));
    }
    let (node_id, name): (String, String) = connection
        .query_row(
            "SELECT node_id, name FROM node_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| sqlite_error("cannot read management identity", error))?;
    if !valid_id(&node_id)
        || name.is_empty()
        || name.len() > 128
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        return Err(invalid_data("management node identity is malformed"));
    }
    let count: i64 = connection
        .query_row("SELECT count(*) FROM administrators", [], |row| row.get(0))
        .map_err(|error| sqlite_error("cannot count management administrators", error))?;
    let administrator_count = u32::try_from(count)
        .map_err(|_| invalid_data("management administrator count is out of range"))?;
    if administrator_count == 0 {
        return Err(invalid_data("management database has no administrator"));
    }
    Ok(Overview {
        node_id,
        name,
        administrator_count,
        schema_version,
        sqlite_version: rusqlite::version().to_owned(),
    })
}

/// Generates independent 128-bit identifiers from the operating system RNG.
fn random_id() -> io::Result<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| io::Error::other("cannot obtain randomness for management identity"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Requires the canonical no-padding encoding of exactly 128 bits.
pub(super) fn valid_id(value: &str) -> bool {
    if value.len() != 22 {
        return false;
    }
    let mut bytes = [0; 16];
    URL_SAFE_NO_PAD
        .decode_slice(value, &mut bytes)
        .is_ok_and(|length| length == bytes.len())
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Uses only fixed context and numeric SQLite codes, never SQL or bound secrets.
fn sqlite_error(context: &'static str, error: rusqlite::Error) -> io::Error {
    if let rusqlite::Error::SqliteFailure(failure, _) = error {
        let kind = match failure.code {
            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => {
                io::ErrorKind::WouldBlock
            }
            rusqlite::ErrorCode::PermissionDenied | rusqlite::ErrorCode::ReadOnly => {
                io::ErrorKind::PermissionDenied
            }
            rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt => {
                io::ErrorKind::InvalidData
            }
            // All SQL in this module is fixed. SQLITE_ERROR on inspection is
            // typically a missing table/column, not an operator's SQL syntax.
            _ if failure.extended_code & 0xff == rusqlite::ffi::SQLITE_ERROR => {
                io::ErrorKind::InvalidData
            }
            _ => io::ErrorKind::Other,
        };
        io::Error::new(
            kind,
            format!("{context} (SQLite code {})", failure.extended_code),
        )
    } else {
        invalid_data(context)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    // The caller owns password hashing; this fixed fixture is intentionally not
    // a usable credential and cannot accidentally reveal a developer password.
    const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$Zml4dHVyZQ";

    /// Owns only a freshly and exclusively created test directory.
    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!("vproxy-management-{}", random_id()?));
            let builder = DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder.create(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            // No caller-controlled path is accepted; the random leaf was
            // exclusively created by this fixture, never a shared temp root.
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn reopening_preserves_identity_and_hash() -> io::Result<()> {
        let directory = TestDirectory::new()?;
        let first = initialize(&directory.0, "Taipei node", "admin", PHC)?;
        let reopened = inspect(&directory.0)?;
        assert_eq!(first.node_id, reopened.node_id);
        assert_eq!(reopened.name, "Taipei node");
        assert_eq!(reopened.administrator_count, 1);
        assert_eq!(reopened.schema_version, SCHEMA_VERSION);
        assert_eq!(reopened.sqlite_version, rusqlite::version());
        assert!(valid_id(&reopened.node_id));

        let connection = open(
            &directory.0.join(DATABASE_NAME),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let (id, hash): (String, String) = connection
            .query_row("SELECT id, password_hash FROM administrators", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(|error| sqlite_error("cannot read fixture administrator", error))?;
        assert!(valid_id(&id));
        assert_ne!(id, first.node_id);
        assert_eq!(hash, PHC);
        Ok(())
    }

    #[test]
    fn issued_operations_refuse_legacy_reconstruction_without_changing_namespaces() -> io::Result<()>
    {
        let directory = TestDirectory::new()?;
        initialize(&directory.0, "node", "admin", PHC)?;
        let connection = peers::open_existing(&directory.0, true)?;
        let actor: String = connection
            .query_row("SELECT id FROM administrators", [], |row| row.get(0))
            .map_err(io::Error::other)?;
        let gate = update_lock(&directory.0)?;
        let operation = operations::reserve(
            &directory.0,
            &gate,
            &actor,
            &operations::Input {
                expected_node_id: None,
                expected_revision: 1,
                expected_epoch: 1,
                change: operations::UserChange::CreateUser {
                    name: "reserved fixture".into(),
                    protocols: vec![crate::access::Protocol::Http],
                    concurrent_limit: 1,
                },
            },
        )?;
        let schema: u32 = connection
            .pragma_query_value(None, "schema_version", |row| row.get(0))
            .map_err(io::Error::other)?;
        let changes = connection.total_changes();
        assert_eq!(
            remove_operations_schema_for_test(&connection)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            connection
                .pragma_query_value::<u32, _>(None, "schema_version", |row| row.get(0))
                .map_err(io::Error::other)?,
            schema
        );
        assert_eq!(connection.total_changes(), changes);
        assert!(automation::list(&directory.0)?.is_empty());
        assert_eq!(
            operations::get(&directory.0, &actor, &operation.id)?,
            operation
        );
        Ok(())
    }

    #[test]
    fn authentication_never_promotes_dummy_matches_or_hides_broken_hashes() -> io::Result<()> {
        use argon2::PasswordHasher as _;

        let directory = TestDirectory::new()?;
        let password = b"fixture administrator passphrase";
        let hash = Argon2::default()
            .hash_password(password)
            .map_err(|_| io::Error::other("cannot hash fixture password"))?
            .to_string();
        initialize(&directory.0, "node", "admin", &hash)?;
        let administrator = authenticate(&directory.0, "admin", password, &hash)?.unwrap();
        assert!(valid_id(&administrator.id));
        assert_eq!(administrator.username, "admin");
        assert!(authenticate(&directory.0, "admin", b"wrong password", &hash)?.is_none());
        // Even a match against the dummy is never a real identity.
        assert!(authenticate(&directory.0, "unknown", password, &hash)?.is_none());

        let connection = open(
            &directory.0.join(DATABASE_NAME),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        let excessive_cost = hash.replace("m=19456", "m=4294967295");
        connection
            .execute(
                "UPDATE administrators SET password_hash = ?1",
                [excessive_cost],
            )
            .map_err(|error| sqlite_error("cannot corrupt fixture hash cost", error))?;
        assert!(
            matches!(authenticate(&directory.0, "admin", password, &hash), Err(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
        Ok(())
    }

    #[test]
    fn repeated_initialization_never_resets_records() -> io::Result<()> {
        let directory = TestDirectory::new()?;
        let first = initialize(&directory.0, "Original", "admin", PHC)?;
        let result = initialize(&directory.0, "Replacement", "other", "replacement hash");
        assert!(matches!(result, Err(ref error) if error.kind() == io::ErrorKind::AlreadyExists));
        let reopened = inspect(&directory.0)?;
        assert_eq!(reopened.node_id, first.node_id);
        assert_eq!(reopened.name, "Original");
        let connection = open(
            &directory.0.join(DATABASE_NAME),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let (username, hash): (String, String) = connection
            .query_row(
                "SELECT username, password_hash FROM administrators",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| sqlite_error("cannot read unchanged fixture credential", error))?;
        assert_eq!(username, "admin");
        assert_eq!(hash, PHC);
        Ok(())
    }

    #[test]
    fn absent_and_corrupt_databases_are_not_recreated() -> io::Result<()> {
        use std::io::Write as _;

        let directory = TestDirectory::new()?;
        let path = directory.0.join(DATABASE_NAME);
        assert!(
            matches!(inspect(&directory.0), Err(ref error) if error.kind() == io::ErrorKind::NotFound)
        );
        assert!(!path.exists());

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        file.write_all(b"not a sqlite database")?;
        drop(file);
        assert!(
            matches!(inspect(&directory.0), Err(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert!(
            matches!(initialize(&directory.0, "node", "admin", PHC), Err(ref error) if error.kind() == io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fs::read(path)?, b"not a sqlite database");
        Ok(())
    }

    #[test]
    fn namespace_schema_and_required_records_are_validated() -> io::Result<()> {
        let directory = TestDirectory::new()?;
        initialize(&directory.0, "node", "admin", PHC)?;
        let connection = open(
            &directory.0.join(DATABASE_NAME),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        connection
            .pragma_update(None, "application_id", 0)
            .map_err(|error| sqlite_error("cannot change fixture namespace", error))?;
        assert!(
            matches!(inspect(&directory.0), Err(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
        connection
            .pragma_update(None, "application_id", APPLICATION_ID)
            .map_err(|error| sqlite_error("cannot restore fixture namespace", error))?;
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .map_err(|error| sqlite_error("cannot change fixture schema", error))?;
        assert!(
            matches!(inspect(&directory.0), Err(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .and_then(|()| {
                connection
                    .execute("DELETE FROM administrators", [])
                    .map(|_| ())
            })
            .map_err(|error| sqlite_error("cannot remove fixture administrator", error))?;
        assert!(
            matches!(inspect(&directory.0), Err(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
        connection
            .execute(
                "INSERT INTO administrators (id, username, password_hash) VALUES (?1, 'admin', ?2)",
                params![random_id()?, PHC],
            )
            .and_then(|_| connection.execute("DELETE FROM node_identity", []))
            .map_err(|error| sqlite_error("cannot remove fixture identity", error))?;
        assert!(
            matches!(inspect(&directory.0), Err(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unix_private_permissions_and_symlink_boundaries() -> io::Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = TestDirectory::new()?;
        let private = directory.0.join("new-node");
        initialize(&private, "node", "admin", PHC)?;
        let database = private.join(DATABASE_NAME);
        assert_eq!(fs::metadata(&private)?.permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&database)?.permissions().mode() & 0o777, 0o600);

        let redirect = directory.0.join("redirect");
        symlink(&private, &redirect)?;
        assert!(
            matches!(inspect(&redirect), Err(ref error) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        let linked = directory.0.join(DATABASE_NAME);
        symlink(&database, &linked)?;
        assert!(
            matches!(inspect(&directory.0), Err(ref error) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        assert!(
            matches!(initialize(&directory.0, "other", "admin", PHC), Err(ref error) if error.kind() == io::ErrorKind::AlreadyExists)
        );

        fs::set_permissions(&private, fs::Permissions::from_mode(0o755))?;
        assert!(
            matches!(inspect(&private), Err(ref error) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        assert_eq!(fs::metadata(&private)?.permissions().mode() & 0o777, 0o755);
        Ok(())
    }
}
