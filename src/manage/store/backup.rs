//! Offline SQLite snapshots, not authorization rollback or disaster recovery.
//!
//! A final manifest marks a completed private package. Its unkeyed hash detects
//! changed bytes relative to that manifest, not an attacker's replacement of
//! both files, freshness, or permission to restore old identities/revocations.

use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[cfg(not(windows))]
use std::fs::{DirBuilder, OpenOptions};

use super::{
    APPLICATION_ID, DATABASE_NAME, SCHEMA_VERSION, configure, invalid_data, lock,
    peers::{backup_existing, open_existing},
    read_overview, sqlite_error, update_lock, valid_id, validate_database, validate_directory,
};

const MANIFEST_NAME: &str = "manifest.json";
const FORMAT_VERSION: u32 = 1;
const SNAPSHOT_FORMAT: u32 = 2;
pub(super) const SNAPSHOT_FILE: &str = "snapshot.json";
// Never expose an unsealed retained copy under the live database name. The
// marker is an extra gate, not the sole defense against interrupted publication.
const SNAPSHOT_DATABASE_FILE: &str = "snapshot.sqlite3.partial";
const MAX_MANIFEST_BYTES: u64 = 4_096;

// A current user_version alone cannot prove that required tables exist. This
// checks the table catalog, not exact DDL or every application's row semantics.
const TABLES_V13: &[&str] = &[
    "node_identity",
    "administrators",
    "administrator_audit_state",
    "administrator_audit",
    "peers",
    "peer_certificates",
    "peer_audit",
    "proxy_policy_state",
    "proxy_users",
    "proxy_credentials",
    "proxy_policy_audit",
    "control_ownership",
    "control_receipts",
    "control_audit",
    "managed_targets",
    "control_outbox",
    "controller_audit",
    "routing_prefixes",
    "routing_addresses",
    "routing_pools",
    "routing_pool_members",
    "routing_permissions",
    "routing_exit_grants",
    "routing_pool_grants",
    "routing_audit",
    "traffic_state",
    "traffic_series",
    "traffic_windows",
    "remote_traffic_sources",
    "user_presets",
    "pool_presets",
    "preset_audit",
];

/// Non-secret metadata bound to the standalone database's exact bytes.
///
/// The database itself contains password verifiers and other sensitive state.
/// This format deliberately includes neither these values nor TLS/config files.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct BackupManifest {
    /// Package format, independent of the management database schema.
    pub(in crate::manage) format_version: u32,
    /// SQLite's application namespace; a hash alone does not identify this format.
    application_id: i32,
    /// Explicitly supported source schema; verification never migrates a backup.
    pub(in crate::manage) schema_version: u32,
    /// Stable source identity, not an assertion that restoring it would be safe.
    pub(in crate::manage) node_id: String,
    /// Exact standalone database size, checked before and after streaming it.
    pub(in crate::manage) database_bytes: u64,
    /// Lowercase SHA-256 of the database file, not a credential digest.
    pub(in crate::manage) database_sha256: String,
    /// Logical schema/row commitment for new retained-identity archives only.
    /// Legacy/ordinary backups omit it and never gain freshness approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::manage) database_content_sha256: Option<String>,
    /// This host's wall clock after copy/validation, not proof of age or ordering.
    pub(in crate::manage) created_at_unix_ms: u64,
}

/// Make a standalone SQLite snapshot while holding both offline writer gates.
///
/// The source must already have the current schema. The output is a new private
/// directory outside the source tree, with an existing private parent. No path
/// is overwritten and no service is stopped automatically. Locks fail promptly;
/// SQLite's existing backup step/lock budgets apply, not a hard filesystem or
/// whole-command deadline. Failed output is retained privately for diagnosis
/// and may be incomplete; callers must choose a different new output to retry.
pub(in crate::manage) fn create_backup(
    directory: &Path,
    output: &Path,
) -> io::Result<BackupManifest> {
    validate_directory(directory)?;
    private_file(&directory.join(DATABASE_NAME))?;
    let output = output_path(directory, output)?;
    let author = lock(directory)?;
    let update = update_lock(directory)?;
    create_copy(directory, &output, &author, &update, None)
}

/// Copy under the source guards already held while collecting identity assets.
/// A marker is flushed before SQL copying and an intrinsic takeover fence is
/// committed before any completed manifest. No source row or existing path is
/// modified. This does not grant permission to activate the retained identity.
pub(in crate::manage) fn create_identity_snapshot(
    directory: &Path,
    output: &Path,
    author: &super::Guard,
    update: &super::UpdateGuard,
    node_key_sha256: [u8; 32],
) -> io::Result<BackupManifest> {
    create_copy(directory, output, author, update, Some(node_key_sha256))
}

fn create_copy(
    directory: &Path,
    output: &Path,
    author: &super::Guard,
    update: &super::UpdateGuard,
    node_key_sha256: Option<[u8; 32]>,
) -> io::Result<BackupManifest> {
    author.ensure(directory)?;
    update.ensure(directory)?;
    private_file(&directory.join(DATABASE_NAME))?;
    let output = output_path(directory, output)?;
    let mut source = open_existing(directory, true)?;
    copy_locked(directory, &output, &mut source, node_key_sha256)
}

/// Only the Source snapshot adapter supplies this original validated connection.
/// The source is never written: the sole new database is intrinsically inert.
/// This is not a general writable opener or an alternative startup permission.
#[cfg(feature = "witness-journal")]
pub(super) fn create_source_identity_snapshot(
    directory: &Path,
    output: &Path,
    author: &super::Guard,
    update: &super::UpdateGuard,
    source: &mut Connection,
    node_key_sha256: [u8; 32],
) -> io::Result<BackupManifest> {
    author.ensure(directory)?;
    update.ensure(directory)?;
    private_file(&directory.join(DATABASE_NAME))?;
    if !source.is_autocommit()
        || fs::canonicalize(
            source
                .path()
                .ok_or_else(|| invalid_data("source path missing"))?,
        )? != fs::canonicalize(directory.join(DATABASE_NAME))?
        || super::source::load(source, SCHEMA_VERSION)?.is_none()
    {
        return Err(invalid_data(
            "source snapshot connection does not match its author",
        ));
    }
    let output = output_path(directory, output)?;
    copy_locked(directory, &output, source, Some(node_key_sha256))
}

fn copy_locked(
    directory: &Path,
    output: &Path,
    source: &mut Connection,
    node_key_sha256: Option<[u8; 32]>,
) -> io::Result<BackupManifest> {
    // This excludes non-cooperating SQLite writers too. Backup reads through a
    // separate connection: SQLite does not allow backing up its writer handle.
    let transaction = source
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin offline backup snapshot", error))?;
    let overview = read_overview(&transaction)?;
    require_current(overview.schema_version)?;
    let snapshot = node_key_sha256
        .map(|key| super::recovery::prepare_snapshot(&transaction, key))
        .transpose()?;
    create_directory(output)?;
    if let Some(snapshot) = &snapshot {
        let bytes = serde_json::to_vec(snapshot)
            .map_err(|_| io::Error::other("cannot encode identity snapshot marker"))?;
        super::super::files::write(output, SNAPSHOT_FILE, &bytes)?;
    }
    let destination = output.join(if snapshot.is_some() {
        SNAPSHOT_DATABASE_FILE
    } else {
        DATABASE_NAME
    });
    backup_existing(directory, &destination, &overview)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot complete offline backup snapshot", error))?;
    if let Some(snapshot) = &snapshot {
        let source_hash = fingerprint(&destination)?.1;
        // This exact private CreateNew copy still contains the source binding.
        // Ordinary open must keep refusing that binding. Only this unpublished
        // copy is opened here to install its intrinsic PendingTakeover fence;
        // it is not a writable opener for the original or an activation path.
        let mut copied = super::connect(&destination, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure(&copied)?;
        super::recovery::seal_snapshot(&mut copied, snapshot, &source_hash)?;
        copied
            .close()
            .map_err(|(_, error)| sqlite_error("cannot close quarantined identity copy", error))?;
        publish_snapshot_database(output, snapshot)?;
    }
    validate_snapshot(output, snapshot.as_ref())?;
    let (database_bytes, database_sha256) = fingerprint(&output.join(DATABASE_NAME))?;
    let manifest = BackupManifest {
        format_version: if snapshot.is_some() {
            SNAPSHOT_FORMAT
        } else {
            FORMAT_VERSION
        },
        application_id: APPLICATION_ID,
        schema_version: overview.schema_version,
        node_id: overview.node_id,
        database_bytes,
        database_sha256,
        database_content_sha256: snapshot
            .as_ref()
            .and_then(|s| s.database_content_sha256.clone()),
        created_at_unix_ms: u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| io::Error::other("management backup clock is before the Unix epoch"))?
                .as_millis(),
        )
        .map_err(|_| io::Error::other("management backup clock exceeds its supported range"))?,
    };
    let encoded = serde_json::to_vec_pretty(&manifest)
        .map_err(|_| io::Error::other("cannot encode management backup manifest"))?;
    let mut file = new_file(&output.join(MANIFEST_NAME))?;
    file.write_all(&encoded)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    // The private Windows writer intentionally does not share write access.
    // Close it before the audited readers hash and inspect the completed package.
    drop(file);
    sync_directory(output)?;
    check_entries(output, snapshot.is_some())?;
    compare_fingerprint(&output.join(DATABASE_NAME), &manifest)?;
    Ok(manifest)
}

/// Publish only an already sealed, closed copy. A hard link provides an atomic
/// no-replace claim using the same private inode/DACL; rename would overwrite
/// an unexpected destination. Only the task-owned temporary link is removed.
/// Interruption can leave two links or a partial name, but never a Ready live
/// database. Unsupported hard links fail closed; no copy/rename fallback runs.
fn publish_snapshot_database(
    output: &Path,
    snapshot: &super::recovery::Snapshot,
) -> io::Result<()> {
    let partial = output.join(SNAPSHOT_DATABASE_FILE);
    private_file(&partial)?;
    let connection = super::open(&partial, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    configure(&connection)?;
    super::recovery::check_snapshot(&connection, Some(snapshot))?;
    connection
        .close()
        .map_err(|(_, error)| sqlite_error("cannot close sealed snapshot inspection", error))?;
    fs::hard_link(&partial, output.join(DATABASE_NAME))?;
    fs::remove_file(partial)?;
    sync_directory(output)
}

/// Verify one completed package, without opening live state or restoring data.
///
/// Rejects sidecars, symbolic-link leaves, hard links/non-private Unix modes,
/// non-private Windows DACLs/reparse points, unknown namespace/schema,
/// manifest/size/hash mismatches and SQLite integrity/foreign-key failures. Typed
/// readers additionally validate access/routing/presets, peer summaries, owner
/// state and local traffic restoration seeds/counts. This is not a full semantic
/// validator for all audit, remote-traffic, certificate or executable outbox
/// rows. Schema20's non-executable controller history has a separate typed
/// validator; accepting its metadata never grants permission to replay a job.
/// Schema21 also validates retained events and episode/acknowledgement metadata;
/// those records cannot restore live observations or node control authority.
/// The bundled SQLite omits CHECK expressions on read-only connections, so only
/// the typed subset's equivalent constraints are additionally checked here.
/// Full integrity checking and file reads have no hard whole-command deadline;
/// SQLite lock waits retain the store's bounded timeout. Run on trusted private
/// storage; parent ACLs and hostile same-account path replacement are not audited.
pub(in crate::manage) fn verify_backup(input: &Path) -> io::Result<BackupManifest> {
    validate_directory(input)?;
    #[cfg(windows)]
    crate::windows_files::check_directory(input, true)?;
    let path = input.join(MANIFEST_NAME);
    let mut encoded = Vec::new();
    private_reader(&path)?
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(invalid_data(
            "management backup manifest exceeds its size limit",
        ));
    }
    let manifest: BackupManifest = serde_json::from_slice(&encoded)
        .map_err(|_| invalid_data("management backup manifest is malformed"))?;
    if !matches!(manifest.format_version, FORMAT_VERSION | SNAPSHOT_FORMAT)
        || manifest.application_id != APPLICATION_ID
        || !valid_id(&manifest.node_id)
        || manifest.database_sha256.len() != 64
        || !manifest
            .database_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_data(
            "management backup manifest is unsupported or malformed",
        ));
    }
    let snapshot = match manifest.format_version {
        SNAPSHOT_FORMAT => {
            let bytes = super::super::files::read(&input.join(SNAPSHOT_FILE), 1024, true)?;
            Some(
                serde_json::from_slice::<super::recovery::Snapshot>(&bytes)
                    .map_err(|_| invalid_data("identity snapshot marker is malformed"))?,
            )
        }
        _ => None,
    };
    if manifest.database_content_sha256
        != snapshot
            .as_ref()
            .and_then(|s| s.database_content_sha256.clone())
    {
        return Err(invalid_data(
            "backup content commitment does not match its snapshot marker",
        ));
    }
    check_entries(input, snapshot.is_some())?;
    require_supported(manifest.schema_version)?;
    let database = input.join(DATABASE_NAME);
    compare_fingerprint(&database, &manifest)?;
    let overview = validate_snapshot(input, snapshot.as_ref())?;
    if overview.node_id != manifest.node_id || overview.schema_version != manifest.schema_version {
        return Err(invalid_data(
            "management backup identity does not match its manifest",
        ));
    }
    compare_fingerprint(&database, &manifest)?;
    check_entries(input, snapshot.is_some())?;
    Ok(manifest)
}

/// Resolve existing ancestors before claiming a single new package directory.
pub(super) fn output_path(source: &Path, output: &Path) -> io::Result<PathBuf> {
    let absolute = if output.is_absolute() {
        output.to_owned()
    } else {
        std::env::current_dir()?.join(output)
    };
    let parent = absolute.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup output requires a parent directory",
        )
    })?;
    validate_directory(parent)?;
    let name = absolute.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup output requires a new directory name",
        )
    })?;
    let resolved = fs::canonicalize(parent)?.join(name);
    let source = fs::canonicalize(source)?;
    if resolved.starts_with(&source) || source.starts_with(&resolved) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup output must be outside the management data directory and its ancestors",
        ));
    }
    Ok(resolved)
}

pub(super) fn create_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return crate::windows_files::create_directory(path);
    #[cfg(not(windows))]
    {
        let builder = DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        builder.create(path)?;
        validate_directory(path)?;
        if let Some(parent) = path.parent() {
            sync_directory(parent)?;
        }
        Ok(())
    }
}

pub(super) fn new_file(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    return crate::windows_files::create_file(path);
    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        options.open(path)
    }
}

/// Refuse sidecars and extra leaves instead of allowing SQLite to replay them.
fn check_entries(directory: &Path, snapshot: bool) -> io::Result<()> {
    let mut count = 0_u8;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_name() != DATABASE_NAME
            && entry.file_name() != MANIFEST_NAME
            && !(snapshot && entry.file_name() == SNAPSHOT_FILE)
        {
            return Err(invalid_data(
                "management backup contains unexpected files or sidecars",
            ));
        }
        private_file(&entry.path())?;
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid_data("management backup contains too many files"))?;
    }
    if count != if snapshot { 3 } else { 2 } {
        return Err(invalid_data("management backup is incomplete"));
    }
    Ok(())
}

fn private_file(path: &Path) -> io::Result<()> {
    validate_database(path)?;
    #[cfg(windows)]
    drop(crate::windows_files::open_shared_file(path)?);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fs::symlink_metadata(path)?.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "management backup files must not have hard links",
            ));
        }
    }
    Ok(())
}

/// Keep the Windows handle whose DACL, link count and object type were audited
/// for the actual bounded read. Parent paths still belong to the operator.
fn private_reader(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    return crate::windows_files::open_shared_file(path);
    #[cfg(not(windows))]
    {
        private_file(path)?;
        File::open(path)
    }
}

pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn require_current(version: u32) -> io::Result<()> {
    if version != SCHEMA_VERSION {
        return Err(invalid_data(
            "management backup requires the current database schema",
        ));
    }
    Ok(())
}

/// Schema thirteen packages predate recovery fences but remain valid inputs;
/// known source versions are not silently upgraded or treated as a new node.
fn require_supported(version: u32) -> io::Result<()> {
    if !(13..=SCHEMA_VERSION).contains(&version) {
        return Err(invalid_data(
            "management backup schema version is unsupported",
        ));
    }
    Ok(())
}

/// Hash bounded chunks and at most the initially observed file length plus one.
fn fingerprint(path: &Path) -> io::Result<(u64, String)> {
    let file = private_reader(path)?;
    let size = file.metadata()?.len();
    let mut reader = file.take(
        size.checked_add(1)
            .ok_or_else(|| invalid_data("management backup file is too large"))?,
    );
    let mut hash = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .ok_or_else(|| invalid_data("management backup size overflow"))?;
        hash.update(&buffer[..count]);
    }
    if bytes != size || reader.get_ref().metadata()?.len() != size {
        return Err(invalid_data(
            "management backup changed during verification",
        ));
    }
    let mut encoded = String::with_capacity(64);
    for byte in hash.finalize() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 15)]));
    }
    Ok((size, encoded))
}

fn compare_fingerprint(path: &Path, manifest: &BackupManifest) -> io::Result<()> {
    let (size, hash) = fingerprint(path)?;
    if size != manifest.database_bytes || hash != manifest.database_sha256 {
        return Err(invalid_data(
            "management backup size or SHA-256 does not match its manifest",
        ));
    }
    Ok(())
}

/// SQLite integrity/foreign-key checks and typed readers, without migration/repair.
fn validate_snapshot(
    directory: &Path,
    snapshot: Option<&super::recovery::Snapshot>,
) -> io::Result<super::Overview> {
    let connection = open_snapshot(directory)?;
    let overview = read_overview(&connection)?;
    super::recovery::check_snapshot(&connection, snapshot)?;
    sqlite_checks(&connection)?;
    for table in tables(overview.schema_version) {
        let present: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
                [table],
                |row| row.get(0),
            )
            .map_err(|error| {
                sqlite_error("cannot inspect management backup table catalog", error)
            })?;
        if !present {
            return Err(invalid_data(
                "management backup is missing a required schema table",
            ));
        }
    }
    if let Some(snapshot) = snapshot
        && let Some(expected) = &snapshot.database_content_sha256
        && super::content::calculate(&connection, Some(snapshot))? != *expected
    {
        return Err(invalid_data(
            "identity snapshot content commitment does not match",
        ));
    }
    if overview.schema_version >= 16 {
        super::operations::validate_snapshot(&connection)?;
    }
    if overview.schema_version >= 17 {
        super::automation::validate_snapshot(&connection, overview.schema_version)?;
    }
    if overview.schema_version >= 18 {
        super::users::validate_operation_audit(&connection)?;
    }
    if overview.schema_version >= 19 {
        super::admission::validate_snapshot(&connection)?;
    }
    if overview.schema_version >= 20 {
        super::targets::history::validate_snapshot(&connection)?;
    }
    if overview.schema_version >= 21 {
        super::alerts::history::validate_snapshot(&connection)?;
    }
    if overview.schema_version >= 25 {
        super::witness::validate_snapshot(&connection, &overview.node_id)?;
    }
    if overview.schema_version >= 27 {
        super::proxy_service::validate_snapshot(&connection)?;
    }
    if overview.schema_version >= 28 {
        super::secrets::validate_snapshot(&connection)?;
    }
    drop(connection);
    super::load_policy(directory)?;
    super::list_peers(directory)?;
    super::ownership(directory)?;
    super::traffic::restore(directory)?;
    Ok(overview)
}

/// Exact supported application table inventory, shared by package validation
/// and logical content commitments. New persistent tables must enter both.
pub(super) fn tables(version: u32) -> impl Iterator<Item = &'static str> {
    TABLES_V13
        .iter()
        .copied()
        .chain((version >= 14).then_some("recovery_state"))
        .chain((version >= 15).then_some("endpoint_state"))
        .chain((version >= 15).then_some("endpoint_overrides"))
        .chain((version >= 15).then_some("endpoint_audit"))
        .chain((version >= 16).then_some("operations_state"))
        .chain((version >= 16).then_some("user_operations"))
        .chain((version >= 17).then_some("automation_state"))
        .chain((version >= 17).then_some("automation_principals"))
        .chain((version >= 17).then_some("automation_audit"))
        .chain((version >= 19).then_some("proxy_admission_state"))
        .chain((version >= 19).then_some("proxy_admission_audit"))
        .chain((version >= 20).then_some("controller_history_state"))
        .chain((version >= 20).then_some("controller_history"))
        .chain((version >= 21).then_some("alert_history_state"))
        .chain((version >= 21).then_some("alert_episodes"))
        .chain((version >= 21).then_some("alert_events"))
        .chain((version >= 23).then_some("webhook_state"))
        .chain((version >= 25).then_some("recovery_witness"))
        .chain((version >= 26).then_some("recovery_source"))
        .chain((version >= 27).then_some("proxy_service_state"))
        .chain((version >= 27).then_some("proxy_service_operations"))
        .chain((version >= 28).then_some("proxy_credential_secrets"))
}

/// Read typed restore input through the same immutable handle, then recheck the
/// entire manifest and file fingerprint. No source connection is writable.
pub(in crate::manage) fn read_verified<T>(
    input: &Path,
    read: impl FnOnce(&Connection, &BackupManifest) -> io::Result<T>,
) -> io::Result<T> {
    let before = verify_backup(input)?;
    let connection = open_snapshot(input)?;
    let value = read(&connection, &before)?;
    drop(connection);
    if verify_backup(input)? != before {
        return Err(invalid_data(
            "management backup changed while reading recovery input",
        ));
    }
    Ok(value)
}

fn open_snapshot(directory: &Path) -> io::Result<Connection> {
    let path = directory.join(DATABASE_NAME);
    private_file(&path)?;
    super::reject_orphan_sidecars(directory)?;
    let mut header = [0_u8; 100];
    File::open(&path)?.read_exact(&mut header)?;
    // immutable deliberately ignores WAL/locking. First require rollback-journal
    // format (header read/write versions 1), so a missing WAL is never mistaken
    // for a complete snapshot. No SQLite connection has been opened yet:
    // https://www.sqlite.org/fileformat.html#the_database_header
    if &header[..16] != b"SQLite format 3\0" || header[18] != 1 || header[19] != 1 {
        return Err(invalid_data(
            "management backup is not a standalone rollback-journal database",
        ));
    }
    // A normal READ_ONLY WAL connection may create sidecars. Only this private
    // package inspection uses immutable; live-store open semantics stay intact.
    // URL encoding prevents '?' / '#' in real paths becoming SQLite URI options:
    // https://www.sqlite.org/uri.html#uriimmutable
    let mut uri = url::Url::from_file_path(fs::canonicalize(&path)?)
        .map_err(|_| invalid_data("management backup path cannot be encoded as a file URL"))?;
    uri.query_pairs_mut()
        .append_pair("mode", "ro")
        .append_pair("immutable", "1");
    let connection = Connection::open_with_flags(
        uri.as_str(),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|error| sqlite_error("cannot open immutable management backup", error))?;
    configure(&connection)?;
    let overview = read_overview(&connection)?;
    require_supported(overview.schema_version)?;
    let journal: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|error| sqlite_error("cannot inspect management backup journal mode", error))?;
    if !journal.eq_ignore_ascii_case("delete") {
        return Err(invalid_data(
            "management backup must use standalone DELETE journal mode",
        ));
    }
    Ok(connection)
}

pub(super) fn sqlite_checks(connection: &Connection) -> io::Result<()> {
    // Use integrity_check rather than quick_check for index/UNIQUE coverage.
    // SQLite 3.53.2 discards CHECK expressions on read-only connections in
    // sqlite3AddCheckConstraint; do not claim all CHECK constraints are covered.
    // Foreign keys are separately excluded by integrity_check itself:
    // https://www.sqlite.org/pragma.html#pragma_integrity_check
    let mut statement = connection
        .prepare("PRAGMA integrity_check")
        .map_err(|error| sqlite_error("cannot prepare management backup integrity check", error))?;
    let mut rows = statement
        .query([])
        .map_err(|error| sqlite_error("cannot check management backup integrity", error))?;
    let mut ok = false;
    while let Some(row) = rows
        .next()
        .map_err(|error| sqlite_error("cannot read management backup integrity result", error))?
    {
        let result: String = row.get(0).map_err(|error| {
            sqlite_error("cannot decode management backup integrity result", error)
        })?;
        if ok || result != "ok" {
            return Err(invalid_data(
                "management backup failed SQLite integrity checking",
            ));
        }
        ok = true;
    }
    if !ok {
        return Err(invalid_data(
            "management backup has no SQLite integrity result",
        ));
    }
    let mut statement = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|error| {
            sqlite_error("cannot prepare management backup foreign-key check", error)
        })?;
    if statement
        .query([])
        .map_err(|error| sqlite_error("cannot check management backup foreign keys", error))?
        .next()
        .map_err(|error| sqlite_error("cannot read management backup foreign-key result", error))?
        .is_some()
    {
        return Err(invalid_data(
            "management backup failed SQLite foreign-key checking",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::open;
    use super::*;

    const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$Zml4dHVyZQ";
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Owns only one exclusively created random temporary leaf and its children.
    struct Fixture {
        root: PathBuf,
        source: PathBuf,
        output: PathBuf,
    }

    impl Fixture {
        fn new() -> io::Result<Self> {
            let root =
                std::env::temp_dir().join(format!("vproxy-backup-{}", super::super::random_id()?));
            create_directory(&root)?;
            let source = root.join("source");
            super::super::initialize(&source, "backup node", "admin", PHC)?;
            let output = root.join("backup");
            Ok(Self {
                root,
                source,
                output,
            })
        }

        /// Rewrite only fixture metadata so deeper SQLite checks are exercised,
        /// rather than having every corrupt fixture rejected by the earlier hash.
        fn update_manifest(&self) -> io::Result<()> {
            let path = self.output.join(MANIFEST_NAME);
            let mut manifest: BackupManifest = serde_json::from_slice(&fs::read(&path)?)?;
            let (size, hash) = fingerprint(&self.output.join(DATABASE_NAME))?;
            manifest.database_bytes = size;
            manifest.database_sha256 = hash;
            fs::write(path, serde_json::to_vec(&manifest)?)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn retained_copy_is_not_live_before_sealing_and_publication_never_replaces_a_leaf() -> TestResult
    {
        let fixture = Fixture::new()?;
        create_directory(&fixture.output)?;
        let source = open_existing(&fixture.source, false)?;
        let overview = read_overview(&source)?;
        let snapshot = super::super::recovery::prepare_snapshot(&source, [7; 32])?;
        drop(source);
        let partial = fixture.output.join(SNAPSHOT_DATABASE_FILE);
        backup_existing(&fixture.source, &partial, &overview)?;
        // Deliberately omit the filesystem marker: even its loss cannot expose a
        // native/Ready copied database through the ordinary startup filename.
        assert!(!fixture.output.join(DATABASE_NAME).exists());
        assert!(super::super::recovery::startup(&fixture.output).is_err());
        assert!(publish_snapshot_database(&fixture.output, &snapshot).is_err());
        assert!(!fixture.output.join(DATABASE_NAME).exists());
        let hash = fingerprint(&partial)?.1;
        let mut connection = super::super::open(&partial, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure(&connection)?;
        super::super::recovery::seal_snapshot(&mut connection, &snapshot, &hash)?;
        drop(connection);
        // No-replace publication protects even an unexpected private leaf.
        let sentinel = b"must not be replaced";
        super::super::super::files::write(&fixture.output, DATABASE_NAME, sentinel)?;
        assert_eq!(
            publish_snapshot_database(&fixture.output, &snapshot)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(fixture.output.join(DATABASE_NAME))?, sentinel);
        assert!(partial.exists());
        fs::remove_file(fixture.output.join(DATABASE_NAME))?;
        publish_snapshot_database(&fixture.output, &snapshot)?;
        assert!(!partial.exists());
        assert_eq!(
            super::super::recovery::startup(&fixture.output)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        private_file(&fixture.output.join(DATABASE_NAME))?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_backup_objects_have_private_dacls_and_linked_inputs_are_rejected() -> TestResult {
        let fixture = Fixture::new()?;
        let before = fs::read(fixture.source.join(DATABASE_NAME))?;
        let manifest = create_backup(&fixture.source, &fixture.output)?;
        crate::windows_files::check_directory(&fixture.output, true)?;
        for name in [DATABASE_NAME, MANIFEST_NAME] {
            drop(crate::windows_files::open_file(
                &fixture.output.join(name),
                true,
            )?);
            let alias = fixture.root.join("backup-alias");
            fs::hard_link(fixture.output.join(name), &alias)?;
            assert!(verify_backup(&fixture.output).is_err());
            fs::remove_file(alias)?;
        }
        assert_eq!(verify_backup(&fixture.output)?, manifest);
        assert_eq!(fs::read(fixture.source.join(DATABASE_NAME))?, before);
        Ok(())
    }

    fn controller_job(fixture: &Fixture) -> io::Result<super::super::targets::Job> {
        let connection = open_existing(&fixture.source, false)?;
        let actor: String = connection
            .query_row("SELECT id FROM administrators", [], |row| row.get(0))
            .map_err(|error| sqlite_error("cannot inspect backup history fixture actor", error))?;
        drop(connection);
        let peer = super::super::random_id()?;
        super::super::register_peer(
            &fixture.source,
            &peer,
            "backup history peer",
            b"public fixture certificate",
            "history.invalid",
            None,
        )?;
        super::super::targets::configure(
            &fixture.source,
            &actor,
            &peer,
            None,
            "https://history.invalid",
            true,
            None,
        )?;
        super::super::targets::observe(&fixture.source, &peer, 1, 2, 0, 1)?;
        super::super::targets::enqueue(
            &fixture.source,
            &actor,
            1,
            super::super::Command {
                target_node_id: peer,
                epoch: 2,
                command_id: 1,
                expected_policy_revision: 1,
                source_administrator_id: actor.clone(),
                change: super::super::PolicyChange::CreateUser {
                    name: "non-secret history fixture".into(),
                    protocols: vec![],
                    concurrent_limit: 1,
                },
            },
        )
    }

    #[test]
    fn history_metadata_is_verified_readonly_without_granting_execution_authority() -> TestResult {
        for mutation in [
            None,
            Some("DROP TABLE controller_history;"),
            Some("DELETE FROM controller_history_state;"),
            Some("UPDATE controller_history_state SET last_sequence=0;"),
            Some("UPDATE controller_history SET snapshot=x'7b7d';"),
            Some("UPDATE controller_history SET action='set_admission';"),
            Some("PRAGMA ignore_check_constraints=ON; UPDATE controller_history SET imported=2;"),
            Some(
                "PRAGMA ignore_check_constraints=ON; UPDATE controller_history SET recorded_at=-1;",
            ),
            Some("DELETE FROM controller_history;"),
        ] {
            let fixture = Fixture::new()?;
            let queued = controller_job(&fixture)?;
            let manifest = create_backup(&fixture.source, &fixture.output)?;
            assert_eq!(verify_backup(&fixture.output)?, manifest);
            let copied = open(
                &fixture.output.join(DATABASE_NAME),
                OpenFlags::SQLITE_OPEN_READ_WRITE,
            )?;
            let identity: (String, i64) = copied.query_row(
                "SELECT job_id,sequence FROM controller_history",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert_eq!(identity, (queued.job_id.clone(), 1));
            if let Some(sql) = mutation {
                copied.execute_batch(sql)?;
            }
            drop(copied);
            if mutation.is_some() {
                fixture.update_manifest()?;
            }
            let database = fs::read(fixture.output.join(DATABASE_NAME))?;
            let metadata = fs::read(fixture.output.join(MANIFEST_NAME))?;
            if mutation.is_some() {
                assert!(verify_backup(&fixture.output).is_err());
            } else {
                assert_eq!(verify_backup(&fixture.output)?, manifest);
            }
            assert_eq!(fs::read(fixture.output.join(DATABASE_NAME))?, database);
            assert_eq!(fs::read(fixture.output.join(MANIFEST_NAME))?, metadata);
            assert_eq!(fs::read_dir(&fixture.output)?.count(), 2);
            // Inspecting a package cannot consume, replay or change the live slot.
            assert!(
                super::super::targets::job(&fixture.source, &queued.peer_id)?
                    .is_some_and(|job| job.job_id == queued.job_id
                        && job.state == super::super::targets::JobState::Pending)
            );
        }
        Ok(())
    }

    #[test]
    fn backup_includes_committed_wal_and_does_not_change_source_state() -> TestResult {
        let fixture = Fixture::new()?;
        let connection = open_existing(&fixture.source, true)?;
        connection.pragma_update(None, "wal_autocheckpoint", 0)?;
        connection.execute(
            "UPDATE node_identity SET name='committed WAL name' WHERE singleton=1",
            [],
        )?;
        assert!(fs::metadata(fixture.source.join(format!("{DATABASE_NAME}-wal")))?.len() > 0);
        let original_database = fs::read(fixture.source.join(DATABASE_NAME))?;
        let original_wal = fs::read(fixture.source.join(format!("{DATABASE_NAME}-wal")))?;
        let manifest = create_backup(&fixture.source, &fixture.output)?;
        assert_eq!(manifest, verify_backup(&fixture.output)?);
        let package_bytes = fs::read(fixture.output.join(DATABASE_NAME))?;
        let package_manifest = fs::read(fixture.output.join(MANIFEST_NAME))?;
        verify_backup(&fixture.output)?;
        assert_eq!(fs::read(fixture.output.join(DATABASE_NAME))?, package_bytes);
        assert_eq!(
            fs::read(fixture.output.join(MANIFEST_NAME))?,
            package_manifest
        );
        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
        assert_eq!(read_overview(&connection)?.name, "committed WAL name");
        assert_eq!(
            super::super::inspect(&fixture.output)?.name,
            "committed WAL name"
        );
        assert_eq!(
            fs::read(fixture.source.join(DATABASE_NAME))?,
            original_database
        );
        assert_eq!(
            fs::read(fixture.source.join(format!("{DATABASE_NAME}-wal")))?,
            original_wal
        );
        let encoded = fs::read_to_string(fixture.output.join(MANIFEST_NAME))?;
        for secret in [
            PHC,
            "\"password_hash\"",
            "\"secret_digest\"",
            "\"certificate\"",
            "\"administrator\"",
        ] {
            assert!(!encoded.contains(secret));
        }
        let copied = open_existing(&fixture.output, false)?;
        let phc: String =
            copied.query_row("SELECT password_hash FROM administrators", [], |row| {
                row.get(0)
            })?;
        assert_eq!(phc, PHC); // The database, unlike its manifest, is secret-bearing.
        // Advancing SCHEMA_VERSION must also update the verifier's required table
        // catalog. A fresh initialized fixture is the canonical current schema.
        let mut statement = copied.prepare(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'",
    )?;
        let actual = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        let expected = TABLES_V13
            .iter()
            .copied()
            .chain(Some("recovery_state"))
            .chain(["endpoint_state", "endpoint_overrides", "endpoint_audit"])
            .chain(["operations_state", "user_operations"])
            .chain(["proxy_admission_state", "proxy_admission_audit"])
            .chain(["controller_history_state", "controller_history"])
            .chain(["alert_history_state", "alert_episodes", "alert_events"])
            .chain(Some("webhook_state"))
            .chain(Some("recovery_witness"))
            .chain(Some("recovery_source"))
            .chain(["proxy_service_state", "proxy_service_operations"])
            .chain(Some("proxy_credential_secrets"))
            .chain([
                "automation_state",
                "automation_principals",
                "automation_audit",
            ])
            .map(str::to_owned)
            .collect();
        assert_eq!(actual, expected);
        super::super::proxy_service::require_unused_for_test(&copied)?;
        super::super::notifications::ensure_unused_for_test(&copied)?;
        assert_eq!(fs::read_dir(&fixture.output)?.count(), 2);
        Ok(())
    }

    fn acknowledged_alert(
        fixture: &Fixture,
    ) -> io::Result<(String, super::super::alerts::history::Episode)> {
        use super::super::alerts::history::{
            self, Ack, Batch, Observation, Transition, TransitionKind,
        };
        let connection = open_existing(&fixture.source, false)?;
        let actor: String = connection
            .query_row("SELECT id FROM administrators", [], |row| row.get(0))
            .map_err(|error| sqlite_error("cannot inspect alert backup actor", error))?;
        let node = read_overview(&connection)?.node_id;
        drop(connection);
        let gate = update_lock(&fixture.source)?;
        let boot = super::super::random_id()?;
        history::start(&fixture.source, &gate, &boot)?;
        let commit = history::record(
            &fixture.source,
            &gate,
            &Batch {
                boot_id: boot,
                sequence: 1,
                transitions: vec![Transition {
                    kind: TransitionKind::Opened,
                    observation: Observation {
                        incident_id: 1,
                        kind: crate::manage::alerts::Kind::EgressCheck,
                        origin_node_id: node.clone(),
                        resource_id: Some(super::super::random_id()?),
                        slot: "bind".into(),
                        check: Some(crate::manage::health::CheckKind::Bind),
                        target: None,
                        code: "egress_failed".into(),
                        first_observed_at_unix_ms: Some(1),
                        last_observed_at_unix_ms: Some(1),
                        evidence_sequence: Some(1),
                    },
                    observed_at_unix_ms: Some(1),
                    ended_reason: None,
                }],
            },
        )?;
        let sequence = commit
            .first_event_sequence
            .ok_or_else(|| io::Error::other("missing fixture transition"))?;
        let episode = history::acknowledge(
            &fixture.source,
            &gate,
            &actor,
            &Ack {
                expected_node_id: node,
                episode_id: sequence,
                expected_transition_sequence: sequence,
            },
        )?;
        Ok((actor, episode))
    }

    #[test]
    fn alert_events_and_acknowledgements_are_verified_readonly_after_matching_hash() -> TestResult {
        use super::super::alerts::history;
        for mutation in [
            None,
            Some("DROP TABLE alert_events;"),
            Some("DELETE FROM alert_history_state;"),
            Some("UPDATE alert_history_state SET last_sequence=0;"),
            Some("DELETE FROM alert_events WHERE sequence=2;"),
            Some("UPDATE alert_events SET payload=x'7b7d';"),
            Some("UPDATE alert_episodes SET payload=x'7b7d';"),
            Some("UPDATE alert_episodes SET ack_event_sequence=1;"),
            Some("UPDATE alert_events SET administrator_id=NULL WHERE sequence=2;"),
            Some(
                "PRAGMA ignore_check_constraints=ON; UPDATE alert_history_state SET batch_sequence=-1;",
            ),
        ] {
            let fixture = Fixture::new()?;
            let (actor, episode) = acknowledged_alert(&fixture)?;
            assert!(episode.is_acknowledged);
            let manifest = create_backup(&fixture.source, &fixture.output)?;
            assert_eq!(manifest.schema_version, SCHEMA_VERSION);
            assert_eq!(
                history::episode(&fixture.output, &actor, episode.id)?,
                Some(episode.clone())
            );
            let ack = history::get(&fixture.output, &actor, 2)?.expect("real acknowledgement");
            assert_eq!(ack.kind, history::EventKind::Acknowledged);
            assert_eq!(ack.administrator_id.as_deref(), Some(actor.as_str()));
            let copied = open(
                &fixture.output.join(DATABASE_NAME),
                OpenFlags::SQLITE_OPEN_READ_WRITE,
            )?;
            if let Some(sql) = mutation {
                copied.execute_batch(sql)?;
            }
            drop(copied);
            if mutation.is_some() {
                fixture.update_manifest()?;
            }
            let database = fs::read(fixture.output.join(DATABASE_NAME))?;
            let metadata = fs::read(fixture.output.join(MANIFEST_NAME))?;
            if mutation.is_some() {
                assert!(verify_backup(&fixture.output).is_err());
            } else {
                assert_eq!(verify_backup(&fixture.output)?, manifest);
            }
            assert_eq!(fs::read(fixture.output.join(DATABASE_NAME))?, database);
            assert_eq!(fs::read(fixture.output.join(MANIFEST_NAME))?, metadata);
            assert_eq!(fs::read_dir(&fixture.output)?.count(), 2);
            assert_eq!(
                history::episode(&fixture.source, &actor, episode.id)?,
                Some(episode)
            );
        }
        Ok(())
    }

    #[test]
    fn real_schema_twenty_one_package_restores_as_new_without_old_authority_or_events() -> TestResult
    {
        use super::super::{PolicyChange, alerts::history, recovery};
        use rcgen::PublicKeyData as _;

        let fixture = Fixture::new()?;
        let queued = controller_job(&fixture)?;
        let (actor, episode) = acknowledged_alert(&fixture)?;
        let created = super::super::apply_policy(
            &fixture.source,
            &actor,
            1,
            PolicyChange::CreateUser {
                name: "legacy recovery draft".into(),
                protocols: vec![crate::access::Protocol::Http],
                concurrent_limit: 2,
            },
            &update_lock(&fixture.source)?,
        )?;
        let user = created.user.expect("source user").id;
        super::super::apply_policy(
            &fixture.source,
            &actor,
            created.policy.revision,
            PolicyChange::CreateCredential {
                user_id: user.clone(),
            },
            &update_lock(&fixture.source)?,
        )?;
        assert_eq!(
            super::super::load_policy(&fixture.source)?
                .credentials
                .len(),
            1
        );
        let mut manifest = create_backup(&fixture.source, &fixture.output)?;
        let copied = open(
            &fixture.output.join(DATABASE_NAME),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        // Reconstruct the actual old recovery CHECK, not just its user_version.
        // Local events and acknowledgements retain their original typed bytes.
        recovery::restore_schema_twenty_one_for_test(&copied)?;
        let ddl: String = copied.query_row(
            "SELECT sql FROM sqlite_schema WHERE name='recovery_state'",
            [],
            |row| row.get(0),
        )?;
        assert!(ddl.contains("13,14,15,16,17,18,19,20,21"));
        assert!(!ddl.contains(",22"));
        drop(copied);
        manifest.schema_version = 21;
        (manifest.database_bytes, manifest.database_sha256) =
            fingerprint(&fixture.output.join(DATABASE_NAME))?;
        fs::write(
            fixture.output.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest)?,
        )?;
        let database = fs::read(fixture.output.join(DATABASE_NAME))?;
        let metadata = fs::read(fixture.output.join(MANIFEST_NAME))?;
        assert_eq!(verify_backup(&fixture.output)?, manifest);
        assert_eq!(
            history::episode(&fixture.output, &actor, episode.id)?,
            Some(episode)
        );
        let ack = history::get(&fixture.output, &actor, 2)?.expect("legacy acknowledgement");
        assert_eq!(ack.kind, history::EventKind::Acknowledged);
        assert_eq!(ack.administrator_id.as_deref(), Some(actor.as_str()));

        let key = rcgen::KeyPair::generate()?;
        let identity = recovery::Identity {
            key_pem: zeroize::Zeroizing::new(key.serialize_pem()),
            request_pem: rcgen::CertificateParams::new(vec!["new.invalid".into()])?
                .serialize_request(&key)?
                .pem()?,
            public_key_sha256: Sha256::digest(key.subject_public_key_info()).into(),
        };
        let output = fixture.root.join("restored");
        let restored = recovery::restore(
            &fixture.output,
            &output,
            "new node",
            "new-admin",
            "new fixture PHC",
            identity,
        )?;
        assert_eq!(restored.schema_version, SCHEMA_VERSION);
        assert_ne!(restored.node_id, manifest.node_id);
        let record = restored.recovery.expect("new identity provenance");
        assert_eq!(record.source_schema_version, 21);
        assert_eq!(record.source_node_id, manifest.node_id);
        assert_eq!(record.phase, recovery::Phase::PendingReview);
        assert_eq!(
            recovery::startup(&output).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let policy = super::super::load_policy(&output)?;
        assert_eq!(policy.users.len(), 1);
        assert_ne!(policy.users[0].id, user);
        assert!(!policy.users[0].active && policy.users[0].protocols.is_empty());
        assert!(policy.credentials.is_empty());
        let destination = open_existing(&output, false)?;
        let administrator: (String, String) =
            destination.query_row("SELECT id,password_hash FROM administrators", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;
        assert_ne!(administrator.0, actor);
        assert_eq!(administrator.1, "new fixture PHC");
        history::require_empty(&destination)?;
        let empty: (i64, i64, i64, i64, i64) = destination.query_row(
        "SELECT (SELECT count(*) FROM peers), (SELECT count(*) FROM peer_certificates), (SELECT count(*) FROM control_outbox), (SELECT count(*) FROM controller_history), (SELECT last_sequence FROM controller_history_state)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    )?;
        assert_eq!(empty, (0, 0, 0, 0, 0));
        drop(destination);
        assert!(super::super::targets::job(&output, &queued.peer_id)?.is_none());
        assert_eq!(verify_backup(&fixture.output)?, manifest);
        assert_eq!(fs::read(fixture.output.join(DATABASE_NAME))?, database);
        assert_eq!(fs::read(fixture.output.join(MANIFEST_NAME))?, metadata);
        assert_eq!(fs::read_dir(&fixture.output)?.count(), 2);
        Ok(())
    }

    #[test]
    fn offline_gates_fail_before_creating_a_package() -> TestResult {
        let fixture = Fixture::new()?;
        let author = lock(&fixture.source)?;
        assert_eq!(
            create_backup(&fixture.source, &fixture.output)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(!fixture.output.exists());
        drop(author);
        let update = update_lock(&fixture.source)?;
        assert_eq!(
            create_backup(&fixture.source, &fixture.output)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(!fixture.output.exists());
        drop(update);
        create_backup(&fixture.source, &fixture.output)?;
        Ok(())
    }

    #[test]
    fn admission_state_and_actor_rows_are_verified_readonly_after_matching_manifest_hash()
    -> TestResult {
        for mutation in [
            None,
            Some(
                "PRAGMA ignore_check_constraints=ON; UPDATE proxy_admission_state SET accepting=2;",
            ),
            Some("DELETE FROM proxy_admission_state;"),
            Some(
                "PRAGMA ignore_check_constraints=ON; UPDATE proxy_admission_audit SET entry='automation_management';",
            ),
            Some(
                "PRAGMA ignore_check_constraints=ON; UPDATE proxy_admission_audit SET accepting=2;",
            ),
        ] {
            let fixture = Fixture::new()?;
            let connection = open_existing(&fixture.source, false)?;
            let administrator: String =
                connection.query_row("SELECT id FROM administrators", [], |row| row.get(0))?;
            let node = read_overview(&connection)?.node_id;
            drop(connection);
            let gate = update_lock(&fixture.source)?;
            super::super::apply_policy_asserted(
                &fixture.source,
                &administrator,
                1,
                super::super::PolicyChange::SetAdmission { accepting: false },
                &gate,
                &super::super::admission::Assertion {
                    node_id: node,
                    epoch: 1,
                },
            )?;
            drop(gate);
            create_backup(&fixture.source, &fixture.output)?;
            assert!(!super::super::load_policy(&fixture.output)?.accepting);
            let Some(mutation) = mutation else { continue };
            let copied = open(
                &fixture.output.join(DATABASE_NAME),
                OpenFlags::SQLITE_OPEN_READ_WRITE,
            )?;
            copied.execute_batch(mutation)?;
            drop(copied);
            fixture.update_manifest()?;
            let database = fs::read(fixture.output.join(DATABASE_NAME))?;
            let manifest = fs::read(fixture.output.join(MANIFEST_NAME))?;
            assert!(verify_backup(&fixture.output).is_err());
            assert_eq!(fs::read(fixture.output.join(DATABASE_NAME))?, database);
            assert_eq!(fs::read(fixture.output.join(MANIFEST_NAME))?, manifest);
        }
        Ok(())
    }

    #[test]
    fn backup_never_reuses_an_existing_target_or_source_tree() -> TestResult {
        let fixture = Fixture::new()?;
        fs::write(&fixture.output, b"keep existing file")?;
        assert_eq!(
            create_backup(&fixture.source, &fixture.output)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&fixture.output)?, b"keep existing file");
        fs::remove_file(&fixture.output)?;
        create_directory(&fixture.output)?;
        assert_eq!(
            create_backup(&fixture.source, &fixture.output)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        for output in [
            &fixture.source,
            &fixture.source.join("nested"),
            &fixture.root,
        ] {
            assert!(create_backup(&fixture.source, output).is_err());
        }
        assert_eq!(super::super::inspect(&fixture.source)?.name, "backup node");
        Ok(())
    }

    #[test]
    fn verify_refuses_missing_markers_sidecars_and_manifest_changes() -> TestResult {
        let fixture = Fixture::new()?;
        let manifest = create_backup(&fixture.source, &fixture.output)?;
        let path = fixture.output.join(MANIFEST_NAME);
        let original = fs::read(&path)?;
        fs::remove_file(&path)?;
        assert!(verify_backup(&fixture.output).is_err());
        fs::write(&path, &original)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        let sidecar = fixture.output.join(format!("{DATABASE_NAME}-wal"));
        fs::write(&sidecar, b"must not be replayed")?;
        assert!(verify_backup(&fixture.output).is_err());
        fs::remove_file(sidecar)?;
        for value in [
            serde_json::json!({"format_version": 99}),
            {
                let mut value = serde_json::to_value(&manifest)?;
                value["database_bytes"] = 1.into();
                value
            },
            {
                let mut value = serde_json::to_value(&manifest)?;
                value["database_sha256"] = "0".repeat(64).into();
                value
            },
            {
                let mut value = serde_json::to_value(&manifest)?;
                value["node_id"] = super::super::random_id()?.into();
                value
            },
            {
                let mut value = serde_json::to_value(&manifest)?;
                value["schema_version"] = (SCHEMA_VERSION + 1).into();
                value
            },
            {
                let mut value = serde_json::to_value(&manifest)?;
                value["unexpected"] = true.into();
                value
            },
        ] {
            fs::write(&path, serde_json::to_vec(&value)?)?;
            assert!(verify_backup(&fixture.output).is_err());
        }
        fs::write(&path, original)?;
        assert_eq!(verify_backup(&fixture.output)?, manifest);
        Ok(())
    }

    #[test]
    fn verify_rejects_wrong_namespace_schema_missing_tables_and_corrupt_bytes() -> TestResult {
        for statement in [
            "PRAGMA application_id=0",
            "PRAGMA user_version=1",
            "PRAGMA user_version=999",
            "DROP TABLE administrator_audit",
        ] {
            let fixture = Fixture::new()?;
            create_backup(&fixture.source, &fixture.output)?;
            let connection = open(
                &fixture.output.join(DATABASE_NAME),
                OpenFlags::SQLITE_OPEN_READ_WRITE,
            )?;
            connection.execute_batch(statement)?;
            drop(connection);
            fixture.update_manifest()?;
            assert!(verify_backup(&fixture.output).is_err(), "{statement}");
        }
        let fixture = Fixture::new()?;
        create_backup(&fixture.source, &fixture.output)?;
        fs::write(fixture.output.join(DATABASE_NAME), b"not a SQLite database")?;
        fixture.update_manifest()?;
        assert!(verify_backup(&fixture.output).is_err());
        Ok(())
    }

    #[test]
    fn verify_rejects_wal_format_without_creating_or_replaying_sidecars() -> TestResult {
        let fixture = Fixture::new()?;
        create_backup(&fixture.source, &fixture.output)?;
        let path = fixture.output.join(DATABASE_NAME);
        let connection = open(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute("UPDATE node_identity SET name='WAL snapshot'", [])?;
        connection
            .close()
            .map_err(|(_, error)| io::Error::other(error))?;
        fixture.update_manifest()?;
        let database = fs::read(&path)?;
        let manifest = fs::read(fixture.output.join(MANIFEST_NAME))?;
        assert_eq!(&database[18..20], &[2, 2]);
        assert_eq!(fs::read_dir(&fixture.output)?.count(), 2);
        assert!(verify_backup(&fixture.output).is_err());
        assert_eq!(fs::read_dir(&fixture.output)?.count(), 2);
        assert_eq!(fs::read(path)?, database);
        assert_eq!(fs::read(fixture.output.join(MANIFEST_NAME))?, manifest);
        Ok(())
    }

    #[test]
    fn verify_checks_typed_endpoint_rows_without_mutating_a_matching_hash_package() -> TestResult {
        let fixture = Fixture::new()?;
        create_backup(&fixture.source, &fixture.output)?;
        let connection = open(
            &fixture.output.join(DATABASE_NAME),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        configure(&connection)?;
        let node = read_overview(&connection)?.node_id;
        let bind = "127.0.0.1:18080".parse()?;
        let id =
            crate::manage::proxy::endpoint_id(&node, crate::manage::proxy::Protocol::Http, bind);
        connection.execute_batch("PRAGMA ignore_check_constraints=ON;")?;
        connection.execute(
            "UPDATE endpoint_state SET revision=2,digest=?1",
            ["0".repeat(64)],
        )?;
        connection.execute(
        "INSERT INTO endpoint_overrides VALUES(?1,'http',?2,'custom','https://wrong.example:443')",
        rusqlite::params![id, bind.to_string()],
    )?;
        drop(connection);
        fixture.update_manifest()?;
        let database = fs::read(fixture.output.join(DATABASE_NAME))?;
        let manifest = fs::read(fixture.output.join(MANIFEST_NAME))?;
        assert!(verify_backup(&fixture.output).is_err());
        assert_eq!(fs::read(fixture.output.join(DATABASE_NAME))?, database);
        assert_eq!(fs::read(fixture.output.join(MANIFEST_NAME))?, manifest);
        assert_eq!(fs::read_dir(&fixture.output)?.count(), 2);
        Ok(())
    }

    #[test]
    fn verify_checks_operation_rows_readonly_even_when_manifest_hash_matches() -> TestResult {
        use super::super::operations::{self, Input, UserChange};

        for mutation in [
            "PRAGMA ignore_check_constraints=ON; UPDATE user_operations SET state='saved',saved_revision=NULL;",
            "UPDATE operations_state SET last_sequence=0;",
            "PRAGMA user_version=15;",
        ] {
            let fixture = Fixture::new()?;
            let connection = open_existing(&fixture.source, false)?;
            let actor: String =
                connection.query_row("SELECT id FROM administrators", [], |row| row.get(0))?;
            drop(connection);
            let input = Input {
                expected_node_id: None,
                expected_revision: 1,
                expected_epoch: 1,
                change: UserChange::CreateUser {
                    name: "backup operation".into(),
                    protocols: vec![crate::access::Protocol::Http],
                    concurrent_limit: 1,
                },
            };
            operations::reserve(
                &fixture.source,
                &update_lock(&fixture.source)?,
                &actor,
                &input,
            )?;
            create_backup(&fixture.source, &fixture.output)?;
            assert_eq!(
                verify_backup(&fixture.output)?.schema_version,
                SCHEMA_VERSION
            );
            let connection = open(
                &fixture.output.join(DATABASE_NAME),
                OpenFlags::SQLITE_OPEN_READ_WRITE,
            )?;
            connection.execute_batch(mutation)?;
            drop(connection);
            fixture.update_manifest()?;
            let database = fs::read(fixture.output.join(DATABASE_NAME))?;
            let manifest = fs::read(fixture.output.join(MANIFEST_NAME))?;
            assert!(verify_backup(&fixture.output).is_err(), "{mutation}");
            assert_eq!(fs::read(fixture.output.join(DATABASE_NAME))?, database);
            assert_eq!(fs::read(fixture.output.join(MANIFEST_NAME))?, manifest);
            assert_eq!(fs::read_dir(&fixture.output)?.count(), 2);
        }
        Ok(())
    }

    #[test]
    fn verify_checks_machine_policy_actor_rows_without_trusting_readonly_checks() -> TestResult {
        use crate::manage::store::{automation, operations};
        use std::sync::Arc;
        use zeroize::Zeroizing;

        for mutation in [
            "PRAGMA ignore_check_constraints=ON; UPDATE proxy_policy_audit SET automation_generation=NULL;",
            "PRAGMA ignore_check_constraints=ON; UPDATE proxy_policy_audit SET administrator_id=(SELECT id FROM administrators);",
            "UPDATE proxy_policy_audit SET automation_generation=automation_generation+1;",
            "UPDATE user_operations SET automation_principal_id=(SELECT id FROM automation_principals WHERE scope='users:read');",
            "UPDATE proxy_policy_audit SET automation_principal_id=(SELECT id FROM automation_principals WHERE scope='users:read');",
        ] {
            let fixture = Fixture::new()?;
            let mut token = Zeroizing::new(String::new());
            let writer = automation::create(
                &fixture.source,
                "backup writer",
                automation::Scope::UsersWrite,
                3600,
                |value| {
                    token.push_str(value);
                    Ok(())
                },
            )?;
            automation::create(
                &fixture.source,
                "backup reader",
                automation::Scope::UsersRead,
                3600,
                |_| Ok(()),
            )?;
            let caller =
                operations::Caller::Automation(Arc::new(automation::Credential::parse(&token)?));
            let input = operations::Input {
                expected_node_id: None,
                expected_revision: 1,
                expected_epoch: 1,
                change: operations::UserChange::CreateUser {
                    name: "machine backup user".into(),
                    protocols: vec![crate::access::Protocol::Http],
                    concurrent_limit: 1,
                },
            };
            let gate = update_lock(&fixture.source)?;
            let reserved = operations::reserve_as(&fixture.source, &gate, &caller, &input)?;
            assert!(matches!(
                operations::execute_as(&fixture.source, &gate, &caller, &reserved.id, input)?,
                operations::Outcome::Accepted { .. }
            ));
            drop(gate);
            // Revocation cannot erase valid historical write provenance. Creating
            // this backup succeeds before either actor is forged to the reader.
            automation::revoke(&fixture.source, &writer.id, writer.generation)?;
            create_backup(&fixture.source, &fixture.output)?;
            let connection = open(
                &fixture.output.join(DATABASE_NAME),
                OpenFlags::SQLITE_OPEN_READ_WRITE,
            )?;
            connection.execute_batch(mutation)?;
            drop(connection);
            fixture.update_manifest()?;
            let database = fs::read(fixture.output.join(DATABASE_NAME))?;
            let manifest = fs::read(fixture.output.join(MANIFEST_NAME))?;
            assert!(verify_backup(&fixture.output).is_err());
            assert!(fs::read(fixture.output.join(DATABASE_NAME))? == database);
            assert!(fs::read(fixture.output.join(MANIFEST_NAME))? == manifest);
            assert_eq!(fs::read_dir(&fixture.output)?.count(), 2);
        }
        Ok(())
    }

    #[test]
    fn backup_preserves_automation_authority_and_checks_matching_hash_rows_readonly() -> TestResult
    {
        use super::super::automation;

        for mutation in [
            None,
            Some("UPDATE automation_state SET last_sequence=0"),
            Some(
                "PRAGMA ignore_check_constraints=ON; UPDATE automation_principals SET secret_digest=x'01' WHERE revoked=0",
            ),
            Some("PRAGMA user_version=16"),
        ] {
            let fixture = Fixture::new()?;
            // Keep committed changes in WAL while the backup takes its snapshot.
            let source = open_existing(&fixture.source, true)?;
            source.pragma_update(None, "wal_autocheckpoint", 0)?;
            let principal = automation::create(
                &fixture.source,
                "active automation",
                automation::Scope::UsersRead,
                3600,
                |_| Ok(()),
            )?;
            automation::rotate(
                &fixture.source,
                &principal.id,
                principal.generation,
                3600,
                |_| Ok(()),
            )?;
            let revoked = automation::create(
                &fixture.source,
                "revoked automation",
                automation::Scope::UsersRead,
                3600,
                |_| Ok(()),
            )?;
            automation::revoke(&fixture.source, &revoked.id, revoked.generation)?;
            let expected = automation::list(&fixture.source)?;
            let source_database = fs::read(fixture.source.join(DATABASE_NAME))?;
            let source_wal = fs::read(fixture.source.join(format!("{DATABASE_NAME}-wal")))?;

            let manifest = create_backup(&fixture.source, &fixture.output)?;
            assert_eq!(manifest.schema_version, SCHEMA_VERSION);
            assert_eq!(automation::list(&fixture.output)?, expected);
            let copied = open_existing(&fixture.output, false)?;
            let state: (i64, i64, i64) = copied.query_row(
                "SELECT (SELECT last_sequence FROM automation_state WHERE singleton=1),
                    (SELECT count(*) FROM automation_principals),
                    (SELECT count(*) FROM automation_audit)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            assert_eq!(state, (4, 2, 4));
            drop(copied);
            assert_eq!(
                fs::read(fixture.source.join(DATABASE_NAME))?,
                source_database
            );
            assert_eq!(
                fs::read(fixture.source.join(format!("{DATABASE_NAME}-wal")))?,
                source_wal
            );
            drop(source);

            if let Some(sql) = mutation {
                let copied = open(
                    &fixture.output.join(DATABASE_NAME),
                    OpenFlags::SQLITE_OPEN_READ_WRITE,
                )?;
                copied.execute_batch(sql)?;
                drop(copied);
                fixture.update_manifest()?;
            }
            let database = fs::read(fixture.output.join(DATABASE_NAME))?;
            let manifest = fs::read(fixture.output.join(MANIFEST_NAME))?;
            if mutation.is_some() {
                assert!(verify_backup(&fixture.output).is_err(), "{mutation:?}");
            } else {
                verify_backup(&fixture.output)?;
            }
            assert_eq!(fs::read(fixture.output.join(DATABASE_NAME))?, database);
            assert_eq!(fs::read(fixture.output.join(MANIFEST_NAME))?, manifest);
            assert_eq!(fs::read_dir(&fixture.output)?.count(), 2);
        }
        Ok(())
    }

    #[test]
    fn verify_refuses_main_file_copied_without_its_committed_wal() -> TestResult {
        let fixture = Fixture::new()?;
        create_backup(&fixture.source, &fixture.output)?;
        let connection = open_existing(&fixture.source, true)?;
        connection.pragma_update(None, "wal_autocheckpoint", 0)?;
        connection.execute("UPDATE node_identity SET name='only in committed WAL'", [])?;
        assert!(fs::metadata(fixture.source.join(format!("{DATABASE_NAME}-wal")))?.len() > 0);
        fs::copy(
            fixture.source.join(DATABASE_NAME),
            fixture.output.join(DATABASE_NAME),
        )?;
        fixture.update_manifest()?;
        let before = fs::read(fixture.output.join(DATABASE_NAME))?;
        let result = verify_backup(&fixture.output).unwrap_err();
        assert!(result.to_string().contains("standalone rollback-journal"));
        assert_eq!(fs::read_dir(&fixture.output)?.count(), 2);
        assert_eq!(fs::read(fixture.output.join(DATABASE_NAME))?, before);
        assert_eq!(read_overview(&connection)?.name, "only in committed WAL");
        Ok(())
    }

    #[test]
    fn verify_bounds_manifest_reads_and_encodes_real_path_characters() -> TestResult {
        let mut fixture = Fixture::new()?;
        fixture.output = fixture.root.join("backup # literal%20 节点");
        #[cfg(unix)]
        {
            fixture.output = fixture.root.join("backup ?mode=rw#literal%20 节点");
        }
        let manifest = create_backup(&fixture.source, &fixture.output)?;
        assert_eq!(verify_backup(&fixture.output)?, manifest);
        fs::write(
            fixture.output.join(MANIFEST_NAME),
            vec![b' '; MAX_MANIFEST_BYTES as usize + 1],
        )?;
        assert!(
            verify_backup(&fixture.output)
                .unwrap_err()
                .to_string()
                .contains("size limit")
        );
        assert_eq!(fs::read_dir(&fixture.output)?.count(), 2);
        Ok(())
    }

    #[test]
    fn verify_checks_foreign_keys_and_typed_policy_invariants() -> TestResult {
        for (statement, expected) in [
            (
                "INSERT INTO user_presets VALUES('AAAAAAAAAAAAAAAAAAAAAA',NULL,0)",
                "foreign-key",
            ),
            (
                "INSERT INTO proxy_users VALUES('AAAAAAAAAAAAAAAAAAAAAA','user',1,0,7,10,2)",
                "proxy user",
            ),
        ] {
            let fixture = Fixture::new()?;
            create_backup(&fixture.source, &fixture.output)?;
            let connection = open(
                &fixture.output.join(DATABASE_NAME),
                OpenFlags::SQLITE_OPEN_READ_WRITE,
            )?;
            connection.pragma_update(None, "foreign_keys", false)?;
            connection.execute_batch(statement)?;
            drop(connection);
            fixture.update_manifest()?;
            let error = verify_backup(&fixture.output).unwrap_err();
            assert!(error.to_string().contains(expected), "{statement}: {error}");
        }
        Ok(())
    }

    #[test]
    fn read_only_sqlite_check_omission_does_not_replace_typed_validation() -> TestResult {
        let fixture = Fixture::new()?;
        create_backup(&fixture.source, &fixture.output)?;
        let path = fixture.output.join(DATABASE_NAME);
        let connection = open(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        connection.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE traffic_state SET clean=7; PRAGMA ignore_check_constraints=OFF")?;
        let check: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        assert_ne!(check, "ok", "the injected CHECK violation must be real");
        drop(connection);
        fixture.update_manifest()?;
        let database = fs::read(&path)?;
        let manifest = fs::read(fixture.output.join(MANIFEST_NAME))?;
        let readonly = open(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        configure(&readonly)?;
        let check: String = readonly.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        // This assertion records the pinned bundled SQLite contract that limits
        // E1a verification. Re-evaluate the documented boundary if SQLite changes.
        assert_eq!(check, "ok");
        let mut uri = url::Url::from_file_path(fs::canonicalize(&path)?).unwrap();
        uri.query_pairs_mut()
            .append_pair("mode", "ro")
            .append_pair("immutable", "1");
        let immutable = Connection::open_with_flags(
            uri.as_str(),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )?;
        configure(&immutable)?;
        let value: i64 =
            immutable.query_row("SELECT clean FROM traffic_state", [], |row| row.get(0))?;
        assert_eq!(value, 7);
        let check: String = immutable.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        assert_eq!(check, "ok");
        let error = verify_backup(&fixture.output).unwrap_err();
        assert!(error.to_string().contains("traffic flag is malformed"));
        assert_eq!(fs::read(&path)?, database);
        assert_eq!(fs::read(fixture.output.join(MANIFEST_NAME))?, manifest);
        assert_eq!(fs::read_dir(&fixture.output)?.count(), 2);
        Ok(())
    }

    #[test]
    fn invalid_source_does_not_receive_a_success_manifest() -> TestResult {
        let fixture = Fixture::new()?;
        let connection = open_existing(&fixture.source, true)?;
        connection.pragma_update(None, "user_version", SCHEMA_VERSION + 1)?;
        drop(connection);
        assert!(create_backup(&fixture.source, &fixture.output).is_err());
        assert!(!fixture.output.exists());
        let connection = open(
            &fixture.source.join(DATABASE_NAME),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        configure(&connection)?;
        connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        connection.execute("UPDATE traffic_state SET series_count=1", [])?;
        drop(connection);
        assert!(create_backup(&fixture.source, &fixture.output).is_err());
        assert!(fixture.output.join(DATABASE_NAME).is_file());
        assert!(!fixture.output.join(MANIFEST_NAME).exists());
        assert!(verify_backup(&fixture.output).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn packages_refuse_nonprivate_permissions_symlinks_and_hardlinks() -> TestResult {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let fixture = Fixture::new()?;
        let parent = fixture.root.join("public");
        fs::create_dir(&parent)?;
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755))?;
        assert_eq!(
            create_backup(&fixture.source, &parent.join("backup"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let alias = fixture.root.join("alias");
        symlink(&fixture.source, &alias)?;
        assert!(create_backup(&alias, &fixture.output).is_err());
        create_backup(&fixture.source, &fixture.output)?;
        let database = fixture.output.join(DATABASE_NAME);
        fs::set_permissions(&database, fs::Permissions::from_mode(0o640))?;
        assert!(verify_backup(&fixture.output).is_err());
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600))?;
        let linked = fixture.root.join("linked");
        fs::hard_link(&database, &linked)?;
        assert!(verify_backup(&fixture.output).is_err());
        fs::remove_file(linked)?;
        let saved = fixture.root.join("database-saved");
        fs::rename(&database, &saved)?;
        symlink(&saved, &database)?;
        assert!(verify_backup(&fixture.output).is_err());
        Ok(())
    }
}
