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
