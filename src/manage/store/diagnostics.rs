//! Redacted local-storage observations, not a server readiness or integrity test.
//!
//! No process-lifetime/update gate is acquired and no database is initialized,
//! migrated or repaired. A normal read-only SQLite connection still participates
//! in WAL operation: it may access/create WAL/SHM sidecars or change read marks.
//! Immutable backup semantics would ignore live WAL and are deliberately not used.
//! The directory's ancestors remain operator-controlled; leaf checks are not a
//! defense against concurrent replacement by a process with the same file rights.

use std::{fs, io, path::Path};

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;

use super::{APPLICATION_ID, DATABASE_NAME, SCHEMA_VERSION, configure, open, read_overview};

/// Allows the CLI to report an unresolved directory without opening a fake path.
pub(in crate::manage) const EXPECTED_SCHEMA_VERSION: u32 = SCHEMA_VERSION;

/// Only version numbers and fixed diagnostic enums may enter the report.
/// Identity metadata read for validation is discarded, never serialized here.
#[derive(Debug, Serialize)]
pub(in crate::manage) struct Inspection {
    pub(in crate::manage) observed_schema: Option<u32>,
    pub(in crate::manage) expected_schema: u32,
    pub(in crate::manage) checks: Vec<Check>,
}

/// One local observation; a failure leaves dependent stages explicitly unchecked.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(in crate::manage) struct Check {
    pub(in crate::manage) component: Component,
    pub(in crate::manage) status: Status,
    pub(in crate::manage) code: Code,
}

/// Components include the CLI's directory and optional public-certificate checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum Component {
    DirectoryResolution,
    Directory,
    Database,
    Sidecars,
    DatabaseRead,
    Namespace,
    Schema,
    Metadata,
    Recovery,
    NodeCertificate,
}

/// Passed is limited to the named check; it never asserts service availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum Status {
    Passed,
    NeedsAttention,
    Failed,
    NotChecked,
}

/// Fixed output vocabulary, without paths, OS error text or stored values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum Code {
    NotRequested,
    InvalidArguments,
    InvalidCertificate,
    Checked,
    IoFailure,
    InvalidPath,
    Missing,
    PermissionDenied,
    UnsafePath,
    OrphanedSidecars,
    Busy,
    InvalidDatabase,
    NamespaceMismatch,
    UnsupportedSchema,
    OlderSupported,
    CurrentSchema,
    InvalidMetadata,
    RecoveryPending,
    RecoveryReady,
    RecoveryNative,
    RecoveryLegacy,
    PrerequisiteFailed,
}

const STORAGE_COMPONENTS: [Component; 8] = [
    Component::Directory,
    Component::Database,
    Component::Sidecars,
    Component::DatabaseRead,
    Component::Namespace,
    Component::Schema,
    Component::Metadata,
    Component::Recovery,
];

impl Inspection {
    fn new() -> Self {
        Self {
            observed_schema: None,
            expected_schema: EXPECTED_SCHEMA_VERSION,
            checks: STORAGE_COMPONENTS
                .into_iter()
                .map(|component| Check {
                    component,
                    status: Status::NotChecked,
                    code: Code::PrerequisiteFailed,
                })
                .collect(),
        }
    }

    /// Only fixed storage components are recorded. Replacing a prior observation
    /// also lets a failed read-transaction completion invalidate DatabaseRead
    /// without erasing the useful, already observed snapshot classifications.
    fn record(&mut self, component: Component, status: Status, code: Code) {
        for check in &mut self.checks {
            if check.component == component {
                check.status = status;
                check.code = code;
                return;
            }
        }
    }
}

/// Inspect existing private storage through one normal read-only SQL snapshot.
///
/// This accepts supported older schemas without upgrading them. Pending recovery
/// needs operator attention, whereas a Ready row does not prove the configured
/// certificate/key, listeners or any running service is usable. The usual two-
/// second SQLite busy timeout bounds lock waits, not total query/diagnostic time.
/// Unix private mode checks do not audit ACLs, ownership or ancestor paths;
/// Windows inherits its existing ACL boundary and no ACL audit is performed.
/// Failures are reduced to fixed codes and never returned as raw errors.
pub(in crate::manage) fn inspect(directory: &Path) -> Inspection {
    let mut report = Inspection::new();
    if let Err(code) = private_leaf(directory, true) {
        report.record(Component::Directory, Status::Failed, code);
        return report;
    }
    report.record(Component::Directory, Status::Passed, Code::Checked);
    let missing = match private_leaf(&directory.join(DATABASE_NAME), false) {
        Ok(()) => {
            report.record(Component::Database, Status::Passed, Code::Checked);
            false
        }
        Err(Code::Missing) => {
            report.record(Component::Database, Status::Failed, Code::Missing);
            true
        }
        Err(code) => {
            report.record(Component::Database, Status::Failed, code);
            return report;
        }
    };
    match sidecars(directory) {
        Ok(true) if missing => report.record(
            Component::Sidecars,
            Status::NeedsAttention,
            Code::OrphanedSidecars,
        ),
        Ok(_) => report.record(Component::Sidecars, Status::Passed, Code::Checked),
        Err(code) => {
            report.record(Component::Sidecars, Status::Failed, code);
            return report;
        }
    }
    if missing {
        return report;
    }

    let connection = open(
        &directory.join(DATABASE_NAME),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .and_then(|connection| {
        configure(&connection)?;
        connection
            .pragma_update(None, "query_only", true)
            .map_err(|error| super::sqlite_error("cannot restrict diagnostic connection", error))?;
        Ok(connection)
    });
    let mut connection = match connection {
        Ok(connection) => connection,
        Err(error) => {
            report.record(
                Component::DatabaseRead,
                Status::Failed,
                classify(error, Code::InvalidDatabase),
            );
            return report;
        }
    };
    let transaction = match connection.transaction() {
        Ok(transaction) => transaction,
        Err(error) => {
            report.record(
                Component::DatabaseRead,
                Status::Failed,
                classify(
                    super::sqlite_error("cannot begin diagnostic snapshot", error),
                    Code::InvalidDatabase,
                ),
            );
            return report;
        }
    };
    report.record(Component::DatabaseRead, Status::Passed, Code::Checked);
    inspect_snapshot(&transaction, &mut report);
    if let Err(error) = transaction.commit() {
        report.record(
            Component::DatabaseRead,
            Status::Failed,
            classify(
                super::sqlite_error("cannot complete diagnostic snapshot", error),
                Code::InvalidDatabase,
            ),
        );
    }
    report
}

/// Observe dependent database facts only after the prior stage passed, keeping
/// all values on the caller's one read snapshot. Unknown namespaces/versions are
/// never interpreted as current metadata; later stages remain NotChecked.
fn inspect_snapshot(connection: &Connection, report: &mut Inspection) {
    let application_id: i32 =
        match connection.pragma_query_value(None, "application_id", |row| row.get(0)) {
            Ok(value) => value,
            Err(error) => {
                report.record(
                    Component::Namespace,
                    Status::Failed,
                    classify(
                        super::sqlite_error("cannot read diagnostic namespace", error),
                        Code::InvalidDatabase,
                    ),
                );
                return;
            }
        };
    if application_id != APPLICATION_ID {
        report.record(
            Component::Namespace,
            Status::Failed,
            Code::NamespaceMismatch,
        );
        return;
    }
    report.record(Component::Namespace, Status::Passed, Code::Checked);
    let version: i64 = match connection.pragma_query_value(None, "user_version", |row| row.get(0)) {
        Ok(version) => version,
        Err(error) => {
            report.record(
                Component::Schema,
                Status::Failed,
                classify(
                    super::sqlite_error("cannot read diagnostic schema", error),
                    Code::InvalidDatabase,
                ),
            );
            return;
        }
    };
    report.observed_schema = u32::try_from(version).ok();
    let Some(version) = report
        .observed_schema
        .filter(|version| (1..=SCHEMA_VERSION).contains(version))
    else {
        report.record(Component::Schema, Status::Failed, Code::UnsupportedSchema);
        return;
    };
    report.record(
        Component::Schema,
        Status::Passed,
        if version == SCHEMA_VERSION {
            Code::CurrentSchema
        } else {
            Code::OlderSupported
        },
    );
    if let Err(error) = read_overview(connection) {
        report.record(
            Component::Metadata,
            Status::Failed,
            classify(error, Code::InvalidMetadata),
        );
        return;
    }
    report.record(Component::Metadata, Status::Passed, Code::Checked);
    if version < 14 {
        report.record(Component::Recovery, Status::Passed, Code::RecoveryLegacy);
        return;
    }
    // read_overview has validated the complete recovery row, including its pin
    // and provenance. Project only booleans from that same transaction, not an
    // independently opened recovery::status snapshot or any stored identity.
    match connection.query_row(
        "SELECT kind='native',phase='pending_review' FROM recovery_state WHERE singleton=1",
        [],
        |row| Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?)),
    ) {
        Ok((_, true)) => report.record(
            Component::Recovery,
            Status::NeedsAttention,
            Code::RecoveryPending,
        ),
        Ok((true, false)) => {
            report.record(Component::Recovery, Status::Passed, Code::RecoveryNative)
        }
        Ok((false, false)) => {
            report.record(Component::Recovery, Status::Passed, Code::RecoveryReady)
        }
        Err(error) => report.record(
            Component::Recovery,
            Status::Failed,
            classify(
                super::sqlite_error("cannot project diagnostic recovery state", error),
                Code::InvalidMetadata,
            ),
        ),
    }
}

/// Inspect only constant sidecar leaves, even when the main database is absent.
/// The result notes orphaned material without treating it as a new identity seed.
/// SQLite controls legitimate sidecar lifetime; no leaf is deleted or repaired.
fn sidecars(directory: &Path) -> Result<bool, Code> {
    let mut present = false;
    for suffix in ["-wal", "-shm", "-journal"] {
        let path = directory.join(format!("{DATABASE_NAME}{suffix}"));
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                private_leaf(&path, false)?;
                present = true;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(classify(error, Code::InvalidPath)),
        }
    }
    Ok(present)
}

/// Keep the established leaf/mode validators authoritative. The preliminary
/// metadata check separates unsafe leaves from ordinary access denial without
/// interpreting an OS error message or following a symlink target.
fn private_leaf(path: &Path, is_directory: bool) -> Result<(), Code> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| classify(error, Code::InvalidPath))?;
    if metadata.file_type().is_symlink()
        || (is_directory && !metadata.is_dir())
        || (!is_directory && !metadata.is_file())
    {
        return Err(Code::UnsafePath);
    }
    let result = if is_directory {
        super::validate_directory(path)
    } else {
        super::validate_database(path)
    };
    result.map_err(|error| classify(error, Code::InvalidPath))
}

fn classify(error: io::Error, invalid: Code) -> Code {
    match error.kind() {
        io::ErrorKind::NotFound => Code::Missing,
        io::ErrorKind::PermissionDenied => Code::PermissionDenied,
        io::ErrorKind::WouldBlock => Code::Busy,
        io::ErrorKind::InvalidData => invalid,
        _ => Code::IoFailure,
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::DirBuilder, io::Write as _, path::PathBuf};

    use super::*;
    use crate::manage::store;

    const PHC: &str = "diagnostic-private-password-verifier";

    /// Owns only an exclusively created private leaf; no deployed state is accepted.
    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> io::Result<Self> {
            let path =
                std::env::temp_dir().join(format!("vproxy-diagnostics-{}", store::random_id()?));
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

        fn initialize(&self) -> io::Result<store::Overview> {
            store::initialize(
                &self.0,
                "diagnostic-private-node-name",
                "private_admin",
                PHC,
            )
        }

        fn writable(&self) -> io::Result<Connection> {
            store::open(
                &self.0.join(DATABASE_NAME),
                OpenFlags::SQLITE_OPEN_READ_WRITE,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // This fresh random directory was claimed by Fixture::new, never a
            // caller-selected persistent directory or shared temporary root.
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn check(report: &Inspection, component: Component) -> Check {
        *report
            .checks
            .iter()
            .find(|check| check.component == component)
            .expect("fixed storage component")
    }

    fn private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)?.write_all(bytes)
    }

    #[test]
    fn missing_or_corrupt_storage_reports_fixed_stages_without_initializing() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let missing = fixture.0.join("missing");
        let report = inspect(&missing);
        assert_eq!(check(&report, Component::Directory).code, Code::Missing);
        assert_eq!(
            check(&report, Component::Database).status,
            Status::NotChecked
        );
        assert!(!missing.exists());

        let report = inspect(&fixture.0);
        assert_eq!(check(&report, Component::Directory).status, Status::Passed);
        assert_eq!(check(&report, Component::Database).code, Code::Missing);
        assert_eq!(check(&report, Component::Sidecars).code, Code::Checked);
        assert_eq!(fs::read_dir(&fixture.0)?.count(), 0);
        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar = fixture.0.join(format!("{DATABASE_NAME}{suffix}"));
            private_file(&sidecar, b"orphaned-diagnostic-private-sentinel")?;
            let report = inspect(&fixture.0);
            assert_eq!(check(&report, Component::Database).code, Code::Missing);
            assert_eq!(
                check(&report, Component::Sidecars),
                Check {
                    component: Component::Sidecars,
                    status: Status::NeedsAttention,
                    code: Code::OrphanedSidecars,
                }
            );
            assert_eq!(
                check(&report, Component::DatabaseRead).status,
                Status::NotChecked
            );
            assert_eq!(fs::read(&sidecar)?, b"orphaned-diagnostic-private-sentinel");
            assert_eq!(fs::read_dir(&fixture.0)?.count(), 1);
            fs::remove_file(&sidecar)?;
        }

        let path = fixture.0.join(DATABASE_NAME);
        let invalid = b"diagnostic-private-corrupt-database-value";
        private_file(&path, invalid)?;
        let report = inspect(&fixture.0);
        assert_eq!(
            check(&report, Component::Namespace).code,
            Code::InvalidDatabase
        );
        assert_eq!(
            check(&report, Component::Metadata).status,
            Status::NotChecked
        );
        assert_eq!(fs::read(&path)?, invalid);
        assert!(
            !serde_json::to_string(&report)
                .map_err(io::Error::other)?
                .contains("diagnostic-private")
        );
        assert_eq!(fs::read_dir(&fixture.0)?.count(), 1);
        Ok(())
    }

    #[test]
    fn valid_storage_is_redacted_and_does_not_claim_process_or_update_gates() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let overview = fixture.initialize()?;
        let connection = fixture.writable()?;
        let _author = store::lock(&fixture.0)?;
        let _update = store::update_lock(&fixture.0)?;
        let before: (String, String, String) = connection
            .query_row(
                "SELECT node_id,name,password_hash FROM node_identity CROSS JOIN administrators",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(io::Error::other)?;
        let report = inspect(&fixture.0);
        assert_eq!(report.observed_schema, Some(SCHEMA_VERSION));
        assert_eq!(report.expected_schema, SCHEMA_VERSION);
        assert!(
            report
                .checks
                .iter()
                .all(|check| check.status == Status::Passed)
        );
        assert_eq!(check(&report, Component::Schema).code, Code::CurrentSchema);
        assert_eq!(
            check(&report, Component::Recovery).code,
            Code::RecoveryNative
        );
        let json = serde_json::to_value(&report).map_err(io::Error::other)?;
        let mut keys = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(keys, ["checks", "expected_schema", "observed_schema"]);
        let text = json.to_string();
        for sensitive in [
            overview.node_id.as_str(),
            overview.name.as_str(),
            "private_admin",
            PHC,
            fixture.0.file_name().unwrap().to_str().unwrap(),
        ] {
            assert!(!text.contains(sensitive));
        }
        let after: (String, String, String) = connection
            .query_row(
                "SELECT node_id,name,password_hash FROM node_identity CROSS JOIN administrators",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(io::Error::other)?;
        assert_eq!(after, before);
        assert!(
            matches!(store::lock(&fixture.0), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert!(
            matches!(store::update_lock(&fixture.0), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        Ok(())
    }

    #[test]
    fn namespace_future_schema_and_invalid_metadata_are_distinct_and_never_repaired()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.initialize()?;
        let connection = fixture.writable()?;
        connection
            .pragma_update(None, "application_id", 0)
            .map_err(io::Error::other)?;
        let report = inspect(&fixture.0);
        assert_eq!(
            check(&report, Component::Namespace).code,
            Code::NamespaceMismatch
        );
        assert_eq!(report.observed_schema, None);
        assert_eq!(check(&report, Component::Schema).status, Status::NotChecked);
        connection
            .pragma_update(None, "application_id", APPLICATION_ID)
            .map_err(io::Error::other)?;
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .map_err(io::Error::other)?;
        let report = inspect(&fixture.0);
        assert_eq!(report.observed_schema, Some(SCHEMA_VERSION + 1));
        assert_eq!(
            check(&report, Component::Schema).code,
            Code::UnsupportedSchema
        );
        assert_eq!(
            check(&report, Component::Metadata).status,
            Status::NotChecked
        );
        assert_eq!(
            connection
                .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
                .map_err(io::Error::other)?,
            SCHEMA_VERSION + 1
        );
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(io::Error::other)?;
        connection
            .execute("DELETE FROM administrators", [])
            .map_err(io::Error::other)?;
        let report = inspect(&fixture.0);
        assert_eq!(
            check(&report, Component::Metadata).code,
            Code::InvalidMetadata
        );
        assert_eq!(
            check(&report, Component::Recovery).status,
            Status::NotChecked
        );
        assert_eq!(
            connection
                .query_row::<i64, _, _>("SELECT count(*) FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)?,
            0
        );
        Ok(())
    }

    #[test]
    fn genuine_supported_legacy_schema_is_read_without_migration() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.initialize()?;
        let connection = fixture.writable()?;
        // A version-only downgrade retains newer namespaces and must not masquerade
        // as a supported older database.
        connection
            .pragma_update(None, "user_version", 16)
            .map_err(io::Error::other)?;
        let invalid = inspect(&fixture.0);
        assert_eq!(
            check(&invalid, Component::Metadata).code,
            Code::InvalidMetadata
        );
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(io::Error::other)?;
        store::recovery::restore_schema_sixteen_for_test(&connection)?;
        let report = inspect(&fixture.0);
        assert_eq!(report.observed_schema, Some(16));
        assert_eq!(
            check(&report, Component::Schema),
            Check {
                component: Component::Schema,
                status: Status::Passed,
                code: Code::OlderSupported,
            }
        );
        assert!(
            report
                .checks
                .iter()
                .all(|check| check.status == Status::Passed)
        );
        assert_eq!(
            connection
                .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
                .map_err(io::Error::other)?,
            16
        );
        assert_eq!(
            connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM sqlite_schema WHERE name LIKE 'automation_%'",
                    [],
                    |row| row.get(0),
                )
                .map_err(io::Error::other)?,
            0
        );
        store::recovery::remove_schema_for_test(&connection)?;
        let report = inspect(&fixture.0);
        assert_eq!(report.observed_schema, Some(13));
        assert_eq!(
            check(&report, Component::Recovery).code,
            Code::RecoveryLegacy
        );
        assert!(
            report
                .checks
                .iter()
                .all(|check| check.status == Status::Passed)
        );
        Ok(())
    }

    #[test]
    fn committed_wal_recovery_is_read_while_cooperative_process_gates_are_held() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.initialize()?;
        let mut connection = fixture.writable()?;
        connection
            .pragma_update(None, "wal_autocheckpoint", 0)
            .map_err(io::Error::other)?;
        let _author = store::lock(&fixture.0)?;
        let _update = store::update_lock(&fixture.0)?;
        connection.execute(
        "UPDATE recovery_state SET kind='restored',phase='pending_review',recovery_id=?1,
         source_node_id=?2,source_schema_version=13,source_database_sha256=?3,node_key_sha256=?4,
         imported_users=0,imported_prefixes=0,imported_addresses=0,imported_pools=0 WHERE singleton=1",
        rusqlite::params![store::random_id()?, store::random_id()?, "a".repeat(64), &[7_u8; 32][..]],
    ).map_err(io::Error::other)?;
        assert!(fs::metadata(fixture.0.join(format!("{DATABASE_NAME}-wal")))?.len() > 0);
        // The uncommitted newer row must not leak into the read snapshot.
        let transaction = connection.transaction().map_err(io::Error::other)?;
        transaction
            .execute(
                "UPDATE recovery_state SET phase='ready' WHERE singleton=1",
                [],
            )
            .map_err(io::Error::other)?;
        let pending = inspect(&fixture.0);
        assert_eq!(check(&pending, Component::Metadata).status, Status::Passed);
        assert_eq!(
            check(&pending, Component::Recovery),
            Check {
                component: Component::Recovery,
                status: Status::NeedsAttention,
                code: Code::RecoveryPending,
            }
        );
        transaction.commit().map_err(io::Error::other)?;
        let ready = inspect(&fixture.0);
        assert_eq!(check(&ready, Component::Recovery).code, Code::RecoveryReady);
        assert_eq!(check(&ready, Component::Recovery).status, Status::Passed);
        Ok(())
    }

    #[test]
    fn a_real_sqlite_exclusive_lock_is_reported_without_claiming_metadata_validity()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.initialize()?;
        let connection = fixture.writable()?;
        // Rollback-journal EXCLUSIVE blocks readers, unlike the WAL writer used by
        // the snapshot test. Exercise SQLite's real busy result, not a mock error.
        connection
            .pragma_update(None, "journal_mode", "DELETE")
            .map_err(io::Error::other)?;
        connection
            .execute_batch("BEGIN EXCLUSIVE")
            .map_err(io::Error::other)?;
        let report = inspect(&fixture.0);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.status == Status::Failed && check.code == Code::Busy)
        );
        assert_eq!(
            check(&report, Component::Metadata).status,
            Status::NotChecked
        );
        assert_eq!(
            check(&report, Component::Recovery).status,
            Status::NotChecked
        );
        connection
            .execute_batch("ROLLBACK")
            .map_err(io::Error::other)?;
        assert!(
            inspect(&fixture.0)
                .checks
                .iter()
                .all(|check| check.status == Status::Passed)
        );
        Ok(())
    }

    #[test]
    fn nonregular_sidecars_are_rejected_before_opening_sqlite() -> io::Result<()> {
        for suffix in ["-wal", "-shm", "-journal"] {
            let fixture = Fixture::new()?;
            private_file(
                &fixture.0.join(DATABASE_NAME),
                b"not read before sidecar checks",
            )?;
            let sidecar = fixture.0.join(format!("{DATABASE_NAME}{suffix}"));
            fs::create_dir(&sidecar)?;
            let report = inspect(&fixture.0);
            assert_eq!(check(&report, Component::Sidecars).code, Code::UnsafePath);
            assert_eq!(
                check(&report, Component::DatabaseRead).status,
                Status::NotChecked
            );
            assert!(sidecar.is_dir());
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_links_and_public_modes_are_refused_without_following_or_repairing() -> io::Result<()>
    {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let fixture = Fixture::new()?;
        let target = fixture.0.join("private-target");
        private_file(&target, b"diagnostic-private-outside-sentinel")?;
        let linked_directory = fixture.0.join("linked-directory");
        symlink(&fixture.0, &linked_directory)?;
        assert_eq!(
            check(&inspect(&linked_directory), Component::Directory).code,
            Code::UnsafePath
        );
        let database = fixture.0.join(DATABASE_NAME);
        symlink(&target, &database)?;
        assert_eq!(
            check(&inspect(&fixture.0), Component::Database).code,
            Code::UnsafePath
        );
        fs::remove_file(&database)?;
        private_file(&database, b"not opened before sidecar checks")?;
        fs::set_permissions(&database, fs::Permissions::from_mode(0o644))?;
        assert_eq!(
            check(&inspect(&fixture.0), Component::Database).code,
            Code::PermissionDenied
        );
        assert_eq!(fs::metadata(&database)?.permissions().mode() & 0o777, 0o644);
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600))?;
        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar = fixture.0.join(format!("{DATABASE_NAME}{suffix}"));
            symlink(&target, &sidecar)?;
            assert_eq!(
                check(&inspect(&fixture.0), Component::Sidecars).code,
                Code::UnsafePath
            );
            assert!(fs::symlink_metadata(&sidecar)?.file_type().is_symlink());
            fs::remove_file(&sidecar)?;
            private_file(&sidecar, b"not a public WAL to open")?;
            fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o644))?;
            assert_eq!(
                check(&inspect(&fixture.0), Component::Sidecars).code,
                Code::PermissionDenied
            );
            assert_eq!(fs::metadata(&sidecar)?.permissions().mode() & 0o777, 0o644);
            fs::remove_file(&sidecar)?;
        }
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o755))?;
        assert_eq!(
            check(&inspect(&fixture.0), Component::Directory).code,
            Code::PermissionDenied
        );
        assert_eq!(
            fs::metadata(&fixture.0)?.permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(fs::read(&target)?, b"diagnostic-private-outside-sentinel");
        Ok(())
    }

    #[test]
    fn io_failure_classification_never_uses_dynamic_error_text() {
        for (kind, expected) in [
            (io::ErrorKind::NotFound, Code::Missing),
            (io::ErrorKind::PermissionDenied, Code::PermissionDenied),
            (io::ErrorKind::WouldBlock, Code::Busy),
            (io::ErrorKind::InvalidData, Code::InvalidMetadata),
            (io::ErrorKind::Other, Code::IoFailure),
        ] {
            assert_eq!(
                classify(
                    io::Error::new(kind, "diagnostic-private-error-source"),
                    Code::InvalidMetadata
                ),
                expected
            );
        }
    }
}
