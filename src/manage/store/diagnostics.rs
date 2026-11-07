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
