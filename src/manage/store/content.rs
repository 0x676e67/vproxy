//! Logical database commitment, independent of SQLite page layout and WAL.
//!
//! Streams the supported application catalog and every row in primary-key
//! order through a typed, length-framed SHA-256 encoding. This is content
//! identity, not provenance, freshness or permission to activate a backup.
//! It currently runs only during offline identity capture/verification, never
//! on the proxy data path or as a substitute for pre-commit witness admission.

use super::{backup, invalid_data, read_overview, recovery, sqlite_error};
use rusqlite::{Connection, types::ValueRef};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeSet, io};

const DOMAIN: &[u8] = b"vproxy.database.content.v1\0";
const MAX_SCHEMA_OBJECTS: usize = 512;
const MAX_COLUMNS: usize = 128;

/// Schema-only commitment for a source transaction; no row scan. The current
/// journal kernel accepts only supported STRICT rowid tables, whose declared
/// PKs cannot contain NULL rows silently omitted by SQLite Session.
#[cfg(feature = "witness-journal")]
pub(super) fn schema(connection: &Connection) -> io::Result<String> {
    let overview = read_overview(connection)?;
    if overview.schema_version != super::SCHEMA_VERSION || overview.schema_version < 25 {
        return Err(malformed());
    }
    let mut hash = Sha256::new();
    hash.update(b"vproxy.database.schema.v1\0");
    hash.update(super::APPLICATION_ID.to_be_bytes());
    hash.update(overview.schema_version.to_be_bytes());
    let tables = catalog(connection, &mut hash)?;
    if tables
        != backup::tables(overview.schema_version)
            .map(str::to_owned)
            .collect()
    {
        return Err(malformed());
    }
    for table in tables {
        bytes(&mut hash, table.as_bytes())?;
        columns(connection, &table, &mut hash)?;
        let eligible: bool = connection.query_row(
            "SELECT type='table' AND wr=0 AND strict=1 FROM pragma_table_list WHERE schema='main' AND name=?1",
            [&table], |r| r.get(0),
        ).map_err(|e| sqlite_error("cannot inspect journal table eligibility", e))?;
        if !eligible {
            return Err(malformed());
        }
    }
    Ok(encode(&hash.finalize()))
}

/// Hash one consistent SQL view. A caller's existing transaction is reused,
/// including its uncommitted rows; otherwise a private read transaction spans
/// the entire scan. No SQL data, journal mode, checkpoint or permission changes.
/// Unknown application tables, unsupported schema, malformed catalog/value
/// types and SQLite errors fail closed. I/O/scan time has no whole-command
/// deadline. Application code retains only the catalog and one row at a time;
/// SQLite retains its own cache/query-plan allocation policy. No serialized
/// database or second vector of secret payloads is built.
///
/// A quarantined snapshot is checked first, then only its recovery singleton
/// is projected to the recorded source state. This does not remove its actual
/// SQL fence or make the archive runnable.
pub(super) fn calculate(
    connection: &Connection,
    snapshot: Option<&recovery::Snapshot>,
) -> io::Result<String> {
    if connection.is_autocommit() {
        let transaction = connection
            .unchecked_transaction()
            .map_err(|e| sqlite_error("cannot begin content commitment snapshot", e))?;
        let result = calculate_in(&transaction, snapshot)?;
        transaction
            .commit()
            .map_err(|e| sqlite_error("cannot complete content commitment snapshot", e))?;
        Ok(result)
    } else {
        calculate_in(connection, snapshot)
    }
}

fn calculate_in(
    connection: &Connection,
    snapshot: Option<&recovery::Snapshot>,
) -> io::Result<String> {
    let overview = read_overview(connection)?;
    if !(25..=super::SCHEMA_VERSION).contains(&overview.schema_version) {
        return Err(invalid_data(
            "unsupported database content commitment schema",
        ));
    }
    if let Some(snapshot) = snapshot {
        recovery::check_snapshot(connection, Some(snapshot))?;
    }
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(super::APPLICATION_ID.to_be_bytes());
    hash.update(overview.schema_version.to_be_bytes());
    let tables = catalog(connection, &mut hash)?;
    let required: BTreeSet<_> = backup::tables(overview.schema_version)
        .map(str::to_owned)
        .collect();
    if tables != required {
        return Err(invalid_data(
            "database content catalog is not the supported table set",
        ));
    }
    for table in tables {
        hash.update([0x10]);
        bytes(&mut hash, table.as_bytes())?;
        let columns = columns(connection, &table, &mut hash)?;
        if table == "recovery_state"
            && let Some(snapshot) = snapshot
        {
            let original = recovery::source_recovery_row(snapshot);
            if original.len() != columns.count {
                return Err(malformed());
            }
            hash.update([0x20]);
            for value in &original {
                cell(&mut hash, ValueRef::from(value))?;
            }
            hash.update([0x21]);
            hash.update(1_u64.to_be_bytes());
            continue;
        }
        // Only validated schema identifiers enter this SQL. Values from a
        // caller/row/marker are never interpolated, including recovery IDs.
        let order = columns
            .primary_key
            .iter()
            .map(|(_, name)| format!("\"{name}\" COLLATE BINARY"))
            .collect::<Vec<_>>()
            .join(",");
        let mut statement = connection
            .prepare(&format!("SELECT * FROM \"{table}\" ORDER BY {order}"))
            .map_err(|e| sqlite_error("cannot prepare content rows", e))?;
        let mut rows = statement
            .query([])
            .map_err(|e| sqlite_error("cannot read content rows", e))?;
        let mut count = 0_u64;
        while let Some(row) = rows
            .next()
            .map_err(|e| sqlite_error("cannot scan content rows", e))?
        {
            count = count.checked_add(1).ok_or_else(malformed)?;
            // Non-STRICT SQLite can permit NULL in a declared PK. Such rows
            // need not have a unique ordering, so refuse instead of hashing
            // insertion/page order as though it were logical content.
            for (index, _) in &columns.primary_key {
                if matches!(
                    row.get_ref(*index).map_err(|_| malformed())?,
                    ValueRef::Null
                ) {
                    return Err(malformed());
                }
            }
            hash.update([0x20]);
            for index in 0..columns.count {
                cell(&mut hash, row.get_ref(index).map_err(|_| malformed())?)?;
            }
        }
        hash.update([0x21]);
        hash.update(count.to_be_bytes());
    }
    Ok(encode(&hash.finalize()))
}

/// Hash schema semantics as recorded by SQLite, but not root pages, physical
/// rowids or planner statistics. PK/column contracts are separately checked.
fn catalog(connection: &Connection, hash: &mut Sha256) -> io::Result<BTreeSet<String>> {
    let mut statement = connection.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY type COLLATE BINARY,name COLLATE BINARY")
        .map_err(|e|sqlite_error("cannot prepare content catalog",e))?;
    let mut rows = statement
        .query([])
        .map_err(|e| sqlite_error("cannot read content catalog", e))?;
    let mut tables = BTreeSet::new();
    let mut count = 0;
    while let Some(row) = rows
        .next()
        .map_err(|e| sqlite_error("cannot scan content catalog", e))?
    {
        count += 1;
        if count > MAX_SCHEMA_OBJECTS {
            return Err(malformed());
        }
        let kind = identifier_at(row, 0)?;
        let name = identifier_at(row, 1)?;
        identifier_at(row, 2)?;
        if !matches!(kind, "table" | "index" | "trigger") {
            return Err(malformed());
        }
        if kind == "table" {
            tables.insert(name.to_owned());
        }
        hash.update([0x01]);
        for index in 0..4 {
            cell(hash, row.get_ref(index).map_err(|_| malformed())?)?;
        }
    }
    // Current supported tables do not use implicit AUTOINCREMENT state. A
    // future sqlite_sequence must not silently fall outside the commitment.
    let sequence: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='sqlite_sequence')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot inspect content sequence catalog", e))?;
    if sequence {
        return Err(malformed());
    }
    hash.update([0x02]);
    Ok(tables)
}

/// Names and PK positions only; no copied row payloads survive an iteration.
pub(super) struct Columns {
    pub(super) count: usize,
    /// Column offset and name, ordered by the declared composite PK position.
    pub(super) primary_key: Vec<(usize, String)>,
}

pub(super) fn columns(
    connection: &Connection,
    table: &str,
    hash: &mut Sha256,
) -> io::Result<Columns> {
    let mut statement = connection.prepare("SELECT cid,name,type,\"notnull\",dflt_value,pk,hidden FROM pragma_table_xinfo(?1) ORDER BY cid")
        .map_err(|e|sqlite_error("cannot inspect content columns",e))?;
    let mut rows = statement
        .query([table])
        .map_err(|e| sqlite_error("cannot read content columns", e))?;
    let mut count = 0_usize;
    let mut keys = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|e| sqlite_error("cannot scan content columns", e))?
    {
        let cid: i64 = row.get(0).map_err(|_| malformed())?;
        let name = identifier_at(row, 1)?;
        let pk: i64 = row.get(5).map_err(|_| malformed())?;
        let hidden: i64 = row.get(6).map_err(|_| malformed())?;
        if count >= MAX_COLUMNS || usize::try_from(cid).ok() != Some(count) || hidden != 0 || pk < 0
        {
            return Err(malformed());
        }
        count += 1;
        hash.update([0x11]);
        for index in 0..7 {
            cell(hash, row.get_ref(index).map_err(|_| malformed())?)?;
        }
        if pk != 0 {
            keys.push((pk, count - 1, name.to_owned()));
        }
    }
    keys.sort_unstable_by_key(|(index, _, _)| *index);
    if count == 0
        || keys.is_empty()
        || keys
            .iter()
            .enumerate()
            .any(|(i, (index, _, _))| usize::try_from(*index).ok() != i.checked_add(1))
    {
        return Err(malformed());
    }
    hash.update([0x12]);
    Ok(Columns {
        count,
        primary_key: keys
            .into_iter()
            .map(|(_, index, name)| (index, name))
            .collect(),
    })
}

fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Check borrowed catalog bytes before allocating an identifier. Only this
/// restricted alphabet is later quoted into a SELECT; arbitrary SQL is never
/// accepted from a database's table/column names.
fn identifier_at<'a>(row: &'a rusqlite::Row<'_>, index: usize) -> io::Result<&'a str> {
    let ValueRef::Text(value) = row.get_ref(index).map_err(|_| malformed())? else {
        return Err(malformed());
    };
    let name = std::str::from_utf8(value).map_err(|_| malformed())?;
    if !identifier(name) {
        return Err(malformed());
    }
    Ok(name)
}
fn malformed() -> io::Error {
    invalid_data("database content has an unsupported shape")
}

/// Tags and explicit lengths distinguish NULL, integer, real, UTF-8 bytes and
/// BLOBs, as well as adjacent empty/nonempty values. No diagnostic echoes data.
pub(super) fn cell(hash: &mut Sha256, value: ValueRef<'_>) -> io::Result<()> {
    match value {
        ValueRef::Null => hash.update([0]),
        ValueRef::Integer(n) => {
            hash.update([1]);
            hash.update(n.to_be_bytes());
        }
        ValueRef::Real(n) => {
            if !n.is_finite() {
                return Err(malformed());
            }
            hash.update([2]);
            // SQLite may normalize negative zero when a page is written.
            hash.update((if n == 0.0 { 0.0 } else { n }).to_bits().to_be_bytes());
        }
        ValueRef::Text(value) => {
            hash.update([3]);
            bytes(hash, value)?;
        }
        ValueRef::Blob(value) => {
            hash.update([4]);
            bytes(hash, value)?;
        }
    }
    Ok(())
}
fn bytes(hash: &mut Sha256, value: &[u8]) -> io::Result<()> {
    let length = u64::try_from(value.len()).map_err(|_| malformed())?;
    hash.update(length.to_be_bytes());
    hash.update(value);
    Ok(())
}

fn encode(digest: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for &byte in digest {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 15)]));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::{files, store};
    use std::{fs, path::PathBuf};

    /// Exclusively owns a new private fixture; no live identity or trust is used.
    struct Fixture {
        root: PathBuf,
        state: PathBuf,
    }
    impl Fixture {
        fn new() -> io::Result<Self> {
            let root = std::env::temp_dir().join(format!("vproxy-content-{}", store::random_id()?));
            files::create_directory(&root)?;
            let state = root.join("state");
            files::create_directory(&state)?;
            store::initialize(&state, "content fixture", "admin", "non-login fixture PHC")?;
            Ok(Self { root, state })
        }
        fn connection(&self) -> io::Result<Connection> {
            store::peers::open_existing(&self.state, true)
        }
        fn capture(&self, name: &str) -> io::Result<(PathBuf, super::super::BackupManifest)> {
            let output = self.root.join(name);
            let manifest = store::create_identity_snapshot(
                &self.state,
                &output,
                &store::lock(&self.state)?,
                &store::update_lock(&self.state)?,
                [7; 32],
            )?;
            Ok((output, manifest))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn content_binds_verifiers_credential_status_command_floor_and_meter_cursor() -> io::Result<()>
    {
        use crate::access::Protocol;
        let f = Fixture::new()?;
        let mut connection = f.connection()?;
        let actor: String = connection
            .query_row("SELECT id FROM administrators", [], |r| r.get(0))
            .map_err(io::Error::other)?;
        let user = store::apply_policy(
            &f.state,
            &actor,
            1,
            store::PolicyChange::CreateUser {
                name: "content user".into(),
                protocols: vec![Protocol::Http],
                concurrent_limit: 1,
            },
            &store::update_lock(&f.state)?,
        )?
        .user
        .ok_or_else(|| io::Error::other("missing fixture user"))?;
        store::apply_policy(
            &f.state,
            &actor,
            2,
            store::PolicyChange::CreateCredential { user_id: user.id },
            &store::update_lock(&f.state)?,
        )?;
        let original = calculate(&connection, None)?;
        // Raw single-field changes deliberately do not advance the policy revision:
        // hashing only that revision would fail this authority/command/meter test.
        for sql in [
            "UPDATE administrators SET password_hash='changed fixture verifier'",
            "UPDATE proxy_credentials SET active=0",
            "UPDATE control_ownership SET last_terminal_command=1",
            "UPDATE traffic_state SET cursor=1",
        ] {
            let tx = connection.transaction().map_err(io::Error::other)?;
            assert_eq!(tx.execute(sql, []).map_err(io::Error::other)?, 1);
            assert_ne!(calculate(&tx, None)?, original, "{sql}");
            tx.rollback().map_err(io::Error::other)?;
            assert_eq!(calculate(&connection, None)?, original);
        }
        Ok(())
    }

    #[test]
    fn content_snapshot_sees_own_uncommitted_rows_and_rollback_but_not_file_layout()
    -> io::Result<()> {
        let f = Fixture::new()?;
        let mut connection = f.connection()?;
        let original = calculate(&connection, None)?;
        let transaction = connection.transaction().map_err(io::Error::other)?;
        transaction
            .execute("UPDATE administrator_audit_state SET last_sequence=19", [])
            .map_err(io::Error::other)?;
        let changed = calculate(&transaction, None)?;
        assert_ne!(original, changed);
        transaction.rollback().map_err(io::Error::other)?;
        assert_eq!(calculate(&connection, None)?, original);
        connection
            .execute("UPDATE administrator_audit_state SET last_sequence=19", [])
            .map_err(io::Error::other)?;
        assert_eq!(calculate(&connection, None)?, changed);
        let package = f.root.join("ordinary");
        store::create_backup(&f.state, &package)?;
        let copied =
            Connection::open(package.join(store::DATABASE_NAME)).map_err(io::Error::other)?;
        assert_eq!(calculate(&copied, None)?, changed);
        copied.execute_batch("VACUUM;").map_err(io::Error::other)?;
        assert_eq!(calculate(&copied, None)?, changed);
        assert!(store::verify_backup(&package).is_err()); // file hash, unlike content, changed
        Ok(())
    }

    #[test]
    fn content_encoding_separates_types_lengths_order_and_zero() -> io::Result<()> {
        let hash = |values: &[ValueRef<'_>]| -> io::Result<Vec<u8>> {
            let mut hash = Sha256::new();
            for value in values {
                cell(&mut hash, *value)?;
            }
            Ok(hash.finalize().to_vec())
        };
        let values = [
            ValueRef::Null,
            ValueRef::Integer(0),
            ValueRef::Real(0.0),
            ValueRef::Text(b""),
            ValueRef::Blob(b""),
        ];
        let encoded: BTreeSet<_> = values
            .into_iter()
            .map(|v| hash(&[v]))
            .collect::<io::Result<_>>()?;
        assert_eq!(encoded.len(), values.len());
        assert_ne!(
            hash(&[ValueRef::Text(b"a"), ValueRef::Text(b"bc")])?,
            hash(&[ValueRef::Text(b"ab"), ValueRef::Text(b"c")])?
        );
        assert_ne!(
            hash(&[ValueRef::Integer(1), ValueRef::Integer(2)])?,
            hash(&[ValueRef::Integer(2), ValueRef::Integer(1)])?
        );
        assert_eq!(
            hash(&[ValueRef::Real(-0.0)])?,
            hash(&[ValueRef::Real(0.0)])?
        );
        assert!(hash(&[ValueRef::Real(f64::INFINITY)]).is_err());
        assert!(hash(&[ValueRef::Real(f64::NAN)]).is_err());
        Ok(())
    }

    #[test]
    fn content_catalog_and_ddl_changes_cannot_be_omitted() -> io::Result<()> {
        let f = Fixture::new()?;
        let connection = f.connection()?;
        let original = calculate(&connection, None)?;
        connection
            .execute_batch(
                "CREATE INDEX extra_content_index ON administrators(username COLLATE BINARY);",
            )
            .map_err(io::Error::other)?;
        let indexed = calculate(&connection, None)?;
        assert_ne!(indexed, original);
        connection
            .execute_batch("DROP INDEX extra_content_index;")
            .map_err(io::Error::other)?;
        assert_eq!(calculate(&connection, None)?, original);
        connection
            .execute_batch("CREATE TABLE unknown_content(id INTEGER PRIMARY KEY) STRICT;")
            .map_err(io::Error::other)?;
        assert!(calculate(&connection, None).is_err());
        connection
            .execute_batch("DROP TABLE unknown_content; CREATE VIEW hidden_content AS SELECT 1;")
            .map_err(io::Error::other)?;
        assert!(calculate(&connection, None).is_err());
        connection
            .execute_batch("DROP VIEW hidden_content; DROP TABLE proxy_users;")
            .map_err(io::Error::other)?;
        assert!(calculate(&connection, None).is_err());
        Ok(())
    }

    #[test]
    fn content_refuses_nullable_primary_key_rows_instead_of_using_page_order() -> io::Result<()> {
        let f = Fixture::new()?;
        let connection = f.connection()?;
        connection.execute_batch("DROP TABLE administrators;
        CREATE TABLE administrators(id TEXT PRIMARY KEY,username TEXT NOT NULL,password_hash TEXT NOT NULL);
        INSERT INTO administrators VALUES(NULL,'a','fixture a'),(NULL,'b','fixture b');").map_err(io::Error::other)?;
        assert!(calculate(&connection, None).is_err());
        Ok(())
    }

    #[test]
    fn identity_content_normalizes_only_the_checked_quarantine_singleton() -> io::Result<()> {
        let f = Fixture::new()?;
        let connection = f.connection()?;
        let original = calculate(&connection, None)?;
        let (output, manifest) = f.capture("snapshot")?;
        let marker: recovery::Snapshot =
            serde_json::from_slice(&fs::read(output.join(backup::SNAPSHOT_FILE))?)
                .map_err(io::Error::other)?;
        assert_eq!(
            manifest.database_content_sha256.as_deref(),
            Some(original.as_str())
        );
        assert_eq!(
            marker.database_content_sha256,
            manifest.database_content_sha256
        );
        let copied =
            Connection::open(output.join(store::DATABASE_NAME)).map_err(io::Error::other)?;
        assert_ne!(calculate(&copied, None)?, original);
        assert_eq!(calculate(&copied, Some(&marker))?, original);
        assert_eq!(store::verify_backup(&output)?, manifest);
        assert_eq!(
            store::recovery::startup(&output).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        copied
            .execute("UPDATE administrator_audit_state SET last_sequence=21", [])
            .map_err(io::Error::other)?;
        assert_ne!(calculate(&copied, Some(&marker))?, original);
        copied
            .execute(
                "UPDATE recovery_state SET recovery_id=?1",
                [store::random_id()?],
            )
            .map_err(io::Error::other)?;
        assert!(calculate(&copied, Some(&marker)).is_err());
        Ok(())
    }

    /// Rewrite only this fixture's outer file checksum, emulating a package whose
    /// bytes are internally consistent but still claim an old logical commitment.
    fn rehash_file(output: &std::path::Path) -> io::Result<()> {
        let file = output.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&file)?).map_err(io::Error::other)?;
        let bytes = fs::read(output.join(store::DATABASE_NAME))?;
        manifest["database_sha256"] = encode(&Sha256::digest(&bytes)).into();
        manifest["database_bytes"] = (bytes.len() as u64).into();
        fs::write(
            file,
            serde_json::to_vec(&manifest).map_err(io::Error::other)?,
        )
    }

    #[test]
    fn matching_file_hash_and_raised_counter_do_not_match_old_content_commitment() -> io::Result<()>
    {
        let f = Fixture::new()?;
        let (output, original) = f.capture("tamper")?;
        let copied =
            Connection::open(output.join(store::DATABASE_NAME)).map_err(io::Error::other)?;
        copied
            .execute(
                "UPDATE administrator_audit_state SET last_sequence=999999",
                [],
            )
            .map_err(io::Error::other)?;
        drop(copied);
        rehash_file(&output)?;
        let error = store::verify_backup(&output)
            .err()
            .ok_or_else(|| io::Error::other("changed content unexpectedly verified"))?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("content commitment"));
        let bytes = fs::read(output.join("manifest.json"))?;
        let changed: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        assert_eq!(
            changed["database_content_sha256"],
            serde_json::to_value(original.database_content_sha256).map_err(io::Error::other)?
        );
        Ok(())
    }

    #[test]
    fn legacy_content_is_absent_and_partial_or_disagreeing_downgrade_is_rejected() -> io::Result<()>
    {
        let f = Fixture::new()?;
        let (output, manifest) = f.capture("legacy")?;
        let marker_file = output.join(backup::SNAPSHOT_FILE);
        let manifest_file = output.join("manifest.json");
        let mut marker: serde_json::Value =
            serde_json::from_slice(&fs::read(&marker_file)?).map_err(io::Error::other)?;
        let mut outer: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_file)?).map_err(io::Error::other)?;
        marker
            .as_object_mut()
            .unwrap()
            .remove("database_content_sha256");
        fs::write(
            &marker_file,
            serde_json::to_vec(&marker).map_err(io::Error::other)?,
        )?;
        assert!(store::verify_backup(&output).is_err());
        outer
            .as_object_mut()
            .unwrap()
            .remove("database_content_sha256");
        fs::write(
            &manifest_file,
            serde_json::to_vec(&outer).map_err(io::Error::other)?,
        )?;
        assert!(store::verify_backup(&output).is_err()); // v2 requires the field
        marker["format_version"] = 1.into();
        fs::write(
            &marker_file,
            serde_json::to_vec(&marker).map_err(io::Error::other)?,
        )?;
        let legacy = store::verify_backup(&output)?;
        assert!(legacy.database_content_sha256.is_none());
        assert_eq!(legacy.node_id, manifest.node_id);
        assert!(store::recovery::startup(&output).is_err());
        Ok(())
    }

    #[test]
    fn content_full_audit_streams_by_primary_key_without_an_order_by_sort() -> io::Result<()> {
        let f = Fixture::new()?;
        let peer = store::random_id()?;
        store::register_peer(
            &f.state,
            &peer,
            "content sample",
            b"metadata-only fixture DER",
            "peer.test",
            None,
        )?;
        let mut connection = f.connection()?;
        let tx = connection.transaction().map_err(io::Error::other)?;
        {
            let mut insert = tx
                .prepare("INSERT INTO peer_audit VALUES(?1,'offline','update',?2,?1)")
                .map_err(io::Error::other)?;
            for sequence in 2..=16384_i64 {
                insert
                    .execute(rusqlite::params![sequence, peer])
                    .map_err(io::Error::other)?;
            }
            tx.execute(
                "UPDATE peers SET authorization_revision=16384 WHERE node_id=?1",
                [&peer],
            )
            .map_err(io::Error::other)?;
        }
        tx.commit().map_err(io::Error::other)?;
        for table in backup::tables(store::SCHEMA_VERSION) {
            let columns = columns(&connection, table, &mut Sha256::new())?;
            let order = columns
                .primary_key
                .iter()
                .map(|(_, name)| format!("\"{name}\" COLLATE BINARY"))
                .collect::<Vec<_>>()
                .join(",");
            let mut query = connection
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN SELECT * FROM \"{table}\" ORDER BY {order}"
                ))
                .map_err(io::Error::other)?;
            for item in query
                .query_map([], |r| r.get::<_, String>(3))
                .map_err(io::Error::other)?
            {
                assert!(
                    !item.map_err(io::Error::other)?.contains("USE TEMP B-TREE"),
                    "{table}"
                );
            }
        }
        let mut samples = Vec::new();
        let mut previous = None;
        for _ in 0..3 {
            let start = std::time::Instant::now();
            let current = calculate(&connection, None)?;
            samples.push(start.elapsed().as_secs_f64() * 1000.0);
            if let Some(previous) = &previous {
                assert_eq!(&current, previous);
            }
            previous = Some(current);
        }
        // Diagnostic sample only: no timing assertion and no optimized production
        // throughput claim. Only non-secret counts/durations leave this fixture.
        eprintln!(
            "CONTENT_SCAN_SAMPLE={}",
            serde_json::json!({"audit_rows":16384,"debug_scan_ms":samples})
        );
        Ok(())
    }
}
