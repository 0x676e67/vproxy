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
