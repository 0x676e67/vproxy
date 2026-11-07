//! Administrator verifiers and bounded audit, separate from proxy credentials.
//!
//! Offline recovery uses filesystem authority and requires the serve-lifetime
//! author lock, so it cannot run alongside a live API process. Online self-service
//! instead requires a verified session/current password and an in-process login
//! fence; both paths share verifier storage and the same durable audit counter.

use std::{
    io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use argon2::{Argon2, PasswordHasher};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use zeroize::Zeroizing;

use super::{
    Overview, SCHEMA_VERSION, invalid_data,
    peers::{backup_existing, open_existing},
    read_overview, sqlite_error, valid_id,
};

const MAX_AUDIT_RECORDS: u32 = 16_384;

/// Schema twelve expands only audit vocabulary; previous rows and the permanent
/// high-water survive the rebuild. The caller owns the migration transaction.
pub(super) fn upgrade_schema(connection: &Connection) -> io::Result<()> {
    connection.execute_batch(
        "CREATE TABLE administrator_audit_v12 (
            sequence INTEGER PRIMARY KEY CHECK(sequence >= 1),
            entry TEXT NOT NULL, action TEXT NOT NULL,
            administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
            recorded_at INTEGER NOT NULL CHECK(recorded_at >= 0),
            CHECK((entry='offline' AND action='reset_password') OR
                  (entry='web' AND action='change_password'))
         ) STRICT;
         INSERT INTO administrator_audit_v12 SELECT sequence,entry,action,administrator_id,recorded_at FROM administrator_audit;
         DROP TABLE administrator_audit;
         ALTER TABLE administrator_audit_v12 RENAME TO administrator_audit;"
    ).map_err(|error| sqlite_error("cannot upgrade administrator audit vocabulary", error))
}

/// Add recovery records and a permanent sequence high-water in the caller's
/// transaction. Pruning history must not permit sequence reuse after a restart.
/// `administrator_id` is the recovery subject, not a logged-in Web actor.
/// `recorded_at` is the host's Unix time for operators; ordering uses sequence,
/// not an assumption that this clock is trustworthy or moves only forward.
pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection
        .execute_batch(
            "CREATE TABLE administrator_audit_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0)
             ) STRICT;
             INSERT INTO administrator_audit_state VALUES (1, 0);
             CREATE TABLE administrator_audit (
                sequence INTEGER PRIMARY KEY CHECK (sequence >= 1),
                entry TEXT NOT NULL CHECK (entry = 'offline'),
                action TEXT NOT NULL CHECK (action = 'reset_password'),
                administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
                recorded_at INTEGER NOT NULL CHECK (recorded_at >= 0)
             ) STRICT;",
        )
        .map_err(|error| sqlite_error("cannot create administrator recovery schema", error))
}

/// Replace only the named existing administrator's verifier after a new backup.
///
/// The caller supplies an Argon2id PHC derived from bounded, protected input,
/// never plaintext. No identity, proxy policy, authorization or owner changes.
/// Current schema is required: an old store needs explicit `migrate --backup`.
/// Both OS locks fail immediately on contention; SQLite waits and backup work
/// use the existing bounded store limits. The backup is the committed pre-change
/// snapshot, retained even if a later audit or commit fails. PHC, audit and audit
/// high-water changes commit together or all roll back. No live session map is
/// edited: the author lock requires stopping serve, whose restart clears sessions.
pub(in crate::manage) fn reset_password(
    directory: &Path,
    administrator: &str,
    password_hash: &str,
    backup_path: &Path,
) -> io::Result<Overview> {
    super::super::validate_administrator(administrator)?;
    let _author = super::lock(directory)?;
    let _update = super::update_lock(directory)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin administrator recovery", error))?;
    let overview = reset_transaction(
        directory,
        &transaction,
        administrator,
        password_hash,
        backup_path,
    )?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit administrator recovery", error))?;
    Ok(overview)
}

fn reset_transaction(
    directory: &Path,
    transaction: &rusqlite::Transaction<'_>,
    administrator: &str,
    password_hash: &str,
    backup_path: &Path,
) -> io::Result<Overview> {
    if transaction.is_autocommit() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "administrator recovery requires a held transaction",
        ));
    }
    let overview = read_overview(transaction)?;
    if overview.schema_version != SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "administrator recovery requires the current schema; first run manage migrate --backup with a different new backup path",
        ));
    }
    let id: String = transaction
        .query_row(
            "SELECT id FROM administrators WHERE username = ?1",
            [administrator],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| sqlite_error("cannot select recovery administrator", error))?
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "administrator is not registered")
        })?;
    if !valid_id(&id) {
        return Err(invalid_data("recovery administrator identity is malformed"));
    }
    let (sequence, recorded_at) = audit_values(transaction)?;

    // Reserve the writer slot before opening the separate backup reader. No SQL
    // mutation precedes this snapshot, so it includes the old verifier and WAL.
    backup_existing(directory, backup_path, &overview)?;
    let changed = transaction
        .execute(
            "UPDATE administrators SET password_hash = ?1 WHERE id = ?2",
            params![password_hash, id],
        )
        .map_err(|error| sqlite_error("cannot update administrator verifier", error))?;
    if changed != 1 {
        return Err(invalid_data(
            "administrator recovery did not update one identity",
        ));
    }
    append_audit(
        transaction,
        &id,
        "offline",
        "reset_password",
        sequence,
        recorded_at,
    )?;
    Ok(overview)
}

/// Append/prune inside the caller's verifier transaction. Entry/action are only
/// internal literals and SQL additionally enforces valid subject/action pairs.
fn append_audit(
    connection: &Connection,
    id: &str,
    entry: &str,
    action: &str,
    sequence: i64,
    recorded_at: i64,
) -> io::Result<()> {
    let audited = connection
        .execute(
            "INSERT INTO administrator_audit
             (sequence, entry, action, administrator_id, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![sequence, entry, action, id, recorded_at],
        )
        .map_err(|error| sqlite_error("cannot audit administrator recovery", error))?;
    if audited != 1 {
        return Err(invalid_data("administrator recovery audit was not stored"));
    }
    let advanced = connection
        .execute(
            "UPDATE administrator_audit_state SET last_sequence = ?1 WHERE singleton = 1",
            [sequence],
        )
        .map_err(|error| sqlite_error("cannot advance administrator recovery sequence", error))?;
    if advanced != 1 {
        return Err(invalid_data(
            "administrator recovery sequence was not advanced",
        ));
    }
    connection
        .execute(
            "DELETE FROM administrator_audit WHERE sequence IN
             (SELECT sequence FROM administrator_audit ORDER BY sequence DESC LIMIT -1 OFFSET ?1)",
            [MAX_AUDIT_RECORDS],
        )
        .map_err(|error| sqlite_error("cannot prune administrator recovery history", error))?;
    Ok(())
}

/// Derive metadata before any verifier mutation or offline backup is attempted.
fn audit_values(connection: &Connection) -> io::Result<(i64, i64)> {
    let sequence = next_sequence(connection)?;
    let recorded_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .ok_or_else(|| invalid_data("administrator recovery clock is out of range"))?;
    Ok((sequence, recorded_at))
}

/// Verified comparison token, never serialized, logged, cloned or sent to a UI.
/// Both verifiers stay zeroizing and the stable ID prevents username substitution.
pub(in crate::manage) struct PasswordChange {
    administrator_id: String,
    expected_hash: Zeroizing<String>,
    new_hash: Zeroizing<String>,
}

/// Distinguishes CAS rejection and an uncertain commit without exposing SQL.
pub(in crate::manage) enum PasswordChangeOutcome {
    Committed,
    Conflict,
    NotCommitted,
    Unknown,
}

/// Read one credential snapshot, finish its SQL read, then perform Argon2 work.
/// The caller bounds input and owns the password-work permit through commit.
/// A missing identity or incorrect current password returns None, not a mutation.
pub(in crate::manage) fn prepare_password_change(
    directory: &Path,
    id: &str,
    username: &str,
    current_password: &[u8],
    new_password: &[u8],
) -> io::Result<Option<PasswordChange>> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot inspect password-change credential", error))?;
    if read_overview(&transaction)?.schema_version < 12 || !valid_id(id) {
        return Err(invalid_data(
            "password change requires administrator schema twelve or newer",
        ));
    }
    let expected_hash = transaction
        .query_row(
            "SELECT password_hash FROM administrators WHERE id=?1 AND username=?2",
            params![id, username],
            |row| Ok(Zeroizing::new(row.get::<_, String>(0)?)),
        )
        .optional()
        .map_err(|error| sqlite_error("cannot inspect current administrator verifier", error))?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot finish password-change inspection", error))?;
    let Some(expected_hash) = expected_hash else {
        return Ok(None);
    };
    if !super::verify_password(&expected_hash, current_password)? {
        return Ok(None);
    }
    let new_hash = Argon2::default()
        .hash_password(new_password)
        .map_err(|_| io::Error::other("cannot derive replacement administrator verifier"))?;
    Ok(Some(PasswordChange {
        administrator_id: id.to_owned(),
        expected_hash,
        new_hash: Zeroizing::new(new_hash.to_string()),
    }))
}

/// Commit only if the verified PHC is still current, using the existing update
/// gate (not the serve-lifetime author lock). Audit and verifier share one commit.
/// A commit error gets one new read snapshot under the same gate, never a replay;
/// any result other than proven old/no-audit or new/exact-audit remains Unknown.
pub(in crate::manage) fn change_password(
    directory: &Path,
    change: &PasswordChange,
    guard: &super::UpdateGuard,
) -> io::Result<PasswordChangeOutcome> {
    guard.ensure(directory)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin administrator password change", error))?;
    let Some(sequence) = replace_password_in(&transaction, change)? else {
        return Ok(PasswordChangeOutcome::Conflict);
    };
    if transaction.commit().is_ok() {
        return Ok(PasswordChangeOutcome::Committed);
    }
    drop(connection);
    Ok(confirm_password_change(directory, change, sequence)
        .unwrap_or(PasswordChangeOutcome::Unknown))
}

fn replace_password_in(
    transaction: &rusqlite::Transaction<'_>,
    change: &PasswordChange,
) -> io::Result<Option<i64>> {
    if read_overview(transaction)?.schema_version < 12 {
        return Err(invalid_data(
            "password change requires administrator schema twelve or newer",
        ));
    }
    let (sequence, recorded_at) = audit_values(transaction)?;
    let changed = transaction
        .execute(
            "UPDATE administrators SET password_hash=?1 WHERE id=?2 AND password_hash=?3",
            params![
                change.new_hash.as_str(),
                change.administrator_id,
                change.expected_hash.as_str()
            ],
        )
        .map_err(|error| sqlite_error("cannot replace administrator verifier", error))?;
    if changed == 0 {
        return Ok(None);
    }
    if changed != 1 {
        return Err(invalid_data(
            "password change affected an invalid administrator count",
        ));
    }
    append_audit(
        transaction,
        &change.administrator_id,
        "web",
        "change_password",
        sequence,
        recorded_at,
    )?;
    Ok(Some(sequence))
}

/// Confirmation is evidence only, not permission to repeat a possibly committed
/// write. No cooperating writer can prune this operation while its gate is held.
fn confirm_password_change(
    directory: &Path,
    change: &PasswordChange,
    sequence: i64,
) -> io::Result<PasswordChangeOutcome> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot confirm administrator password change", error))?;
    let hash: Option<Zeroizing<String>> = transaction
        .query_row(
            "SELECT password_hash FROM administrators WHERE id=?1",
            [&change.administrator_id],
            |row| Ok(Zeroizing::new(row.get::<_, String>(0)?)),
        )
        .optional()
        .map_err(|error| sqlite_error("cannot confirm administrator verifier", error))?;
    let audit: Option<(String, String, String)> = transaction
        .query_row(
            "SELECT entry,action,administrator_id FROM administrator_audit WHERE sequence=?1",
            [sequence],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| sqlite_error("cannot confirm administrator audit", error))?;
    let highwater: i64 = transaction
        .query_row(
            "SELECT last_sequence FROM administrator_audit_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot confirm administrator audit counter", error))?;
    let result = if hash.as_deref().map(String::as_str) == Some(change.new_hash.as_str())
        && audit.as_ref().is_some_and(|(entry, action, id)| {
            entry == "web" && action == "change_password" && id == &change.administrator_id
        })
        && highwater == sequence
    {
        PasswordChangeOutcome::Committed
    } else if hash.as_deref().map(String::as_str) == Some(change.expected_hash.as_str())
        && audit.is_none()
        && sequence.checked_sub(1) == Some(highwater)
    {
        PasswordChangeOutcome::NotCommitted
    } else {
        PasswordChangeOutcome::Unknown
    };
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot finish password-change confirmation", error))?;
    Ok(result)
}

/// Check the permanent counter against retained history before checked increment.
/// SQLite's implicit ROWID allocation may choose a smaller unused ID at i64::MAX;
/// explicit allocation is required for this durable, monotonic audit sequence.
fn next_sequence(connection: &Connection) -> io::Result<i64> {
    let previous: i64 = connection
        .query_row(
            "SELECT last_sequence FROM administrator_audit_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot inspect administrator recovery sequence", error))?;
    let retained: Option<i64> = connection
        .query_row("SELECT max(sequence) FROM administrator_audit", [], |row| {
            row.get(0)
        })
        .map_err(|error| sqlite_error("cannot inspect administrator recovery history", error))?;
    if previous < 0 || retained.is_some_and(|last| last < 1 || last > previous) {
        return Err(invalid_data(
            "administrator recovery sequence is inconsistent",
        ));
    }
    previous
        .checked_add(1)
        .ok_or_else(|| invalid_data("administrator recovery sequence is exhausted"))
}
