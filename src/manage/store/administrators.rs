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

/// Trusted offline file-author recovery. The enclosing caller owns both source
/// guards and must not have a live API/session owner. The new private backup
/// precedes SQL mutation and survives any later failure; it is not a restore or
/// activation permit. Only the outer Source confirmation reports completion.
/// A Source-marked output parent is refused before claiming a partial file.
#[cfg(feature = "witness-journal")]
pub(super) fn reset_in(
    directory: &Path,
    transaction: &rusqlite::Transaction<'_>,
    administrator: &str,
    password_hash: &str,
    backup_path: &Path,
) -> io::Result<Overview> {
    super::super::validate_administrator(administrator)?;
    if let Some(parent) = backup_path.parent() {
        super::source::reject_marker(parent)?;
    }
    reset_transaction(
        directory,
        transaction,
        administrator,
        password_hash,
        backup_path,
    )
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

/// Stage the already-verified PHC comparison and audit in the source worker's
/// transaction. True means candidate rows changed, not that they committed;
/// only the outer witness confirmation may report success. False is a read-only
/// comparison conflict. No hashing, session mutation or commit occurs here.
#[cfg(feature = "witness-journal")]
pub(in crate::manage) fn apply_password_change_in(
    transaction: &rusqlite::Transaction<'_>,
    change: &PasswordChange,
) -> io::Result<bool> {
    replace_password_in(transaction, change).map(|sequence| sequence.is_some())
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

/// Reconstruct old fixtures without falsely retaining schema-eleven objects.
#[cfg(test)]
pub(in crate::manage::store) fn remove_schema_for_test(connection: &Connection) -> io::Result<()> {
    connection
        .execute_batch("DROP TABLE administrator_audit; DROP TABLE administrator_audit_state;")
        .map_err(|error| sqlite_error("cannot remove administrator recovery fixture", error))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::OnceLock};

    use argon2::{Argon2, PasswordHasher};
    use rusqlite::types::Value;

    use super::*;
    use crate::access::Protocol;
    use crate::manage::store::{
        self, DATABASE_NAME, PolicyChange, authenticate, initialize, prepare_directory, random_id,
    };

    const OLD_PASSWORD: &[u8] = b"old fixture passphrase";
    const NEW_PASSWORD: &[u8] = b"new fixture passphrase";

    /// Test-owned verifiers only; deriving once avoids repeated Argon2 work in cases
    /// concerned with locking, SQL rollback and migration rather than hashing costs.
    fn hashes() -> &'static (String, String) {
        static HASHES: OnceLock<(String, String)> = OnceLock::new();
        HASHES.get_or_init(|| {
            let hash = |value| Argon2::default().hash_password(value).unwrap().to_string();
            (hash(OLD_PASSWORD), hash(NEW_PASSWORD))
        })
    }

    /// Owns only a random private leaf, not an operator-selected directory.
    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory =
                std::env::temp_dir().join(format!("vproxy-admin-recovery-{}", random_id()?));
            prepare_directory(&directory)?;
            initialize(&directory, "recovery fixture", "admin", &hashes().0)?;
            Ok(Self(directory))
        }

        fn connection(&self) -> io::Result<Connection> {
            open_existing(&self.0, true)
        }

        fn reset(&self, backup: &str) -> io::Result<Overview> {
            reset_password(&self.0, "admin", &hashes().1, &self.0.join(backup))
        }

        fn administrator(&self) -> io::Result<(String, String)> {
            self.connection()?
                .query_row(
                    "SELECT id,password_hash FROM administrators WHERE username='admin'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(io::Error::other)
        }

        fn version_ten(&self) -> io::Result<()> {
            let connection = self.connection()?;
            store::restore_legacy_owner_audit(&connection)?;
            remove_schema_for_test(&connection)?;
            connection
                .pragma_update(None, "user_version", 10)
                .map_err(io::Error::other)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    type Rows = Vec<(String, Vec<Vec<Value>>)>;

    /// Preserve every existing SQL value, optionally omitting only this operation's
    /// audit tables and the selected administrator's verifier. Other verifiers stay.
    fn rows(connection: &Connection, omit_recovery: bool, mask_password: bool) -> io::Result<Rows> {
        let names = connection
            .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
            .map_err(io::Error::other)?
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(io::Error::other)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)?;
        let mut result = Vec::new();
        for name in names {
            if omit_recovery
                && ["administrator_audit", "administrator_audit_state"].contains(&name.as_str())
            {
                continue;
            }
            let quoted = format!("\"{}\"", name.replace('"', "\"\""));
            let mut statement = connection
                .prepare(&format!("SELECT * FROM {quoted} ORDER BY rowid"))
                .map_err(io::Error::other)?;
            let columns = statement.column_count();
            let values = statement
                .query_map([], |row| {
                    let mut values = (0..columns)
                        .map(|index| row.get(index))
                        .collect::<rusqlite::Result<Vec<Value>>>()?;
                    if mask_password
                        && name == "administrators"
                        && values[1] == Value::Text("admin".into())
                    {
                        values[2] = Value::Null;
                    }
                    Ok(values)
                })
                .map_err(io::Error::other)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(io::Error::other)?;
            result.push((name, values));
        }
        Ok(result)
    }

    fn assert_fresh_automation_namespace(connection: &Connection) -> io::Result<()> {
        let state: (i64, i64, i64, i64) = connection
            .query_row(
                "SELECT (SELECT count(*) FROM automation_state),
                    (SELECT last_sequence FROM automation_state WHERE singleton=1),
                    (SELECT count(*) FROM automation_principals),
                    (SELECT count(*) FROM automation_audit)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(io::Error::other)?;
        assert_eq!(state, (1, 0, 0, 0));
        Ok(())
    }

    fn assert_fresh_admission_namespace(connection: &Connection) -> io::Result<()> {
        let state: (i64, i64, i64, i64) = connection
            .query_row(
                "SELECT (SELECT count(*) FROM proxy_admission_state),
                    (SELECT singleton FROM proxy_admission_state),
                    (SELECT accepting FROM proxy_admission_state),
                    (SELECT count(*) FROM proxy_admission_audit)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(io::Error::other)?;
        assert_eq!(state, (1, 1, 1, 0));
        Ok(())
    }

    fn assert_fresh_controller_history_namespace(connection: &Connection) -> io::Result<()> {
        store::targets::history::validate_snapshot(connection)?;
        let state: (i64, i64, i64, i64) = connection
            .query_row(
                "SELECT (SELECT count(*) FROM controller_history_state),
                    (SELECT singleton FROM controller_history_state),
                    (SELECT last_sequence FROM controller_history_state),
                    (SELECT count(*) FROM controller_history)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(io::Error::other)?;
        assert_eq!(state, (1, 1, 0, 0));
        Ok(())
    }

    fn assert_fresh_alert_history_namespace(connection: &Connection) -> io::Result<()> {
        store::alerts::history::validate_snapshot(connection)?;
        // A migration creates the namespace, not a monitor boot or observations.
        store::alerts::history::require_empty(connection)
    }

    #[test]
    fn recovery_preserves_identity_policy_and_authorization_with_prechange_backup() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        let (id, _) = fixture.administrator()?;
        let connection = fixture.connection()?;
        connection
            .execute(
                "INSERT INTO administrators VALUES (?1,'other',?2)",
                params![random_id()?, hashes().0],
            )
            .map_err(io::Error::other)?;
        let gate = store::update_lock(&fixture.0)?;
        let created = store::apply_policy(
            &fixture.0,
            &id,
            1,
            PolicyChange::CreateUser {
                name: "existing proxy user".into(),
                protocols: vec![Protocol::Socks5],
                concurrent_limit: 2,
            },
            &gate,
        )?;
        store::apply_policy(
            &fixture.0,
            &id,
            2,
            PolicyChange::CreateCredential {
                user_id: created.user.unwrap().id,
            },
            &gate,
        )?;
        drop(gate);
        let peer = random_id()?;
        store::register_peer(
            &fixture.0,
            &peer,
            "peer",
            b"fixture certificate",
            "peer.example",
            None,
        )?;
        let gate = store::update_lock(&fixture.0)?;
        store::set_owner(&fixture.0, &gate, &id, 1, Some(&peer))?;
        drop(gate);
        let before = rows(&connection, true, true)?;
        let overview = store::inspect(&fixture.0)?;

        let recovered = fixture.reset("before.sqlite3")?;
        assert_eq!(
            (
                recovered.node_id,
                recovered.name,
                recovered.administrator_count
            ),
            (overview.node_id, overview.name, 2)
        );
        assert_eq!(rows(&connection, true, true)?, before);
        assert_eq!(fixture.administrator()?, (id.clone(), hashes().1.clone()));
        assert!(authenticate(&fixture.0, "admin", OLD_PASSWORD, &hashes().0)?.is_none());
        assert_eq!(
            authenticate(&fixture.0, "admin", NEW_PASSWORD, &hashes().0)?
                .unwrap()
                .id,
            id
        );
        let audit: (i64, String, String, String, i64) = connection
        .query_row(
            "SELECT sequence,entry,action,administrator_id,recorded_at FROM administrator_audit",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(io::Error::other)?;
        assert_eq!(
            (audit.0, audit.1.as_str(), audit.2.as_str(), audit.3),
            (1, "offline", "reset_password", id)
        );
        assert!(audit.4 > 0);
        let backup =
            Connection::open(fixture.0.join("before.sqlite3")).map_err(io::Error::other)?;
        assert_eq!(rows(&backup, true, true)?, before);
        let old_hash: String = backup
            .query_row(
                "SELECT password_hash FROM administrators WHERE username='admin'",
                [],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        assert_eq!(old_hash, hashes().0);
        let journal: String = backup
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(io::Error::other)?;
        assert_eq!(journal, "delete");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(fixture.0.join("before.sqlite3"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        Ok(())
    }

    #[test]
    fn running_author_or_update_writer_blocks_recovery_without_backup() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let before = fixture.administrator()?;
        let author = store::lock(&fixture.0)?;
        assert_eq!(
            fixture.reset("running.sqlite3").err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(author);
        let update = store::update_lock(&fixture.0)?;
        assert_eq!(
            fixture.reset("updating.sqlite3").err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(update);
        assert_eq!(fixture.administrator()?, before);
        assert!(
            !fixture.0.join("running.sqlite3").exists()
                && !fixture.0.join("updating.sqlite3").exists()
        );
        Ok(())
    }

    #[test]
    fn selection_and_backup_failures_never_create_or_change_an_administrator() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let before = rows(&fixture.connection()?, false, false)?;
        for (name, kind) in [
            ("missing", io::ErrorKind::NotFound),
            ("bad:name", io::ErrorKind::InvalidInput),
        ] {
            assert_eq!(
                reset_password(
                    &fixture.0,
                    name,
                    &hashes().1,
                    &fixture.0.join("unused.sqlite3")
                )
                .err()
                .unwrap()
                .kind(),
                kind
            );
        }
        assert!(!fixture.0.join("unused.sqlite3").exists());
        let existing = fixture.0.join("existing.sqlite3");
        fs::write(&existing, b"operator owned")?;
        assert_eq!(
            fixture.reset("existing.sqlite3").err().unwrap().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&existing)?, b"operator owned");
        assert_eq!(
            fixture.reset(DATABASE_NAME).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(rows(&fixture.connection()?, false, false)?, before);

        let missing = fixture.0.join("not-initialized");
        prepare_directory(&missing)?;
        assert_eq!(
            reset_password(
                &missing,
                "admin",
                &hashes().1,
                &fixture.0.join("missing.sqlite3")
            )
            .err()
            .unwrap()
            .kind(),
            io::ErrorKind::NotFound
        );
        assert!(!missing.join(DATABASE_NAME).exists());
        fs::write(missing.join(DATABASE_NAME), b"damaged database")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                missing.join(DATABASE_NAME),
                fs::Permissions::from_mode(0o600),
            )?;
        }
        assert!(
            reset_password(
                &missing,
                "admin",
                &hashes().1,
                &fixture.0.join("damaged.sqlite3")
            )
            .is_err()
        );
        assert_eq!(fs::read(missing.join(DATABASE_NAME))?, b"damaged database");
        assert!(
            !fixture.0.join("missing.sqlite3").exists()
                && !fixture.0.join("damaged.sqlite3").exists()
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn recovery_rejects_symlink_backup_and_nonprivate_parent_without_mutation() -> io::Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let fixture = Fixture::new()?;
        let before = rows(&fixture.connection()?, false, false)?;
        let target = fixture.0.join("operator-file");
        fs::write(&target, b"must remain unchanged")?;
        symlink(&target, fixture.0.join("symlink.sqlite3"))?;
        assert!(fixture.reset("symlink.sqlite3").is_err());
        assert_eq!(fs::read(target)?, b"must remain unchanged");

        let public = fixture.0.join("nonprivate");
        prepare_directory(&public)?;
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755))?;
        assert_eq!(
            reset_password(
                &fixture.0,
                "admin",
                &hashes().1,
                &public.join("backup.sqlite3")
            )
            .err()
            .unwrap()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!public.join("backup.sqlite3").exists());
        assert_eq!(fs::metadata(public)?.permissions().mode() & 0o777, 0o755);
        assert_eq!(rows(&fixture.connection()?, false, false)?, before);
        Ok(())
    }

    #[test]
    fn audit_insert_counter_and_prune_failures_roll_back_the_verifier() -> io::Result<()> {
        for (index, trigger) in [
        "CREATE TRIGGER failed_audit BEFORE INSERT ON administrator_audit BEGIN SELECT RAISE(ABORT,'fixture'); END;",
        "CREATE TRIGGER failed_audit BEFORE INSERT ON administrator_audit BEGIN SELECT RAISE(IGNORE); END;",
        "CREATE TRIGGER failed_counter BEFORE UPDATE ON administrator_audit_state BEGIN SELECT RAISE(ABORT,'fixture'); END;",
        "CREATE TRIGGER failed_counter BEFORE UPDATE ON administrator_audit_state BEGIN SELECT RAISE(IGNORE); END;",
        "CREATE TRIGGER failed_prune BEFORE DELETE ON administrator_audit BEGIN SELECT RAISE(ABORT,'fixture'); END;",
    ].iter().enumerate() {
        let fixture = Fixture::new()?;
        let connection = fixture.connection()?;
        let id = fixture.administrator()?.0;
        seed_history(&connection, &id)?;
        connection.execute_batch(trigger).map_err(io::Error::other)?;
        let before = rows(&connection, false, false)?;
        let filename = format!("failed-{index}.sqlite3");
        assert!(fixture.reset(&filename).is_err());
        assert_eq!(rows(&connection, false, false)?, before);
        let backup = Connection::open(fixture.0.join(filename)).map_err(io::Error::other)?;
        assert_eq!(rows(&backup, false, false)?, before);
    }
        Ok(())
    }

    fn seed_history(connection: &Connection, id: &str) -> io::Result<()> {
        connection.execute(
        "WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM numbers WHERE n < ?1)
         INSERT INTO administrator_audit SELECT n,'offline','reset_password',?2,0 FROM numbers",
        params![MAX_AUDIT_RECORDS, id],
    ).map_err(io::Error::other)?;
        connection
            .execute(
                "UPDATE administrator_audit_state SET last_sequence=?1",
                [MAX_AUDIT_RECORDS],
            )
            .map_err(io::Error::other)?;
        Ok(())
    }

    #[test]
    fn pruning_keeps_the_high_water_and_sequence_exhaustion_is_atomic() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let connection = fixture.connection()?;
        let id = fixture.administrator()?.0;
        seed_history(&connection, &id)?;
        fixture.reset("bounded.sqlite3")?;
        let retained: (i64, i64, i64) = connection
            .query_row(
                "SELECT count(*),min(sequence),max(sequence) FROM administrator_audit",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(io::Error::other)?;
        assert_eq!(
            retained,
            (
                i64::from(MAX_AUDIT_RECORDS),
                2,
                i64::from(MAX_AUDIT_RECORDS) + 1
            )
        );
        connection
            .execute("DELETE FROM administrator_audit", [])
            .map_err(io::Error::other)?;
        fixture.reset("pruned.sqlite3")?;
        let last: i64 = connection
            .query_row(
                "SELECT last_sequence FROM administrator_audit_state",
                [],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        assert_eq!(last, i64::from(MAX_AUDIT_RECORDS) + 2);
        connection
            .execute(
                "UPDATE administrator_audit_state SET last_sequence=?1",
                [i64::MAX],
            )
            .map_err(io::Error::other)?;
        let before = rows(&connection, false, false)?;
        assert_eq!(
            fixture.reset("exhausted.sqlite3").err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(rows(&connection, false, false)?, before);
        assert!(!fixture.0.join("exhausted.sqlite3").exists());
        // A damaged counter below a retained sequence must also refuse reuse.
        connection
            .execute("UPDATE administrator_audit_state SET last_sequence=0", [])
            .map_err(io::Error::other)?;
        assert_eq!(
            fixture.reset("inconsistent.sqlite3").err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!fixture.0.join("inconsistent.sqlite3").exists());
        Ok(())
    }

    #[test]
    fn schema_ten_requires_explicit_backed_up_migration_and_preserves_all_rows() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.version_ten()?;
        let connection = fixture.connection()?;
        let before = rows(&connection, false, false)?;
        let node_id = store::inspect(&fixture.0)?.node_id;
        assert_eq!(
            fixture.reset("implicit.sqlite3").err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!fixture.0.join("implicit.sqlite3").exists());
        assert_eq!(store::inspect(&fixture.0)?.schema_version, 10);
        store::migrate(&fixture.0, &fixture.0.join("schema10.sqlite3"))?;
        store::proxy_service::require_unused_for_test(&connection)?;
        store::notifications::ensure_unused_for_test(&connection)?;
        // Newly introduced namespaces are checked separately; every old table still
        // participates in the value-for-value comparison below.
        assert_eq!(
            rows(&connection, true, false)?
                .into_iter()
                .filter(|(name, _)| ![
                    "recovery_state",
                    "endpoint_state",
                    "endpoint_overrides",
                    "endpoint_audit",
                    "operations_state",
                    "user_operations",
                    "automation_state",
                    "automation_principals",
                    "automation_audit",
                    "proxy_admission_state",
                    "proxy_admission_audit",
                    "controller_history_state",
                    "controller_history",
                    "alert_history_state",
                    "alert_episodes",
                    "alert_events",
                    "webhook_state",
                    "recovery_witness",
                    "recovery_source",
                    "proxy_service_state",
                    "proxy_service_operations",
                    "proxy_credential_secrets"
                ]
                .contains(&name.as_str()))
                .collect::<Rows>(),
            before
        );
        assert_fresh_automation_namespace(&connection)?;
        assert_fresh_admission_namespace(&connection)?;
        assert_fresh_controller_history_namespace(&connection)?;
        assert_fresh_alert_history_namespace(&connection)?;
        assert!(store::recovery::status(&fixture.0)?.recovery.is_none());
        assert!(store::endpoints::read(&fixture.0)?.digest.is_empty());
        assert_eq!(
            (
                store::inspect(&fixture.0)?.schema_version,
                store::inspect(&fixture.0)?.node_id
            ),
            (SCHEMA_VERSION, node_id)
        );
        let backup =
            Connection::open(fixture.0.join("schema10.sqlite3")).map_err(io::Error::other)?;
        assert_eq!(store::read_overview(&backup)?.schema_version, 10);
        assert_eq!(rows(&backup, false, false)?, before);
        fixture.reset("after-migration.sqlite3")?;
        assert_eq!(fixture.administrator()?.1, hashes().1);
        Ok(())
    }

    #[test]
    fn schema_eleven_creation_failure_rolls_back_migration_and_keeps_backup() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.version_ten()?;
        let connection = fixture.connection()?;
        connection.execute_batch("CREATE TABLE administrator_audit (sentinel TEXT); INSERT INTO administrator_audit VALUES ('operator data');").map_err(io::Error::other)?;
        let before = rows(&connection, false, false)?;
        assert!(store::migrate(&fixture.0, &fixture.0.join("failed-migration.sqlite3")).is_err());
        assert_eq!(store::inspect(&fixture.0)?.schema_version, 10);
        assert_eq!(rows(&connection, false, false)?, before);
        let backup = Connection::open(fixture.0.join("failed-migration.sqlite3"))
            .map_err(io::Error::other)?;
        assert_eq!(rows(&backup, false, false)?, before);
        assert!(
            connection
                .prepare("SELECT * FROM administrator_audit_state")
                .is_err()
        );
        Ok(())
    }

    fn prepare(fixture: &Fixture) -> io::Result<PasswordChange> {
        Ok(prepare_password_change(
            &fixture.0,
            &fixture.administrator()?.0,
            "admin",
            OLD_PASSWORD,
            NEW_PASSWORD,
        )?
        .unwrap())
    }

    #[test]
    fn online_change_uses_phc_cas_and_never_overwrites_a_newer_verifier() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let original = prepare(&fixture)?;
        let stale = prepare(&fixture)?;
        let gate = store::update_lock(&fixture.0)?;
        assert!(matches!(
            change_password(&fixture.0, &original, &gate)?,
            PasswordChangeOutcome::Committed
        ));
        let before = rows(&fixture.connection()?, false, false)?;
        assert!(matches!(
            change_password(&fixture.0, &stale, &gate)?,
            PasswordChangeOutcome::Conflict
        ));
        assert_eq!(rows(&fixture.connection()?, false, false)?, before);
        assert!(
            prepare_password_change(
                &fixture.0,
                &fixture.administrator()?.0,
                "admin",
                OLD_PASSWORD,
                NEW_PASSWORD
            )?
            .is_none()
        );
        Ok(())
    }

    #[test]
    fn deferred_commit_failure_is_confirmed_once_as_not_committed() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let change = prepare(&fixture)?;
        let connection = fixture.connection()?;
        // The verifier and audit writes succeed; only COMMIT discovers this deferred
        // constraint. Closing its failed transaction rolls back before confirmation.
        connection.execute_batch(
        "CREATE TABLE deferred_guard (id TEXT REFERENCES administrators(id) DEFERRABLE INITIALLY DEFERRED);
         CREATE TRIGGER fail_commit AFTER UPDATE ON administrators BEGIN INSERT INTO deferred_guard VALUES ('missing'); END;"
    ).map_err(io::Error::other)?;
        let before = rows(&connection, false, false)?;
        let gate = store::update_lock(&fixture.0)?;
        assert!(matches!(
            change_password(&fixture.0, &change, &gate)?,
            PasswordChangeOutcome::NotCommitted
        ));
        assert_eq!(rows(&connection, false, false)?, before);
        Ok(())
    }

    #[test]
    fn confirmation_requires_both_exact_verifier_and_this_audit_record() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let change = prepare(&fixture)?;
        assert!(matches!(
            confirm_password_change(&fixture.0, &change, 1)?,
            PasswordChangeOutcome::NotCommitted
        ));
        let gate = store::update_lock(&fixture.0)?;
        assert!(matches!(
            change_password(&fixture.0, &change, &gate)?,
            PasswordChangeOutcome::Committed
        ));
        assert!(matches!(
            confirm_password_change(&fixture.0, &change, 1)?,
            PasswordChangeOutcome::Committed
        ));
        fixture
            .connection()?
            .execute("DELETE FROM administrator_audit", [])
            .map_err(io::Error::other)?;
        assert!(matches!(
            confirm_password_change(&fixture.0, &change, 1)?,
            PasswordChangeOutcome::Unknown
        ));
        Ok(())
    }

    /// Exact historical schema eleven; merely lowering user_version would retain
    /// the new Web audit vocabulary and would not exercise the real migration.
    fn version_eleven(fixture: &Fixture) -> io::Result<()> {
        store::restore_legacy_owner_audit(&fixture.connection()?)?;
        fixture.connection()?.execute_batch(
        "CREATE TABLE administrator_audit_v11 (
           sequence INTEGER PRIMARY KEY CHECK(sequence>=1),
           entry TEXT NOT NULL CHECK(entry='offline'),action TEXT NOT NULL CHECK(action='reset_password'),
           administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
           recorded_at INTEGER NOT NULL CHECK(recorded_at>=0)
         ) STRICT;
         INSERT INTO administrator_audit_v11 SELECT * FROM administrator_audit;
         DROP TABLE administrator_audit;
         ALTER TABLE administrator_audit_v11 RENAME TO administrator_audit;
         PRAGMA user_version=11;"
    ).map_err(io::Error::other)
    }

    #[test]
    fn schema_twelve_preserves_old_recoveries_and_the_permanent_high_water() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.reset("offline-recovery.sqlite3")?;
        fixture
            .connection()?
            .execute("UPDATE administrator_audit_state SET last_sequence=41", [])
            .map_err(io::Error::other)?;
        version_eleven(&fixture)?;
        let before = rows(&fixture.connection()?, false, false)?;
        store::migrate(&fixture.0, &fixture.0.join("schema11.sqlite3"))?;
        store::proxy_service::require_unused_for_test(&fixture.connection()?)?;
        store::notifications::ensure_unused_for_test(&fixture.connection()?)?;
        assert_eq!(
            rows(&fixture.connection()?, false, false)?
                .into_iter()
                .filter(|(name, _)| ![
                    "recovery_state",
                    "endpoint_state",
                    "endpoint_overrides",
                    "endpoint_audit",
                    "operations_state",
                    "user_operations",
                    "automation_state",
                    "automation_principals",
                    "automation_audit",
                    "proxy_admission_state",
                    "proxy_admission_audit",
                    "controller_history_state",
                    "controller_history",
                    "alert_history_state",
                    "alert_episodes",
                    "alert_events",
                    "webhook_state",
                    "recovery_witness",
                    "recovery_source",
                    "proxy_service_state",
                    "proxy_service_operations",
                    "proxy_credential_secrets"
                ]
                .contains(&name.as_str()))
                .collect::<Rows>(),
            before
        );
        assert_fresh_automation_namespace(&fixture.connection()?)?;
        assert_fresh_admission_namespace(&fixture.connection()?)?;
        assert_fresh_controller_history_namespace(&fixture.connection()?)?;
        assert_fresh_alert_history_namespace(&fixture.connection()?)?;
        assert!(store::recovery::status(&fixture.0)?.recovery.is_none());
        assert!(store::endpoints::read(&fixture.0)?.digest.is_empty());
        let backup =
            Connection::open(fixture.0.join("schema11.sqlite3")).map_err(io::Error::other)?;
        assert_eq!(store::read_overview(&backup)?.schema_version, 11);
        assert_eq!(rows(&backup, false, false)?, before);
        let id = fixture.administrator()?.0;
        let change =
            prepare_password_change(&fixture.0, &id, "admin", NEW_PASSWORD, OLD_PASSWORD)?.unwrap();
        let gate = store::update_lock(&fixture.0)?;
        assert!(matches!(
            change_password(&fixture.0, &change, &gate)?,
            PasswordChangeOutcome::Committed
        ));
        let connection = fixture.connection()?;
        let last: i64 = connection
            .query_row(
                "SELECT last_sequence FROM administrator_audit_state",
                [],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        assert_eq!(last, 42);
        assert!(
            connection
                .execute(
                    "INSERT INTO administrator_audit VALUES (43,'web','reset_password',?1,0)",
                    [&id]
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn schema_twelve_migration_failure_preserves_rows_version_and_backup() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.reset("offline-recovery.sqlite3")?;
        version_eleven(&fixture)?;
        let connection = fixture.connection()?;
        connection.execute_batch("CREATE TABLE administrator_audit_v12 (sentinel TEXT); INSERT INTO administrator_audit_v12 VALUES ('do not replace');").map_err(io::Error::other)?;
        let before = rows(&connection, false, false)?;
        assert!(store::migrate(&fixture.0, &fixture.0.join("failed12.sqlite3")).is_err());
        assert_eq!(store::inspect(&fixture.0)?.schema_version, 11);
        assert_eq!(rows(&connection, false, false)?, before);
        let backup =
            Connection::open(fixture.0.join("failed12.sqlite3")).map_err(io::Error::other)?;
        assert_eq!(rows(&backup, false, false)?, before);
        Ok(())
    }
}
