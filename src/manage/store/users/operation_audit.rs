//! Actor provenance for schema18 user operations. Legacy columns retain their
//! order and values; automation never masquerades as the creating administrator.

use super::*;

const LEGACY: &str = "sequence,entry,administrator_id,controller_node_id,controller_epoch,command_id,source_administrator_id,action,user_id,credential_id,policy_revision";

fn create_table(connection: &Connection, name: &str, automation: bool) -> io::Result<()> {
    let entries = if automation {
        "'local_management','node_management','automation_management'"
    } else {
        "'local_management','node_management'"
    };
    let columns = if automation {
        "automation_principal_id TEXT REFERENCES automation_principals(id) ON DELETE RESTRICT,
         automation_generation INTEGER CHECK(automation_generation>=1),"
    } else {
        ""
    };
    let absent = if automation {
        "AND automation_principal_id IS NULL AND automation_generation IS NULL"
    } else {
        ""
    };
    let extra = if automation {
        "OR (entry='automation_management' AND administrator_id IS NULL AND controller_node_id IS NULL
           AND controller_epoch IS NULL AND command_id IS NULL AND source_administrator_id IS NULL
           AND automation_principal_id IS NOT NULL AND automation_generation IS NOT NULL
           AND credential_id IS NULL AND action IN('create_user','update_user','enable_user','disable_user','delete_user'))"
    } else {
        ""
    };
    connection.execute_batch(&format!(
        "CREATE TABLE {name}(
          sequence INTEGER PRIMARY KEY,
          entry TEXT NOT NULL CHECK(entry IN({entries})),
          administrator_id TEXT REFERENCES administrators(id) ON DELETE RESTRICT,
          controller_node_id TEXT REFERENCES peers(node_id) ON DELETE RESTRICT,
          controller_epoch INTEGER CHECK(controller_epoch>=1),
          command_id INTEGER CHECK(command_id>=1),
          source_administrator_id TEXT CHECK(length(source_administrator_id)=22),
          action TEXT NOT NULL CHECK(action IN('create_user','update_user','enable_user','disable_user','delete_user','create_credential','enable_credential','disable_credential','rotate_credential','revoke_credential')),
          user_id TEXT NOT NULL REFERENCES proxy_users(id) ON DELETE RESTRICT,
          credential_id TEXT REFERENCES proxy_credentials(id) ON DELETE RESTRICT,
          policy_revision INTEGER NOT NULL CHECK(policy_revision>=1),
          {columns}
          CHECK((entry='local_management' AND administrator_id IS NOT NULL AND controller_node_id IS NULL
              AND controller_epoch IS NULL AND command_id IS NULL AND source_administrator_id IS NULL {absent})
            OR (entry='node_management' AND administrator_id IS NULL AND controller_node_id IS NOT NULL
              AND controller_epoch IS NOT NULL AND command_id IS NOT NULL AND source_administrator_id IS NOT NULL {absent})
            {extra})
         ) STRICT;"
    )).map_err(|error| sqlite_error("cannot create policy actor audit", error))
}

/// Runs only after the automation parent exists, within backed-up migration.
/// Existing eleven-column rows are copied without allocating new sequences.
pub(in crate::manage::store) fn upgrade_schema(connection: &Connection) -> io::Result<()> {
    create_table(connection, "proxy_policy_audit_v18", true)?;
    connection.execute_batch(&format!(
        "INSERT INTO proxy_policy_audit_v18({LEGACY}) SELECT {LEGACY} FROM proxy_policy_audit;
         DROP TABLE proxy_policy_audit; ALTER TABLE proxy_policy_audit_v18 RENAME TO proxy_policy_audit;"
    )).map_err(|error| sqlite_error("cannot preserve policy audit actors", error))
}

/// Immutable SQLite reads may not enforce stored CHECK clauses. Bound and type
/// every new actor row explicitly rather than trusting user_version or DDL.
pub(in crate::manage::store) fn validate_snapshot(connection: &Connection) -> io::Result<()> {
    let mut statement = connection.prepare(&format!(
        "SELECT {LEGACY},automation_principal_id,automation_generation,p.generation,p.scope FROM proxy_policy_audit LEFT JOIN automation_principals p ON p.id=automation_principal_id ORDER BY sequence LIMIT 16385"
    )).map_err(|error| sqlite_error("cannot prepare policy actor audit validation", error))?;
    let mut rows = statement
        .query([])
        .map_err(|error| sqlite_error("cannot inspect policy actor audit", error))?;
    let mut count = 0_u32;
    while let Some(row) = rows
        .next()
        .map_err(|error| sqlite_error("cannot read policy actor audit", error))?
    {
        count += 1;
        if count > MAX_AUDIT_RECORDS {
            return Err(malformed());
        }
        let read = || -> rusqlite::Result<()> {
            read_revision(row, 0)?;
            let entry = row.get_ref(1)?;
            let administrator = id(row, 2)?;
            let controller = id(row, 3)?;
            let epoch = number(row, 4)?;
            let command = number(row, 5)?;
            let source = id(row, 6)?;
            let user = id(row, 8)?;
            let credential = id(row, 9)?;
            read_revision(row, 10)?;
            let principal = id(row, 11)?;
            let generation = number(row, 12)?;
            let current_generation = number(row, 13)?;
            let user_action = matches!(
                row.get_ref(7)?,
                ValueRef::Text(
                    b"create_user"
                        | b"update_user"
                        | b"enable_user"
                        | b"disable_user"
                        | b"delete_user"
                )
            );
            let credential_action = matches!(
                row.get_ref(7)?,
                ValueRef::Text(
                    b"create_credential"
                        | b"enable_credential"
                        | b"disable_credential"
                        | b"rotate_credential"
                        | b"revoke_credential"
                )
            );
            let valid = user.is_some()
                && (user_action || credential_action)
                && match entry {
                    ValueRef::Text(b"local_management") => {
                        administrator.is_some()
                            && controller.is_none()
                            && epoch.is_none()
                            && command.is_none()
                            && source.is_none()
                            && principal.is_none()
                            && generation.is_none()
                    }
                    ValueRef::Text(b"node_management") => {
                        administrator.is_none()
                            && controller.is_some()
                            && epoch.is_some()
                            && command.is_some()
                            && source.is_some()
                            && principal.is_none()
                            && generation.is_none()
                    }
                    ValueRef::Text(b"automation_management") => {
                        administrator.is_none()
                            && controller.is_none()
                            && epoch.is_none()
                            && command.is_none()
                            && source.is_none()
                            && principal.is_some()
                            && matches!(row.get_ref(14)?, ValueRef::Text(b"users:write"))
                            && generation
                                .zip(current_generation)
                                .is_some_and(|(old, current)| old <= current)
                            && credential.is_none()
                            && user_action
                    }
                    _ => false,
                };
            if valid {
                Ok(())
            } else {
                Err(rusqlite::Error::InvalidQuery)
            }
        };
        read().map_err(|_| malformed())?;
    }
    Ok(())
}

fn id<'a>(row: &'a Row<'_>, column: usize) -> rusqlite::Result<Option<&'a str>> {
    match row.get_ref(column)? {
        ValueRef::Null => Ok(None),
        ValueRef::Text(bytes) if bytes.len() == 22 => {
            let value = std::str::from_utf8(bytes).map_err(|_| rusqlite::Error::InvalidQuery)?;
            if valid_id(value) {
                Ok(Some(value))
            } else {
                Err(rusqlite::Error::InvalidQuery)
            }
        }
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn number(row: &Row<'_>, column: usize) -> rusqlite::Result<Option<u64>> {
    if matches!(row.get_ref(column)?, ValueRef::Null) {
        Ok(None)
    } else {
        read_revision(row, column).map(Some)
    }
}

fn malformed() -> io::Error {
    super::super::invalid_data("policy actor audit is malformed")
}

#[cfg(test)]
pub(in crate::manage) fn require_legacy_for_test(connection: &Connection) -> io::Result<()> {
    let current: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('proxy_policy_audit') WHERE name='automation_principal_id')", [], |row| row.get(0))
        .map_err(|error| sqlite_error("cannot inspect policy audit fixture layout", error))?;
    if current {
        let present: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM proxy_policy_audit WHERE entry='automation_management' OR automation_principal_id IS NOT NULL OR automation_generation IS NOT NULL)", [], |row| row.get(0))
            .map_err(|error| sqlite_error("cannot inspect policy audit fixture actors", error))?;
        if present {
            return Err(malformed());
        }
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::manage) fn restore_legacy_for_test(connection: &Connection) -> io::Result<()> {
    require_legacy_for_test(connection)?;
    let current: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('proxy_policy_audit') WHERE name='automation_principal_id')", [], |row| row.get(0))
        .map_err(|error| sqlite_error("cannot inspect policy audit fixture layout", error))?;
    if !current {
        return Ok(());
    }
    create_table(connection, "proxy_policy_audit_fixture17", false)?;
    connection.execute_batch(&format!("INSERT INTO proxy_policy_audit_fixture17({LEGACY}) SELECT {LEGACY} FROM proxy_policy_audit; DROP TABLE proxy_policy_audit; ALTER TABLE proxy_policy_audit_fixture17 RENAME TO proxy_policy_audit;"))
        .map_err(|error| sqlite_error("cannot reconstruct policy audit fixture", error))
}
