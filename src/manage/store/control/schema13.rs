//! Keep filesystem-authorized ownership separate from authenticated Web actors.

use super::*;

/// Rebuild only this audit's action constraints, preserving every old row and
/// sequence in the caller's migration transaction. Other durable state is untouched.
pub(in crate::manage::store) fn upgrade_owner_audit(connection: &Connection) -> io::Result<()> {
    connection.execute_batch(
        "CREATE TABLE control_audit_v13 (
          sequence INTEGER PRIMARY KEY,
          action TEXT NOT NULL CHECK(action IN ('set_owner','command_rejected','set_owner_offline')),
          administrator_id TEXT REFERENCES administrators(id) ON DELETE RESTRICT,
          controller_node_id TEXT REFERENCES peers(node_id) ON DELETE RESTRICT,
          epoch INTEGER NOT NULL CHECK(epoch >= 1), command_id INTEGER CHECK(command_id >= 1),
          source_administrator_id TEXT CHECK(length(source_administrator_id)=22),
          rejection TEXT CHECK(rejection IN ('invalid_policy','policy_conflict','resource_not_found','policy_capacity')),
          CHECK((action='set_owner' AND administrator_id IS NOT NULL AND command_id IS NULL AND source_administrator_id IS NULL AND rejection IS NULL)
             OR (action='set_owner_offline' AND administrator_id IS NULL AND command_id IS NULL AND source_administrator_id IS NULL AND rejection IS NULL)
             OR (action='command_rejected' AND administrator_id IS NULL AND controller_node_id IS NOT NULL AND command_id IS NOT NULL AND source_administrator_id IS NOT NULL AND rejection IS NOT NULL))
         ) STRICT;
         INSERT INTO control_audit_v13 SELECT sequence,action,administrator_id,controller_node_id,epoch,command_id,source_administrator_id,rejection FROM control_audit;
         DROP TABLE control_audit;
         ALTER TABLE control_audit_v13 RENAME TO control_audit;"
    ).map_err(|error| sqlite_error("cannot upgrade offline ownership audit", error))
}

/// Restore the actual historical CHECKs, not merely a lower user_version.
#[cfg(test)]
pub(in crate::manage) fn restore_legacy_owner_audit(connection: &Connection) -> io::Result<()> {
    crate::manage::store::recovery::remove_schema_for_test(connection)?;
    connection.execute_batch(
        "CREATE TABLE control_audit_legacy (
          sequence INTEGER PRIMARY KEY,
          action TEXT NOT NULL CHECK(action IN ('set_owner','command_rejected')),
          administrator_id TEXT REFERENCES administrators(id) ON DELETE RESTRICT,
          controller_node_id TEXT REFERENCES peers(node_id) ON DELETE RESTRICT,
          epoch INTEGER NOT NULL CHECK(epoch >= 1), command_id INTEGER CHECK(command_id >= 1),
          source_administrator_id TEXT CHECK(length(source_administrator_id)=22),
          rejection TEXT CHECK(rejection IN ('invalid_policy','policy_conflict','resource_not_found','policy_capacity')),
          CHECK((action='set_owner' AND administrator_id IS NOT NULL AND command_id IS NULL AND source_administrator_id IS NULL AND rejection IS NULL)
             OR (action='command_rejected' AND administrator_id IS NULL AND controller_node_id IS NOT NULL AND command_id IS NOT NULL AND source_administrator_id IS NOT NULL AND rejection IS NOT NULL))
         ) STRICT;
         INSERT INTO control_audit_legacy SELECT sequence,action,administrator_id,controller_node_id,epoch,command_id,source_administrator_id,rejection FROM control_audit;
         DROP TABLE control_audit;
         ALTER TABLE control_audit_legacy RENAME TO control_audit;"
    ).map_err(|error| sqlite_error("cannot restore legacy ownership audit fixture", error))
}
