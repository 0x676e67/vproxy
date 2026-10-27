//! Extend only the closed preset vocabulary. Old command blobs, digests, owner
//! epochs, receipts and audit sequence numbers are copied without re-encoding.

use super::*;

/// Called after a consistent backup inside the migration's immediate write
/// transaction, or once during initialization. Failure rolls back every table.
pub(in crate::manage::store) fn upgrade_presets(connection: &Connection) -> io::Result<()> {
    connection.execute_batch(
        "CREATE TABLE control_receipts_v9 (
          epoch INTEGER NOT NULL CHECK(epoch>=1),command_id INTEGER NOT NULL CHECK(command_id>=1),
          controller_node_id TEXT NOT NULL REFERENCES peers(node_id) ON DELETE RESTRICT,
          digest BLOB NOT NULL CHECK(length(digest)=32),
          status TEXT NOT NULL CHECK(status IN('saved','applied','rejected')),
          policy_revision INTEGER CHECK(policy_revision>=1),
          rejection TEXT CHECK(rejection IN('invalid_policy','policy_conflict','resource_not_found','policy_capacity')),
          user_id TEXT REFERENCES proxy_users(id) ON DELETE RESTRICT,
          credential_id TEXT REFERENCES proxy_credentials(id) ON DELETE RESTRICT,
          version INTEGER NOT NULL DEFAULT 1 CHECK(version IN(1,2,3)),
          routing_kind TEXT CHECK(routing_kind IN('prefix','address','pool','permission')),
          routing_id TEXT CHECK(length(routing_id)=22),
          preset_kind TEXT CHECK(preset_kind IN('user','pool')),
          preset_id TEXT CHECK(length(preset_id)=22),
          PRIMARY KEY(epoch,command_id),
          CHECK((status='rejected' AND rejection IS NOT NULL AND policy_revision IS NULL
                    AND user_id IS NULL AND credential_id IS NULL AND routing_kind IS NULL AND routing_id IS NULL AND preset_kind IS NULL AND preset_id IS NULL)
             OR (status IN('saved','applied') AND rejection IS NULL AND policy_revision IS NOT NULL
                 AND ((version=1 AND user_id IS NOT NULL AND routing_kind IS NULL AND routing_id IS NULL AND preset_kind IS NULL AND preset_id IS NULL)
                   OR (version=2 AND user_id IS NULL AND credential_id IS NULL AND routing_kind IS NOT NULL AND routing_id IS NOT NULL AND preset_kind IS NULL AND preset_id IS NULL)
                   OR (version=3 AND user_id IS NULL AND credential_id IS NULL AND routing_kind IS NULL AND routing_id IS NULL AND preset_kind IS NOT NULL AND preset_id IS NOT NULL))))
         ) STRICT;
         INSERT INTO control_receipts_v9(epoch,command_id,controller_node_id,digest,status,policy_revision,rejection,user_id,credential_id,version,routing_kind,routing_id)
          SELECT epoch,command_id,controller_node_id,digest,status,policy_revision,rejection,user_id,credential_id,version,routing_kind,routing_id FROM control_receipts;
         DROP TABLE control_receipts;
         ALTER TABLE control_receipts_v9 RENAME TO control_receipts;"
    ).map_err(|error|sqlite_error("cannot upgrade preset command receipts",error))?;
    super::super::targets::upgrade_presets(connection)
}

#[cfg(test)]
pub(in crate::manage::store) mod legacy {
    //! Exact schema-eight changed tables for migration tests, not an operator API.

    use super::*;

    /// Preserve old data while actually removing the schema-nine constraints and
    /// objects. Fixtures containing v3 actions cannot be silently called v8.
    pub(in crate::manage::store) fn reconstruct_v8(connection: &Connection) -> io::Result<()> {
        if super::super::super::read_overview(connection)?.schema_version >= 13 {
            super::super::super::restore_legacy_owner_audit(connection)?;
        }
        if super::super::super::read_overview(connection)?.schema_version >= 11 {
            super::super::super::administrators::remove_schema_for_test(connection)?;
        }
        if super::super::super::read_overview(connection)?.schema_version >= 10 {
            connection
                .execute_batch("ALTER TABLE managed_targets DROP COLUMN server_ip;")
                .map_err(|error| {
                    sqlite_error("cannot remove newer target metadata fixture", error)
                })?;
        }
        connection.execute_batch(
        "DROP TABLE preset_audit; DROP TABLE pool_presets; DROP TABLE user_presets;
         CREATE TABLE control_receipts_v8 (
          epoch INTEGER NOT NULL CHECK(epoch>=1),command_id INTEGER NOT NULL CHECK(command_id>=1),
          controller_node_id TEXT NOT NULL REFERENCES peers(node_id) ON DELETE RESTRICT,
          digest BLOB NOT NULL CHECK(length(digest)=32),status TEXT NOT NULL CHECK(status IN('saved','applied','rejected')),
          policy_revision INTEGER CHECK(policy_revision>=1),rejection TEXT CHECK(rejection IN('invalid_policy','policy_conflict','resource_not_found','policy_capacity')),
          user_id TEXT REFERENCES proxy_users(id) ON DELETE RESTRICT,credential_id TEXT REFERENCES proxy_credentials(id) ON DELETE RESTRICT,
          version INTEGER NOT NULL DEFAULT 1 CHECK(version IN(1,2)),
          routing_kind TEXT CHECK(routing_kind IN('prefix','address','pool','permission')),routing_id TEXT CHECK(length(routing_id)=22),
          PRIMARY KEY(epoch,command_id),
          CHECK((status='rejected' AND rejection IS NOT NULL AND policy_revision IS NULL AND user_id IS NULL AND credential_id IS NULL AND routing_kind IS NULL AND routing_id IS NULL)
             OR (status IN('saved','applied') AND rejection IS NULL AND policy_revision IS NOT NULL
                 AND ((version=1 AND user_id IS NOT NULL AND routing_kind IS NULL AND routing_id IS NULL)
                   OR (version=2 AND user_id IS NULL AND credential_id IS NULL AND routing_kind IS NOT NULL AND routing_id IS NOT NULL))))
         ) STRICT;
         INSERT INTO control_receipts_v8 SELECT epoch,command_id,controller_node_id,digest,status,policy_revision,rejection,user_id,credential_id,version,routing_kind,routing_id FROM control_receipts;
         DROP TABLE control_receipts; ALTER TABLE control_receipts_v8 RENAME TO control_receipts;
         ALTER TABLE control_outbox DROP COLUMN preset_id;
         ALTER TABLE control_outbox DROP COLUMN preset_kind;
         CREATE TABLE controller_audit_v8 (
            sequence INTEGER PRIMARY KEY CHECK(sequence>=1),administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
            action TEXT NOT NULL CHECK(action IN('register','update','state','retire','enqueue','retry','supersede')),
            peer_id TEXT NOT NULL REFERENCES managed_targets(peer_id) ON DELETE RESTRICT,target_revision INTEGER NOT NULL CHECK(target_revision>=1),
            job_id TEXT CHECK(job_id IS NULL OR length(job_id)=22),controller_epoch INTEGER CHECK(controller_epoch>=1),command_id INTEGER CHECK(command_id>=1),
            mutation_action TEXT CHECK(mutation_action IN('create_user','update_user','set_user_active','delete_user','create_credential','set_credential_active','rotate_credential','revoke_credential',
                'create_prefix','retire_prefix','create_address','set_address_state','create_pool','set_pool_state','add_pool_member','remove_pool_member','set_route_permission')),
            recorded_at INTEGER NOT NULL CHECK(recorded_at>=0),
            CHECK((action IN('register','update','state','retire') AND job_id IS NULL AND controller_epoch IS NULL AND command_id IS NULL AND mutation_action IS NULL)
                OR (action IN('enqueue','retry','supersede') AND job_id IS NOT NULL AND controller_epoch IS NOT NULL AND command_id IS NOT NULL AND mutation_action IS NOT NULL))
         ) STRICT;
         INSERT INTO controller_audit_v8 SELECT * FROM controller_audit;
         DROP TABLE controller_audit; ALTER TABLE controller_audit_v8 RENAME TO controller_audit;
         PRAGMA user_version=8;"
    ).map_err(|error|sqlite_error("cannot reconstruct historical schema eight",error))
    }
}
