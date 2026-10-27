//! Atomic v4/v5 receipt upgrade. This is called only after the consistent old
//! snapshot backup and inside initialization/migration's immediate transaction.

use super::*;

/// Preserve every old receipt/digest while adding an explicit protocol version
/// and a mutually exclusive routing identity. No policy or high water is reset.
pub(in crate::manage::store) fn upgrade_schema(connection: &Connection) -> io::Result<()> {
    connection.execute_batch(
        "CREATE TABLE control_receipts_v6 (
          epoch INTEGER NOT NULL CHECK(epoch>=1),command_id INTEGER NOT NULL CHECK(command_id>=1),
          controller_node_id TEXT NOT NULL REFERENCES peers(node_id) ON DELETE RESTRICT,
          digest BLOB NOT NULL CHECK(length(digest)=32),
          status TEXT NOT NULL CHECK(status IN('saved','applied','rejected')),
          policy_revision INTEGER CHECK(policy_revision>=1),
          rejection TEXT CHECK(rejection IN('invalid_policy','policy_conflict','resource_not_found','policy_capacity')),
          user_id TEXT REFERENCES proxy_users(id) ON DELETE RESTRICT,
          credential_id TEXT REFERENCES proxy_credentials(id) ON DELETE RESTRICT,
          version INTEGER NOT NULL DEFAULT 1 CHECK(version IN(1,2)),
          routing_kind TEXT CHECK(routing_kind IN('prefix','address','pool','permission')),
          routing_id TEXT CHECK(length(routing_id)=22),
          PRIMARY KEY(epoch,command_id),
          CHECK((status='rejected' AND rejection IS NOT NULL AND policy_revision IS NULL
                    AND user_id IS NULL AND credential_id IS NULL AND routing_kind IS NULL AND routing_id IS NULL)
             OR (status IN('saved','applied') AND rejection IS NULL AND policy_revision IS NOT NULL
                 AND ((version=1 AND user_id IS NOT NULL AND routing_kind IS NULL AND routing_id IS NULL)
                   OR (version=2 AND user_id IS NULL AND credential_id IS NULL AND routing_kind IS NOT NULL AND routing_id IS NOT NULL))))
         ) STRICT;
         INSERT INTO control_receipts_v6(epoch,command_id,controller_node_id,digest,status,policy_revision,rejection,user_id,credential_id,version)
          SELECT epoch,command_id,controller_node_id,digest,status,policy_revision,rejection,user_id,credential_id,1 FROM control_receipts;
         DROP TABLE control_receipts;
         ALTER TABLE control_receipts_v6 RENAME TO control_receipts;"
    ).map_err(|error| sqlite_error("cannot upgrade command receipts",error))?;
    super::super::targets::upgrade_schema(connection)
}

#[cfg(test)]
pub(in crate::manage::store) mod legacy {
    //! Historical v5 DDL for migration tests, not a production downgrade path.

    use super::*;

    /// Rebuild the three changed tables with the exact historical constraints;
    /// valid legacy rows and payload blobs are copied without re-encoding.
    pub(in crate::manage::store) fn reconstruct_v5(connection: &Connection) -> io::Result<()> {
        if crate::manage::store::read_overview(connection)?.schema_version >= 13 {
            crate::manage::store::restore_legacy_owner_audit(connection)?;
        }
        crate::manage::store::traffic::remove_schema_for_test(connection)?;
        connection.execute_batch(
        "CREATE TABLE control_receipts_v5 (
          epoch INTEGER NOT NULL CHECK(epoch>=1),command_id INTEGER NOT NULL CHECK(command_id>=1),
          controller_node_id TEXT NOT NULL REFERENCES peers(node_id) ON DELETE RESTRICT,
          digest BLOB NOT NULL CHECK(length(digest)=32),
          status TEXT NOT NULL CHECK(status IN('saved','applied','rejected')),
          policy_revision INTEGER CHECK(policy_revision>=1),
          rejection TEXT CHECK(rejection IN('invalid_policy','policy_conflict','resource_not_found','policy_capacity')),
          user_id TEXT REFERENCES proxy_users(id) ON DELETE RESTRICT,
          credential_id TEXT REFERENCES proxy_credentials(id) ON DELETE RESTRICT,
          PRIMARY KEY(epoch,command_id),
          CHECK((status='rejected' AND rejection IS NOT NULL AND policy_revision IS NULL AND user_id IS NULL AND credential_id IS NULL)
             OR (status IN('saved','applied') AND rejection IS NULL AND policy_revision IS NOT NULL AND user_id IS NOT NULL))
         ) STRICT;
         INSERT INTO control_receipts_v5 SELECT epoch,command_id,controller_node_id,digest,status,policy_revision,rejection,user_id,credential_id FROM control_receipts;
         DROP TABLE control_receipts; ALTER TABLE control_receipts_v5 RENAME TO control_receipts;
         CREATE TABLE control_outbox_v5 (
            peer_id TEXT PRIMARY KEY NOT NULL REFERENCES managed_targets(peer_id) ON DELETE RESTRICT,
            job_id TEXT NOT NULL UNIQUE CHECK(length(job_id)=22),
            administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
            controller_epoch INTEGER NOT NULL CHECK(controller_epoch>=1),command_id INTEGER NOT NULL CHECK(command_id>=1),
            expected_policy_revision INTEGER NOT NULL CHECK(expected_policy_revision>=1),
            command BLOB NOT NULL CHECK(length(command) BETWEEN 1 AND 4096),
            state TEXT NOT NULL CHECK(state IN('pending','blocked','saved','applied','rejected','superseded')),
            policy_revision INTEGER CHECK(policy_revision>=1),
            outcome_code TEXT CHECK(outcome_code IN('remote_rejected','node_permission_or_state','node_unavailable')),
            attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 4294967295),next_attempt INTEGER NOT NULL CHECK(next_attempt>=0),
            CHECK((state IN('pending','blocked','rejected','superseded') AND policy_revision IS NULL)
                OR (state IN('saved','applied') AND expected_policy_revision<9223372036854775807 AND policy_revision=expected_policy_revision+1))
         ) STRICT;
         INSERT INTO control_outbox_v5 SELECT peer_id,job_id,administrator_id,controller_epoch,command_id,expected_policy_revision,command,state,policy_revision,outcome_code,attempts,next_attempt FROM control_outbox;
         DROP TABLE control_outbox; ALTER TABLE control_outbox_v5 RENAME TO control_outbox;
         CREATE TABLE controller_audit_v5 (
            sequence INTEGER PRIMARY KEY CHECK(sequence>=1),
            administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
            action TEXT NOT NULL CHECK(action IN('register','update','state','retire','enqueue','retry','supersede')),
            peer_id TEXT NOT NULL REFERENCES managed_targets(peer_id) ON DELETE RESTRICT,
            target_revision INTEGER NOT NULL CHECK(target_revision>=1),job_id TEXT CHECK(job_id IS NULL OR length(job_id)=22),
            controller_epoch INTEGER CHECK(controller_epoch>=1),command_id INTEGER CHECK(command_id>=1),
            mutation_action TEXT CHECK(mutation_action IN('create_user','update_user','set_user_active','delete_user','create_credential','set_credential_active','rotate_credential','revoke_credential')),
            recorded_at INTEGER NOT NULL CHECK(recorded_at>=0),
            CHECK((action IN('register','update','state','retire') AND job_id IS NULL AND controller_epoch IS NULL AND command_id IS NULL AND mutation_action IS NULL)
                OR (action IN('enqueue','retry','supersede') AND job_id IS NOT NULL AND controller_epoch IS NOT NULL AND command_id IS NOT NULL AND mutation_action IS NOT NULL))
         ) STRICT;
         INSERT INTO controller_audit_v5 SELECT * FROM controller_audit;
         DROP TABLE controller_audit; ALTER TABLE controller_audit_v5 RENAME TO controller_audit;
         PRAGMA user_version=5;"
    ).map_err(|error|sqlite_error("cannot reconstruct historical control tables",error))
    }
}
