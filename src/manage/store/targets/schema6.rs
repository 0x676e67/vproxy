//! Preserve controller outbox bytes and audit history while extending only the
//! closed routing vocabulary. The caller owns migration's immediate transaction.

use super::*;

pub(in crate::manage::store) fn upgrade_schema(connection: &Connection) -> io::Result<()> {
    connection.execute_batch(
        "CREATE TABLE control_outbox_v6 (
            peer_id TEXT PRIMARY KEY NOT NULL REFERENCES managed_targets(peer_id) ON DELETE RESTRICT,
            job_id TEXT NOT NULL UNIQUE CHECK(length(job_id)=22),
            administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
            controller_epoch INTEGER NOT NULL CHECK(controller_epoch>=1),
            command_id INTEGER NOT NULL CHECK(command_id>=1),
            expected_policy_revision INTEGER NOT NULL CHECK(expected_policy_revision>=1),
            command BLOB NOT NULL CHECK(length(command) BETWEEN 1 AND 4096),
            state TEXT NOT NULL CHECK(state IN('pending','blocked','saved','applied','rejected','superseded')),
            policy_revision INTEGER CHECK(policy_revision>=1),
            outcome_code TEXT CHECK(outcome_code IN('remote_rejected','node_permission_or_state','node_unavailable')),
            attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 4294967295),
            next_attempt INTEGER NOT NULL CHECK(next_attempt>=0),
            routing_kind TEXT CHECK(routing_kind IN('prefix','address','pool','permission')),
            routing_id TEXT CHECK(length(routing_id)=22),
            CHECK((routing_kind IS NULL AND routing_id IS NULL) OR (routing_kind IS NOT NULL AND routing_id IS NOT NULL)),
            CHECK((state IN('pending','blocked','rejected','superseded') AND policy_revision IS NULL AND routing_kind IS NULL AND routing_id IS NULL)
                OR (state IN('saved','applied') AND expected_policy_revision<9223372036854775807 AND policy_revision=expected_policy_revision+1))
         ) STRICT;
         INSERT INTO control_outbox_v6(peer_id,job_id,administrator_id,controller_epoch,command_id,expected_policy_revision,command,state,policy_revision,outcome_code,attempts,next_attempt)
          SELECT peer_id,job_id,administrator_id,controller_epoch,command_id,expected_policy_revision,command,state,policy_revision,outcome_code,attempts,next_attempt FROM control_outbox;
         DROP TABLE control_outbox;
         ALTER TABLE control_outbox_v6 RENAME TO control_outbox;
         CREATE TABLE controller_audit_v6 (
            sequence INTEGER PRIMARY KEY CHECK(sequence>=1),
            administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
            action TEXT NOT NULL CHECK(action IN('register','update','state','retire','enqueue','retry','supersede')),
            peer_id TEXT NOT NULL REFERENCES managed_targets(peer_id) ON DELETE RESTRICT,
            target_revision INTEGER NOT NULL CHECK(target_revision>=1),
            job_id TEXT CHECK(job_id IS NULL OR length(job_id)=22),
            controller_epoch INTEGER CHECK(controller_epoch>=1),
            command_id INTEGER CHECK(command_id>=1),
            mutation_action TEXT CHECK(mutation_action IN('create_user','update_user','set_user_active','delete_user','create_credential','set_credential_active','rotate_credential','revoke_credential',
                'create_prefix','retire_prefix','create_address','set_address_state','create_pool','set_pool_state','add_pool_member','remove_pool_member','set_route_permission')),
            recorded_at INTEGER NOT NULL CHECK(recorded_at>=0),
            CHECK((action IN('register','update','state','retire') AND job_id IS NULL AND controller_epoch IS NULL AND command_id IS NULL AND mutation_action IS NULL)
                OR (action IN('enqueue','retry','supersede') AND job_id IS NOT NULL AND controller_epoch IS NOT NULL AND command_id IS NOT NULL AND mutation_action IS NOT NULL))
         ) STRICT;
         INSERT INTO controller_audit_v6 SELECT * FROM controller_audit;
         DROP TABLE controller_audit;
         ALTER TABLE controller_audit_v6 RENAME TO controller_audit;"
    ).map_err(|error|sqlite_error("cannot upgrade controller routing metadata",error))
}
