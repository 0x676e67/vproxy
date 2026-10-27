//! Extend the private outbox metadata without re-encoding its versioned blob.

use super::*;

/// Existing v1/v2 rows gain NULL preset references. Preset and routing metadata
/// cannot mix, and non-terminal jobs cannot claim a created resource identity.
pub(in crate::manage::store) fn upgrade_presets(connection: &Connection) -> io::Result<()> {
    connection.execute_batch(
        "ALTER TABLE control_outbox ADD COLUMN preset_kind TEXT CHECK(preset_kind IS NULL OR (preset_kind IN('user','pool') AND routing_kind IS NULL));
         ALTER TABLE control_outbox ADD COLUMN preset_id TEXT CHECK((preset_id IS NULL AND preset_kind IS NULL)
           OR (preset_id IS NOT NULL AND preset_kind IS NOT NULL AND length(preset_id)=22 AND routing_kind IS NULL AND routing_id IS NULL AND state IN('saved','applied')));
         CREATE TABLE controller_audit_v9 (
            sequence INTEGER PRIMARY KEY CHECK(sequence>=1),
            administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
            action TEXT NOT NULL CHECK(action IN('register','update','state','retire','enqueue','retry','supersede')),
            peer_id TEXT NOT NULL REFERENCES managed_targets(peer_id) ON DELETE RESTRICT,
            target_revision INTEGER NOT NULL CHECK(target_revision>=1),
            job_id TEXT CHECK(job_id IS NULL OR length(job_id)=22),
            controller_epoch INTEGER CHECK(controller_epoch>=1),command_id INTEGER CHECK(command_id>=1),
            mutation_action TEXT CHECK(mutation_action IN('create_user','update_user','set_user_active','delete_user','create_credential','set_credential_active','rotate_credential','revoke_credential',
                'create_prefix','retire_prefix','create_address','set_address_state','create_pool','set_pool_state','add_pool_member','remove_pool_member','set_route_permission','set_user_presets','set_pool_preset')),
            recorded_at INTEGER NOT NULL CHECK(recorded_at>=0),
            CHECK((action IN('register','update','state','retire') AND job_id IS NULL AND controller_epoch IS NULL AND command_id IS NULL AND mutation_action IS NULL)
                OR (action IN('enqueue','retry','supersede') AND job_id IS NOT NULL AND controller_epoch IS NOT NULL AND command_id IS NOT NULL AND mutation_action IS NOT NULL))
         ) STRICT;
         INSERT INTO controller_audit_v9 SELECT * FROM controller_audit;
         DROP TABLE controller_audit;
         ALTER TABLE controller_audit_v9 RENAME TO controller_audit;"
    ).map_err(|error|sqlite_error("cannot upgrade preset outbox metadata",error))
}
