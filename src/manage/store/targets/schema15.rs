//! Extend the existing single per-peer outbox with metadata-only commands.
//! Policy and metadata revisions are different nullable columns, never aliases.

use super::*;

const OUTBOX_COLUMNS: &str = "peer_id,job_id,administrator_id,controller_epoch,command_id,expected_policy_revision,command,state,policy_revision,outcome_code,attempts,next_attempt,routing_kind,routing_id,preset_kind,preset_id";
const AUDIT_COLUMNS: &str = "sequence,administrator_id,action,peer_id,target_revision,job_id,controller_epoch,command_id,mutation_action,recorded_at";
const POLICY_ACTIONS: &str = "'create_user','update_user','set_user_active','delete_user','create_credential','set_credential_active','rotate_credential','revoke_credential','create_prefix','retire_prefix','create_address','set_address_state','create_pool','set_pool_state','add_pool_member','remove_pool_member','set_route_permission','set_user_presets','set_pool_preset'";

/// Rebuild in the caller's initialization/backed-up migration transaction.
/// Exact old command BLOBs, tickets, retry state and audit sequences survive.
pub(in crate::manage::store) fn upgrade_endpoints(connection: &Connection) -> io::Result<()> {
    outbox(connection, true)?;
    audit(connection, true)
}

/// Historical fixtures must actually remove the new vocabulary. Refuse newer
/// rows before rebuilding so a test cannot quietly discard a metadata command.
#[cfg(test)]
pub(in crate::manage::store) fn remove_endpoints_schema_for_test(
    connection: &Connection,
) -> io::Result<()> {
    let present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('control_outbox') WHERE name='resource')",
        [], |row| row.get(0),
    ).map_err(|error| sqlite_error("cannot inspect endpoint outbox fixture", error))?;
    if !present {
        return Ok(());
    }
    let newer: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM control_outbox WHERE resource<>'proxy_policy'
          OR expected_metadata_revision IS NOT NULL OR metadata_revision IS NOT NULL)
          OR EXISTS(SELECT 1 FROM controller_audit WHERE mutation_action='set_public_address')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("cannot inspect newer endpoint outbox rows", error))?;
    if newer {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "endpoint delivery rows cannot become a legacy fixture",
        ));
    }
    outbox(connection, false)?;
    audit(connection, false)
}

/// All interpolated fragments are fixed internal DDL for v14/v15, not input
/// strings. Versioned command BLOBs never pass through a JSON serializer here.
fn outbox(connection: &Connection, endpoints: bool) -> io::Result<()> {
    // The historical CHECK allowed NULL to propagate through its equality;
    // reproduce that only in test fixtures. The v15 success branch explicitly
    // requires a result, because SQLite accepts a CHECK that evaluates to NULL.
    let success_nonnull = if endpoints {
        "AND policy_revision IS NOT NULL"
    } else {
        ""
    };
    // v14 added preset columns through ALTER TABLE, so its older table CHECK
    // cannot depend on them. Historical fixtures must still be able to remove
    // those columns when reconstructing a pre-preset schema.
    let pending_presets = if endpoints {
        "AND preset_kind IS NULL AND preset_id IS NULL"
    } else {
        ""
    };
    let (policy_required, metadata_columns, resource_case, metadata_case) = if endpoints {
        (
            "",
            "resource TEXT NOT NULL DEFAULT 'proxy_policy' CHECK(resource IN('proxy_policy','proxy_endpoints')),
             expected_metadata_revision INTEGER CHECK(expected_metadata_revision>=1),
             metadata_revision INTEGER CHECK(metadata_revision>=1),",
            "resource='proxy_policy' AND expected_metadata_revision IS NULL AND metadata_revision IS NULL AND",
            "OR (resource='proxy_endpoints' AND expected_policy_revision IS NULL AND policy_revision IS NULL
              AND expected_metadata_revision IS NOT NULL AND routing_kind IS NULL AND routing_id IS NULL
              AND preset_kind IS NULL AND preset_id IS NULL
              AND ((state='saved' AND metadata_revision IS NOT NULL AND expected_metadata_revision<9223372036854775807
                    AND metadata_revision=expected_metadata_revision+1)
                OR (state IN('pending','blocked','rejected','superseded') AND metadata_revision IS NULL)))",
        )
    } else {
        ("NOT NULL", "", "", "")
    };
    connection.execute_batch(&format!(
        "CREATE TABLE control_outbox_endpoint_rebuild (
          peer_id TEXT PRIMARY KEY NOT NULL REFERENCES managed_targets(peer_id) ON DELETE RESTRICT,
          job_id TEXT NOT NULL UNIQUE CHECK(length(job_id)=22),
          administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
          controller_epoch INTEGER NOT NULL CHECK(controller_epoch>=1),
          command_id INTEGER NOT NULL CHECK(command_id>=1),
          expected_policy_revision INTEGER {policy_required} CHECK(expected_policy_revision>=1),
          command BLOB NOT NULL CHECK(length(command) BETWEEN 1 AND 4096),
          state TEXT NOT NULL CHECK(state IN('pending','blocked','saved','applied','rejected','superseded')),
          policy_revision INTEGER CHECK(policy_revision>=1),
          outcome_code TEXT CHECK(outcome_code IN('remote_rejected','node_permission_or_state','node_unavailable')),
          attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 4294967295),
          next_attempt INTEGER NOT NULL CHECK(next_attempt>=0),
          routing_kind TEXT CHECK(routing_kind IN('prefix','address','pool','permission')),
          routing_id TEXT CHECK(length(routing_id)=22),
          preset_kind TEXT CHECK(preset_kind IS NULL OR (preset_kind IN('user','pool') AND routing_kind IS NULL)),
          preset_id TEXT CHECK((preset_id IS NULL AND preset_kind IS NULL)
            OR (preset_id IS NOT NULL AND preset_kind IS NOT NULL AND length(preset_id)=22
                AND routing_kind IS NULL AND routing_id IS NULL AND state IN('saved','applied'))),
          {metadata_columns}
          CHECK((routing_kind IS NULL AND routing_id IS NULL) OR (routing_kind IS NOT NULL AND routing_id IS NOT NULL)),
          CHECK(({resource_case} expected_policy_revision IS NOT NULL
            AND ((state IN('pending','blocked','rejected','superseded') AND policy_revision IS NULL
                  AND routing_kind IS NULL AND routing_id IS NULL {pending_presets})
              OR (state IN('saved','applied') {success_nonnull}
                  AND expected_policy_revision<9223372036854775807 AND policy_revision=expected_policy_revision+1)))
            {metadata_case})
         ) STRICT;
         INSERT INTO control_outbox_endpoint_rebuild({OUTBOX_COLUMNS}) SELECT {OUTBOX_COLUMNS} FROM control_outbox;
         DROP TABLE control_outbox;
         ALTER TABLE control_outbox_endpoint_rebuild RENAME TO control_outbox;"
    )).map_err(|error| sqlite_error("cannot rebuild public endpoint outbox", error))
}

fn audit(connection: &Connection, endpoints: bool) -> io::Result<()> {
    let actions = if endpoints {
        format!("{POLICY_ACTIONS},'set_public_address'")
    } else {
        POLICY_ACTIONS.to_owned()
    };
    connection.execute_batch(&format!(
        "CREATE TABLE controller_audit_endpoint_rebuild (
          sequence INTEGER PRIMARY KEY CHECK(sequence>=1),
          administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
          action TEXT NOT NULL CHECK(action IN('register','update','state','retire','enqueue','retry','supersede')),
          peer_id TEXT NOT NULL REFERENCES managed_targets(peer_id) ON DELETE RESTRICT,
          target_revision INTEGER NOT NULL CHECK(target_revision>=1),
          job_id TEXT CHECK(job_id IS NULL OR length(job_id)=22),
          controller_epoch INTEGER CHECK(controller_epoch>=1),command_id INTEGER CHECK(command_id>=1),
          mutation_action TEXT CHECK(mutation_action IN({actions})),
          recorded_at INTEGER NOT NULL CHECK(recorded_at>=0),
          CHECK((action IN('register','update','state','retire') AND job_id IS NULL AND controller_epoch IS NULL AND command_id IS NULL AND mutation_action IS NULL)
            OR (action IN('enqueue','retry','supersede') AND job_id IS NOT NULL AND controller_epoch IS NOT NULL AND command_id IS NOT NULL AND mutation_action IS NOT NULL))
         ) STRICT;
         INSERT INTO controller_audit_endpoint_rebuild({AUDIT_COLUMNS}) SELECT {AUDIT_COLUMNS} FROM controller_audit;
         DROP TABLE controller_audit;
         ALTER TABLE controller_audit_endpoint_rebuild RENAME TO controller_audit;"
    )).map_err(|error| sqlite_error("cannot rebuild endpoint delivery audit", error))
}
