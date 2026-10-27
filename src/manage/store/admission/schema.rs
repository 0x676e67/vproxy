//! Schema19 widens only command/actor vocabulary. Old command BLOBs, digests,
//! receipt statuses, owner epochs and shared high-water marks are copied intact.

use super::*;

const RECEIPT_COLUMNS: &str = "epoch,command_id,controller_node_id,digest,status,policy_revision,rejection,user_id,credential_id,version,routing_kind,routing_id,preset_kind,preset_id,metadata_revision,endpoint_id,endpoint_generation";
const AUDIT_COLUMNS: &str = "sequence,administrator_id,action,peer_id,target_revision,job_id,controller_epoch,command_id,mutation_action,recorded_at";
const POLICY_ACTIONS: &str = "'create_user','update_user','set_user_active','delete_user','create_credential','set_credential_active','rotate_credential','revoke_credential','create_prefix','retire_prefix','create_address','set_address_state','create_pool','set_pool_state','add_pool_member','remove_pool_member','set_route_permission','set_user_presets','set_pool_preset','set_public_address'";
const POLICY_REJECTIONS: &str =
    "'invalid_policy','policy_conflict','resource_not_found','policy_capacity'";
const ENDPOINT_REJECTIONS: &str = "'invalid_endpoint','endpoint_revision_changed','endpoint_configuration_changed','endpoint_capacity'";

pub(in crate::manage::store) fn create_schema(connection: &Connection) -> io::Result<()> {
    if connection.is_autocommit() {
        return Err(corrupt());
    }
    receipts(connection, true)?;
    controller_audit(connection, true)?;
    connection.execute_batch(
        "CREATE TABLE proxy_admission_state(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            accepting INTEGER NOT NULL CHECK(accepting IN(0,1))
         ) STRICT;
         INSERT INTO proxy_admission_state VALUES(1,1);
         CREATE TABLE proxy_admission_audit(
            policy_revision INTEGER PRIMARY KEY CHECK(policy_revision>=1),
            entry TEXT NOT NULL CHECK(entry IN('local_management','node_management')),
            administrator_id TEXT REFERENCES administrators(id) ON DELETE RESTRICT,
            controller_node_id TEXT REFERENCES peers(node_id) ON DELETE RESTRICT,
            controller_epoch INTEGER CHECK(controller_epoch>=1),
            command_id INTEGER CHECK(command_id>=1),
            source_administrator_id TEXT CHECK(length(source_administrator_id)=22),
            accepting INTEGER NOT NULL CHECK(accepting IN(0,1)),
            CHECK((entry='local_management' AND administrator_id IS NOT NULL AND controller_node_id IS NULL
                    AND controller_epoch IS NULL AND command_id IS NULL AND source_administrator_id IS NULL)
                OR(entry='node_management' AND administrator_id IS NULL AND controller_node_id IS NOT NULL
                    AND controller_epoch IS NOT NULL AND command_id IS NOT NULL AND source_administrator_id IS NOT NULL))
         ) STRICT;"
    ).map_err(|error|sqlite_error("cannot create proxy admission schema",error))
}

#[cfg(test)]
pub(in crate::manage) fn remove_schema_for_test(connection: &Connection) -> io::Result<()> {
    let present:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='proxy_admission_state' AND type='table')",[],|row|row.get(0))
        .map_err(|error|sqlite_error("cannot inspect admission fixture schema",error))?;
    if !present {
        return Ok(());
    }
    let unused:bool=connection.query_row("SELECT (SELECT count(*)=1 AND min(singleton)=1 AND min(accepting)=1 FROM proxy_admission_state)
        AND NOT EXISTS(SELECT 1 FROM proxy_admission_audit)
        AND NOT EXISTS(SELECT 1 FROM control_receipts WHERE version=5)
        AND NOT EXISTS(SELECT 1 FROM controller_audit WHERE mutation_action='set_admission')",[],|row|row.get(0))
        .map_err(|error|sqlite_error("cannot inspect issued admission fixture history",error))?;
    if !unused {
        return Err(corrupt());
    }
    // A pending v5 has no audit or target receipt yet. Inspect only its new
    // discriminators: older migration fixtures deliberately retain opaque BLOB
    // bytes, which must not be parsed/re-serialized as a modern command.
    let mut statement = connection
        .prepare("SELECT command FROM control_outbox ORDER BY peer_id LIMIT 129")
        .map_err(|error| sqlite_error("cannot inspect admission fixture commands", error))?;
    let commands = statement
        .query_map([], |row| match row.get_ref(0)? {
            rusqlite::types::ValueRef::Blob(bytes) if !bytes.is_empty() && bytes.len() <= 4096 => {
                Ok(bytes.to_vec())
            }
            value => Err(rusqlite::Error::InvalidColumnType(
                0,
                "command".into(),
                value.data_type(),
            )),
        })
        .map_err(|error| sqlite_error("cannot read admission fixture commands", error))?;
    for (index, bytes) in commands.enumerate() {
        if index >= 128 {
            return Err(corrupt());
        }
        let bytes = bytes.map_err(|_| corrupt())?;
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && (value.get("version").and_then(serde_json::Value::as_u64) == Some(5)
                || value
                    .get("mutation")
                    .and_then(|mutation| mutation.get("action"))
                    .and_then(serde_json::Value::as_str)
                    == Some("set_admission"))
        {
            return Err(corrupt());
        }
    }
    drop(statement);
    receipts(connection, false)?;
    controller_audit(connection, false)?;
    connection
        .execute_batch("DROP TABLE proxy_admission_audit; DROP TABLE proxy_admission_state;")
        .map_err(|error| sqlite_error("cannot reconstruct pre-admission fixture", error))
}

fn receipts(connection: &Connection, admission: bool) -> io::Result<()> {
    let versions = if admission { "1,2,3,4,5" } else { "1,2,3,4" };
    let policy_versions = if admission { "1,2,3,5" } else { "1,2,3" };
    let admission_case = if admission {
        "OR(version=5 AND user_id IS NULL AND credential_id IS NULL AND routing_kind IS NULL AND routing_id IS NULL AND preset_kind IS NULL AND preset_id IS NULL)"
    } else {
        ""
    };
    connection.execute_batch(&format!(
        "CREATE TABLE control_receipts_admission_rebuild(
          epoch INTEGER NOT NULL CHECK(epoch>=1),command_id INTEGER NOT NULL CHECK(command_id>=1),
          controller_node_id TEXT NOT NULL REFERENCES peers(node_id) ON DELETE RESTRICT,
          digest BLOB NOT NULL CHECK(length(digest)=32),
          status TEXT NOT NULL CHECK(status IN('saved','applied','rejected')),
          policy_revision INTEGER CHECK(policy_revision>=1),
          rejection TEXT CHECK(rejection IN({POLICY_REJECTIONS},{ENDPOINT_REJECTIONS})),
          user_id TEXT REFERENCES proxy_users(id) ON DELETE RESTRICT,
          credential_id TEXT REFERENCES proxy_credentials(id) ON DELETE RESTRICT,
          version INTEGER NOT NULL DEFAULT 1 CHECK(version IN({versions})),
          routing_kind TEXT CHECK(routing_kind IN('prefix','address','pool','permission')),
          routing_id TEXT CHECK(length(routing_id)=22),
          preset_kind TEXT CHECK(preset_kind IN('user','pool')),
          preset_id TEXT CHECK(length(preset_id)=22),
          metadata_revision INTEGER CHECK(metadata_revision>=1),
          endpoint_id TEXT CHECK(length(endpoint_id)=22),
          endpoint_generation TEXT CHECK(length(endpoint_generation)=64 AND endpoint_generation NOT GLOB '*[^0-9a-f]*'),
          PRIMARY KEY(epoch,command_id),
          CHECK((version IN({policy_versions}) AND metadata_revision IS NULL AND endpoint_id IS NULL AND endpoint_generation IS NULL
            AND ((status='rejected' AND rejection IS NOT NULL AND rejection IN({POLICY_REJECTIONS})
                 AND policy_revision IS NULL AND user_id IS NULL AND credential_id IS NULL
                 AND routing_kind IS NULL AND routing_id IS NULL AND preset_kind IS NULL AND preset_id IS NULL)
              OR(status IN('saved','applied') AND rejection IS NULL AND policy_revision IS NOT NULL
                AND ((version=1 AND user_id IS NOT NULL AND routing_kind IS NULL AND routing_id IS NULL AND preset_kind IS NULL AND preset_id IS NULL)
                  OR(version=2 AND user_id IS NULL AND credential_id IS NULL AND routing_kind IS NOT NULL AND routing_id IS NOT NULL AND preset_kind IS NULL AND preset_id IS NULL)
                  OR(version=3 AND user_id IS NULL AND credential_id IS NULL AND routing_kind IS NULL AND routing_id IS NULL AND preset_kind IS NOT NULL AND preset_id IS NOT NULL)
                  {admission_case}))))
            OR(version=4 AND policy_revision IS NULL AND user_id IS NULL AND credential_id IS NULL
               AND routing_kind IS NULL AND routing_id IS NULL AND preset_kind IS NULL AND preset_id IS NULL
               AND ((status='saved' AND rejection IS NULL AND metadata_revision IS NOT NULL AND endpoint_id IS NOT NULL AND endpoint_generation IS NOT NULL)
                 OR(status='rejected' AND rejection IS NOT NULL AND rejection IN({ENDPOINT_REJECTIONS}) AND metadata_revision IS NULL AND endpoint_id IS NULL AND endpoint_generation IS NULL))))
         ) STRICT;
         INSERT INTO control_receipts_admission_rebuild({RECEIPT_COLUMNS}) SELECT {RECEIPT_COLUMNS} FROM control_receipts;
         DROP TABLE control_receipts;
         ALTER TABLE control_receipts_admission_rebuild RENAME TO control_receipts;"
    )).map_err(|error|sqlite_error("cannot rebuild admission command receipts",error))
}

fn controller_audit(connection: &Connection, admission: bool) -> io::Result<()> {
    let extra = if admission { ",'set_admission'" } else { "" };
    connection.execute_batch(&format!(
        "CREATE TABLE controller_audit_admission_rebuild(
          sequence INTEGER PRIMARY KEY CHECK(sequence>=1),
          administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
          action TEXT NOT NULL CHECK(action IN('register','update','state','retire','enqueue','retry','supersede')),
          peer_id TEXT NOT NULL REFERENCES managed_targets(peer_id) ON DELETE RESTRICT,
          target_revision INTEGER NOT NULL CHECK(target_revision>=1),
          job_id TEXT CHECK(job_id IS NULL OR length(job_id)=22),
          controller_epoch INTEGER CHECK(controller_epoch>=1),command_id INTEGER CHECK(command_id>=1),
          mutation_action TEXT CHECK(mutation_action IN({POLICY_ACTIONS}{extra})),
          recorded_at INTEGER NOT NULL CHECK(recorded_at>=0),
          CHECK((action IN('register','update','state','retire') AND job_id IS NULL AND controller_epoch IS NULL AND command_id IS NULL AND mutation_action IS NULL)
            OR(action IN('enqueue','retry','supersede') AND job_id IS NOT NULL AND controller_epoch IS NOT NULL AND command_id IS NOT NULL AND mutation_action IS NOT NULL))
         ) STRICT;
         INSERT INTO controller_audit_admission_rebuild({AUDIT_COLUMNS}) SELECT {AUDIT_COLUMNS} FROM controller_audit;
         DROP TABLE controller_audit;
         ALTER TABLE controller_audit_admission_rebuild RENAME TO controller_audit;"
    )).map_err(|error|sqlite_error("cannot rebuild admission controller audit",error))
}
