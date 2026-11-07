//! Add a separate public-address receipt vocabulary without changing historical
//! policy command bytes, digests, owner epochs or shared command high-water marks.

use super::*;

const POLICY_REJECTIONS: &str =
    "'invalid_policy','policy_conflict','resource_not_found','policy_capacity'";
const ENDPOINT_REJECTIONS: &str = "'invalid_endpoint','endpoint_revision_changed','endpoint_configuration_changed','endpoint_capacity'";
const RECEIPT_COLUMNS: &str = "epoch,command_id,controller_node_id,digest,status,policy_revision,rejection,user_id,credential_id,version,routing_kind,routing_id,preset_kind,preset_id";
const AUDIT_COLUMNS: &str = "sequence,action,administrator_id,controller_node_id,epoch,command_id,source_administrator_id,rejection";

/// Called only inside initialization or a backed-up migration transaction.
/// A failure rolls back all rebuilt objects with the caller's transaction;
/// existing BLOB payloads and digests are copied directly, never deserialized.
pub(in crate::manage::store) fn upgrade_endpoints(connection: &Connection) -> io::Result<()> {
    if connection.is_autocommit() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "endpoint schema upgrade requires a transaction",
        ));
    }
    receipts(connection, true)?;
    audit(connection, true)?;
    super::super::targets::upgrade_endpoints(connection)
}

/// The only interpolated fragments select two fixed internal schemas. No
/// browser, backup value, identifier or SQL text enters this DDL vocabulary.
fn receipts(connection: &Connection, endpoints: bool) -> io::Result<()> {
    let (versions, rejections, metadata_columns, metadata_null, metadata_case, copy) = if endpoints
    {
        (
            "1,2,3,4",
            format!("{POLICY_REJECTIONS},{ENDPOINT_REJECTIONS}"),
            "metadata_revision INTEGER CHECK(metadata_revision>=1),
             endpoint_id TEXT CHECK(length(endpoint_id)=22),
             endpoint_generation TEXT CHECK(length(endpoint_generation)=64 AND endpoint_generation NOT GLOB '*[^0-9a-f]*'),",
            "AND metadata_revision IS NULL AND endpoint_id IS NULL AND endpoint_generation IS NULL",
            format!("OR (version=4 AND policy_revision IS NULL AND user_id IS NULL AND credential_id IS NULL
               AND routing_kind IS NULL AND routing_id IS NULL AND preset_kind IS NULL AND preset_id IS NULL
               AND ((status='saved' AND rejection IS NULL AND metadata_revision IS NOT NULL
                   AND endpoint_id IS NOT NULL AND endpoint_generation IS NOT NULL)
                 OR (status='rejected' AND rejection IS NOT NULL AND rejection IN({ENDPOINT_REJECTIONS})
                   AND metadata_revision IS NULL AND endpoint_id IS NULL AND endpoint_generation IS NULL)))"),
            RECEIPT_COLUMNS.to_owned(),
        )
    } else {
        (
            "1,2,3",
            POLICY_REJECTIONS.to_owned(),
            "",
            "",
            String::new(),
            RECEIPT_COLUMNS.to_owned(),
        )
    };
    connection.execute_batch(&format!(
        "CREATE TABLE control_receipts_endpoint_rebuild (
          epoch INTEGER NOT NULL CHECK(epoch>=1),command_id INTEGER NOT NULL CHECK(command_id>=1),
          controller_node_id TEXT NOT NULL REFERENCES peers(node_id) ON DELETE RESTRICT,
          digest BLOB NOT NULL CHECK(length(digest)=32),
          status TEXT NOT NULL CHECK(status IN('saved','applied','rejected')),
          policy_revision INTEGER CHECK(policy_revision>=1),
          rejection TEXT CHECK(rejection IN({rejections})),
          user_id TEXT REFERENCES proxy_users(id) ON DELETE RESTRICT,
          credential_id TEXT REFERENCES proxy_credentials(id) ON DELETE RESTRICT,
          version INTEGER NOT NULL DEFAULT 1 CHECK(version IN({versions})),
          routing_kind TEXT CHECK(routing_kind IN('prefix','address','pool','permission')),
          routing_id TEXT CHECK(length(routing_id)=22),
          preset_kind TEXT CHECK(preset_kind IN('user','pool')),
          preset_id TEXT CHECK(length(preset_id)=22),
          {metadata_columns}
          PRIMARY KEY(epoch,command_id),
          CHECK((version IN(1,2,3) {metadata_null}
            AND ((status='rejected' AND rejection IS NOT NULL AND rejection IN({POLICY_REJECTIONS})
                 AND policy_revision IS NULL AND user_id IS NULL AND credential_id IS NULL
                 AND routing_kind IS NULL AND routing_id IS NULL AND preset_kind IS NULL AND preset_id IS NULL)
              OR (status IN('saved','applied') AND rejection IS NULL AND policy_revision IS NOT NULL
                AND ((version=1 AND user_id IS NOT NULL AND routing_kind IS NULL AND routing_id IS NULL AND preset_kind IS NULL AND preset_id IS NULL)
                  OR (version=2 AND user_id IS NULL AND credential_id IS NULL AND routing_kind IS NOT NULL AND routing_id IS NOT NULL AND preset_kind IS NULL AND preset_id IS NULL)
                  OR (version=3 AND user_id IS NULL AND credential_id IS NULL AND routing_kind IS NULL AND routing_id IS NULL AND preset_kind IS NOT NULL AND preset_id IS NOT NULL)))))
            {metadata_case})
         ) STRICT;
         INSERT INTO control_receipts_endpoint_rebuild({copy}) SELECT {copy} FROM control_receipts;
         DROP TABLE control_receipts;
         ALTER TABLE control_receipts_endpoint_rebuild RENAME TO control_receipts;"
    )).map_err(|error| sqlite_error("cannot rebuild public endpoint command receipts", error))
}

fn audit(connection: &Connection, endpoints: bool) -> io::Result<()> {
    let rejections = if endpoints {
        format!("{POLICY_REJECTIONS},{ENDPOINT_REJECTIONS}")
    } else {
        POLICY_REJECTIONS.to_owned()
    };
    connection.execute_batch(&format!(
        "CREATE TABLE control_audit_endpoint_rebuild (
          sequence INTEGER PRIMARY KEY,
          action TEXT NOT NULL CHECK(action IN('set_owner','command_rejected','set_owner_offline')),
          administrator_id TEXT REFERENCES administrators(id) ON DELETE RESTRICT,
          controller_node_id TEXT REFERENCES peers(node_id) ON DELETE RESTRICT,
          epoch INTEGER NOT NULL CHECK(epoch>=1),command_id INTEGER CHECK(command_id>=1),
          source_administrator_id TEXT CHECK(length(source_administrator_id)=22),
          rejection TEXT CHECK(rejection IN({rejections})),
          CHECK((action='set_owner' AND administrator_id IS NOT NULL AND command_id IS NULL AND source_administrator_id IS NULL AND rejection IS NULL)
            OR (action='set_owner_offline' AND administrator_id IS NULL AND command_id IS NULL AND source_administrator_id IS NULL AND rejection IS NULL)
            OR (action='command_rejected' AND administrator_id IS NULL AND controller_node_id IS NOT NULL AND command_id IS NOT NULL AND source_administrator_id IS NOT NULL AND rejection IS NOT NULL))
         ) STRICT;
         INSERT INTO control_audit_endpoint_rebuild({AUDIT_COLUMNS}) SELECT {AUDIT_COLUMNS} FROM control_audit;
         DROP TABLE control_audit;
         ALTER TABLE control_audit_endpoint_rebuild RENAME TO control_audit;"
    )).map_err(|error| sqlite_error("cannot rebuild endpoint rejection audit", error))
}
