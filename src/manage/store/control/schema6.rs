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
