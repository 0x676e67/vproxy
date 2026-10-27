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

/// Reconstruct actual schema-14 constraints for versioned migration fixtures.
/// New-vocabulary rows cannot be discarded or relabelled as historical policy.
/// This is test-only and does not alter user_version or endpoint-state tables.
#[cfg(test)]
pub(in crate::manage::store) fn remove_endpoints_schema_for_test(
    connection: &Connection,
) -> io::Result<()> {
    let present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('control_receipts') WHERE name='metadata_revision')",
        [], |row| row.get(0),
    ).map_err(|error| sqlite_error("cannot inspect endpoint receipt fixture", error))?;
    if !present {
        return Ok(());
    }
    let newer: bool = connection.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM control_receipts WHERE version=4 OR metadata_revision IS NOT NULL
          OR endpoint_id IS NOT NULL OR endpoint_generation IS NOT NULL)
          OR EXISTS(SELECT 1 FROM control_audit WHERE rejection IN({ENDPOINT_REJECTIONS}))"),
        [], |row| row.get(0),
    ).map_err(|error| sqlite_error("cannot inspect newer endpoint receipt rows", error))?;
    if newer {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "endpoint command rows cannot become a legacy fixture",
        ));
    }
    super::super::targets::remove_endpoints_schema_for_test(connection)?;
    receipts(connection, false)?;
    audit(connection, false)
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

#[cfg(test)]
mod tests {
    //! Direct SQL constraints complement typed-command tests. The opaque fixture
    //! BLOB below proves byte preservation, not successful command deserialization.

    use super::*;
    use rusqlite::types::Value;
    use std::{fs, path::PathBuf};

    struct Fixture {
        connection: Connection,
        // Fields drop in declaration order: close SQLite before removing files on
        // Windows, where an open database handle can prevent directory cleanup.
        _directory: Directory,
        peer: String,
        administrator: String,
        user: String,
    }

    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory = std::env::temp_dir().join(format!(
                "vproxy-endpoint-schema-{}",
                crate::manage::store::random_id()?
            ));
            crate::manage::store::initialize(&directory, "schema test", "admin", "fixture PHC")?;
            let connection = crate::manage::store::peers::open_existing(&directory, true)?;
            let peer = crate::manage::store::random_id()?;
            let user = crate::manage::store::random_id()?;
            let administrator: String = connection
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)?;
            connection
                .execute("INSERT INTO peers VALUES(?1,'test peer',1,1)", [&peer])
                .map_err(io::Error::other)?;
            connection
                .execute(
                    "INSERT INTO proxy_users VALUES(?1,'test user',1,0,1,1,1)",
                    [&user],
                )
                .map_err(io::Error::other)?;
            connection.execute(
            "INSERT INTO managed_targets(peer_id,origin,active,retired,revision,rollback_detected)
             VALUES(?1,'https://target.example:9443',1,0,1,0)", [&peer],
        ).map_err(io::Error::other)?;
            Ok(Self {
                connection,
                _directory: Directory(directory),
                peer,
                administrator,
                user,
            })
        }

        fn seed_legacy_columns(&self) -> io::Result<()> {
            self.connection.execute(
            "INSERT INTO control_receipts(epoch,command_id,controller_node_id,digest,status,policy_revision,user_id,version)
             VALUES(2,7,?1,?2,'saved',9,?3,1)",
            params![self.peer, &[0x81_u8;32], self.user],
        ).map_err(io::Error::other)?;
            self.connection.execute(
            "INSERT INTO control_outbox(peer_id,job_id,administrator_id,controller_epoch,command_id,expected_policy_revision,
             command,state,policy_revision,attempts,next_attempt) VALUES(?1,?2,?3,2,7,8,?4,'saved',9,4,0)",
            params![self.peer, crate::manage::store::random_id()?, self.administrator,
                b"{ \"opaque\": \"\\u0061\", \"number\": 7 }".as_slice()],
        ).map_err(io::Error::other)?;
            self.connection.execute(
            "INSERT INTO control_audit(sequence,action,administrator_id,epoch) VALUES(17,'set_owner',?1,2)",
            [&self.administrator],
        ).map_err(io::Error::other)?;
            self.connection.execute(
            "INSERT INTO controller_audit(sequence,administrator_id,action,peer_id,target_revision,job_id,
             controller_epoch,command_id,mutation_action,recorded_at)
             SELECT 23,administrator_id,'enqueue',peer_id,1,job_id,controller_epoch,command_id,'create_user',1 FROM control_outbox", [],
        ).map_err(io::Error::other)?;
            Ok(())
        }
    }

    struct Directory(PathBuf);

    impl Drop for Directory {
        fn drop(&mut self) {
            // Only the exclusively initialized random fixture directory is removed.
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn rows(connection: &Connection, query: &str) -> io::Result<Vec<Vec<Value>>> {
        let mut statement = connection.prepare(query).map_err(io::Error::other)?;
        let width = statement.column_count();
        statement
            .query_map([], |row| (0..width).map(|index| row.get(index)).collect())
            .map_err(io::Error::other)?
            .collect::<Result<_, _>>()
            .map_err(io::Error::other)
    }

    fn legacy_rows(connection: &Connection) -> io::Result<Vec<Vec<Vec<Value>>>> {
        [
        format!("SELECT {RECEIPT_COLUMNS} FROM control_receipts ORDER BY epoch,command_id"),
        "SELECT peer_id,job_id,administrator_id,controller_epoch,command_id,expected_policy_revision,command,state,policy_revision,outcome_code,attempts,next_attempt,routing_kind,routing_id,preset_kind,preset_id FROM control_outbox ORDER BY peer_id".to_owned(),
        format!("SELECT {AUDIT_COLUMNS} FROM control_audit ORDER BY sequence"),
        "SELECT sequence,administrator_id,action,peer_id,target_revision,job_id,controller_epoch,command_id,mutation_action,recorded_at FROM controller_audit ORDER BY sequence".to_owned(),
    ].iter().map(|query| rows(connection, query)).collect()
    }

    fn constraint(result: rusqlite::Result<usize>) {
        assert!(matches!(result,Err(rusqlite::Error::SqliteFailure(error,_))
        if error.code==rusqlite::ErrorCode::ConstraintViolation));
    }

    #[test]
    fn old_receipt_digest_blob_retry_and_audit_columns_survive_both_schema_shapes() -> io::Result<()>
    {
        let mut fixture = Fixture::new()?;
        fixture.seed_legacy_columns()?;
        let before = legacy_rows(&fixture.connection)?;
        let transaction = fixture.connection.transaction().map_err(io::Error::other)?;
        remove_endpoints_schema_for_test(&transaction)?;
        assert_eq!(legacy_rows(&transaction)?, before);
        let columns: i64 = transaction.query_row(
        "SELECT count(*) FROM pragma_table_info('control_receipts') WHERE name='metadata_revision'", [], |row|row.get(0),
    ).map_err(io::Error::other)?;
        assert_eq!(columns, 0);
        upgrade_endpoints(&transaction)?;
        assert_eq!(legacy_rows(&transaction)?, before);
        let metadata: (String, Option<i64>, Option<i64>) = transaction
            .query_row(
                "SELECT resource,expected_metadata_revision,metadata_revision FROM control_outbox",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(io::Error::other)?;
        assert_eq!(metadata, ("proxy_policy".into(), None, None));
        transaction.commit().map_err(io::Error::other)?;
        assert_eq!(legacy_rows(&fixture.connection)?, before);
        Ok(())
    }

    #[test]
    fn legacy_null_success_is_not_repaired_or_partially_migrated() -> io::Result<()> {
        let mut fixture = Fixture::new()?;
        fixture.seed_legacy_columns()?;
        let transaction = fixture.connection.transaction().map_err(io::Error::other)?;
        remove_endpoints_schema_for_test(&transaction)?;
        // Historical CHECK equality evaluates to NULL here and SQLite accepts it.
        // The typed old reader rejects it; migration must not silently invent a
        // successful revision to make this malformed legacy row fit the new DDL.
        transaction
            .execute("UPDATE control_outbox SET policy_revision=NULL", [])
            .map_err(io::Error::other)?;
        transaction.commit().map_err(io::Error::other)?;
        let before = legacy_rows(&fixture.connection)?;
        let transaction = fixture.connection.transaction().map_err(io::Error::other)?;
        assert!(upgrade_endpoints(&transaction).is_err());
        transaction.rollback().map_err(io::Error::other)?;
        assert_eq!(legacy_rows(&fixture.connection)?, before);
        let columns: i64 = fixture
            .connection
            .query_row(
                "SELECT count(*) FROM pragma_table_info('control_outbox') WHERE name='resource'",
                [],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        assert_eq!(columns, 0);
        Ok(())
    }

    #[test]
    fn receipts_reject_cross_resource_fields_null_success_and_metadata_applied() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let insert = |command: i64,
                      version: i64,
                      status: &str,
                      policy: Option<i64>,
                      rejection: Option<&str>,
                      user: Option<&str>,
                      metadata: Option<i64>,
                      endpoint: Option<&str>,
                      generation: Option<&str>| {
            fixture.connection.execute(
            "INSERT INTO control_receipts(epoch,command_id,controller_node_id,digest,status,policy_revision,
             rejection,user_id,version,metadata_revision,endpoint_id,endpoint_generation)
             VALUES(2,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![command,fixture.peer,&[0x37_u8;32],status,policy,rejection,user,version,metadata,endpoint,generation],
        )
        };
        let id = "AAAAAAAAAAAAAAAAAAAAAA";
        let generation = "a".repeat(64);
        assert_eq!(
            insert(
                1,
                4,
                "saved",
                None,
                None,
                None,
                Some(2),
                Some(id),
                Some(&generation)
            )
            .map_err(io::Error::other)?,
            1
        );
        assert_eq!(
            insert(
                2,
                4,
                "rejected",
                None,
                Some("endpoint_revision_changed"),
                None,
                None,
                None,
                None
            )
            .map_err(io::Error::other)?,
            1
        );
        for (index, (version, status, policy, rejection, user, metadata, endpoint, digest)) in [
            (
                4,
                "applied",
                None,
                None,
                None,
                Some(2),
                Some(id),
                Some(generation.as_str()),
            ),
            (
                4,
                "saved",
                None,
                None,
                None,
                None,
                Some(id),
                Some(generation.as_str()),
            ),
            (
                4,
                "saved",
                None,
                None,
                None,
                Some(2),
                None,
                Some(generation.as_str()),
            ),
            (4, "saved", None, None, None, Some(2), Some(id), None),
            (
                4,
                "saved",
                Some(9),
                None,
                None,
                Some(2),
                Some(id),
                Some(generation.as_str()),
            ),
            (
                4,
                "saved",
                None,
                None,
                Some(fixture.user.as_str()),
                Some(2),
                Some(id),
                Some(generation.as_str()),
            ),
            (
                4,
                "rejected",
                None,
                Some("policy_conflict"),
                None,
                None,
                None,
                None,
            ),
            (
                4,
                "rejected",
                None,
                Some("endpoint_capacity"),
                None,
                Some(2),
                None,
                None,
            ),
            (
                1,
                "saved",
                Some(9),
                None,
                Some(fixture.user.as_str()),
                Some(2),
                None,
                None,
            ),
            (
                1,
                "rejected",
                None,
                Some("endpoint_revision_changed"),
                None,
                None,
                None,
                None,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            constraint(insert(
                100 + i64::try_from(index).unwrap(),
                version,
                status,
                policy,
                rejection,
                user,
                metadata,
                endpoint,
                digest,
            ));
        }
        let before = rows(
            &fixture.connection,
            "SELECT * FROM control_receipts ORDER BY command_id",
        )?;
        assert!(remove_endpoints_schema_for_test(&fixture.connection).is_err());
        assert_eq!(
            rows(
                &fixture.connection,
                "SELECT * FROM control_receipts ORDER BY command_id"
            )?,
            before
        );
        Ok(())
    }

    #[test]
    fn outbox_metadata_has_its_own_revision_never_policy_or_applied() -> io::Result<()> {
        let fixture = Fixture::new()?;
        fixture.seed_legacy_columns()?;
        fixture.connection.execute(
        "UPDATE control_outbox SET resource='proxy_endpoints',expected_policy_revision=NULL,policy_revision=NULL,
         expected_metadata_revision=7,metadata_revision=8,state='saved'", [],
    ).map_err(io::Error::other)?;
        let before = rows(&fixture.connection, "SELECT * FROM control_outbox")?;
        for change in [
            "state='applied'",
            "expected_policy_revision=7",
            "policy_revision=8",
            "expected_metadata_revision=NULL",
            "metadata_revision=NULL",
            "metadata_revision=9",
            "expected_metadata_revision=9223372036854775807,metadata_revision=9223372036854775807",
            "resource='proxy_policy'",
            "routing_kind='pool',routing_id='AAAAAAAAAAAAAAAAAAAAAA'",
            "preset_kind='user',preset_id='AAAAAAAAAAAAAAAAAAAAAA'",
            "state='pending'",
        ] {
            constraint(
                fixture
                    .connection
                    .execute(&format!("UPDATE control_outbox SET {change}"), []),
            );
            assert_eq!(
                rows(&fixture.connection, "SELECT * FROM control_outbox")?,
                before
            );
        }
        assert!(remove_endpoints_schema_for_test(&fixture.connection).is_err());
        assert_eq!(
            rows(&fixture.connection, "SELECT * FROM control_outbox")?,
            before
        );
        fixture
            .connection
            .execute(
                "UPDATE control_outbox SET state='pending',metadata_revision=NULL",
                [],
            )
            .map_err(io::Error::other)?;
        let pending = rows(&fixture.connection, "SELECT * FROM control_outbox")?;
        constraint(
            fixture
                .connection
                .execute("UPDATE control_outbox SET metadata_revision=8", []),
        );
        assert_eq!(
            rows(&fixture.connection, "SELECT * FROM control_outbox")?,
            pending
        );
        Ok(())
    }
}
