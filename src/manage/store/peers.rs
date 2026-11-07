//! Durable peer enrollment, compare-and-swap authorization and certificate tombstones.
//!
//! These synchronous operations are for bounded blocking workers or offline CLI
//! commands, never proxy data-plane tasks. TLS validates certificate contents;
//! this module binds the exact leaf bytes to a locally authorized node identity.

use std::{
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, TransactionBehavior,
    backup::{Backup, StepResult},
    params,
};

#[cfg(not(windows))]
use std::fs::OpenOptions;

use super::{
    DATABASE_NAME, Overview, SCHEMA_VERSION, configure, invalid_data, open, read_overview,
    sqlite_error, valid_id, validate_database, validate_directory,
};

const MAX_PEERS: u32 = 1_024;
const MAX_CERTIFICATES: u32 = 8_192;
const MAX_AUDIT_RECORDS: u32 = 16_384;
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const BACKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Non-secret enrollment facts; certificate count includes permanent tombstones.
#[serde_with::serde_as]
#[derive(Debug, Eq, PartialEq, serde::Deserialize)]
pub(in crate::manage) struct PeerSummary {
    /// Stable remote identity, independent of its name or certificate rotation.
    pub(in crate::manage) node_id: String,
    /// Local operator's display name, never an authentication claim.
    pub(in crate::manage) name: String,
    /// Whether currently valid certificates may authorize requests for this peer.
    #[serde_as(as = "serde_with::BoolFromInt")]
    pub(in crate::manage) active: bool,
    /// Local authorization generation, not a configuration or control-owner epoch.
    pub(in crate::manage) authorization_revision: u64,
    /// All registered leaf certificates, including permanently revoked ones.
    pub(in crate::manage) certificate_count: u32,
}

/// A current authorization decision for an exact, TLS-verified peer leaf.
#[derive(Debug, Eq, PartialEq)]
pub(in crate::manage) struct PeerAuthorization {
    /// Stable identity obtained from local enrollment, never from request JSON.
    pub(in crate::manage) node_id: String,
    /// Locally configured display name.
    pub(in crate::manage) name: String,
    /// Trusted reference name for the TLS layer's additional client SAN check.
    pub(in crate::manage) expected_san: String,
    /// Rechecked for every request so keep-alive cannot retain revoked authority.
    pub(in crate::manage) authorization_revision: u64,
}

/// Raw signed values are checked before becoming an authorization decision.
struct AuthorizationRow {
    node_id: String,
    name: String,
    expected_san: String,
    revision: i64,
    active: i64,
    revoked: i64,
}

/// Creates only the new v2 objects inside the caller's initialization/migration transaction.
pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection
        .execute_batch(
            "CREATE TABLE peers (
                node_id TEXT PRIMARY KEY NOT NULL CHECK (length(node_id) = 22),
                name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
                active INTEGER NOT NULL CHECK (active IN (0, 1)),
                authorization_revision INTEGER NOT NULL CHECK (authorization_revision >= 1)
             ) STRICT;
             CREATE TABLE peer_certificates (
                der BLOB PRIMARY KEY NOT NULL CHECK (length(der) BETWEEN 1 AND 16384),
                node_id TEXT NOT NULL REFERENCES peers(node_id) ON DELETE RESTRICT,
                expected_san TEXT NOT NULL CHECK (length(expected_san) BETWEEN 1 AND 253),
                revoked INTEGER NOT NULL CHECK (revoked IN (0, 1))
             ) STRICT;
             CREATE INDEX peer_certificates_node ON peer_certificates(node_id);
             CREATE TABLE peer_audit (
                sequence INTEGER PRIMARY KEY,
                entry TEXT NOT NULL CHECK (entry = 'offline'),
                action TEXT NOT NULL CHECK (action IN ('register', 'update', 'enable', 'disable', 'revoke')),
                node_id TEXT NOT NULL REFERENCES peers(node_id) ON DELETE RESTRICT,
                authorization_revision INTEGER NOT NULL CHECK (authorization_revision >= 1)
             ) STRICT;",
        )
        .map_err(|error| sqlite_error("cannot create peer enrollment schema", error))
}

/// Explicitly migrates older supported schemas after a private, consistent backup.
///
/// The caller must stop management instances first. An immediate source write
/// transaction excludes other writers while a separate read-only connection
/// backs up the committed old snapshot, before any schema changes. The backup's
/// parent must be an existing private real directory controlled by the operator.
/// Existing backups/sidecars, symlinks, unsupported schemas and invalid storage
/// fail without replacement. New partial backups are retained on failure for
/// diagnosis; changes roll back atomically. Calls block on filesystem/SQLite,
/// with bounded lock waits and a 10-second backup stepping deadline.
pub(in crate::manage) fn migrate(directory: &Path, backup_path: &Path) -> io::Result<Overview> {
    let _guard = super::lock(directory)?;
    let _update = super::update_lock(directory)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin management schema migration", error))?;
    let before = read_overview(&transaction)?;
    if before.schema_version == SCHEMA_VERSION {
        return Err(conflict("management schema is already current"));
    }
    backup_existing(directory, backup_path, &before)?;
    if before.schema_version == 1 {
        create_schema(&transaction)?;
    }
    if before.schema_version < 3 {
        super::users::create_schema(&transaction)?;
    }
    if before.schema_version < 4 {
        super::control::create_schema(&transaction)?;
    }
    if before.schema_version < 5 {
        super::routing::create_schema(&transaction)?;
    }
    if before.schema_version < 6 {
        super::control::upgrade_schema(&transaction)?;
    }
    if before.schema_version < 7 {
        super::traffic::create_schema(&transaction)?;
    }
    if before.schema_version < 8 {
        super::remote_traffic::create_schema(&transaction)?;
    }
    if before.schema_version < 9 {
        super::presets::create_schema(&transaction)?;
        super::control::upgrade_presets(&transaction)?;
    }
    if before.schema_version < 10 {
        super::targets::upgrade_metadata(&transaction)?;
    }
    if before.schema_version < 11 {
        super::administrators::create_schema(&transaction)?;
    }
    if before.schema_version < 12 {
        super::administrators::upgrade_schema(&transaction)?;
    }
    if before.schema_version < 13 {
        super::control::upgrade_owner_audit(&transaction)?;
    }
    if before.schema_version < 14 {
        super::recovery::create_schema(&transaction)?;
    } else if before.schema_version < 19 {
        super::recovery::upgrade_schema(&transaction)?;
    } else if before.schema_version == 19 {
        super::recovery::migrate_nineteen(&transaction)?;
    } else if before.schema_version == 20 {
        super::recovery::migrate_twenty(&transaction)?;
    } else if before.schema_version == 21 {
        super::recovery::migrate_twenty_one(&transaction)?;
    } else if before.schema_version == 22 {
        super::recovery::migrate_twenty_two(&transaction)?;
    } else if before.schema_version == 23 {
        super::recovery::migrate_twenty_three(&transaction)?;
    } else if before.schema_version == 24 {
        super::recovery::migrate_twenty_four(&transaction)?;
    } else if before.schema_version == 25 {
        super::recovery::migrate_twenty_five(&transaction)?;
    } else if before.schema_version == 26 {
        super::recovery::migrate_twenty_six(&transaction)?;
    } else if before.schema_version == 27 {
        super::recovery::migrate_twenty_seven(&transaction)?;
    } else if before.schema_version == 28 {
        super::recovery::migrate_twenty_eight(&transaction)?;
    }
    if before.schema_version < 15 {
        super::endpoints::create_schema(&transaction)?;
        super::control::upgrade_endpoints(&transaction)?;
    }
    if before.schema_version < 17 {
        super::automation::create_schema(&transaction)?;
    } else if before.schema_version < 18 {
        super::automation::migrate_to_18(&transaction)?;
    }
    if before.schema_version < 16 {
        super::operations::create_schema(&transaction)?;
    } else if before.schema_version < 18 {
        super::operations::upgrade_schema(&transaction)?;
    }
    if before.schema_version < 18 {
        super::users::upgrade_operation_audit(&transaction)?;
    }
    if before.schema_version < 19 {
        super::admission::create_schema(&transaction)?;
    }
    if before.schema_version < 20 {
        super::targets::history::create_schema(&transaction)?;
    }
    if before.schema_version < 21 {
        super::alerts::history::create_schema(&transaction)?;
    }
    if before.schema_version < 23 {
        super::notifications::create_schema(&transaction)?;
    }
    if before.schema_version < 25 {
        super::witness::create_schema(&transaction)?;
    }
    if before.schema_version < 26 {
        super::source::create_schema(&transaction)?;
    }
    if before.schema_version < 27 {
        super::proxy_service::create_schema(&transaction)?;
    }
    if before.schema_version < 28 {
        super::secrets::create_schema(&transaction)?;
    }
    if before.schema_version < 29 {
        super::traffic::upgrade_protocols(&transaction)?;
        super::remote_traffic::upgrade_protocols(&transaction)?;
    }
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(|error| sqlite_error("cannot version migrated management schema", error))?;
    if before.schema_version < 20 {
        super::targets::history::migrate(&transaction)?;
    }
    let overview = read_overview(&transaction)?;
    super::targets::history::validate_snapshot(&transaction)?;
    super::alerts::history::validate_snapshot(&transaction)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit management schema migration", error))?;
    Ok(overview)
}

/// Registers a new peer or updates an existing peer using its expected revision.
///
/// IDs must use the canonical local 128-bit encoding and cannot identify this
/// node. Names are trimmed, non-control text up to 128 bytes; TLS-verified DER
/// must be nonempty and at most 16 KiB, with an ASCII SAN up to 253 bytes. New
/// peers require `None`; existing names/rotations require a matching `Some` CAS.
/// Reusing this peer's active DER updates its name/SAN without adding a row.
/// Revoked or differently owned DER always conflicts. Tombstones count toward
/// capacity, are never erased, and failures do not consume a revision. Blocking
/// writes use an immediate transaction, FULL durability and bounded lock waits.
pub(in crate::manage) fn register_peer(
    directory: &Path,
    node_id: &str,
    name: &str,
    der: &[u8],
    expected_san: &str,
    expected_revision: Option<u64>,
) -> io::Result<PeerSummary> {
    let _update = super::update_lock(directory)?;
    validate_registration(node_id, name, der, expected_san, expected_revision)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin peer registration", error))?;
    let peer = register_transaction(
        &transaction,
        node_id,
        name,
        der,
        expected_san,
        expected_revision,
    )?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit peer authorization change", error))?;
    Ok(peer)
}

fn validate_registration(
    node_id: &str,
    name: &str,
    der: &[u8],
    expected_san: &str,
    expected_revision: Option<u64>,
) -> io::Result<()> {
    validate_id(node_id)?;
    validate_name(name)?;
    validate_certificate(der)?;
    validate_san(expected_san)?;
    if let Some(revision) = expected_revision {
        revision_as_sql(revision)?;
    }
    Ok(())
}

fn register_transaction(
    transaction: &Connection,
    node_id: &str,
    name: &str,
    der: &[u8],
    expected_san: &str,
    expected_revision: Option<u64>,
) -> io::Result<PeerSummary> {
    require_transaction(transaction)?;
    let overview = require_peers(transaction)?;
    if node_id == overview.node_id {
        return Err(invalid_input("a node cannot enroll itself as a peer"));
    }
    let existing = find_summary(transaction, node_id)?;
    let revision = match (&existing, expected_revision) {
        (None, None) => {
            check_capacity(transaction, "SELECT count(*) FROM peers", MAX_PEERS)?;
            1
        }
        (Some(peer), Some(expected)) => next_revision(peer, expected)?,
        (None, Some(_)) => return Err(not_found("peer is not registered")),
        (Some(_), None) => return Err(conflict("peer registration requires its current revision")),
    };
    let certificate: Option<(String, i64)> = transaction
        .query_row(
            "SELECT node_id, revoked FROM peer_certificates WHERE der = ?1",
            [der],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| sqlite_error("cannot inspect peer certificate ownership", error))?;
    if certificate
        .as_ref()
        .is_some_and(|(_, revoked)| ![0, 1].contains(revoked))
    {
        return Err(invalid_data(
            "peer certificate revocation state is malformed",
        ));
    }
    if certificate
        .as_ref()
        .is_some_and(|(owner, revoked)| owner != node_id || *revoked == 1)
    {
        return Err(conflict(
            "certificate is revoked or already belongs to another peer",
        ));
    }
    if certificate.is_none() {
        check_capacity(
            transaction,
            "SELECT count(*) FROM peer_certificates",
            MAX_CERTIFICATES,
        )?;
    }
    let revision_sql = revision_as_sql(revision)?;
    if existing.is_some() {
        transaction
            .execute(
                "UPDATE peers SET name = ?1, authorization_revision = ?2 WHERE node_id = ?3",
                params![name, revision_sql, node_id],
            )
            .map_err(|error| sqlite_error("cannot update peer registration", error))?;
    } else {
        transaction
            .execute(
                "INSERT INTO peers (node_id, name, active, authorization_revision)
                 VALUES (?1, ?2, 1, ?3)",
                params![node_id, name, revision_sql],
            )
            .map_err(|error| sqlite_error("cannot register peer", error))?;
    }
    if certificate.is_some() {
        transaction
            .execute(
                "UPDATE peer_certificates SET expected_san = ?1 WHERE der = ?2",
                params![expected_san, der],
            )
            .map_err(|error| {
                sqlite_error("cannot update peer certificate reference name", error)
            })?;
    } else {
        transaction
            .execute(
                "INSERT INTO peer_certificates (der, node_id, expected_san, revoked)
                 VALUES (?1, ?2, ?3, 0)",
                params![der, node_id, expected_san],
            )
            .map_err(|error| sqlite_error("cannot register peer certificate", error))?;
    }
    audit(
        transaction,
        if existing.is_some() {
            "update"
        } else {
            "register"
        },
        node_id,
        revision_sql,
    )?;
    changed_peer(transaction, node_id)
}

/// Enables/disables an existing peer with CAS, advancing even an unchanged value.
///
/// Disabling does not erase certificates or undo permanent revocations. Invalid
/// IDs/revisions, missing peers and stale CAS fail without a partial write. This
/// is synchronous blocking work with a bounded SQLite lock wait.
pub(in crate::manage) fn set_peer_active(
    directory: &Path,
    node_id: &str,
    expected_revision: u64,
    active: bool,
) -> io::Result<PeerSummary> {
    let _update = super::update_lock(directory)?;
    validate_id(node_id)?;
    revision_as_sql(expected_revision)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin peer status change", error))?;
    let peer = active_transaction(&transaction, node_id, expected_revision, active)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit peer authorization change", error))?;
    Ok(peer)
}

fn active_transaction(
    transaction: &Connection,
    node_id: &str,
    expected_revision: u64,
    active: bool,
) -> io::Result<PeerSummary> {
    require_transaction(transaction)?;
    require_peers(transaction)?;
    let peer =
        find_summary(transaction, node_id)?.ok_or_else(|| not_found("peer is not registered"))?;
    let revision = revision_as_sql(next_revision(&peer, expected_revision)?)?;
    transaction
        .execute(
            "UPDATE peers SET active = ?1, authorization_revision = ?2 WHERE node_id = ?3",
            params![active, revision, node_id],
        )
        .map_err(|error| sqlite_error("cannot update peer status", error))?;
    audit(
        transaction,
        if active { "enable" } else { "disable" },
        node_id,
        revision,
    )?;
    changed_peer(transaction, node_id)
}

/// Permanently revokes one exact DER and advances its owner's expected revision.
///
/// A missing certificate returns `NotFound`; stale CAS or an existing tombstone
/// returns `AlreadyExists`. Revoked bytes cannot be enrolled again, even for a
/// different node. No certificate or audit data is returned to the caller.
/// This blocking operation uses one FULL-durable immediate transaction.
pub(in crate::manage) fn revoke_certificate(
    directory: &Path,
    der: &[u8],
    expected_revision: u64,
) -> io::Result<PeerSummary> {
    let _update = super::update_lock(directory)?;
    validate_certificate(der)?;
    revision_as_sql(expected_revision)?;
    let mut connection = open_existing(directory, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("cannot begin certificate revocation", error))?;
    let peer = revoke_transaction(&transaction, der, expected_revision)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot commit peer authorization change", error))?;
    Ok(peer)
}

fn revoke_transaction(
    transaction: &Connection,
    der: &[u8],
    expected_revision: u64,
) -> io::Result<PeerSummary> {
    require_transaction(transaction)?;
    require_peers(transaction)?;
    let certificate: Option<(String, i64)> = transaction
        .query_row(
            "SELECT node_id, revoked FROM peer_certificates WHERE der = ?1",
            [der],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| sqlite_error("cannot read certificate for revocation", error))?;
    let (node_id, revoked) =
        certificate.ok_or_else(|| not_found("certificate is not registered"))?;
    if ![0, 1].contains(&revoked) {
        return Err(invalid_data(
            "peer certificate revocation state is malformed",
        ));
    }
    if revoked == 1 {
        return Err(conflict("certificate is permanently revoked"));
    }
    let peer = find_summary(transaction, &node_id)?
        .ok_or_else(|| invalid_data("registered certificate has no peer"))?;
    let revision = revision_as_sql(next_revision(&peer, expected_revision)?)?;
    transaction
        .execute(
            "UPDATE peer_certificates SET revoked = 1 WHERE der = ?1",
            [der],
        )
        .and_then(|_| {
            transaction.execute(
                "UPDATE peers SET authorization_revision = ?1 WHERE node_id = ?2",
                params![revision, node_id],
            )
        })
        .map_err(|error| sqlite_error("cannot persist certificate revocation", error))?;
    audit(transaction, "revoke", &node_id, revision)?;
    changed_peer(transaction, &node_id)
}

/// Reads a bounded, deterministic peer list from one read-only snapshot.
///
/// Schema v1 requires explicit migration; unreadable or malformed storage is an
/// error, never an empty list. Performs blocking SQLite work and bounded waits.
pub(in crate::manage) fn list_peers(directory: &Path) -> io::Result<Vec<PeerSummary>> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin peer inspection", error))?;
    require_peers(&transaction)?;
    let peers = {
        let mut statement = transaction
            .prepare(
                "SELECT p.node_id, p.name, p.active, p.authorization_revision,
                        count(c.node_id) AS certificate_count
                 FROM peers p LEFT JOIN peer_certificates c ON c.node_id = p.node_id
                 GROUP BY p.node_id ORDER BY p.node_id LIMIT 1025",
            )
            .map_err(|error| sqlite_error("cannot prepare peer inspection", error))?;
        let rows = serde_rusqlite::from_rows::<PeerSummary>(
            statement
                .query([])
                .map_err(|error| sqlite_error("cannot query peer inspection", error))?,
        );
        let mut peers = Vec::new();
        for row in rows {
            let peer = row.map_err(|error| sqlite_error("cannot read peer inspection", error))?;
            validate_summary(&peer)?;
            if peers.len() >= MAX_PEERS as usize {
                return Err(invalid_data("peer registry exceeds its capacity"));
            }
            peers.push(peer);
        }
        peers
    };
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot complete peer inspection", error))?;
    Ok(peers)
}

/// Looks up current local permission for TLS-verified DER on every request.
///
/// Unknown, inactive or revoked identities return `None`. Schema, I/O, busy or
/// corrupt-state failures remain errors and must fail closed, not be cached as a
/// valid decision. The caller still verifies the returned trusted SAN and compares
/// revisions with its connection context. This is bounded blocking DB work.
pub(in crate::manage) fn authorize_peer(
    directory: &Path,
    der: &[u8],
) -> io::Result<Option<PeerAuthorization>> {
    validate_certificate(der)?;
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin peer authorization", error))?;
    let authorization = authorize_in(&transaction, der)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot complete peer authorization", error))?;
    Ok(authorization)
}

/// Uses the caller's snapshot/write transaction; never opens a second authorization view.
pub(super) fn authorize_in(
    connection: &Connection,
    der: &[u8],
) -> io::Result<Option<PeerAuthorization>> {
    authorize_in_with_overview(connection, der).map(|(_, authorization)| authorization)
}

/// Returns the metadata already validated before reading this exact leaf. Reuse
/// it only in the same transaction, with no intervening writes; it is not a
/// cached authorization for another request or connection.
pub(super) fn authorize_in_with_overview(
    connection: &Connection,
    der: &[u8],
) -> io::Result<(Overview, Option<PeerAuthorization>)> {
    validate_certificate(der)?;
    let overview = require_peers(connection)?;
    let record = connection
        .query_row(
            "SELECT c.node_id, p.name, c.expected_san, p.authorization_revision, p.active, c.revoked
             FROM peer_certificates c LEFT JOIN peers p ON p.node_id = c.node_id WHERE c.der = ?1",
            [der],
            |row| Ok(AuthorizationRow {
                node_id: row.get(0)?,
                name: row.get(1)?,
                expected_san: row.get(2)?,
                revision: row.get(3)?,
                active: row.get(4)?,
                revoked: row.get(5)?,
            }),
        )
        .optional()
        .map_err(|error| sqlite_error("cannot read current peer authorization", error))?;
    let authorization = if let Some(record) = record {
        if !valid_id(&record.node_id)
            || validate_name(&record.name).is_err()
            || validate_san(&record.expected_san).is_err()
            || record.revision < 1
            || ![0, 1].contains(&record.active)
            || ![0, 1].contains(&record.revoked)
        {
            return Err(invalid_data("peer authorization record is malformed"));
        }
        if record.active == 1 && record.revoked == 0 {
            Some(PeerAuthorization {
                node_id: record.node_id,
                name: record.name,
                expected_san: record.expected_san,
                authorization_revision: u64::try_from(record.revision)
                    .map_err(|_| invalid_data("peer authorization revision is malformed"))?,
            })
        } else {
            None
        }
    } else {
        None
    };
    Ok((overview, authorization))
}

/// Opens only validated existing storage; durability is connection-local in SQLite.
pub(super) fn open_existing(directory: &Path, writable: bool) -> io::Result<Connection> {
    if writable {
        super::reject_snapshot_directory(directory)?;
    }
    validate_directory(directory)?;
    let path = directory.join(DATABASE_NAME);
    validate_database(&path)?;
    let connection = open(
        &path,
        if writable {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        },
    )?;
    configure(&connection)?;
    if writable {
        super::recovery::require_writable(&connection)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|error| sqlite_error("cannot configure peer database durability", error))?;
    } else {
        connection
            .pragma_update(None, "query_only", true)
            .map_err(|error| {
                sqlite_error("cannot configure read-only peer database access", error)
            })?;
    }
    Ok(connection)
}

/// Keeps v1 usable for administrators without silently enabling node operations.
fn require_peers(connection: &Connection) -> io::Result<Overview> {
    let overview = read_overview(connection)?;
    if overview.schema_version < 2 {
        return Err(invalid_data(
            "peer operations require explicit management schema migration",
        ));
    }
    Ok(overview)
}

/// Reads one peer with its full certificate count, including revoked DER.
fn find_summary(connection: &Connection, node_id: &str) -> io::Result<Option<PeerSummary>> {
    let mut statement = connection
        .prepare(
            "SELECT p.node_id, p.name, p.active, p.authorization_revision,
                    count(c.node_id) AS certificate_count
             FROM peers p LEFT JOIN peer_certificates c ON c.node_id = p.node_id
             WHERE p.node_id = ?1 GROUP BY p.node_id",
        )
        .map_err(|error| sqlite_error("cannot prepare peer registration", error))?;
    let peer = serde_rusqlite::from_rows::<PeerSummary>(
        statement
            .query([node_id])
            .map_err(|error| sqlite_error("cannot query peer registration", error))?,
    )
    .next()
    .transpose()
    .map_err(|error| sqlite_error("cannot read peer registration", error))?;
    if let Some(peer) = &peer {
        validate_summary(peer)?;
    }
    Ok(peer)
}

/// Rejects broken durable values rather than promoting them to a valid identity.
fn validate_summary(peer: &PeerSummary) -> io::Result<()> {
    if !valid_id(&peer.node_id)
        || validate_name(&peer.name).is_err()
        || peer.authorization_revision == 0
        || peer.authorization_revision > i64::MAX as u64
        || peer.certificate_count > MAX_CERTIFICATES
    {
        return Err(invalid_data("peer registration is malformed"));
    }
    Ok(())
}

/// Performs a signed-range CAS before incrementing, avoiding revision wraparound.
fn next_revision(peer: &PeerSummary, expected: u64) -> io::Result<u64> {
    revision_as_sql(expected)?;
    if expected != peer.authorization_revision {
        return Err(conflict("peer authorization revision changed"));
    }
    expected
        .checked_add(1)
        .filter(|revision| *revision <= i64::MAX as u64)
        .ok_or_else(|| invalid_data("peer authorization revision is exhausted"))
}

/// Rejects zero/out-of-range caller revisions before SQLite's signed conversion.
fn revision_as_sql(revision: u64) -> io::Result<i64> {
    if revision == 0 {
        return Err(invalid_input("peer revision must be positive"));
    }
    i64::try_from(revision).map_err(|_| invalid_input("peer revision exceeds SQLite integer range"))
}

/// Checks capacity while the immediate transaction excludes competing writers.
fn check_capacity(connection: &Connection, query: &str, maximum: u32) -> io::Result<()> {
    let count: u32 = connection
        .query_row(query, [], |row| row.get(0))
        .map_err(|error| sqlite_error("cannot check peer registry capacity", error))?;
    if count >= maximum {
        return Err(io::Error::other("peer registry capacity is exhausted"));
    }
    Ok(())
}

/// Keeps fixed, non-secret audit metadata bounded without deleting certificate tombstones.
fn audit(connection: &Connection, action: &str, node_id: &str, revision: i64) -> io::Result<()> {
    connection.execute(
        "INSERT INTO peer_audit (entry, action, node_id, authorization_revision) VALUES ('offline', ?1, ?2, ?3)",
        params![action, node_id, revision],
    ).and_then(|_| connection.execute(
        "DELETE FROM peer_audit WHERE sequence IN
         (SELECT sequence FROM peer_audit ORDER BY sequence DESC LIMIT -1 OFFSET ?1)",
        [MAX_AUDIT_RECORDS],
    )).map_err(|error| sqlite_error("cannot record peer authorization audit", error))?;
    Ok(())
}

/// Read back staged metadata; only the enclosing confirmed writer may publish it.
fn changed_peer(transaction: &Connection, node_id: &str) -> io::Result<PeerSummary> {
    find_summary(transaction, node_id)?
        .ok_or_else(|| invalid_data("peer mutation lost its registration"))
}

fn require_transaction(transaction: &Connection) -> io::Result<()> {
    if transaction.is_autocommit() {
        return Err(invalid_input("peer mutation requires a held transaction"));
    }
    Ok(())
}

/// Requires the existing canonical identity encoding, not a display name or DNS label.
fn validate_id(node_id: &str) -> io::Result<()> {
    if !valid_id(node_id) {
        return Err(invalid_input(
            "peer ID must be a canonical 128-bit identifier",
        ));
    }
    Ok(())
}

/// Bounds human-readable names by UTF-8 bytes and keeps CLI/audit output single-line.
fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 128
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        return Err(invalid_input(
            "peer name must be trimmed non-control text of at most 128 bytes",
        ));
    }
    Ok(())
}

/// Bounds public bytes before binding; TLS owns certificate parsing and trust checks.
fn validate_certificate(der: &[u8]) -> io::Result<()> {
    if der.is_empty() || der.len() > MAX_CERTIFICATE_BYTES {
        return Err(invalid_input(
            "peer certificate must contain 1 to 16384 DER bytes",
        ));
    }
    Ok(())
}

/// Bounds a trusted ASCII reference; TLS still validates DNS/IP syntax and matching.
fn validate_san(san: &str) -> io::Result<()> {
    if san.is_empty()
        || san.len() > 253
        || !san.is_ascii()
        || san
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(invalid_input(
            "peer reference name must be 1 to 253 non-control ASCII bytes",
        ));
    }
    Ok(())
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn conflict(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, message)
}
fn not_found(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, message)
}

/// Claims only a new private backup leaf, then copies the committed old schema.
///
/// Migration and recovery call this before their first SQL mutation, with author
/// and update guards plus an IMMEDIATE transaction retained. Backup reads through
/// a distinct connection: SQLite cannot back up the active write connection.
/// Windows claims the database with a protected DACL while allowing that second
/// SQLite writer, but not replacement of the file. The caller still owns the
/// trust/privacy of an existing parent and any SQLite sidecars created there.
pub(super) fn backup_existing(
    directory: &Path,
    backup_path: &Path,
    before: &Overview,
) -> io::Result<()> {
    let parent = backup_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| invalid_input("backup requires an explicit private parent directory"))?;
    validate_directory(parent)?;
    let filename = backup_path
        .file_name()
        .ok_or_else(|| invalid_input("backup requires a filename"))?;
    if fs::canonicalize(parent)? == fs::canonicalize(directory)?
        && [
            DATABASE_NAME.to_owned(),
            format!("{DATABASE_NAME}-wal"),
            format!("{DATABASE_NAME}-shm"),
            format!("{DATABASE_NAME}-journal"),
        ]
        .iter()
        .any(|reserved| {
            if cfg!(windows) {
                filename
                    .to_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case(reserved))
            } else {
                filename == OsStr::new(reserved)
            }
        })
    {
        return Err(invalid_input(
            "backup cannot use a management database or sidecar path",
        ));
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = backup_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match fs::symlink_metadata(PathBuf::from(sidecar)) {
            Ok(_) => {
                return Err(conflict(
                    "backup sidecars already exist; operator recovery is required",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    #[cfg(windows)]
    let file = crate::windows_files::create_database(backup_path)?;
    #[cfg(not(windows))]
    let file = {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        options.open(backup_path)?
    };
    let source = open_existing(directory, false)?;
    let mut destination = open(backup_path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    configure(&destination)?;
    destination
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|error| sqlite_error("cannot configure management backup durability", error))?;
    {
        let backup = Backup::new(&source, &mut destination)
            .map_err(|error| sqlite_error("cannot begin management backup", error))?;
        let started = Instant::now();
        loop {
            match backup
                .step(128)
                .map_err(|error| sqlite_error("cannot copy management backup", error))?
            {
                StepResult::Done => break,
                StepResult::More if started.elapsed() < BACKUP_TIMEOUT => {}
                StepResult::Busy | StepResult::Locked => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "management backup is busy",
                    ));
                }
                StepResult::More => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "management backup exceeded its deadline",
                    ));
                }
                _ => {
                    return Err(io::Error::other(
                        "management backup returned an unsupported state",
                    ));
                }
            }
        }
    }
    // A backup must be independently restorable; do not leave its contents in a
    // destination WAL that an operator might overlook when copying the file.
    let journal: String = destination
        .pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))
        .map_err(|error| sqlite_error("cannot finalize standalone management backup", error))?;
    if !journal.eq_ignore_ascii_case("delete") {
        return Err(invalid_data("management backup is not standalone"));
    }
    let integrity: String = destination
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|error| sqlite_error("cannot verify management backup integrity", error))?;
    let copied = read_overview(&destination)?;
    if integrity != "ok"
        || copied.schema_version != before.schema_version
        || copied.node_id != before.node_id
        || copied.name != before.name
        || copied.administrator_count != before.administrator_count
    {
        return Err(invalid_data("management backup does not match the source"));
    }
    destination
        .close()
        .map_err(|(_, error)| sqlite_error("cannot close management backup", error))?;
    file.sync_all()?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
