//! Recoverable proxy secrets, independent of the authentication Reader.
//!
//! Only ciphertext is stored in SQLite. The private key is a separate regular
//! file and is never regenerated while encrypted rows exist. A database-only
//! backup intentionally cannot disclose passwords; recovering them also needs
//! the separately protected key. Administrator passwords are not handled here.

use std::{io, path::Path};

use aws_lc_rs::aead::{AES_256_GCM, Aad, Nonce, RandomizedNonceKey};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::{admission, control, invalid_data, peers::open_existing, sqlite_error, valid_id};
use crate::{access, manage::files};

const KEY_NAME: &str = "proxy-secrets.key";
const KEY_DIRECTORY: &str = "secrets";
const KEY_BYTES: usize = 32;
const SECRET_BYTES: usize = 43;
const CIPHERTEXT_BYTES: usize = SECRET_BYTES + 16;
const DOMAIN: &[u8] = b"vproxy.proxy-secret.v1\0";

/// Stable public classes. Filesystem paths, keys and AEAD errors stay private.
#[derive(Debug, thiserror::Error)]
pub(in crate::manage) enum Error {
    #[error("proxy secret requires explicit schema migration")]
    UpgradeRequired,
    #[error("this credential has no recoverable secret")]
    NotSaved,
    #[error("proxy secret no longer matches the selected credential")]
    Changed,
    #[error("proxy secret key is unavailable")]
    KeyUnavailable,
    #[error("stored proxy secret failed authentication")]
    Invalid,
}

impl Error {
    fn io(self) -> io::Error {
        let kind = match self {
            Self::UpgradeRequired => io::ErrorKind::InvalidInput,
            Self::NotSaved => io::ErrorKind::NotFound,
            Self::Changed => io::ErrorKind::AlreadyExists,
            // These are definitive pre-commit failures when sealing. Keep
            // existing verifier policy live; no uncertain SQL commit occurred.
            Self::KeyUnavailable => io::ErrorKind::PermissionDenied,
            Self::Invalid => io::ErrorKind::InvalidInput,
        };
        io::Error::new(kind, self)
    }
}

/// Returned only by an explicit, authorized read of the current generation.
/// Deliberately has no Debug or Serialize implementation.
pub(in crate::manage) struct Secret {
    pub(in crate::manage) credential_id: String,
    pub(in crate::manage) user_id: String,
    pub(in crate::manage) verifier_revision: u64,
    pub(in crate::manage) value: Zeroizing<String>,
}

/// Fixed-width authenticated envelope. Its nonce/key identifier are public;
/// plaintext exists only in the separate zeroizing decryption buffer.
struct Envelope {
    generation: u64,
    key_id: [u8; 32],
    nonce: [u8; 12],
    ciphertext: [u8; CIPHERTEXT_BYTES],
}

pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection.execute_batch(
        "CREATE TABLE proxy_credential_secrets(
           credential_id TEXT PRIMARY KEY NOT NULL REFERENCES proxy_credentials(id) ON DELETE RESTRICT,
           verifier_revision INTEGER NOT NULL CHECK(verifier_revision>=1),
           key_id BLOB NOT NULL CHECK(length(key_id)=32),
           nonce BLOB NOT NULL CHECK(length(nonce)=12),
           ciphertext BLOB NOT NULL CHECK(length(ciphertext)=59)
         ) STRICT;",
    ).map_err(|e| sqlite_error("cannot create recoverable proxy secret storage", e))
}

/// Check the namespace cheaply during ordinary overview reads. Envelope and
/// relationship validation is bounded and performed during backup verification.
pub(super) fn validate_schema(connection: &Connection, version: u32) -> io::Result<()> {
    let kind: Option<String> = connection
        .query_row(
            "SELECT type FROM sqlite_schema WHERE name='proxy_credential_secrets'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| sqlite_error("cannot inspect proxy secret namespace", e))?;
    if if version >= 28 {
        kind.as_deref() != Some("table")
    } else {
        kind.is_some()
    } {
        return Err(corrupt());
    }
    Ok(())
}

fn require_current(connection: &Connection) -> io::Result<()> {
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| sqlite_error("cannot inspect proxy secret storage version", e))?;
    if version < 28 {
        return Err(Error::UpgradeRequired.io());
    }
    Ok(())
}

fn directory(connection: &Connection) -> io::Result<&Path> {
    // Every production caller obtained this connection from open_existing or
    // the validated Source transaction. Never use a user-supplied key path.
    let database = Path::new(connection.path().ok_or_else(corrupt)?);
    if database.file_name() != Some(super::DATABASE_NAME.as_ref()) {
        return Err(corrupt());
    }
    database.parent().ok_or_else(corrupt)
}

fn key(connection: &Connection, create: bool) -> io::Result<(RandomizedNonceKey, [u8; 32])> {
    // Older Windows data directories may inherit read access. Create a new
    // private child rather than changing an operator's existing directory ACL.
    let directory = directory(connection)?.join(KEY_DIRECTORY);
    if let Err(error) = files::check_directory(&directory, true) {
        if !create || error.kind() != io::ErrorKind::NotFound || has_encrypted(connection)? {
            return Err(Error::KeyUnavailable.io());
        }
        files::create_directory(&directory).map_err(|_| Error::KeyUnavailable.io())?;
    }
    let path = directory.join(KEY_NAME);
    let bytes = match files::read(&path, KEY_BYTES, true) {
        Ok(bytes) => bytes,
        Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
            if has_encrypted(connection)? {
                return Err(Error::KeyUnavailable.io());
            }
            let mut bytes = Zeroizing::new(vec![0; KEY_BYTES]);
            getrandom::fill(&mut bytes).map_err(|_| Error::KeyUnavailable.io())?;
            // The caller owns the write transaction/update gate. A failed SQL
            // commit may leave an unused key, which the next attempt reuses.
            files::write(&directory, KEY_NAME, &bytes).map_err(|_| Error::KeyUnavailable.io())?;
            bytes
        }
        Err(_) => return Err(Error::KeyUnavailable.io()),
    };
    if bytes.len() != KEY_BYTES {
        return Err(Error::KeyUnavailable.io());
    }
    let mut digest = Sha256::new();
    digest.update(b"vproxy.proxy-secret-key.v1\0");
    digest.update(&*bytes);
    let id: [u8; 32] = digest.finalize().into();
    if create {
        let mismatched: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM proxy_credential_secrets WHERE key_id!=?1)",
                [id.as_slice()],
                |r| r.get(0),
            )
            .map_err(|e| sqlite_error("cannot verify proxy secret key identity", e))?;
        if mismatched {
            return Err(Error::KeyUnavailable.io());
        }
    }
    let key =
        RandomizedNonceKey::new(&AES_256_GCM, &bytes).map_err(|_| Error::KeyUnavailable.io())?;
    Ok((key, id))
}

fn has_encrypted(connection: &Connection) -> io::Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM proxy_credential_secrets)",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot inspect existing encrypted proxy secrets", e))
}

fn aad(node: &str, credential: &access::CredentialRecord) -> io::Result<Vec<u8>> {
    if !valid_id(node)
        || !valid_id(&credential.id)
        || !valid_id(&credential.user_id)
        || credential.verifier_revision == 0
        || credential.verifier_revision > i64::MAX as u64
    {
        return Err(corrupt());
    }
    let mut aad = Vec::with_capacity(DOMAIN.len() + 66 + 8);
    aad.extend_from_slice(DOMAIN);
    aad.extend_from_slice(node.as_bytes());
    aad.extend_from_slice(credential.user_id.as_bytes());
    aad.extend_from_slice(credential.id.as_bytes());
    aad.extend_from_slice(&credential.verifier_revision.to_be_bytes());
    Ok(aad)
}

/// Seal the generated value in the same SQL transaction as its verifier. No
/// caller can commit a new generation without the matching recoverable value.
/// Old schemas retain their explicit one-time behavior until migrated.
pub(super) fn save(
    connection: &Connection,
    node: &str,
    credential: &access::CredentialRecord,
    secret: &str,
) -> io::Result<()> {
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| sqlite_error("cannot inspect proxy secret storage version", e))?;
    if version < 28 {
        return Ok(());
    }
    if secret.len() != SECRET_BYTES {
        return Err(corrupt());
    }
    let (key, id) = key(connection, true)?;
    let aad = aad(node, credential)?;
    let mut ciphertext = Zeroizing::new(secret.as_bytes().to_vec());
    // AWS-LC generates the nonce, including across process restarts. No local
    // timestamp/counter or hand-rolled nonce sequence can accidentally reset.
    let nonce = key
        .seal_in_place_append_tag(Aad::from(aad), &mut *ciphertext)
        .map_err(|_| Error::Invalid.io())?;
    connection
        .execute(
            "INSERT INTO proxy_credential_secrets VALUES(?1,?2,?3,?4,?5)
         ON CONFLICT(credential_id) DO UPDATE SET verifier_revision=excluded.verifier_revision,
         key_id=excluded.key_id,nonce=excluded.nonce,ciphertext=excluded.ciphertext",
            params![
                credential.id,
                i64::try_from(credential.verifier_revision).map_err(|_| corrupt())?,
                id.as_slice(),
                nonce.as_ref(),
                ciphertext.as_slice()
            ],
        )
        .map_err(|e| sqlite_error("cannot persist encrypted proxy secret", e))?;
    Ok(())
}

/// Read exactly the selected current generation under the shared update gate.
/// The authenticated local administrator, node and owner epoch are rechecked
/// in the same transaction. Revoked/deleted identities cannot disclose secrets;
/// disabling admission alone does not erase an administrator's stored password.
/// Missing keys or failed AEAD authentication never regenerate or rotate data.
pub(in crate::manage) fn reveal(
    directory: &Path,
    administrator: &str,
    assertion: &admission::Assertion,
    id: &str,
    expected_generation: u64,
) -> io::Result<Secret> {
    if !valid_id(administrator) {
        return Err(corrupt());
    }
    reveal_as(directory, id, None, expected_generation, |transaction| {
        control::check_administrator(transaction, administrator)?;
        control::require_local(transaction)?;
        admission::assert_local_in(transaction, assertion)
    })
}

/// Read only the current owner's selected user/credential generation. Exact
/// DER, peer revision, ownership and epoch are rechecked in the same snapshot
/// as decryption; a controller's administrator ID is never a local actor.
pub(in crate::manage) fn reveal_remote(
    directory: &Path,
    authorization: &control::RemoteAuthorization,
    assertion: &admission::Assertion,
    user: &str,
    id: &str,
    expected_generation: u64,
) -> io::Result<Secret> {
    if !valid_id(user) || !valid_id(&assertion.node_id) {
        return Err(corrupt());
    }
    reveal_as(
        directory,
        id,
        Some(user),
        expected_generation,
        |transaction| {
            let owner = control::authorize_in(transaction, authorization)?;
            if super::read_overview(transaction)?.node_id != assertion.node_id {
                return Err(control::ControlError::TargetMismatch.error());
            }
            if owner.epoch != assertion.epoch {
                return Err(control::ControlError::EpochConflict.error());
            }
            Ok(())
        },
    )
}

/// Keep the private key read and AEAD work behind the existing update gate.
/// Both callers supply their real authorization before any plaintext exists.
fn reveal_as(
    directory: &Path,
    id: &str,
    user: Option<&str>,
    expected_generation: u64,
    authorize: impl FnOnce(&Connection) -> io::Result<()>,
) -> io::Result<Secret> {
    if !valid_id(id) || expected_generation == 0 || expected_generation > i64::MAX as u64 {
        return Err(corrupt());
    }
    let _gate = super::update_lock(directory)?;
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|e| sqlite_error("cannot begin proxy secret inspection", e))?;
    require_current(&transaction)?;
    let overview = super::read_overview(&transaction)?;
    authorize(&transaction)?;
    let policy = super::users::read_policy(&transaction)?;
    let credential = policy
        .credentials
        .iter()
        .find(|item| item.id == id && !item.revoked && user.is_none_or(|user| item.user_id == user))
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    if !policy
        .users
        .iter()
        .any(|user| user.id == credential.user_id && !user.deleted)
    {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    if credential.verifier_revision != expected_generation {
        return Err(Error::Changed.io());
    }
    let envelope: Option<Envelope> = transaction.query_row(
        "SELECT verifier_revision,key_id,nonce,ciphertext FROM proxy_credential_secrets WHERE credential_id=?1",
        [id], |r| Ok(Envelope {
            generation: super::users::read_revision(r, 0)?,
            key_id: blob(r, 1)?, nonce: blob(r, 2)?, ciphertext: blob(r, 3)?,
        }),
    ).optional().map_err(|e| sqlite_error("cannot read encrypted proxy secret", e))?;
    let envelope = envelope.ok_or_else(|| Error::NotSaved.io())?;
    if envelope.generation != expected_generation {
        return Err(corrupt());
    }
    let (key, current_id) = key(&transaction, false)?;
    if envelope.key_id != current_id {
        return Err(Error::KeyUnavailable.io());
    }
    let nonce = Nonce::assume_unique_for_key(envelope.nonce);
    let mut bytes = Zeroizing::new(envelope.ciphertext.to_vec());
    let plain = key
        .open_in_place(
            nonce,
            Aad::from(aad(&overview.node_id, credential)?),
            &mut bytes,
        )
        .map_err(|_| Error::Invalid.io())?;
    if plain.len() != SECRET_BYTES
        || !bool::from(access::digest_secret(id, plain).ct_eq(&credential.secret_digest))
    {
        return Err(Error::Invalid.io());
    }
    let value = Zeroizing::new(
        std::str::from_utf8(plain)
            .map_err(|_| corrupt())?
            .to_owned(),
    );
    let result = Secret {
        credential_id: id.to_owned(),
        user_id: credential.user_id.clone(),
        verifier_revision: envelope.generation,
        value,
    };
    transaction
        .commit()
        .map_err(|e| sqlite_error("cannot complete proxy secret inspection", e))?;
    Ok(result)
}

/// A backup checks envelopes without needing the separately protected key.
/// Verification is structural, not a claim that passwords are decryptable.
pub(super) fn validate_snapshot(connection: &Connection) -> io::Result<()> {
    let invalid: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM proxy_credential_secrets s LEFT JOIN proxy_credentials c
         ON c.id=s.credential_id WHERE c.id IS NULL OR s.verifier_revision!=c.verifier_revision
         OR typeof(s.key_id)!='blob' OR length(s.key_id)!=32 OR typeof(s.nonce)!='blob'
         OR length(s.nonce)!=12 OR typeof(s.ciphertext)!='blob' OR length(s.ciphertext)!=59)",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot validate encrypted proxy secret envelopes", e))?;
    if invalid {
        return Err(corrupt());
    }
    let keys: i64 = connection
        .query_row(
            "SELECT count(DISTINCT key_id) FROM proxy_credential_secrets",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot validate proxy secret key namespace", e))?;
    if keys > 1 {
        return Err(corrupt());
    }
    Ok(())
}

/// Project current fixtures to their historical one-way representation. Keep
/// every credential/verifier/tombstone; only validated recoverable copies are
/// discarded. This is test-only and never a migration or key-repair operation.
#[cfg(test)]
pub(in crate::manage) fn project_legacy_for_test(connection: &Connection) -> io::Result<()> {
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='proxy_credential_secrets')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot inspect legacy secret fixture", e))?;
    if exists {
        validate_snapshot(connection)?;
        connection
            .execute_batch("DROP TABLE proxy_credential_secrets;")
            .map_err(|e| sqlite_error("cannot project one-way credential fixture", e))?;
    }
    Ok(())
}

/// A newly migrated historical fixture must have no invented encrypted value.
/// Absence is valid for the old side of the comparison; populated rows refuse.
#[cfg(test)]
pub(in crate::manage) fn require_unused_for_test(connection: &Connection) -> io::Result<()> {
    let present: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='proxy_credential_secrets')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot inspect unused secret fixture", e))?;
    if present && has_encrypted(connection)? {
        return Err(corrupt());
    }
    Ok(())
}

fn corrupt() -> io::Error {
    invalid_data("recoverable proxy secret storage is malformed")
}

fn blob<const N: usize>(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<[u8; N]> {
    match row.get_ref(index)? {
        rusqlite::types::ValueRef::Blob(bytes) => {
            bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
        }
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ChangeResult, PolicyChange};
    use super::*;

    const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$Zml4dHVyZQ";

    struct Fixture {
        directory: std::path::PathBuf,
        administrator: String,
        assertion: admission::Assertion,
        user: String,
        credential: String,
        secret: Zeroizing<String>,
    }

    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory =
                std::env::temp_dir().join(format!("vproxy-secret-{}", super::super::random_id()?));
            let overview = super::super::initialize(&directory, "secret test", "admin", PHC)?;
            let connection = open_existing(&directory, false)?;
            let administrator: String = connection
                .query_row("SELECT id FROM administrators", [], |r| r.get(0))
                .map_err(|e| sqlite_error("cannot inspect test administrator", e))?;
            let apply = |expected, change| {
                super::super::apply_policy(
                    &directory,
                    &administrator,
                    expected,
                    change,
                    &super::super::update_lock(&directory)?,
                )
            };
            let user = apply(
                1,
                PolicyChange::CreateUser {
                    name: "proxy user".into(),
                    protocols: vec![access::Protocol::Http],
                    concurrent_limit: 2,
                },
            )?
            .user
            .ok_or_else(corrupt)?
            .id;
            let created = apply(
                2,
                PolicyChange::CreateCredential {
                    user_id: user.clone(),
                },
            )?;
            Ok(Self {
                directory,
                administrator,
                assertion: admission::Assertion {
                    node_id: overview.node_id,
                    epoch: 1,
                },
                user,
                credential: created.credential.ok_or_else(corrupt)?.id,
                secret: created.secret.ok_or_else(corrupt)?,
            })
        }
        fn read(&self, generation: u64) -> io::Result<Secret> {
            reveal(
                &self.directory,
                &self.administrator,
                &self.assertion,
                &self.credential,
                generation,
            )
        }
        fn apply(&self, expected: u64, change: PolicyChange) -> io::Result<ChangeResult> {
            super::super::apply_policy(
                &self.directory,
                &self.administrator,
                expected,
                change,
                &super::super::update_lock(&self.directory)?,
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn remote_secret_requires_the_current_owner_and_exact_user_epoch_and_generation()
    -> io::Result<()> {
        use super::super::{register_peer, revoke_certificate, set_owner, update_lock};
        let mut fixture = Fixture::new()?;
        let peer = super::super::random_id()?;
        let certificate = rcgen::generate_simple_self_signed(vec!["controller.example".into()])
            .map_err(io::Error::other)?;
        let leaf: std::sync::Arc<[u8]> = certificate.cert.der().to_vec().into();
        register_peer(
            &fixture.directory,
            &peer,
            "controller",
            &leaf,
            "controller.example",
            None,
        )?;
        let authorization = control::RemoteAuthorization {
            node_id: peer.clone(),
            authorization_revision: 1,
            leaf: leaf.clone(),
        };
        let read = |authorization: &control::RemoteAuthorization,
                    assertion: &admission::Assertion,
                    user: &str,
                    generation| {
            reveal_remote(
                &fixture.directory,
                authorization,
                assertion,
                user,
                &fixture.credential,
                generation,
            )
        };
        assert_eq!(
            read(&authorization, &fixture.assertion, &fixture.user, 1)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        set_owner(
            &fixture.directory,
            &update_lock(&fixture.directory)?,
            &fixture.administrator,
            1,
            Some(&peer),
        )?;
        fixture.assertion.epoch = 2;
        assert_eq!(
            read(&authorization, &fixture.assertion, &fixture.user, 1)?
                .value
                .as_str(),
            fixture.secret.as_str()
        );
        assert!(fixture.read(1).is_err()); // A local session cannot impersonate the remote owner.
        let wrong_user = super::super::random_id()?;
        assert_eq!(
            read(&authorization, &fixture.assertion, &wrong_user, 1)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert!(read(&authorization, &fixture.assertion, &fixture.user, 2).is_err());
        for assertion in [
            admission::Assertion {
                node_id: fixture.assertion.node_id.clone(),
                epoch: 1,
            },
            admission::Assertion {
                node_id: wrong_user.clone(),
                epoch: 2,
            },
        ] {
            assert!(read(&authorization, &assertion, &fixture.user, 1).is_err());
        }
        for changed in [
            control::RemoteAuthorization {
                node_id: peer.clone(),
                authorization_revision: 2,
                leaf: leaf.clone(),
            },
            control::RemoteAuthorization {
                node_id: wrong_user,
                authorization_revision: 1,
                leaf: leaf.clone(),
            },
            control::RemoteAuthorization {
                node_id: peer.clone(),
                authorization_revision: 1,
                leaf: std::sync::Arc::from(&b"wrong DER"[..]),
            },
        ] {
            assert!(read(&changed, &fixture.assertion, &fixture.user, 1).is_err());
        }
        // Authorization is evaluated before key access, not merely before serializing
        // an already decrypted value. Missing key must not mask the stale peer.
        let key = fixture.directory.join(KEY_DIRECTORY).join(KEY_NAME);
        let retained = fixture.directory.join("retained-test-key");
        std::fs::rename(&key, &retained)?;
        revoke_certificate(&fixture.directory, &leaf, 1)?;
        assert_eq!(
            read(&authorization, &fixture.assertion, &fixture.user, 1)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::rename(retained, key)?;
        let owner = super::super::ownership(&fixture.directory)?;
        assert_eq!((owner.epoch, owner.last_terminal_command), (2, 0));
        assert_eq!(super::super::load_policy(&fixture.directory)?.revision, 3);
        let connection = open_existing(&fixture.directory, false)?;
        let receipts: i64 = connection
            .query_row("SELECT count(*) FROM control_receipts", [], |row| {
                row.get(0)
            })
            .map_err(io::Error::other)?;
        assert_eq!(receipts, 0);
        Ok(())
    }

    #[test]
    fn current_secret_survives_reopen_and_rotation_but_not_revocation() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let revealed = fixture.read(1)?;
        assert_eq!(revealed.value.as_str(), fixture.secret.as_str());
        assert_eq!(revealed.user_id, fixture.user);
        assert_eq!(revealed.credential_id, fixture.credential);
        let connection = open_existing(&fixture.directory, false)?;
        validate_snapshot(&connection)?;
        let ciphertext: Vec<u8> = connection
            .query_row("SELECT ciphertext FROM proxy_credential_secrets", [], |r| {
                r.get(0)
            })
            .map_err(|e| sqlite_error("cannot inspect test ciphertext", e))?;
        assert_eq!(ciphertext.len(), CIPHERTEXT_BYTES);
        assert!(
            !ciphertext
                .windows(SECRET_BYTES)
                .any(|part| part == fixture.secret.as_bytes())
        );
        assert_eq!(
            files::read(
                &fixture.directory.join(KEY_DIRECTORY).join(KEY_NAME),
                KEY_BYTES,
                true
            )?
            .len(),
            KEY_BYTES
        );
        drop(connection);
        fixture.apply(
            3,
            PolicyChange::SetCredentialActive {
                id: fixture.credential.clone(),
                active: false,
            },
        )?;
        assert_eq!(fixture.read(1)?.value.as_str(), fixture.secret.as_str());
        let rotated = fixture.apply(
            4,
            PolicyChange::RotateCredential {
                id: fixture.credential.clone(),
            },
        )?;
        assert!(matches!(
            fixture
                .read(1)
                .err()
                .and_then(|e| e.into_inner())
                .and_then(|e| e.downcast::<Error>().ok())
                .as_deref(),
            Some(Error::Changed)
        ));
        assert_eq!(
            fixture.read(2)?.value.as_str(),
            rotated.secret.ok_or_else(corrupt)?.as_str()
        );
        fixture.apply(
            5,
            PolicyChange::RevokeCredential {
                id: fixture.credential.clone(),
            },
        )?;
        assert_eq!(
            fixture.read(2).err().map(|e| e.kind()),
            Some(io::ErrorKind::NotFound)
        );
        Ok(())
    }

    #[test]
    fn missing_key_never_regenerates_or_commits_a_replacement_generation() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let path = fixture.directory.join(KEY_DIRECTORY).join(KEY_NAME);
        let original_key = files::read(&path, KEY_BYTES, true)?;
        let saved = fixture.directory.join("test-key-retained");
        std::fs::rename(&path, &saved)?;
        assert!(fixture.read(1).is_err());
        assert!(
            fixture
                .apply(
                    3,
                    PolicyChange::RotateCredential {
                        id: fixture.credential.clone()
                    }
                )
                .is_err()
        );
        assert!(!path.exists());
        assert_eq!(super::super::load_policy(&fixture.directory)?.revision, 3);
        std::fs::rename(saved, &path)?;
        let mut replacement = Zeroizing::new(original_key.to_vec());
        replacement[0] ^= 1;
        std::fs::write(&path, &*replacement)?;
        assert!(fixture.read(1).is_err());
        assert!(
            fixture
                .apply(
                    3,
                    PolicyChange::RotateCredential {
                        id: fixture.credential.clone()
                    }
                )
                .is_err()
        );
        assert_eq!(super::super::load_policy(&fixture.directory)?.revision, 3);
        std::fs::write(&path, &*original_key)?;
        assert_eq!(fixture.read(1)?.value.as_str(), fixture.secret.as_str());
        Ok(())
    }

    #[test]
    fn ciphertext_tampering_and_cross_identity_substitution_fail_closed() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let connection = open_existing(&fixture.directory, true)?;
        let original: Vec<u8> = connection
            .query_row("SELECT ciphertext FROM proxy_credential_secrets", [], |r| {
                r.get(0)
            })
            .map_err(|e| sqlite_error("cannot inspect original test envelope", e))?;
        let mut changed = original.clone();
        changed[0] ^= 1;
        connection
            .execute(
                "UPDATE proxy_credential_secrets SET ciphertext=?1",
                [changed],
            )
            .map_err(|e| sqlite_error("cannot tamper test envelope", e))?;
        assert!(fixture.read(1).is_err());
        connection
            .execute(
                "UPDATE proxy_credential_secrets SET ciphertext=?1",
                [original],
            )
            .map_err(|e| sqlite_error("cannot restore test envelope", e))?;
        let wrong_node = admission::Assertion {
            node_id: super::super::random_id()?,
            epoch: 1,
        };
        assert!(
            reveal(
                &fixture.directory,
                &fixture.administrator,
                &wrong_node,
                &fixture.credential,
                1
            )
            .is_err()
        );
        let wrong_epoch = admission::Assertion {
            node_id: fixture.assertion.node_id.clone(),
            epoch: 2,
        };
        assert!(
            reveal(
                &fixture.directory,
                &fixture.administrator,
                &wrong_epoch,
                &fixture.credential,
                1
            )
            .is_err()
        );
        assert!(
            reveal(
                &fixture.directory,
                &super::super::random_id()?,
                &fixture.assertion,
                &fixture.credential,
                1
            )
            .is_err()
        );
        assert_eq!(fixture.read(1)?.value.as_str(), fixture.secret.as_str());
        let second = fixture
            .apply(
                3,
                PolicyChange::CreateCredential {
                    user_id: fixture.user.clone(),
                },
            )?
            .credential
            .ok_or_else(corrupt)?;
        connection.execute(
        "UPDATE proxy_credential_secrets SET (key_id,nonce,ciphertext)=(SELECT key_id,nonce,ciphertext
         FROM proxy_credential_secrets WHERE credential_id=?1) WHERE credential_id=?2",
        params![fixture.credential, second.id],
    ).map_err(|e| sqlite_error("cannot substitute test credential envelope", e))?;
        assert!(
            reveal(
                &fixture.directory,
                &fixture.administrator,
                &fixture.assertion,
                &second.id,
                1
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn legacy_credential_requires_explicit_rotation_without_changing_its_password() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        let connection = open_existing(&fixture.directory, true)?;
        connection
            .execute("DELETE FROM proxy_credential_secrets", [])
            .map_err(|e| sqlite_error("cannot project legacy test credential", e))?;
        assert!(matches!(
            fixture
                .read(1)
                .err()
                .and_then(|e| e.into_inner())
                .and_then(|e| e.downcast::<Error>().ok())
                .as_deref(),
            Some(Error::NotSaved)
        ));
        assert_eq!(super::super::load_policy(&fixture.directory)?.revision, 3);
        let result = fixture.apply(
            3,
            PolicyChange::RotateCredential {
                id: fixture.credential.clone(),
            },
        )?;
        assert_eq!(
            fixture.read(2)?.value.as_str(),
            result.secret.ok_or_else(corrupt)?.as_str()
        );
        Ok(())
    }

    #[test]
    fn schema_twenty_seven_migration_preserves_verifiers_without_inventing_old_passwords()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let connection = open_existing(&fixture.directory, true)?;
        super::super::recovery::restore_schema_twenty_seven_for_test(&connection)?;
        drop(connection);
        std::fs::remove_file(fixture.directory.join(KEY_DIRECTORY).join(KEY_NAME))?;
        let before = super::super::load_policy(&fixture.directory)?;
        let backup = fixture.directory.join("private-migration-backup");
        files::create_directory(&backup)?;
        let migrated = super::super::migrate(&fixture.directory, &backup.join("before.sqlite3"))?;
        assert_eq!(migrated.schema_version, 28);
        let after = super::super::load_policy(&fixture.directory)?;
        assert_eq!(
            before.credentials[0].secret_digest,
            after.credentials[0].secret_digest
        );
        assert_eq!(before.revision, after.revision);
        assert!(matches!(
            fixture
                .read(1)
                .err()
                .and_then(|e| e.into_inner())
                .and_then(|e| e.downcast::<Error>().ok())
                .as_deref(),
            Some(Error::NotSaved)
        ));
        let rotated = fixture.apply(
            3,
            PolicyChange::RotateCredential {
                id: fixture.credential.clone(),
            },
        )?;
        assert_eq!(
            fixture.read(2)?.value.as_str(),
            rotated.secret.ok_or_else(corrupt)?.as_str()
        );
        Ok(())
    }
}
