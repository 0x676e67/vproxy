//! Private ACME cache entries, separate from immutable offline setup packages.
//!
//! The existing management directory and all of its ancestors must be trusted.
//! Leaves use the shared no-follow/private-file checks; this is not protection
//! against a hostile process with the same account's filesystem rights. No
//! operation repairs an ACL, changes a mode, removes an old identity first, or
//! recursively cleans up a failed output.

use std::{
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::super::{files, store::Guard};

const MAX_BYTES: usize = 256 * 1024;
const MAX_RETRY_BYTES: usize = 128;
/// httpdate can format only 1970..=9999; persisted and observed hints share
/// that horizon so restart cannot feed an unrepresentable date upstream.
pub(super) const MAX_RETRY_AT: u64 = 253_402_300_799;

/// A distinct versioned envelope must fail closed on future/foreign formats,
/// rather than silently treating an unreadable cooldown as permission to retry.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Retry {
    version: u8,
    not_before_unix_s: u64,
}

/// Synchronous cache I/O must run in bounded blocking work, not a handshake or
/// HTTP future. Every clone retains process authority through actual completion,
/// including when the async waiter is cancelled. The caller serializes logical
/// order/identity updates; individual replacements are atomic, not a multi-file
/// transaction or compare-and-swap protocol.
#[derive(Clone)]
pub(super) struct Cache {
    directory: PathBuf,
    _author: Arc<Guard>,
}

/// Enumeration never picks an arbitrary result when more than one exists.
pub(super) enum OrderTemporary {
    Absent,
    Multiple,
    One {
        name: String,
        bytes: Zeroizing<Vec<u8>>,
    },
}

impl Cache {
    #[cfg(test)]
    pub(super) fn create_snapshot_temporary_for_test(
        &self,
        name: &str,
        bytes: &[u8],
    ) -> io::Result<()> {
        validate_input(name, bytes)?;
        self.check_directories()?;
        files::write(&self.directory, &temporary_name(name, bytes), bytes)
    }

    /// Preserve at most 128 private entries, including unresolved atomic-write
    /// temporaries. Unknown names, unsafe leaves or a changed inventory fail;
    /// no candidate is selected and nothing is flushed, repaired or replayed.
    pub(super) fn snapshot_entries(&self) -> io::Result<Vec<(String, Zeroizing<Vec<u8>>)>> {
        self.check_directories()?;
        let names = self.snapshot_names()?;
        let mut entries = Vec::with_capacity(names.len());
        for name in &names {
            Self::check_snapshot_name(name)?;
            let bytes = files::read(&self.directory.join(name), MAX_BYTES, true)?;
            Self::check_snapshot_entry(name, &bytes)?;
            entries.push((name.clone(), bytes));
        }
        if self.snapshot_names()? != names {
            return Err(invalid("ACME snapshot inventory changed"));
        }
        Ok(entries)
    }

    fn snapshot_names(&self) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for (index, entry) in fs::read_dir(&self.directory)?.enumerate() {
            if index >= 128 {
                return Err(invalid("ACME snapshot exceeds its entry limit"));
            }
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| invalid("invalid ACME snapshot filename"))?;
            Self::check_snapshot_name(&name)?;
            names.push(name);
        }
        names.sort_unstable();
        Ok(names)
    }

    /// Validate a single component before joining any manifest-provided name.
    /// Temporary names have a fixed original basename and lowercase SHA-256.
    pub(super) fn check_snapshot_name(name: &str) -> io::Result<()> {
        if validate_name(name).is_ok() {
            return Ok(());
        }
        let Some((original, hash)) = name
            .strip_prefix('.')
            .and_then(|value| value.strip_suffix(".tmp"))
            .and_then(|value| value.rsplit_once('.'))
        else {
            return Err(invalid("unknown ACME snapshot entry"));
        };
        validate_name(original)?;
        validate_namespace(hash)
    }

    pub(super) fn check_snapshot_entry(name: &str, bytes: &[u8]) -> io::Result<()> {
        Self::check_snapshot_name(name)?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid("ACME snapshot entry exceeds its input limit"));
        }
        let original = if let Some(value) = name.strip_prefix('.') {
            let original = value
                .rsplit_once('.')
                .and_then(|(value, suffix)| (suffix == "tmp").then_some(value))
                .and_then(|value| value.rsplit_once('.'))
                .map(|(original, _)| original)
                .ok_or_else(|| invalid("invalid ACME snapshot temporary"))?;
            if temporary_name(original, bytes) != name {
                return Err(invalid("ACME snapshot temporary checksum differs"));
            }
            original
        } else {
            name
        };
        if original == "retry.json" {
            Self::retry_value(Some(bytes))?;
        }
        Ok(())
    }

    /// Missing legacy state has no CA cooldown. Malformed, oversized or unsafe
    /// existing state is an error, never permission to contact the CA early.
    pub(super) fn retry_at(&self) -> io::Result<u64> {
        let bytes = self.load("retry.json")?;
        Self::retry_value(bytes.as_deref().map(Vec::as_slice))
    }

    /// Validate a captured raw retry state without rereading or normalizing it.
    /// Offline confirmation also binds absence, not just the interpreted zero.
    pub(super) fn retry_value(bytes: Option<&[u8]>) -> io::Result<u64> {
        let Some(bytes) = bytes else {
            return Ok(0);
        };
        if bytes.len() > MAX_RETRY_BYTES {
            return Err(invalid("ACME retry state exceeds its size limit"));
        }
        let retry: Retry =
            serde_json::from_slice(bytes).map_err(|_| invalid("invalid ACME retry state"))?;
        if retry.version != 1 || retry.not_before_unix_s > MAX_RETRY_AT {
            return Err(invalid("invalid ACME retry state"));
        }
        Ok(retry.not_before_unix_s)
    }

    /// Caller holds the shared Io writer permit across this read/max/replace.
    /// Replacing even equal bytes retries a prior unknown directory-sync result;
    /// it does not make a failed publication survive every hard-crash scenario.
    pub(super) fn advance_retry(&self, candidate: u64) -> io::Result<u64> {
        if candidate > MAX_RETRY_AT {
            return Err(invalid("invalid ACME retry time"));
        }
        let not_before_unix_s = candidate.max(self.retry_at()?);
        let bytes = serde_json::to_vec(&Retry {
            version: 1,
            not_before_unix_s,
        })
        .map_err(|_| invalid("cannot encode ACME retry state"))?;
        self.replace("retry.json", &bytes)?;
        Ok(not_before_unix_s)
    }

    /// Open/create `acme/<namespace>` beneath an existing trusted data directory.
    /// The namespace is exactly 64 lowercase hexadecimal ASCII bytes, supplied
    /// by the caller's domain/directory binding. Existing directories must already
    /// be private; failure retains any newly claimed directory for inspection.
    /// The caller must supply the process author for this same data directory.
    pub(super) fn open(data_dir: &Path, author: Arc<Guard>, namespace: &str) -> io::Result<Self> {
        validate_namespace(namespace)?;
        files::check_directory(data_dir, false)?;
        let data_dir = fs::canonicalize(data_dir)?;
        files::check_directory(&data_dir, false)?;
        let parent = data_dir.join("acme");
        private_directory(&parent)?;
        let directory = parent.join(namespace);
        private_directory(&directory)?;
        Ok(Self {
            directory,
            _author: author,
        })
    }

    /// Read-only open under the already-held author for this trusted data dir.
    /// Missing cache directories return None; existing leaves must already be
    /// private real directories. This never creates, flushes or repairs them.
    pub(super) fn open_existing(
        data_dir: &Path,
        author: Arc<Guard>,
        namespace: &str,
    ) -> io::Result<Option<Self>> {
        validate_namespace(namespace)?;
        files::check_directory(data_dir, false)?;
        let data_dir = fs::canonicalize(data_dir)?;
        files::check_directory(&data_dir, false)?;
        let parent = data_dir.join("acme");
        let directory = parent.join(namespace);
        for path in [&parent, &directory] {
            match files::check_directory(path, true) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        Ok(Some(Self {
            directory,
            _author: author,
        }))
    }

    /// Inspect at most 128 directory entries and one bounded candidate body.
    /// Foreign/malformed order-temp names are not silently skipped. A single
    /// candidate must be a private regular single-link leaf whose exact bytes
    /// produce its filename. Multiple candidates never yield recovery evidence.
    pub(super) fn order_temporary(&self, limit: usize) -> io::Result<OrderTemporary> {
        if limit > MAX_BYTES {
            return Err(invalid("invalid ACME temporary input limit"));
        }
        self.check_directories()?;
        let mut names = Vec::with_capacity(2);
        for (index, entry) in fs::read_dir(&self.directory)?.enumerate() {
            if index >= 128 {
                return Err(invalid("ACME cache directory exceeds its entry limit"));
            }
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| invalid("invalid ACME cache filename"))?;
            if !name.starts_with(".order.json.") {
                continue;
            }
            let hash = name
                .strip_prefix(".order.json.")
                .and_then(|value| value.strip_suffix(".tmp"))
                .ok_or_else(|| invalid("invalid ACME order temporary name"))?;
            validate_namespace(hash)?;
            if names.len() < 2 {
                names.push(name.to_owned());
            }
        }
        match names.len() {
            0 => Ok(OrderTemporary::Absent),
            1 => {
                let name = names.remove(0);
                let bytes = files::read(&self.directory.join(&name), limit, true)?;
                if name != temporary_name("order.json", &bytes) {
                    return Err(invalid("ACME order temporary checksum does not match"));
                }
                Ok(OrderTemporary::One { name, bytes })
            }
            _ => Ok(OrderTemporary::Multiple),
        }
    }

    /// Missing entries are absent, never an invitation to replace unreadable
    /// state. Existing entries must be private regular single-link files no
    /// larger than 256 KiB. Owned input is zeroized on every return path.
    pub(super) fn load(&self, name: &str) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        validate_name(name)?;
        self.check_directories()?;
        read_optional(&self.directory.join(name))
    }

    /// Claim and flush a new private entry without replacing any existing leaf.
    /// An error can leave a claimed partial file: callers must inspect/validate
    /// it rather than generate and overwrite a new account or order key.
    pub(super) fn create(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        validate_input(name, bytes)?;
        self.check_directories()?;
        files::write(&self.directory, name, bytes)
    }

    /// Publish one complete private entry using a flushed same-directory file.
    /// Identity key and chain must be one caller-validated PEM bundle; separate
    /// entries are not committed atomically. Until rename succeeds the old
    /// target is unchanged. After rename, directory-sync failure explicitly
    /// reports an unknown durability outcome; retain and retry these same bytes.
    ///
    /// The content-bound temporary name permits retries without overwriting a
    /// prior partial/foreign temporary file. An existing temporary must pass
    /// strict private-file checks and match every byte, then be flushed again.
    /// A mismatched or unsafe temporary is retained and requires operator review.
    /// Windows flushes files but the shared helper makes no power-loss directory
    /// durability guarantee. Failures before rename retain the old target and
    /// any temporary; a failure after rename never rolls the publication back.
    pub(super) fn replace(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        self.replace_with_sync(name, bytes, files::sync_directory)
    }

    fn replace_with_sync(
        &self,
        name: &str,
        bytes: &[u8],
        sync_directory: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        validate_input(name, bytes)?;
        self.check_directories()?;
        let destination = self.directory.join(name);
        // Even though rename does not follow a destination symlink, do not
        // silently repair an unsafe existing cache entry by replacing its name.
        drop(read_optional(&destination)?);
        let temporary_name = temporary_name(name, bytes);
        let temporary = self.directory.join(&temporary_name);
        match files::write(&self.directory, &temporary_name, bytes) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let previous = files::read(&temporary, MAX_BYTES, true)?;
                if previous.as_slice() != bytes {
                    return Err(invalid("ACME cache temporary content does not match"));
                }
                // A prior write may have completed its bytes but failed its
                // flush. Equality alone is not evidence of file durability.
                sync_temporary(&temporary)?;
            }
            Err(error) => return Err(error),
        }
        fs::rename(&temporary, &destination)?;
        sync_directory(&self.directory).map_err(|error| {
            io::Error::new(
                error.kind(),
                "ACME cache replacement was published; durability is unknown",
            )
        })
    }

    fn check_directories(&self) -> io::Result<()> {
        let parent = self
            .directory
            .parent()
            .ok_or_else(|| invalid("invalid ACME cache directory"))?;
        files::check_directory(parent, true)?;
        files::check_directory(&self.directory, true)
    }
}

fn validate_namespace(namespace: &str) -> io::Result<()> {
    if namespace.len() != 64
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("invalid ACME cache namespace"));
    }
    Ok(())
}

fn private_directory(path: &Path) -> io::Result<()> {
    match files::create_directory(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            files::check_directory(path, true)?;
            // Opening may be a retry after creation succeeded but its parent
            // directory flush failed. Do not treat existence as durability.
            files::sync_directory(path)?;
            if let Some(parent) = path.parent() {
                files::sync_directory(parent)?;
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn read_optional(path: &Path) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    match files::read(path, MAX_BYTES, true) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Reopen only an immediately audited, byte-matched temporary without truncating
/// it. The shared read checks ACL/owner/link count on its handle; trusted parents
/// and the stated same-account boundary apply between those handles. No-follow
/// flags also keep this flushing open from redirecting through a symlink leaf.
fn sync_temporary(path: &Path) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("ACME cache temporary must be a regular file"));
    }
    file.sync_all()
}

fn validate_input(name: &str, bytes: &[u8]) -> io::Result<()> {
    validate_name(name)?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid("ACME cache entry exceeds its size limit"));
    }
    Ok(())
}

fn validate_name(name: &str) -> io::Result<()> {
    if !matches!(
        name,
        "account.der"
            | "account.json"
            | "identity.pem"
            | "order.json"
            | "retry.json"
            | "pending.der"
            | "pending.csr"
    ) {
        return Err(invalid("invalid ACME cache entry name"));
    }
    Ok(())
}

fn temporary_name(name: &str, bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hash = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        hash.push(char::from(HEX[usize::from(byte >> 4)]));
        hash.push(char::from(HEX[usize::from(byte & 15)]));
    }
    format!(".{name}.{hash}.tmp")
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAMESPACE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Only this exclusively created private fixture is removed. No test opens an
    /// existing management database, real account key, trust store or listener.
    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> io::Result<Self> {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("test entropy unavailable"))?;
            let path = std::env::temp_dir().join(format!(
                "vproxy-acme-storage-{:032x}",
                u128::from_ne_bytes(random)
            ));
            files::create_directory(&path)?;
            Ok(Self(path))
        }

        fn cache(&self) -> io::Result<Cache> {
            Cache::open(
                &self.0,
                Arc::new(super::super::super::store::lock(&self.0)?),
                NAMESPACE,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn retry_state_is_versioned_bounded_and_retains_the_maximum() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let cache = fixture.cache()?;
        assert_eq!(cache.retry_at()?, 0);
        assert_eq!(cache.advance_retry(120)?, 120);
        assert_eq!(cache.advance_retry(80)?, 120);
        assert_eq!(cache.advance_retry(MAX_RETRY_AT)?, MAX_RETRY_AT);
        assert!(cache.advance_retry(MAX_RETRY_AT + 1).is_err());
        assert_eq!(cache.retry_at()?, MAX_RETRY_AT);
        let reopened = Cache::open(&fixture.0, cache._author.clone(), NAMESPACE)?;
        assert_eq!(reopened.retry_at()?, MAX_RETRY_AT);

        let oversized = vec![b' '; MAX_RETRY_BYTES + 1];
        for bytes in [
            b"".as_slice(),
            br#"{}"#.as_slice(),
            br#"{"version":2,"not_before_unix_s":1}"#.as_slice(),
            br#"{"version":1,"not_before_unix_s":253402300800}"#.as_slice(),
            br#"{"version":1,"not_before_unix_s":-1}"#.as_slice(),
            br#"{"version":1,"not_before_unix_s":1.0}"#.as_slice(),
            br#"{"version":1,"not_before_unix_s":"1"}"#.as_slice(),
            br#"{"version":1,"not_before_unix_s":1,"extra":0}"#.as_slice(),
            br#"{"version":1,"version":1,"not_before_unix_s":1}"#.as_slice(),
            oversized.as_slice(),
        ] {
            cache.replace("retry.json", bytes)?;
            assert_eq!(
                cache.retry_at().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert!(cache.advance_retry(0).is_err());
            assert_eq!(
                cache.load("retry.json")?.as_deref().map(Vec::as_slice),
                Some(bytes)
            );
        }
        Ok(())
    }

    #[test]
    fn retry_gate_never_repairs_a_multiply_linked_file() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let cache = fixture.cache()?;
        cache.advance_retry(120)?;
        let original = cache.directory.join("retry.json");
        let alias = cache.directory.join("account.json");
        fs::hard_link(&original, &alias)?;
        let previous = fs::read(&original)?;
        assert!(cache.retry_at().is_err());
        assert!(cache.advance_retry(240).is_err());
        assert_eq!(fs::read(&original)?, previous);
        assert_eq!(fs::read(&alias)?, previous);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn retry_gate_rejects_loose_permissions_and_symlinks_without_repair() -> io::Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let fixture = Fixture::new()?;
        let cache = fixture.cache()?;
        cache.advance_retry(120)?;
        let original = cache.directory.join("retry.json");
        fs::set_permissions(&original, fs::Permissions::from_mode(0o644))?;
        assert!(cache.retry_at().is_err());
        assert!(cache.advance_retry(240).is_err());
        assert_eq!(fs::metadata(&original)?.permissions().mode() & 0o777, 0o644);
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600))?;
        fs::rename(&original, cache.directory.join("account.json"))?;
        symlink("account.json", &original)?;
        assert!(cache.retry_at().is_err());
        assert!(cache.advance_retry(240).is_err());
        assert!(fs::symlink_metadata(&original)?.file_type().is_symlink());
        Ok(())
    }

    #[test]
    fn exclusive_creation_missing_entries_and_bounds_preserve_old_bytes() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let cache = fixture.cache()?;
        assert!(cache.load("identity.pem")?.is_none());
        cache.create("account.der", b"account-key-fixture")?;
        assert_eq!(
            cache
                .create("account.der", b"replacement")
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        let excessive = vec![b'x'; MAX_BYTES + 1];
        assert!(cache.create("account.der", &excessive).is_err());
        assert!(cache.replace("account.der", &excessive).is_err());
        assert_eq!(
            cache.load("account.der")?.as_deref().map(Vec::as_slice),
            Some(b"account-key-fixture".as_slice())
        );
        assert_eq!(fs::read_dir(&cache.directory)?.count(), 1);
        let boundary = vec![b'm'; MAX_BYTES];
        cache.create("account.json", &boundary)?;
        assert_eq!(
            cache.load("account.json")?.as_deref().map(Vec::as_slice),
            Some(boundary.as_slice())
        );
        files::write(&cache.directory, "identity.pem", &excessive)?;
        assert!(cache.load("identity.pem").is_err());
        assert!(cache.replace("identity.pem", b"never published").is_err());
        assert_eq!(
            fs::metadata(cache.directory.join("identity.pem"))?.len(),
            262_145
        );
        Ok(())
    }

    #[test]
    fn names_and_namespaces_are_checked_before_claiming_outputs() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let author = Arc::new(super::super::super::store::lock(&fixture.0)?);
        let uppercase = "A".repeat(64);
        let unicode = "é".repeat(32);
        for namespace in ["../outside", "", uppercase.as_str(), unicode.as_str()] {
            assert!(Cache::open(&fixture.0, author.clone(), namespace).is_err());
        }
        assert!(!fixture.0.join("acme").exists());
        let cache = Cache::open(&fixture.0, author, NAMESPACE)?;
        for name in [
            "../account.der",
            "ACCOUNT.DER",
            "account.der:stream",
            "",
            "other.pem",
        ] {
            assert!(cache.load(name).is_err());
            assert!(cache.create(name, b"never written").is_err());
            assert!(cache.replace(name, b"never written").is_err());
        }
        assert_eq!(fs::read_dir(&cache.directory)?.count(), 0);
        Ok(())
    }

    #[test]
    fn matching_staged_bytes_and_repeated_candidate_are_recoverable() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let cache = fixture.cache()?;
        cache.create("identity.pem", b"old identity")?;
        let candidate = b"same new identity bundle";
        let temporary = temporary_name("identity.pem", candidate);
        files::write(&cache.directory, &temporary, candidate)?;
        cache.replace("identity.pem", candidate)?;
        assert_eq!(fs::read(cache.directory.join("identity.pem"))?, candidate);
        assert!(!cache.directory.join(&temporary).exists());
        cache.replace("identity.pem", candidate)?;
        assert_eq!(fs::read(cache.directory.join("identity.pem"))?, candidate);
        assert_eq!(fs::read_dir(&cache.directory)?.count(), 1);
        // Order recovery state has the same single-file publication boundary.
        cache.create("order.json", b"pending order")?;
        cache.replace("order.json", b"same key and order URL")?;
        assert_eq!(
            fs::read(cache.directory.join("order.json"))?,
            b"same key and order URL"
        );
        Ok(())
    }

    #[test]
    fn mismatched_temporary_never_replaces_the_old_identity() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let cache = fixture.cache()?;
        cache.create("identity.pem", b"old identity")?;
        let candidate = b"new identity";
        let temporary = temporary_name("identity.pem", candidate);
        files::write(&cache.directory, &temporary, b"partial")?;
        assert!(cache.replace("identity.pem", candidate).is_err());
        assert_eq!(
            fs::read(cache.directory.join("identity.pem"))?,
            b"old identity"
        );
        assert_eq!(fs::read(cache.directory.join(&temporary))?, b"partial");
        Ok(())
    }

    #[test]
    fn post_rename_sync_error_reports_unknown_and_same_buffer_retry_succeeds() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let cache = fixture.cache()?;
        cache.create("identity.pem", b"old identity")?;
        let candidate = b"validated candidate";
        let error = cache
            .replace_with_sync("identity.pem", candidate, |_| {
                Err(io::Error::other("injected directory sync failure"))
            })
            .unwrap_err();
        assert!(error.to_string().contains("durability is unknown"));
        assert_eq!(fs::read(cache.directory.join("identity.pem"))?, candidate);
        cache.replace("identity.pem", candidate)?;
        assert_eq!(fs::read(cache.directory.join("identity.pem"))?, candidate);
        Ok(())
    }

    #[test]
    fn cache_clones_retain_the_actual_process_authority() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let cache = fixture.cache()?;
        let blocking_owner = cache.clone();
        drop(cache);
        assert_eq!(
            super::super::super::store::lock(&fixture.0)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        drop(blocking_owner);
        drop(super::super::super::store::lock(&fixture.0)?);
        Ok(())
    }

    #[test]
    fn multiply_linked_entries_and_directory_leaves_are_never_repaired() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let cache = fixture.cache()?;
        cache.create("account.der", b"key fixture")?;
        let original = cache.directory.join("account.der");
        let alias = cache.directory.join("account.json");
        fs::hard_link(&original, &alias)?;
        assert!(cache.load("account.der").is_err());
        assert!(cache.replace("account.der", b"never written").is_err());
        assert_eq!(fs::read(&original)?, b"key fixture");
        assert_eq!(fs::read(&alias)?, b"key fixture");
        files::create_directory(&cache.directory.join("identity.pem"))?;
        assert!(cache.load("identity.pem").is_err());
        assert!(cache.replace("identity.pem", b"never written").is_err());
        assert!(cache.directory.join("identity.pem").is_dir());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unix_loose_modes_symlinks_and_staged_links_are_rejected() -> io::Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let fixture = Fixture::new()?;
        let cache = fixture.cache()?;
        cache.create("identity.pem", b"old identity")?;
        let identity = cache.directory.join("identity.pem");
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o644))?;
        assert!(cache.load("identity.pem").is_err());
        assert!(cache.replace("identity.pem", b"never written").is_err());
        assert_eq!(fs::metadata(&identity)?.permissions().mode() & 0o777, 0o644);
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o600))?;
        let candidate = b"new identity";
        let temporary = cache
            .directory
            .join(temporary_name("identity.pem", candidate));
        symlink(&identity, &temporary)?;
        assert!(cache.replace("identity.pem", candidate).is_err());
        assert_eq!(fs::read(&identity)?, b"old identity");
        let redirected = cache.directory.join("account.der");
        symlink(fixture.0.join("missing"), &redirected)?;
        assert!(cache.load("account.der").is_err());
        assert!(cache.create("account.der", b"never written").is_err());
        assert!(cache.replace("account.der", b"never written").is_err());
        fs::set_permissions(&cache.directory, fs::Permissions::from_mode(0o755))?;
        assert!(cache.load("identity.pem").is_err());
        assert!(Cache::open(&fixture.0, cache._author.clone(), NAMESPACE).is_err());
        assert_eq!(
            fs::metadata(&cache.directory)?.permissions().mode() & 0o777,
            0o755
        );
        fs::set_permissions(&cache.directory, fs::Permissions::from_mode(0o700))?;
        let parent = fixture.0.join("acme");
        let original = fixture.0.join("original-acme");
        fs::rename(&parent, &original)?;
        symlink(&original, &parent)?;
        assert!(Cache::open(&fixture.0, cache._author.clone(), NAMESPACE).is_err());
        assert!(cache.load("identity.pem").is_err());
        assert!(fs::symlink_metadata(parent)?.file_type().is_symlink());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_existing_unprotected_directory_is_not_repaired() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let parent = fixture.0.join("acme");
        // Ordinary directory creation inherits access but does not set the protected
        // DACL bit required for a long-lived private cache directory.
        fs::create_dir(&parent)?;
        assert!(files::check_directory(&parent, true).is_err());
        assert!(fixture.cache().is_err());
        assert!(files::check_directory(&parent, true).is_err());
        assert_eq!(fs::read_dir(&parent)?.count(), 0);
        Ok(())
    }
}
