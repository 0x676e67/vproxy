//! Cooperative, process-lifetime ownership of a management directory.

use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io,
    path::{Path, PathBuf},
};

use super::validate_directory;

const LOCK_NAME: &str = "management.lock";
const UPDATE_LOCK_NAME: &str = "management-update.lock";

/// Holds one OS-managed exclusive lock until the last owning `Arc` is dropped.
///
/// This is not a PID file or protection against a malicious process with the
/// same filesystem rights. Never unlink the persistent lock leaf: another
/// process could otherwise lock a new inode while this guard still owns the old
/// one. Blocking work must retain its guard even if its HTTP request is cancelled.
pub(in crate::manage) struct Guard {
    _file: File,
    directory: PathBuf,
}

impl Guard {
    /// Reject a guard borrowed from another store before snapshot assets or SQL
    /// are read. This is process authority, not remote takeover authorization.
    pub(in crate::manage) fn ensure(&self, directory: &Path) -> io::Result<()> {
        validate_directory(directory)?;
        if fs::canonicalize(directory)? != self.directory {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "management author guard belongs to another directory",
            ));
        }
        Ok(())
    }
}

/// Orders commit/publication with live peer revocation across cooperating processes.
///
/// The coordinator retains this token until its runtime publication and receipt
/// finish. This is separate from the serve-lifetime author guard and its lock
/// file stays in place after release. It does not defend against same-UID tampering.
pub(in crate::manage) struct UpdateGuard {
    _file: File,
    directory: PathBuf,
}

impl UpdateGuard {
    /// Rejects using one directory's token for a different durable store.
    pub(super) fn ensure(&self, directory: &Path) -> io::Result<()> {
        validate_directory(directory)?;
        if fs::canonicalize(directory)? != self.directory {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "management update guard belongs to another directory",
            ));
        }
        Ok(())
    }
}

/// Claims the short update gate before opening a SQL write transaction.
///
/// Contention is WouldBlock, never an unbounded wait. Blocking work owns the
/// token through cancellation. Existing private files are not replaced/repaired.
pub(in crate::manage) fn update_lock(directory: &Path) -> io::Result<UpdateGuard> {
    let file = locked_file(directory, UPDATE_LOCK_NAME)?;
    Ok(UpdateGuard {
        _file: file,
        directory: fs::canonicalize(directory)?,
    })
}

/// Exclusively claims an existing private management directory without waiting.
///
/// This creates only a private, persistent regular lock file, never a database.
/// Existing files are not truncated or chmodded. Contention is `WouldBlock`;
/// symlinks, nonregular leaves and public Unix permissions are rejected. Unix
/// NOFOLLOW/NONBLOCK also protect the open from a replaced symlink/FIFO; Windows
/// inherits the operator-controlled directory ACL rather than auditing it here.
pub(in crate::manage) fn lock(directory: &Path) -> io::Result<Guard> {
    Ok(Guard {
        _file: locked_file(directory, LOCK_NAME)?,
        directory: fs::canonicalize(directory)?,
    })
}

/// Only internal constant leaf names are passed here, never caller-selected paths.
fn locked_file(directory: &Path, name: &str) -> io::Result<File> {
    super::reject_snapshot_directory(directory)?;
    validate_directory(directory)?;
    let path = directory.join(name);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => validate_leaf(&metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    validate_leaf(&file.metadata()?)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "management directory is already in use",
        )),
        Err(TryLockError::Error(error)) => Err(error),
    }
}

/// Validates both the path's pre-open leaf and the actual opened file handle.
fn validate_leaf(metadata: &fs::Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "management lock must be a real regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "management lock requires private file permissions (0600)",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::manage::store::{DATABASE_NAME, initialize, inspect, prepare_directory, random_id};

    /// Owns only an exclusively created random private test leaf.
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!("vproxy-author-{}", random_id()?));
            prepare_directory(&path)?;
            Ok(Self(path))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn guard_survives_arc_owner_and_never_creates_or_removes_database() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let guard = Arc::new(lock(&fixture.0)?);
        let worker = Arc::clone(&guard);
        assert!(
            matches!(lock(&fixture.0), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert!(
            matches!(initialize(&fixture.0, "node", "admin", "fixture hash"), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert!(!fixture.0.join(DATABASE_NAME).exists());
        assert!(inspect(&fixture.0).is_err());
        drop(guard);
        assert!(
            matches!(lock(&fixture.0), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        drop(worker);
        // A parallel test may fork while this file is locked. CLOEXEC closes
        // the inherited descriptor only at exec, so the child's temporary OFD
        // reference can outlive this process's last Arc. Do not weaken the live
        // owner checks above; only bound the wait for this post-drop cleanup.
        // https://man7.org/linux/man-pages/man2/flock.2.html#DESCRIPTION
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let _again = loop {
            match lock(&fixture.0) {
                Ok(guard) => break guard,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => return Err(error),
            }
        };
        assert!(fixture.0.join(LOCK_NAME).is_file());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_fifo_and_nonprivate_lock_without_repair() -> io::Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let fixture = Fixture::new()?;
        let path = fixture.0.join(LOCK_NAME);
        symlink(fixture.0.join("absent"), &path)?;
        assert!(
            matches!(lock(&fixture.0), Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        fs::remove_file(&path)?;
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .and_then(|status| {
                if status.success() {
                    Ok(())
                } else {
                    Err(io::Error::other("cannot create FIFO fixture"))
                }
            })?;
        assert!(
            matches!(lock(&fixture.0), Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        fs::remove_file(&path)?;
        drop(lock(&fixture.0)?);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(
            matches!(lock(&fixture.0), Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o644);
        Ok(())
    }
}
