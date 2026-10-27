//! Private regular-file operations shared by setup and managed identities.
//!
//! Existing ancestors are an operator trust boundary. These helpers reject
//! redirected leaves and do not defend against a hostile process running as
//! the same account, audit ancestor ACLs, or repair existing permissions. A
//! failed write retains its new directory/files for explicit inspection.

#[cfg(windows)]
use crate::windows_files as windows;

use std::{
    fs,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

use zeroize::Zeroizing;

#[cfg(unix)]
use std::fs::OpenOptions;

/// Resolve the existing parent without creating anything; the leaf must be new.
/// The caller must trust that parent and its ancestors for the whole operation.
pub(super) fn output_path(output: &Path) -> io::Result<PathBuf> {
    if !output
        .to_str()
        .is_some_and(|value| !value.chars().any(char::is_control))
    {
        return Err(invalid(
            "setup paths require UTF-8 without control characters",
        ));
    }
    if output.as_os_str().is_empty() {
        return Err(invalid("setup output requires a new directory name"));
    }
    let absolute = if output.is_absolute() {
        output.to_owned()
    } else {
        std::env::current_dir()?.join(output)
    };
    let name = absolute
        .file_name()
        .ok_or_else(|| invalid("setup output requires a new directory name"))?;
    let parent = absolute
        .parent()
        .ok_or_else(|| invalid("setup output requires an existing parent"))?;
    check_directory(parent, false)?;
    let parent = fs::canonicalize(parent)?;
    check_directory(&parent, false)?;
    let resolved = parent.join(name);
    match fs::symlink_metadata(&resolved) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(resolved),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "setup output already exists; it is never overwritten",
        )),
    }
}

/// Atomically claim one private directory, never changing an existing ACL/mode.
/// On Unix directory entries are synced; Windows file flushing does not promise
/// directory-entry durability. Failure never removes the claimed output.
pub(super) fn create_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)?;
        private_directory(path)?;
    }
    #[cfg(windows)]
    windows::create_directory(path)?;
    #[cfg(not(any(unix, windows)))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private setup directories are unsupported on this platform",
    ));
    sync_directory(path)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

/// Create and flush exactly one private package file under a private directory.
/// Names are portable ASCII components, excluding devices/streams/traversal.
/// Existing leaves, including dangling links, are never replaced or truncated.
pub(super) fn write(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    validate_name(name)?;
    private_directory(directory)?;
    let path = directory.join(name);
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?
    };
    #[cfg(windows)]
    let mut file = windows::create_file(&path)?;
    #[cfg(not(any(unix, windows)))]
    let mut file = {
        let _ = path;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private setup files are unsupported on this platform",
        ));
    };
    file.write_all(bytes)?;
    file.sync_all()?;
    sync_directory(directory)
}

/// Read a bounded regular leaf into an owner that zeroizes on all return paths.
/// Private inputs additionally require Unix 0600-or-stricter permissions and a
/// single link, or a Windows handle-audited current-user/SYSTEM-only DACL and a
/// single link. Public inputs may have broader access; no permissions change.
pub(super) fn read(path: &Path, limit: usize, private: bool) -> io::Result<Zeroizing<Vec<u8>>> {
    let read_limit = limit
        .checked_add(1)
        .ok_or_else(|| invalid("invalid setup input size limit"))?;
    let read_limit_u64 =
        u64::try_from(read_limit).map_err(|_| invalid("invalid setup input size limit"))?;
    let file = open_read(path, limit, private)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(read_limit)
        .map_err(|_| io::Error::other("cannot reserve bounded setup input"))?;
    file.take(read_limit_u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid("setup input exceeds its size limit"));
    }
    Ok(bytes)
}

/// Open the same handle-audited regular leaf without allocating its full image.
/// The caller must bound subsequent reads and validate completion: the initial
/// size check alone cannot detect later growth or changed contents. Ancestors
/// and hostile same-account races retain this module's existing trust boundary.
pub(super) fn open_read(path: &Path, limit: usize, private: bool) -> io::Result<fs::File> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid("setup input must be a regular non-symlink file"));
    }
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(invalid("setup input must be a regular file"));
        }
        if private && (metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1) {
            return Err(denied(
                "setup private input requires private permissions and one link",
            ));
        }
        file
    };
    #[cfg(windows)]
    let file = windows::open_file(path, private)?;
    #[cfg(not(any(unix, windows)))]
    let file = {
        let _ = private;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "setup file inspection is unsupported on this platform",
        ));
    };
    if file.metadata()?.len()
        > u64::try_from(limit).map_err(|_| invalid("invalid setup input size limit"))?
    {
        return Err(invalid("setup input exceeds its size limit"));
    }
    Ok(file)
}

/// Flush directory entries on Unix without following a substituted leaf.
/// Windows has no directory-entry fsync in this implementation; files are
/// individually flushed before completion is reported. This is not a promise
/// that a whole package survives power loss atomically on Windows.
pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?
            .sync_all()?;
    }
    #[cfg(windows)]
    windows::check_directory(path, false)?;
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    Ok(())
}

fn private_directory(path: &Path) -> io::Result<()> {
    check_directory(path, true)
}

/// Inspect the directory leaf before canonicalizing or reading package entries.
/// Windows checks the opened object, rejecting junctions and all other reparse
/// points even if the ordinary metadata API reports them as directories.
pub(super) fn check_directory(path: &Path, private: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(denied(
            "setup directory must be a real non-symlink directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if private && metadata.permissions().mode() & 0o077 != 0 {
            return Err(denied(
                "setup directory must not grant group or other access",
            ));
        }
    }
    #[cfg(windows)]
    windows::check_directory(path, private)?;
    #[cfg(not(any(unix, windows)))]
    let _ = private;
    Ok(())
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(invalid(
            "setup file name must be a portable single component",
        ));
    }
    let mut components = Path::new(name).components();
    let stem = name.split('.').next().unwrap_or_default();
    let device = matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON" | "PRN" | "AUX" | "NUL"
    ) || (stem.len() == 4
        && stem.get(..3).is_some_and(|prefix| {
            prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT")
        })
        && matches!(stem.as_bytes()[3], b'1'..=b'9'));
    if name.ends_with('.')
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
        || device
    {
        return Err(invalid(
            "setup file name must be a portable single component",
        ));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> io::Result<Self> {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("test entropy unavailable"))?;
            let path = std::env::temp_dir().join(format!(
                "vproxy-setup-files-{:032x}",
                u128::from_ne_bytes(random)
            ));
            create_directory(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            // Only the exact empty directory created by this fixture is removed.
            let _ = fs::remove_dir(&self.0);
        }
    }

    #[test]
    fn exclusive_files_and_bounded_reads_preserve_existing_contents() -> io::Result<()> {
        let directory = Directory::new()?;
        let child = output_path(&directory.0.join("child"))?;
        create_directory(&child)?;
        assert_eq!(
            create_directory(&child).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            output_path(&child).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        write(&child, "key.pem", b"private")?;
        assert_eq!(&*read(&child.join("key.pem"), 7, true)?, b"private");
        assert!(read(&child.join("key.pem"), 6, true).is_err());
        assert!(read(&child.join("key.pem"), usize::MAX, true).is_err());
        assert!(write(&child, "key.pem", b"replacement").is_err());
        assert_eq!(fs::read(child.join("key.pem"))?, b"private");
        for name in [
            "../outside",
            "a/b",
            "a\\b",
            "x:stream",
            "CON",
            "lpt1.pem",
            ".",
            "..",
            "x.",
            "éé",
            "",
        ] {
            assert!(write(&child, name, b"never written").is_err());
        }
        assert!(read(&child, 20, false).is_err());
        assert!(output_path(&directory.0.join("missing").join("child")).is_err());
        for name in ["line\nbreak", "escape\u{1b}", "control\u{85}"] {
            assert!(output_path(&directory.0.join(name)).is_err());
        }
        fs::remove_file(child.join("key.pem"))?;
        fs::remove_dir(child)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unix_private_modes_links_and_nonregular_leaves_are_checked() -> io::Result<()> {
        use std::os::unix::{
            fs::{PermissionsExt, symlink},
            net::UnixListener,
        };

        let directory = Directory::new()?;
        assert_eq!(fs::metadata(&directory.0)?.permissions().mode() & 0o077, 0);
        write(&directory.0, "key.pem", b"private")?;
        let key = directory.0.join("key.pem");
        assert_eq!(fs::metadata(&key)?.permissions().mode() & 0o077, 0);
        let alias = directory.0.join("alias.pem");
        fs::hard_link(&key, &alias)?;
        assert!(read(&key, 7, true).is_err());
        assert_eq!(&*read(&key, 7, false)?, b"private");
        fs::remove_file(&alias)?;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644))?;
        assert!(read(&key, 7, true).is_err());
        assert_eq!(&*read(&key, 7, false)?, b"private");
        symlink(&key, &alias)?;
        assert!(read(&alias, 7, false).is_err());
        assert!(output_path(&alias).is_err());
        assert!(write(&directory.0, "alias.pem", b"never written").is_err());
        let dangling = directory.0.join("dangling.pem");
        symlink(directory.0.join("absent.pem"), &dangling)?;
        assert!(output_path(&dangling).is_err());
        assert!(write(&directory.0, "dangling.pem", b"never written").is_err());
        let socket = directory.0.join("socket");
        let listener = UnixListener::bind(&socket)?;
        assert!(read(&socket, 20, false).is_err());
        drop(listener);
        fs::remove_file(socket)?;
        fs::remove_file(dangling)?;
        fs::remove_file(alias)?;
        fs::remove_file(key)?;
        Ok(())
    }
}
