//! Private, exclusively created self-update inputs and candidate. Existing
//! ancestors are trusted; hostile same-account mutation is outside this boundary.
//! No existing mode or ACL is repaired, and archive names never become paths.

use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

const MAX_FILES: usize = 2;
const ATTEMPTS: usize = 16;

/// Own one random private directory and at most the downloaded archive and
/// candidate. Cleanup removes only this owner's recorded leaves, never an
/// unknown entry or an existing directory's contents recursively. Open Windows
/// read handles can defer cleanup, so callers keep this owner until after all
/// candidate handles and the one replacement call have completed.
pub(super) struct Stage {
    directory: PathBuf,
    files: Vec<String>,
}

impl Stage {
    /// Claim a new private child of the existing process temporary directory.
    /// A collision retries with fresh OS entropy; other failures stop without
    /// changing an existing object's permissions. Unsupported systems fail closed.
    pub(super) fn new() -> io::Result<Self> {
        Self::in_directory(&std::env::temp_dir())
    }

    fn in_directory(parent: &Path) -> io::Result<Self> {
        check_directory(parent, false)?;
        let parent = fs::canonicalize(parent)?;
        check_directory(&parent, false)?;
        for _ in 0..ATTEMPTS {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("self-update staging entropy unavailable"))?;
            let directory = parent.join(format!(
                "vproxy-update-{:032x}",
                u128::from_ne_bytes(random)
            ));
            match create_directory(&directory) {
                Ok(()) => {
                    return Ok(Self {
                        directory,
                        files: Vec::new(),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cannot claim a new self-update staging directory",
        ))
    }

    /// Create one private regular leaf without overwriting any prior object.
    /// Only fixed caller-selected single-component names are accepted, never
    /// names from release metadata or archive headers. Flush/sync/drop the write
    /// handle before opening a validated read handle or attempting replacement.
    pub(super) fn create(&mut self, name: &str) -> io::Result<File> {
        let path = self.path(name)?;
        if self.files.len() >= MAX_FILES {
            return Err(invalid("self-update staging file limit exceeded"));
        }
        self.files
            .try_reserve(1)
            .map_err(|_| io::Error::other("cannot reserve self-update staging ownership"))?;
        let mut owned_name = String::new();
        owned_name
            .try_reserve_exact(name.len())
            .map_err(|_| io::Error::other("cannot reserve self-update staging ownership"))?;
        owned_name.push_str(name);
        let file = create_file(&path)?;
        self.files.push(owned_name);
        Ok(file)
    }

    /// Audit and open an owned private leaf for reading. Symlinks/reparse points,
    /// non-regular objects, additional hard links and broad permissions are
    /// refused. Windows permits only read sharing while the returned handle lives.
    pub(super) fn open(&self, name: &str) -> io::Result<File> {
        let path = self.path(name)?;
        if !self.files.iter().any(|owned| owned == name) {
            return Err(invalid("self-update staging input is not owned"));
        }
        open_file(&path)
    }

    /// Return a validated fixed leaf path for the eventual replacement API.
    /// A path alone is not an audit of the candidate; retain `open`'s read handle
    /// through replacement so Windows denies write/delete sharing of that leaf.
    pub(super) fn path(&self, name: &str) -> io::Result<PathBuf> {
        validate_name(name)?;
        check_directory(&self.directory, true)?;
        Ok(self.directory.join(name))
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        // A failed audit leaves the exact directory for inspection. Never follow
        // a substituted leaf, enumerate unknown children or recursively delete.
        if check_directory(&self.directory, true).is_err() {
            return;
        }
        for name in &self.files {
            let _ = fs::remove_file(self.directory.join(name));
        }
        let _ = fs::remove_dir(&self.directory);
    }
}

fn validate_name(name: &str) -> io::Result<()> {
    let stem = name.split('.').next().unwrap_or_default();
    let device = matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON" | "PRN" | "AUX" | "NUL"
    ) || (stem.len() == 4
        && stem.get(..3).is_some_and(|prefix| {
            prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT")
        })
        && matches!(stem.as_bytes()[3], b'1'..=b'9'));
    if name.is_empty()
        || name.len() > 128
        || matches!(name, "." | "..")
        || name.ends_with('.')
        || device
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(invalid(
            "self-update staging requires a fixed portable name",
        ));
    }
    Ok(())
}

fn check_directory(path: &Path, private: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (private && metadata.permissions().mode() & 0o077 != 0)
        {
            return Err(denied(
                "self-update staging requires a private real directory",
            ));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        crate::windows_files::check_directory(path, private)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, private);
        Err(unsupported())
    }
}

fn create_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)?;
        check_directory(path, true)
    }
    #[cfg(windows)]
    {
        crate::windows_files::create_directory(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(unsupported())
    }
}

fn create_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        audit_file(&file)?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        crate::windows_files::create_file(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(unsupported())
    }
}

fn open_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        audit_file(&file)?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        crate::windows_files::open_file(path, true)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(unsupported())
    }
}

#[cfg(unix)]
fn audit_file(file: &File) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
        return Err(denied(
            "self-update staging input must be a private single-link file",
        ));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(unix)]
fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(not(any(unix, windows)))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "private self-update staging unsupported",
    )
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    #[test]
    fn exclusive_owned_files_are_audited_and_only_the_owned_directory_is_cleaned() -> io::Result<()>
    {
        let mut stage = Stage::new()?;
        let directory = stage.directory.clone();
        let archive_path = stage.path("archive.tar.gz")?;
        let mut output = stage.create("archive.tar.gz")?;
        output.write_all(b"test archive bytes")?;
        output.flush()?;
        output.sync_all()?;
        drop(output);
        assert_eq!(
            stage.create("archive.tar.gz").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let mut input = stage.open("archive.tar.gz")?;
        let mut bytes = Vec::new();
        input.read_to_end(&mut bytes)?;
        assert_eq!(bytes, b"test archive bytes");
        drop(input);
        assert!(stage.open("unowned.bin").is_err());
        for name in [
            "",
            ".",
            "..",
            "../x",
            "a/b",
            "a\\b",
            "x:stream",
            "CON",
            "nul.exe",
            "LPT1",
            "COM9.txt",
            "x.",
            "bad\nname",
            "é",
        ] {
            assert!(stage.path(name).is_err(), "{name:?}");
            assert!(stage.create(name).is_err(), "{name:?}");
        }
        assert!(!directory.join("unowned.bin").exists());
        drop(stage.create("candidate.bin")?);
        assert!(stage.create("third.bin").is_err());
        drop(stage);
        assert!(!archive_path.exists());
        assert!(!directory.exists());
        Ok(())
    }

    #[test]
    fn cleanup_never_recurses_into_unknown_entries_or_changes_an_existing_parent() -> io::Result<()>
    {
        let mut parent = Stage::new()?;
        let mut child = Stage::in_directory(&parent.directory)?;
        let directory = child.directory.clone();
        drop(child.create("archive.tar.gz")?);
        let unknown = directory.join("unowned");
        fs::create_dir(&unknown)?;
        fs::write(unknown.join("retain"), b"unowned test evidence")?;
        drop(child);
        assert!(!directory.join("archive.tar.gz").exists());
        assert_eq!(fs::read(unknown.join("retain"))?, b"unowned test evidence");
        assert!(Stage::in_directory(&parent.path("absent")?).is_err());
        fs::remove_file(unknown.join("retain"))?;
        fs::remove_dir(unknown)?;
        fs::remove_dir(directory)?;
        // The parent remains usable, rather than being removed by the child owner.
        drop(parent.create("candidate.bin")?);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unix_modes_links_and_nonregular_inputs_fail_closed_without_chmod_repair() -> io::Result<()> {
        use std::os::unix::{
            fs::{PermissionsExt, symlink},
            net::UnixListener,
        };

        let mut stage = Stage::new()?;
        assert_eq!(
            fs::metadata(&stage.directory)?.permissions().mode() & 0o077,
            0
        );
        drop(stage.create("archive.tar.gz")?);
        let path = stage.path("archive.tar.gz")?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o077, 0);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(stage.open("archive.tar.gz").is_err());
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o644);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let alias = stage.directory.join("alias");
        fs::hard_link(&path, &alias)?;
        assert!(stage.open("archive.tar.gz").is_err());
        fs::remove_file(&alias)?;
        fs::remove_file(&path)?;
        symlink("absent", &path)?;
        assert!(stage.open("archive.tar.gz").is_err());
        assert!(stage.create("archive.tar.gz").is_err());
        fs::remove_file(&path)?;
        let socket = UnixListener::bind(&path)?;
        assert!(stage.open("archive.tar.gz").is_err());
        drop(socket);
        fs::remove_file(&path)?;
        fs::set_permissions(&stage.directory, fs::Permissions::from_mode(0o755))?;
        assert!(stage.create("candidate.bin").is_err());
        assert_eq!(
            fs::metadata(&stage.directory)?.permissions().mode() & 0o777,
            0o755
        );
        fs::set_permissions(&stage.directory, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_private_candidate_read_handle_denies_mutation_until_it_is_released() -> io::Result<()>
    {
        let mut stage = Stage::new()?;
        drop(stage.create("candidate.exe")?);
        let path = stage.path("candidate.exe")?;
        let input = stage.open("candidate.exe")?;
        assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::remove_file(&path).is_err());
        assert!(fs::rename(&path, stage.path("moved.exe")?).is_err());
        // Independent read access remains compatible with self_replace's copy.
        assert!(stage.open("candidate.exe").is_ok());
        drop(input);
        fs::remove_file(&path)?;
        Ok(())
    }
}
