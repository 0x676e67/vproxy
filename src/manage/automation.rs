//! Local filesystem authority for narrowly scoped automation credentials.
//!
//! These commands may run beside the management server. Storage uses its short
//! update gate, not the serve-lifetime author lock or the proxy policy reader.
//! A one-time bearer value is delivered only to a newly claimed private header
//! file, before storage may commit it. Neither metadata output nor errors contain
//! the header, token, credential digest or SQL diagnostics.

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use clap::{Subcommand, ValueEnum};

use super::store;

const MAX_VALID_FOR_SECONDS: u64 = 90 * 24 * 60 * 60;

/// Issuance is explicit: rotation has no scope selector and cannot elevate an
/// existing identity. Keep CLI spelling separate from the storage authority.
#[derive(Clone, Copy, Default, ValueEnum)]
pub enum Scope {
    #[default]
    #[value(name = "users:read")]
    UsersRead,
    #[value(name = "users:write")]
    UsersWrite,
}

impl From<Scope> for store::automation::Scope {
    fn from(scope: Scope) -> Self {
        match scope {
            Scope::UsersRead => Self::UsersRead,
            Scope::UsersWrite => Self::UsersWrite,
        }
    }
}

/// Local file access grants issuance authority; this is not browser login or a
/// proxy credential. A generation CAS is required for rotation and revocation.
#[derive(Subcommand)]
pub enum Command {
    /// Issue an explicitly scoped identity and its one-time Authorization header
    Create {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Public display name, not a username or password
        #[arg(long)]
        name: String,
        /// Local user access; writes exclude credentials and remote control
        #[arg(long, value_enum, default_value = "users:read")]
        scope: Scope,
        /// Required validity in seconds, from 60 to 7,776,000 (90 days)
        #[arg(long, value_parser = clap::value_parser!(u64).range(60..=MAX_VALID_FOR_SECONDS))]
        valid_for: u64,
        /// New private header file for `curl --header @FILE`; never overwritten
        #[arg(long)]
        output: PathBuf,
    },
    /// List public metadata; no command can recover an existing token
    List {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Replace an exact generation and write its new one-time header
    Rotate {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        id: String,
        #[arg(long)]
        expected_generation: u64,
        /// Required validity in seconds, from 60 to 7,776,000 (90 days)
        #[arg(long, value_parser = clap::value_parser!(u64).range(60..=MAX_VALID_FOR_SECONDS))]
        valid_for: u64,
        /// A different new private file; the old header is never replaced
        #[arg(long)]
        output: PathBuf,
    },
    /// Permanently revoke this identity without reviving or rotating it
    Revoke {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        id: String,
        #[arg(long)]
        expected_generation: u64,
    },
}

/// Execute one explicit operation without starting a listener or retrying it.
///
/// Create/rotate claim the output before calling storage. Delivery flushes and
/// syncs the new file before SQL commit. Any failure leaves that private file in
/// place: it may be partial, or complete while the commit result is uncertain.
/// Inspect public metadata before issuing another credential; never replay an
/// uncertain rotation. Windows inherits the trusted parent ACL, not an ACL audit.
pub(super) fn run(command: Command) -> io::Result<()> {
    match command {
        Command::Create {
            data_dir,
            name,
            scope,
            valid_for,
            output,
        } => {
            let directory = super::directory(data_dir)?;
            let mut header = HeaderOutput::claim(&output)?;
            let view =
                store::automation::create(&directory, &name, scope.into(), valid_for, |token| {
                    header.deliver(token)
                })
                .map_err(issuance_error)?;
            write_view(&mut io::stdout().lock(), &view).map_err(saved_output_error)
        }
        Command::List { data_dir } => {
            let identities =
                store::automation::list(&super::directory(data_dir)?).map_err(metadata_error)?;
            let mut output = io::stdout().lock();
            for identity in identities {
                write_view(&mut output, &identity)?;
            }
            Ok(())
        }
        Command::Rotate {
            data_dir,
            id,
            expected_generation,
            valid_for,
            output,
        } => {
            let directory = super::directory(data_dir)?;
            let mut header = HeaderOutput::claim(&output)?;
            let view = store::automation::rotate(
                &directory,
                &id,
                expected_generation,
                valid_for,
                |token| header.deliver(token),
            )
            .map_err(issuance_error)?;
            write_view(&mut io::stdout().lock(), &view).map_err(saved_output_error)
        }
        Command::Revoke {
            data_dir,
            id,
            expected_generation,
        } => {
            let view =
                store::automation::revoke(&super::directory(data_dir)?, &id, expected_generation)
                    .map_err(metadata_error)?;
            write_view(&mut io::stdout().lock(), &view)
        }
    }
}

/// The retained handle owns the exclusively created leaf. Ancestors must be
/// controlled by the operator; these checks do not defend against hostile
/// same-account renames or claim to audit Windows/Unix extended ACLs.
struct HeaderOutput {
    file: File,
    #[cfg(unix)]
    parent: File,
    attempted: bool,
}

impl HeaderOutput {
    /// Claim a new regular leaf under an existing real, private parent. Existing
    /// files (including symlinks/FIFOs) are never opened, truncated or repaired.
    fn claim(output: &Path) -> io::Result<Self> {
        if output.as_os_str().is_empty() {
            return Err(invalid_output("automation header output path is empty"));
        }
        let absolute = if output.is_absolute() {
            output.to_owned()
        } else {
            std::env::current_dir()?.join(output)
        };
        let name = absolute
            .file_name()
            .ok_or_else(|| invalid_output("automation header output requires a new file name"))?;
        let parent = absolute.parent().ok_or_else(|| {
            invalid_output("automation header output requires an existing private parent")
        })?;
        validate_parent(&fs::symlink_metadata(parent)?)?;
        let parent = fs::canonicalize(parent)?;
        validate_parent(&fs::symlink_metadata(&parent)?)?;
        let destination = parent.join(name);
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "automation header output already exists; choose a new private file",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        #[cfg(unix)]
        let parent = {
            use std::os::unix::fs::OpenOptionsExt as _;
            let parent = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(parent)?;
            validate_parent(&parent.metadata()?)?;
            parent
        };
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(destination)?;
        validate_file(&file.metadata()?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            // A newly created regular file is owned by this filesystem user.
            // Comparing owners avoids introducing a platform-specific UID call.
            if file.metadata()?.uid() != parent.metadata()?.uid() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "automation header parent must have the same owner as its new file",
                ));
            }
        }
        Ok(Self {
            file,
            #[cfg(unix)]
            parent,
            attempted: false,
        })
    }

    /// Storage invokes this once before commit. A failed or partial delivery may
    /// not be retried on the same handle, and the caller must retain the file.
    fn deliver(&mut self, token: &str) -> io::Result<()> {
        if std::mem::replace(&mut self.attempted, true) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "automation header delivery was already attempted",
            ));
        }
        let result = (|| {
            validate_file(&self.file.metadata()?)?;
            write_header(&mut self.file, token)?;
            self.file.sync_all()?;
            #[cfg(unix)]
            self.parent.sync_all()?;
            validate_file(&self.file.metadata()?)
        })();
        result.map_err(delivery_error)
    }
}

pub(super) fn validate_parent(metadata: &Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "automation header parent must be an existing real private directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "automation header parent requires private permissions (0700)",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "automation header parent must not be a reparse point",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_file(metadata: &Metadata) -> io::Result<()> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "automation header output must be a private regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.permissions().mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "automation header output requires permissions 0600 and no hard links",
            ));
        }
    }
    Ok(())
}

/// Write without constructing a second formatted copy of the one-time token.
/// Validation prevents a future storage bug from injecting a second header.
fn write_header(output: &mut impl Write, token: &str) -> io::Result<()> {
    if token.is_empty()
        || token.len() > 128
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/=".contains(&byte))
    {
        return Err(invalid_output(
            "automation header token is not a bounded bearer value",
        ));
    }
    output.write_all(b"Authorization: Bearer ")?;
    output.write_all(token.as_bytes())?;
    output.write_all(b"\n")?;
    output.flush()
}

fn write_view(output: &mut impl Write, view: &store::automation::View) -> io::Result<()> {
    let name = serde_json::to_string(&view.name)
        .map_err(|_| io::Error::other("cannot encode automation display name"))?;
    writeln!(
        output,
        "id={} name={} generation={} scope={} created_at_unix_ms={} expires_at_unix_ms={} revoked={}",
        view.id,
        name,
        view.generation,
        view.scope,
        view.created_at_unix_ms,
        view.expires_at_unix_ms,
        view.revoked
    )
}

fn invalid_output(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn delivery_error(error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        "automation header delivery failed; private output may be partial and was retained",
    )
}

fn error_code(error: &io::Error) -> &'static str {
    error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<store::automation::Error>())
        .map_or("automation_unavailable", store::automation::Error::code)
}

fn issuance_error(error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "{}; private output was retained; inspect `manage automation list` before issuing another credential; do not replay this command",
            error_code(&error)
        ),
    )
}

fn metadata_error(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), error_code(&error))
}

fn saved_output_error(error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        "automation credential was saved, but metadata output failed; private header file was retained",
    )
}

#[cfg(test)]
mod tests {
    use std::fs::DirBuilder;

    use super::*;

    const TOKEN: &str = "vpa1.AAAAAAAAAAAAAAAAAAAAAA.1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// Owns only an exclusively created random temporary leaf. Test data never uses
    /// an existing credential or a runtime directory.
    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> io::Result<Self> {
            let mut random = [0; 16];
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("test entropy unavailable"))?;
            let path = std::env::temp_dir().join(format!(
                "vproxy-automation-cli-{:032x}",
                u128::from_be_bytes(random)
            ));
            let builder = DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder.create(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn one_time_header_is_synced_and_cannot_be_delivered_twice() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let path = fixture.0.join("request.header");
        let mut output = HeaderOutput::claim(&path)?;
        assert_eq!(fs::metadata(&path)?.len(), 0);
        output.deliver(TOKEN)?;
        let expected = format!("Authorization: Bearer {TOKEN}\n");
        assert_eq!(fs::read(&path)?, expected.as_bytes());
        assert!(matches!(
            output.deliver(TOKEN),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert_eq!(fs::read(&path)?, expected.as_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            let metadata = fs::metadata(&path)?;
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        Ok(())
    }

    #[test]
    fn existing_leaf_is_not_opened_or_overwritten() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let path = fixture.0.join("existing.header");
        fs::write(&path, b"existing nonsecret marker")?;
        assert!(matches!(
            HeaderOutput::claim(&path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert_eq!(fs::read(path)?, b"existing nonsecret marker");
        assert!(HeaderOutput::claim(Path::new("")).is_err());
        assert!(HeaderOutput::claim(&fixture.0.join("missing").join("header")).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_nonprivate_parent_are_rejected_without_repair() -> io::Result<()> {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let fixture = Fixture::new()?;
        let absent = fixture.0.join("absent");
        let link = fixture.0.join("linked.header");
        symlink(&absent, &link)?;
        assert!(matches!(
            HeaderOutput::claim(&link),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert!(fs::symlink_metadata(&link)?.file_type().is_symlink());
        assert!(!absent.exists());

        let parent = fixture.0.join("linked-parent");
        symlink(&fixture.0, &parent)?;
        assert!(matches!(
            HeaderOutput::claim(&parent.join("new.header")),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert!(!fixture.0.join("new.header").exists());

        let public = fixture.0.join("nonprivate");
        fs::create_dir(&public)?;
        fs::set_permissions(&public, fs::Permissions::from_mode(0o750))?;
        assert!(matches!(
            HeaderOutput::claim(&public.join("new.header")),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert_eq!(fs::metadata(&public)?.permissions().mode() & 0o777, 0o750);
        assert!(!public.join("new.header").exists());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn existing_fifo_is_rejected_without_opening_or_waiting() -> io::Result<()> {
        use std::os::unix::fs::FileTypeExt as _;

        let fixture = Fixture::new()?;
        let path = fixture.0.join("pipe.header");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &path,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )?;
        assert!(matches!(
            HeaderOutput::claim(&path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert!(fs::symlink_metadata(path)?.file_type().is_fifo());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn changed_mode_or_hard_link_is_rejected_before_secret_write() -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = Fixture::new()?;
        let path = fixture.0.join("mode.header");
        let mut output = HeaderOutput::claim(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        assert!(output.deliver(TOKEN).is_err());
        assert_eq!(fs::metadata(&path)?.len(), 0);
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o640);

        let path = fixture.0.join("linked.header");
        let mut output = HeaderOutput::claim(&path)?;
        fs::hard_link(&path, fixture.0.join("second-link"))?;
        assert!(output.deliver(TOKEN).is_err());
        assert_eq!(fs::metadata(path)?.len(), 0);
        Ok(())
    }

    #[test]
    fn delivery_failure_retains_file_and_does_not_allow_retry() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let path = fixture.0.join("failed.header");
        let mut output = HeaderOutput::claim(&path)?;
        output.file.write_all(b"partial nonsecret marker")?;
        // A read-only handle produces a real write failure without unsafe FD tricks
        // or a platform-specific filesystem filling fixture.
        output.file = File::open(&path)?;
        let error = output
            .deliver(TOKEN)
            .err()
            .ok_or_else(|| io::Error::other("expected read-only output delivery to fail"))?;
        assert_eq!(
            error.to_string(),
            "automation header delivery failed; private output may be partial and was retained"
        );
        assert_eq!(fs::read(&path)?, b"partial nonsecret marker");
        assert!(matches!(
            output.deliver(TOKEN),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert!(HeaderOutput::claim(&path).is_err());
        Ok(())
    }

    #[test]
    fn header_validation_and_output_errors_never_echo_secret_material() -> io::Result<()> {
        for value in [
            "",
            "Bearer other",
            "token\r\nX-Injected: yes",
            "令牌",
            &"a".repeat(129),
        ] {
            let mut output = Vec::new();
            assert_eq!(
                write_header(&mut output, value)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::InvalidInput)
            );
            assert!(output.is_empty());
        }
        let error = issuance_error(io::Error::other(TOKEN));
        assert_eq!(
            error_code(&io::Error::other(TOKEN)),
            "automation_unavailable"
        );
        assert!(!error.to_string().contains(TOKEN));
        assert!(error.to_string().contains("do not replay"));
        for error in [
            metadata_error(io::Error::other(TOKEN)),
            saved_output_error(io::Error::other(TOKEN)),
        ] {
            assert!(!error.to_string().contains(TOKEN));
        }

        let view = store::automation::View {
            id: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            name: "read \"reports\"".to_owned(),
            generation: 2,
            scope: "users:read",
            created_at_unix_ms: 1000,
            expires_at_unix_ms: 61000,
            revoked: false,
        };
        let mut output = Vec::new();
        write_view(&mut output, &view)?;
        assert_eq!(
            String::from_utf8(output).map_err(io::Error::other)?,
            "id=AAAAAAAAAAAAAAAAAAAAAA name=\"read \\\"reports\\\"\" generation=2 scope=users:read created_at_unix_ms=1000 expires_at_unix_ms=61000 revoked=false\n"
        );
        Ok(())
    }
}
