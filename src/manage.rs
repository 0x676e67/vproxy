//! Node-local administration and the explicitly configured managed proxy runner.
//!
//! Initialization remains offline; the separate HTTPS API uses existing local
//! administrator identities. Browser and node transports share one policy
//! service; neither endpoint offers an unauthenticated bootstrap operation.

mod acme;
mod alerts;
mod api;
#[cfg(feature = "web-ui")]
mod assets;
mod automation;
mod certificates;
mod client;
mod contract;
mod controller;
mod diagnostics;
mod drain;
mod files;
mod health;
mod input;
mod maintenance;
mod node;
mod notifications;
mod observations;
mod operations;
mod owner;
mod peers;
mod policy;
mod proxy;
mod query;
mod recovery;
mod remote_traffic;
mod setup;
mod snapshot;
mod store;
mod tls;
mod traffic;
mod user_search;
mod views;
mod witness;

use std::{
    env,
    io::{self, IsTerminal, Read, Write},
    path::PathBuf,
};

use argon2::{Argon2, PasswordHasher};
use clap::Subcommand;
use zeroize::Zeroizing;

const MAX_PASSWORD_BYTES: usize = 1024;
const MIN_PASSWORD_CHARACTERS: usize = 12;

/// Management operations; administrator secrets are never CLI arguments.
#[derive(Subcommand)]
pub enum Command {
    /// Inspect or restore one saved ACME order result offline; never contacts a CA
    #[command(subcommand)]
    Acme(acme::Command),
    /// Prepare separate HTTPS and node identities offline; never starts a server
    #[command(subcommand)]
    Setup(setup::Command),
    /// Create a private database, stable node identity, and initial administrator
    Init {
        /// Dedicated persistent directory (default: platform local data directory)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Node display name, distinct from its generated stable ID
        #[arg(long)]
        name: Option<String>,
        /// Initial administrator login (not a proxy username)
        #[arg(long)]
        administrator: Option<String>,
        /// Read a single password from redirected stdin, never the terminal
        #[arg(long, requires_all = ["name", "administrator"])]
        password_stdin: bool,
    },
    /// Inspect existing state without creating, repairing, or changing it
    Status {
        /// Dedicated persistent directory used for initialization
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Print a redacted offline diagnostic report without starting services
    Diagnose(diagnostics::Args),
    /// Test one exported proxy connection locally; sends real, metered traffic
    TestConnection(diagnostics::ConnectionArgs),
    /// Explicitly migrate existing state after stopping management instances
    Migrate {
        /// Persistent directory; never initialized by migration
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// New private SQLite backup path; an existing path is never overwritten
        #[arg(long)]
        backup: PathBuf,
    },
    /// Make a verified private database backup after stopping management instances
    Backup {
        /// Existing persistent directory; never initialized or migrated
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// New backup directory under an existing private parent; never overwritten
        #[arg(long)]
        output: PathBuf,
    },
    /// Check a completed backup without restoring it or changing live state
    VerifyBackup {
        /// Backup directory containing management.sqlite3 and manifest.json
        #[arg(long)]
        input: PathBuf,
    },
    /// Create or inspect a private, quarantined identity and configuration snapshot
    #[command(subcommand)]
    Snapshot(snapshot::Command),
    /// Maintain external witness records; does not enable same-identity recovery
    #[command(subcommand)]
    Witness(witness::Command),
    /// Import a backup into a new, inactive node identity for offline review
    Restore(recovery::RestoreArgs),
    /// Inspect or finalize a new node's offline recovery review
    #[command(subcommand)]
    Recovery(recovery::Command),
    /// Recover an existing administrator offline, after making a private backup
    ResetPassword {
        /// Persistent directory; never initialized or migrated by recovery
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Existing administrator login; no new identity is created
        #[arg(long)]
        administrator: String,
        /// Read the new password from redirected stdin, never the terminal
        #[arg(long)]
        password_stdin: bool,
        /// New private SQLite backup path; an existing path is never overwritten
        #[arg(long)]
        backup: PathBuf,
    },
    /// Manage separately authenticated node identities, not proxy credentials
    #[command(subcommand)]
    Peers(peers::Command),
    /// Inspect or change this node's offline policy owner, never a remote node
    #[command(subcommand)]
    Owner(owner::Command),
    /// Manage scoped local automation identities through private file authority
    #[command(subcommand)]
    Automation(automation::Command),
    /// Query user metadata over HTTPS using a separate read-only identity
    #[command(subcommand)]
    Query(query::Command),
    /// Reserve or execute one caller-bound non-secret user change over HTTPS
    #[command(subcommand)]
    Operations(operations::Command),
    /// Print the OpenAPI JSON contract without database, network or credential access
    ApiSpec {
        /// Include only scoped local user reads and non-secret user operations
        #[arg(long)]
        automation: bool,
    },
    /// Run the HTTPS management API (independent of proxy listeners)
    Serve(Box<api::Args>),
}

/// Execute an offline operation or start the independent HTTPS management API.
///
/// Administrator passwords use an explicitly redirected input or a bounded,
/// no-echo terminal prompt, and become Argon2id PHC strings before storage.
/// This synchronous entry point is not called from proxy runtime threads.
pub(crate) fn run(command: Command) -> io::Result<()> {
    let overview = match command {
        Command::Acme(command) => return acme::run_offline(command),
        Command::Setup(command) => return setup::run(command),
        Command::Init {
            data_dir,
            name,
            administrator,
            password_stdin,
        } => {
            let directory = directory(data_dir)?;
            let (name, administrator, password) = if password_stdin {
                let name = name.ok_or_else(|| missing_input("node name"))?;
                let administrator = administrator.ok_or_else(|| missing_input("administrator"))?;
                validate_names(&name, &administrator)?;
                (name, administrator, password_from_stdin()?)
            } else {
                input::initialize(&directory, name, administrator)?
            };
            let password_hash = hash_password(&password)?;
            let overview = store::initialize(&directory, &name, &administrator, &password_hash)?;
            writeln!(
                io::stderr().lock(),
                "Initialized offline. Next configure HTTPS certificates and run `vproxy manage serve --help`. No server was started."
            )?;
            overview
        }
        Command::Status { data_dir } => store::inspect(&directory(data_dir)?)?,
        Command::Diagnose(args) => return diagnostics::run(args),
        Command::TestConnection(args) => return diagnostics::test_connection(args),
        Command::Migrate { data_dir, backup } => store::migrate(&directory(data_dir)?, &backup)?,
        Command::Backup { data_dir, output } => {
            return print_backup(store::create_backup(&directory(data_dir)?, &output)?);
        }
        Command::VerifyBackup { input } => return print_backup(store::verify_backup(&input)?),
        Command::Snapshot(command) => return snapshot::run(command),
        Command::Witness(command) => return witness::run(command),
        Command::Restore(args) => return recovery::restore(args),
        Command::Recovery(command) => return recovery::run(command),
        Command::ResetPassword {
            data_dir,
            administrator,
            password_stdin,
            backup,
        } => {
            validate_administrator(&administrator)?;
            let directory = directory(data_dir)?;
            let password = if password_stdin {
                password_from_stdin()?
            } else {
                input::password()?
            };
            let password_hash = hash_password(&password)?;
            store::reset_password(&directory, &administrator, &password_hash, &backup)?
        }
        Command::Peers(command) => return peers::run(command),
        Command::Owner(command) => return owner::run(command),
        Command::Automation(command) => return automation::run(command),
        Command::Query(command) => return query::run(command),
        Command::Operations(command) => return operations::run(command),
        Command::ApiSpec { automation } => {
            return contract::write(&mut io::stdout().lock(), automation);
        }
        Command::Serve(args) => return api::run(*args),
    };
    let mut output = io::stdout().lock();
    writeln!(output, "node_id={}", overview.node_id)?;
    writeln!(output, "name={}", overview.name)?;
    writeln!(output, "administrators={}", overview.administrator_count)?;
    writeln!(output, "schema_version={}", overview.schema_version)?;
    writeln!(output, "sqlite_version={}", overview.sqlite_version)
}

/// Print only backup metadata, never credential verifiers or certificate bytes.
fn print_backup(manifest: store::BackupManifest) -> io::Result<()> {
    let mut output = io::stdout().lock();
    writeln!(output, "backup_format={}", manifest.format_version)?;
    writeln!(output, "node_id={}", manifest.node_id)?;
    writeln!(output, "schema_version={}", manifest.schema_version)?;
    writeln!(output, "database_bytes={}", manifest.database_bytes)?;
    writeln!(output, "database_sha256={}", manifest.database_sha256)?;
    writeln!(output, "created_at_unix_ms={}", manifest.created_at_unix_ms)
}

/// Resolve durable state independently of the clearable certificate cache.
///
/// An explicit relative path is resolved against the caller's working directory.
/// Otherwise systemd's single `STATE_DIRECTORY` takes precedence over the local
/// platform data directory. Missing/invalid defaults fail instead of falling
/// back to an arbitrary current directory.
fn directory(explicit: Option<PathBuf>) -> io::Result<PathBuf> {
    if let Some(path) = explicit {
        if path.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "data directory is empty",
            ));
        }
        return if path.is_absolute() {
            Ok(path)
        } else {
            Ok(env::current_dir()?.join(path))
        };
    }
    if let Some(value) = env::var_os("STATE_DIRECTORY") {
        let mut paths = env::split_paths(&value);
        let path = paths.next().filter(|path| path.is_absolute());
        if paths.next().is_some() || path.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "STATE_DIRECTORY must contain one absolute path; use --data-dir to choose explicitly",
            ));
        }
        return path
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid state directory"));
    }
    dirs::data_local_dir()
        .map(|path| path.join(env!("CARGO_PKG_NAME")).join("management"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no persistent local data directory is available; specify --data-dir",
            )
        })
}

fn validate_names(name: &str, administrator: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 128
        || name.chars().any(char::is_control)
        || name.trim() != name
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "node name must be 1–128 UTF-8 bytes without control or surrounding whitespace",
        ));
    }
    validate_administrator(administrator)
}

/// Keep recovery login selection identical to initialization, not proxy syntax.
fn validate_administrator(administrator: &str) -> io::Result<()> {
    if administrator.is_empty()
        || administrator.len() > 64
        || !administrator
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "administrator must contain 1–64 ASCII letters, digits, '.', '_' or '-'",
        ));
    }
    Ok(())
}

fn missing_input(field: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("missing {field}"))
}

/// Read only explicitly redirected input; never silently fall back to echo.
fn password_from_stdin() -> io::Result<Zeroizing<Vec<u8>>> {
    if io::stdin().is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--password-stdin requires redirected input; omit it to use hidden terminal prompts",
        ));
    }
    read_password(io::stdin().lock())
}

/// Hash outside terminal mode and before creating or updating durable state.
fn hash_password(password: &[u8]) -> io::Result<Zeroizing<String>> {
    let password_hash = Argon2::default()
        .hash_password(password)
        .map_err(|_| io::Error::other("failed to hash administrator password"))?;
    Ok(Zeroizing::new(password_hash.to_string()))
}

/// Read at most one bounded UTF-8 passphrase and strip only its final line ending.
///
/// Spaces are part of a password. Extra lines and control characters are rejected,
/// not silently trimmed or truncated. This also bounds work before Argon2 runs.
fn read_password(reader: impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut password = Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_BYTES + 3));
    reader
        .take((MAX_PASSWORD_BYTES + 3) as u64)
        .read_to_end(&mut password)?;
    if password.ends_with(b"\n") {
        password.pop();
        if password.ends_with(b"\r") {
            password.pop();
        }
    }
    validate_password(&password)?;
    Ok(password)
}

/// Shared acceptance policy for redirected and interactive password entry.
fn validate_password(password: &[u8]) -> io::Result<()> {
    let value = std::str::from_utf8(password).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "administrator password must be UTF-8",
        )
    })?;
    if password.len() > MAX_PASSWORD_BYTES
        || value.chars().count() < MIN_PASSWORD_CHARACTERS
        || value.chars().any(char::is_control)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "administrator password must contain at least 12 characters, at most 1024 UTF-8 bytes, and no control characters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_input_preserves_spaces_but_rejects_extra_lines_and_overflow() {
        assert_eq!(
            &*read_password(&b"  a long passphrase  \r\n"[..]).unwrap(),
            b"  a long passphrase  "
        );
        for input in [
            &b"short"[..],
            &b"a long passphrase\nsecond line"[..],
            &b"a long\0passphrase"[..],
        ] {
            assert!(read_password(input).is_err());
        }
        assert!(read_password(&vec![b'x'; MAX_PASSWORD_BYTES + 1][..]).is_err());
        assert_eq!(
            read_password(&vec![b'x'; MAX_PASSWORD_BYTES][..])
                .unwrap()
                .len(),
            MAX_PASSWORD_BYTES
        );
    }
}
