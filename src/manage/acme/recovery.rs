//! Offline publication of one already-written newOrder result. No code in this
//! module creates an account/key/order or constructs a network client. Existing
//! cache parents and same-account filesystem activity retain Cache's trust
//! boundary; the confirmation digest is an input binding, not authorization.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::super::{files, store};
use super::{
    Config,
    issuer::{self, Phase},
    storage::{Cache, OrderTemporary},
};

#[derive(Clone, Copy, ValueEnum)]
pub enum Environment {
    Staging,
    Production,
}

/// Explicit existing local scope; neither selection accepts issuance terms.
#[derive(Args)]
pub struct Selection {
    /// Existing trusted private management data directory; never initialized
    #[arg(long)]
    data_dir: PathBuf,
    /// Existing serve public HTTPS DNS origin (not a CA URL)
    #[arg(long)]
    public_origin: String,
    /// Fixed Let's Encrypt environment used by this cache
    #[arg(long, value_enum)]
    environment: Environment,
}

/// These offline commands may create only the ordinary process-author lock
/// leaf during inspection; recovery additionally replaces the saved order.
#[derive(Subcommand)]
pub enum Command {
    /// Inspect existing cache evidence without creating or changing ACME state
    Inspect(Selection),
    /// Publish the unique complete Ordered result of the current saved Intent
    RecoverOrder {
        #[command(flatten)]
        selection: Selection,
        /// Exact confirmation_sha256 from inspect; not an authorization token
        #[arg(long)]
        expected_sha256: String,
        /// Assert the account key has not changed since this Intent was written;
        /// v1 cache evidence cannot prove historical CA-account ownership
        #[arg(long, required = true)]
        account_unchanged: bool,
    },
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
// Local evidence phases, deliberately not RFC/CA order status observations.
enum State {
    CacheAbsent,
    OrderAbsent,
    IntentUnknown,
    AmbiguousCandidates,
    RecoverableOrdered,
    Ordered,
    Complete,
    Failed,
    OrderedRestored,
}

/// Only local evidence is reported. In particular ordered/restored does not
/// assert CA acceptance, completed issuance, or hard-crash durability.
#[derive(Serialize)]
struct Report {
    format_version: u8,
    state: State,
    confirmation_sha256: Option<String>,
}

impl Report {
    fn state(state: State) -> Self {
        Self {
            format_version: 1,
            state,
            confirmation_sha256: None,
        }
    }
}

// Cache retains the author through confirmation comparison and actual publish;
// cancellation cannot separate ownership from a still-running filesystem write.
struct Ready {
    cache: Cache,
    confirmation_sha256: String,
    candidate: Zeroizing<Vec<u8>>,
}

// Keep candidate/key-bearing bytes outside the serializable public report.
enum Inspection {
    State(State),
    Ready(Ready),
}

impl Inspection {
    fn report(self) -> Report {
        match self {
            Self::State(state) => Report::state(state),
            Self::Ready(ready) => Report {
                format_version: 1,
                state: State::RecoverableOrdered,
                confirmation_sha256: Some(ready.confirmation_sha256),
            },
        }
    }
}

/// Synchronous offline entry point. Author contention fails immediately; no
/// SQLite open/migration, cache initialization, directory sync or CA request is
/// performed by inspect. Successful recovery only publishes the same bytes.
pub(in crate::manage) fn run(command: Command) -> io::Result<()> {
    let report = match command {
        Command::Inspect(selection) => inspect(&selection)?.report(),
        Command::RecoverOrder {
            selection,
            expected_sha256,
            account_unchanged,
        } => recover(&selection, &expected_sha256, account_unchanged)?,
    };
    let output = serde_json::to_string_pretty(&report)
        .map_err(|_| invalid("cannot encode ACME inspection report"))?;
    writeln!(io::stdout().lock(), "{output}")
}

/// Capture all confirmation inputs while holding the normal process author.
/// Missing cache directories are absent, not an invitation to initialize them.
/// Unsafe/malformed evidence fails closed with a fixed redacted error.
fn inspect(selection: &Selection) -> io::Result<Inspection> {
    let config = Config::offline_scope(
        &selection.public_origin,
        matches!(selection.environment, Environment::Production),
    )?;
    files::check_directory(&selection.data_dir, false)
        .map_err(|error| redacted(error, "cannot inspect ACME data directory"))?;
    let directory = fs::canonicalize(&selection.data_dir)
        .map_err(|error| redacted(error, "cannot inspect ACME data directory"))?;
    files::check_directory(&directory, false)
        .map_err(|error| redacted(error, "cannot inspect ACME data directory"))?;
    let author = Arc::new(
        store::lock(&directory)
            .map_err(|error| redacted(error, "ACME offline process authority is unavailable"))?,
    );
    let namespace = super::namespace(&config);
    let Some(cache) = Cache::open_existing(&directory, author, &namespace)
        .map_err(|error| redacted(error, "cannot inspect existing ACME cache"))?
    else {
        return Ok(Inspection::State(State::CacheAbsent));
    };
    let retry = load(&cache, "retry.json")?;
    Cache::retry_value(retry.as_deref().map(Vec::as_slice))
        .map_err(|error| redacted(error, "invalid ACME retry evidence"))?;
    let account = load(&cache, "account.der")?;
    if let Some(account) = &account {
        drop(issuer::account_key(account)?);
    }
    let Some(intent) = load(&cache, "order.json")? else {
        return Ok(Inspection::State(State::OrderAbsent));
    };
    let account =
        account.ok_or_else(|| invalid("ACME saved order requires its existing account"))?;
    match issuer::recovery_phase(&intent, &config)? {
        Phase::Ordered => return Ok(Inspection::State(State::Ordered)),
        Phase::Complete => return Ok(Inspection::State(State::Complete)),
        Phase::Failed => return Ok(Inspection::State(State::Failed)),
        Phase::Intent => {}
    }
    let (name, candidate) = match cache
        .order_temporary(issuer::MAX_WORK_BYTES)
        .map_err(|error| redacted(error, "invalid ACME order temporary evidence"))?
    {
        OrderTemporary::Absent => return Ok(Inspection::State(State::IntentUnknown)),
        OrderTemporary::Multiple => return Ok(Inspection::State(State::AmbiguousCandidates)),
        OrderTemporary::One { name, bytes } => (name, bytes),
    };
    issuer::check_order_candidate(&intent, &candidate, &config)?;
    let confirmation_sha256 = confirmation(
        &directory,
        &namespace,
        &account,
        &intent,
        &name,
        &candidate,
        retry.as_deref().map(Vec::as_slice),
    )?;
    Ok(Inspection::Ready(Ready {
        cache,
        confirmation_sha256,
        candidate,
    }))
}

/// Re-read the entire snapshot under exclusive authority, then publish only if
/// both the operator assertion and exact confirmation still match. Replacement
/// sync errors are propagated as unknown outcomes: never roll back or infer
/// success from a later locally Ordered file. No other cache entry is modified.
fn recover(selection: &Selection, expected: &str, account_unchanged: bool) -> io::Result<Report> {
    if !account_unchanged || !lower_hash(expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACME recovery requires a confirmation and --account-unchanged",
        ));
    }
    let Inspection::Ready(ready) = inspect(selection)? else {
        return Err(invalid(
            "ACME cache has no unique recoverable ordered result",
        ));
    };
    if ready.confirmation_sha256 != expected {
        return Err(invalid("ACME recovery evidence changed; inspect again"));
    }
    ready.cache.replace("order.json", &ready.candidate)?;
    Ok(Report::state(State::OrderedRestored))
}

fn load(cache: &Cache, name: &str) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    cache
        .load(name)
        .map_err(|error| redacted(error, "cannot read private ACME evidence"))
}

/// Domain-separated, length/presence-framed input binding, not a bearer secret.
/// The canonical OS path is intentionally local: confirmations cannot be moved
/// to a different directory even when its cache happens to contain equal bytes.
fn confirmation(
    directory: &Path,
    namespace: &str,
    account: &[u8],
    intent: &[u8],
    name: &str,
    candidate: &[u8],
    retry: Option<&[u8]>,
) -> io::Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"vproxy.acme.recover-order.confirmation.v1\0");
    for bytes in [
        directory.as_os_str().as_encoded_bytes(),
        namespace.as_bytes(),
        account,
        intent,
        name.as_bytes(),
        candidate,
    ] {
        framed(&mut hash, Some(bytes))?;
    }
    framed(&mut hash, retry)?;
    Ok(super::hex(&hash.finalize()))
}

fn framed(hash: &mut Sha256, bytes: Option<&[u8]>) -> io::Result<()> {
    match bytes {
        None => hash.update([0]),
        Some(bytes) => {
            let length =
                u64::try_from(bytes.len()).map_err(|_| invalid("ACME evidence is too large"))?;
            hash.update([1]);
            hash.update(length.to_be_bytes());
            hash.update(bytes);
        }
    }
    Ok(())
}

fn lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn redacted(error: io::Error, message: &'static str) -> io::Error {
    io::Error::new(error.kind(), message)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {

    use super::*;

    struct Fixture {
        selection: Selection,
        config: Config,
    }

    impl Fixture {
        fn new() -> io::Result<Self> {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("test entropy unavailable"))?;
            let directory = std::env::temp_dir().join(format!(
                "vproxy-acme-order-recovery-{:032x}",
                u128::from_ne_bytes(random),
            ));
            files::create_directory(&directory)?;
            // Match Cache's canonical root: Windows needs its extended-length
            // form when the namespace and digest-named temporary exceed MAX_PATH.
            let directory = fs::canonicalize(directory)?;
            let public_origin = "https://management.test".to_owned();
            let config = Config::offline_scope(&public_origin, false)?;
            Ok(Self {
                selection: Selection {
                    data_dir: directory,
                    public_origin,
                    environment: Environment::Staging,
                },
                config,
            })
        }

        fn directory(&self) -> PathBuf {
            self.selection
                .data_dir
                .join("acme")
                .join(super::super::namespace(&self.config))
        }

        fn cache(&self) -> io::Result<Cache> {
            Cache::open(
                &self.selection.data_dir,
                Arc::new(store::lock(&self.selection.data_dir)?),
                &super::super::namespace(&self.config),
            )
        }

        fn seed(&self) -> io::Result<issuer::RecoveryMaterial> {
            let material = issuer::recovery_material(&self.config)?;
            let (_, key) = instant_acme::Key::generate_pkcs8()
                .map_err(|_| io::Error::other("test account generation failed"))?;
            let key = Zeroizing::new(key);
            let cache = self.cache()?;
            cache.create("account.der", key.secret_pkcs8_der())?;
            cache.create("order.json", &material.intent)?;
            // Identity is deliberately opaque: offline recovery must not read,
            // rewrite or purport to validate the separately active TLS bundle.
            cache.create("identity.pem", b"unchanged opaque identity fixture")?;
            self.write_candidate(&material.ordered)?;
            Ok(material)
        }

        fn write_candidate(&self, bytes: &[u8]) -> io::Result<()> {
            files::write(&self.directory(), &temporary_name(bytes), bytes)
        }

        fn token(&self) -> io::Result<String> {
            let report = inspect(&self.selection)?.report();
            assert!(report.state == State::RecoverableOrdered);
            report
                .confirmation_sha256
                .ok_or_else(|| invalid("test confirmation missing"))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // Only the exclusively created private fixture is removed. Tests
            // never open a real cache, database, CA endpoint or listener.
            let _ = fs::remove_dir_all(&self.selection.data_dir);
        }
    }

    fn temporary_name(bytes: &[u8]) -> String {
        format!(
            ".order.json.{}.tmp",
            super::super::hex(&Sha256::digest(bytes))
        )
    }

    #[test]
    fn unique_ordered_result_restores_exact_bytes_and_preserves_other_cache_state() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        let seed = fixture.seed()?;
        let cache = fixture.cache()?;
        cache.advance_retry(120)?;
        drop(cache);
        let token = fixture.token()?;
        let report = recover(&fixture.selection, &token, true)?;
        assert!(report.state == State::OrderedRestored);
        assert!(report.confirmation_sha256.is_none());
        let author = Arc::new(store::lock(&fixture.selection.data_dir)?);
        let cache = Cache::open_existing(
            &fixture.selection.data_dir,
            author,
            &super::super::namespace(&fixture.config),
        )?
        .ok_or_else(|| invalid("test cache absent"))?;
        let actual = cache
            .load("order.json")?
            .ok_or_else(|| invalid("test order absent"))?;
        assert!(actual.as_slice() == seed.ordered.as_slice());
        assert!(issuer::recovery_phase(&actual, &fixture.config)? == Phase::Ordered);
        assert_eq!(cache.retry_at()?, 120);
        drop(cache);
        let report = inspect(&fixture.selection)?.report();
        assert!(report.state == State::Ordered && report.confirmation_sha256.is_none());
        assert!(recover(&fixture.selection, &token, true).is_err());
        Ok(())
    }
}
