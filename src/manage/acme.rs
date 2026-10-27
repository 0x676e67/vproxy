//! Browser-only automatic HTTPS identity, independent of node mTLS and proxy TLS.
//!
//! Accounts and pending orders survive cancellation/restart before any retry.
//! No listener performs issuance, disk I/O, or a CA request during its handshake.

pub(super) mod backup;
mod config;
mod http;
mod issuer;
mod recovery;
mod roots;
mod status;
mod storage;
mod tls;
mod transport;

use std::{io, net::SocketAddr, path::Path, sync::Arc, time::Duration};

use rustls::{ClientConfig, RootCertStore, crypto::aws_lc_rs};
use rustls_pki_types::UnixTime;
use sha2::{Digest as _, Sha256};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub use config::Options;
pub(super) use config::PlanOptions;
use config::{Challenge, Config};
pub use recovery::Command;
pub(super) use recovery::run as run_offline;
pub(super) use status::{Failure, Handle, Observation, View};
pub(super) use tls::Tls;
use transport::Client;

const ORDER_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_SLEEP: Duration = Duration::from_secs(24 * 60 * 60);

/// Prepared offline under the existing data-directory author. CA traffic starts
/// only after every required listener has bound and joined the supervisor.
pub(super) struct Prepared {
    runner: Runner,
    http_bind: Option<SocketAddr>,
}

impl Prepared {
    fn new(config: Config, directory: &Path, author: Arc<super::store::Guard>) -> io::Result<Self> {
        let roots = Arc::new(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        });
        let identity_roots = Arc::new(roots::identity_roots(config.production)?);
        if !config.production {
            tracing::warn!("ACME staging selected; issued certificates are not browser-trusted");
        }
        let cache = storage::Cache::open(directory, author, &namespace(&config))?;
        let tls = Tls::new(config.domain.clone())?;
        let mut due = 0;
        let mut certificate = None;
        if let Some(pem) = cache.load("identity.pem")? {
            if cache.load("account.der")?.is_none() {
                return Err(invalid("ACME identity has no durable account key"));
            }
            let identity = cached_identity(&pem, &config.domain, &identity_roots, UnixTime::now())?;
            let now = UnixTime::now().as_secs();
            // Historical validation only permits renewal after downtime. It
            // never makes an expired/not-yet-valid identity available to TLS.
            if identity.not_before <= now && now <= identity.not_after {
                due = renew_at(identity.not_before, identity.not_after)?;
                let validity = (identity.not_before, identity.not_after);
                tls.publish(identity)?;
                certificate = Some(validity);
            }
        }
        let mut client =
            ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| invalid("cannot configure ACME client TLS 1.3"))?
                .with_root_certificates((*roots).clone())
                .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        client.enable_early_data = false;
        client.resumption = rustls::client::Resumption::disabled();
        let io = Io {
            cache,
            capacity: Arc::new(Semaphore::new(1)),
        };
        let client = Client::new(&config.directory, Arc::new(client), io.clone())?;
        due = due.max(client.retry_at());
        let http = http::Http::new(config.domain.clone());
        let status = Handle::new(config.production, config.challenge, certificate, due);
        Ok(Self {
            http_bind: config.http_bind,
            runner: Runner {
                config,
                io,
                client,
                roots: identity_roots,
                tls,
                http,
                due,
                status,
            },
        })
    }

    pub(super) fn tls(&self) -> Tls {
        self.runner.tls.clone()
    }

    pub(super) fn status(&self) -> Handle {
        self.runner.status.clone()
    }

    pub(super) fn http(&self) -> Option<(SocketAddr, http::Http)> {
        self.http_bind.map(|bind| (bind, self.runner.http.clone()))
    }

    pub(super) async fn run(self, shutdown: CancellationToken) -> io::Result<()> {
        self.runner.run(shutdown).await
    }
}

impl Options {
    pub(super) fn prepare(
        &self,
        origin: &str,
        directory: &Path,
        author: Arc<super::store::Guard>,
    ) -> io::Result<Option<Prepared>> {
        self.configure(origin)?
            .map(|config| Prepared::new(config, directory, author))
            .transpose()
    }
}

/// One writer permit belongs to the actual blocking worker. Cancellation drops
/// its async waiter, but cannot release process authority or allow another disk
/// mutation while that worker is still flushing an earlier publication.
#[derive(Clone)]
struct Io {
    cache: storage::Cache,
    capacity: Arc<Semaphore>,
}

impl Io {
    async fn reserve(&self) -> io::Result<OwnedSemaphorePermit> {
        self.capacity
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("ACME cache worker is unavailable"))
    }

    /// Submit without an await between observing a CA hint and transferring
    /// its reserved permit/author to real blocking work. The operation may
    /// return the permit when a preflight must retain it through network I/O.
    fn start_reserved<R: Send + 'static>(
        &self,
        permit: OwnedSemaphorePermit,
        operation: impl FnOnce(storage::Cache, OwnedSemaphorePermit) -> io::Result<R> + Send + 'static,
    ) -> JoinHandle<io::Result<R>> {
        let cache = self.cache.clone();
        tokio::task::spawn_blocking(move || operation(cache, permit))
    }

    async fn work<R: Send + 'static>(
        &self,
        operation: impl FnOnce(storage::Cache) -> io::Result<R> + Send + 'static,
    ) -> io::Result<R> {
        let permit = self.reserve().await?;
        self.start_reserved(permit, move |cache, _permit| operation(cache))
            .await
            .map_err(|_| io::Error::other("ACME cache worker failed"))?
    }

    async fn load(&self, name: &'static str) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        self.work(move |cache| cache.load(name)).await
    }

    async fn create(&self, name: &'static str, bytes: Zeroizing<Vec<u8>>) -> io::Result<()> {
        self.work(move |cache| cache.create(name, &bytes)).await
    }

    async fn replace(&self, name: &'static str, bytes: Zeroizing<Vec<u8>>) -> io::Result<()> {
        self.work(move |cache| cache.replace(name, &bytes)).await
    }
}

/// The supervisor owns this future. Transient issuance errors retain the last
/// valid certificate and durable order; unexpected task exit still stops sibling
/// listeners through the existing management supervisor.
struct Runner {
    config: Config,
    io: Io,
    client: Client,
    roots: Arc<RootCertStore>,
    tls: Tls,
    http: http::Http,
    due: u64,
    status: Handle,
}

impl Drop for Runner {
    fn drop(&mut self) {
        // The runner owner also exists before its future's first poll. Dropping
        // an unpolled/aborted future cannot leave a phantom active observer.
        self.status.stopped();
    }
}

impl Runner {
    async fn run(mut self, shutdown: CancellationToken) -> io::Result<()> {
        let mut retry_secs = 60_u64;
        self.status.waiting(self.due);
        loop {
            let wait = Duration::from_secs(self.due.saturating_sub(UnixTime::now().as_secs()))
                .min(MAX_SLEEP);
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return Ok(()),
                _ = tokio::time::sleep(wait) => {},
            }
            if UnixTime::now().as_secs() < self.due {
                continue;
            }
            self.status.begin();
            let issued = tokio::select! {
                biased;
                _ = shutdown.cancelled() => return Ok(()),
                result = timeout(ORDER_TIMEOUT, issuer::issue(
                    &self.config, self.client.clone(), &self.io, &self.tls, &self.http, &self.roots,
                )) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ACME order timed out")).and_then(|result| result),
            };
            match issued {
                Ok(identity) => {
                    let due = renew_at(identity.not_before, identity.not_after)?;
                    let validity = (identity.not_before, identity.not_after);
                    self.tls.publish(identity)?;
                    tracing::info!("ACME browser certificate saved and activated");
                    // A CA returning an unusually short validity must not turn
                    // the renew-at boundary into an unbounded issuance loop.
                    self.due = due
                        .max(UnixTime::now().as_secs().saturating_add(60))
                        .max(self.client.retry_at());
                    retry_secs = 60;
                    self.status.completed(validity, self.due);
                }
                Err(error) => {
                    self.status.failed(error.kind());
                    let paused = matches!(
                        error.kind(),
                        io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidData
                    );
                    // Issuer errors contain only fixed local labels, never CA
                    // response bodies, tokens, contacts, URLs or private keys.
                    tracing::warn!(kind = ?error.kind(), reason = %error, paused, "ACME issuance unavailable; durable state and current identity retained");
                    let delay = if paused { 3600 } else { retry_secs };
                    self.due = UnixTime::now()
                        .as_secs()
                        .saturating_add(delay + jitter())
                        .max(self.client.retry_at());
                    retry_secs = retry_secs.saturating_mul(2).min(3600);
                    // A timeout may race the successful atomic identity/order
                    // write. Re-read before another issuance decision, including
                    // after a worker outlived the cancelled async waiter.
                    let recovered = tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => return Ok(()),
                        result = self.recover() => result,
                    };
                    match recovered {
                        Ok(Some(due)) if due > UnixTime::now().as_secs() => {
                            self.due = due.max(self.client.retry_at())
                        }
                        Ok(_) => {}
                        Err(error) => {
                            self.status.recovery_failed(error.kind());
                            tracing::warn!(kind = ?error.kind(), "ACME durable identity could not be reloaded")
                        }
                    }
                    self.status.waiting(self.due);
                }
            }
        }
    }

    async fn recover(&self) -> io::Result<Option<u64>> {
        let Some(pem) = self.io.load("identity.pem").await? else {
            return Ok(None);
        };
        let identity = cached_identity(&pem, &self.config.domain, &self.roots, UnixTime::now())?;
        let now = UnixTime::now().as_secs();
        if identity.not_before > now || now > identity.not_after {
            return Ok(None);
        }
        let due = renew_at(identity.not_before, identity.not_after)?;
        let validity = (identity.not_before, identity.not_after);
        self.tls.publish(identity)?;
        self.status.activated(validity);
        Ok(Some(due))
    }
}

fn jitter() -> u64 {
    let mut value = [0; 2];
    // Entropy failure changes only retry spacing, never key generation or trust.
    if getrandom::fill(&mut value).is_ok() {
        u64::from(u16::from_ne_bytes(value) % 31)
    } else {
        0
    }
}

fn namespace(config: &Config) -> String {
    let mut hash = Sha256::new();
    hash.update(config.domain.as_bytes());
    hash.update([0]);
    hash.update(config.directory.as_bytes());
    hex(&hash.finalize())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

fn renew_at(before: u64, after: u64) -> io::Result<u64> {
    let lifetime = after
        .checked_sub(before)
        .filter(|value| *value != 0)
        .ok_or_else(|| invalid("ACME certificate validity is empty"))?;
    // Divide before multiplying so even an untrusted u64 interval cannot wrap.
    before
        .checked_add((lifetime / 3) * 2 + ((lifetime % 3) * 2) / 3)
        .ok_or_else(|| invalid("ACME renewal time overflow"))
}

/// Check expired cache signatures/keys at a time within the leaf's lifetime so
/// renewal after downtime does not require deleting account/order continuity.
/// Only a separately current-time-gated identity can be published by the caller.
fn cached_identity(
    pem: &[u8],
    domain: &str,
    roots: &RootCertStore,
    now: UnixTime,
) -> io::Result<tls::Identity> {
    let mut reader = pem;
    let leaf = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| invalid("ACME cached identity certificate is missing"))?
        .map_err(|_| invalid("invalid ACME cached identity PEM"))?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&leaf)
        .map_err(|_| invalid("invalid ACME cached identity leaf"))?;
    let before = u64::try_from(parsed.validity().not_before.timestamp())
        .map_err(|_| invalid("invalid ACME cached validity"))?;
    let after = u64::try_from(parsed.validity().not_after.timestamp())
        .map_err(|_| invalid("invalid ACME cached validity"))?;
    if before >= after {
        return Err(invalid("ACME cached validity is empty"));
    }
    let time = now.as_secs().clamp(before, after.saturating_sub(1));
    tls::identity(
        pem,
        domain,
        roots,
        UnixTime::since_unix_epoch(Duration::from_secs(time)),
    )
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> io::Result<Self> {
            let mut random = [0; 16];
            getrandom::fill(&mut random).map_err(|_| io::Error::other("test entropy failed"))?;
            let path = std::env::temp_dir().join(format!(
                "vproxy-acme-worker-{:032x}",
                u128::from_ne_bytes(random)
            ));
            super::super::files::create_directory(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Unblocks the exclusively owned fixture worker even after an assertion
    /// panic. Its bounded channel is not part of production cancellation.
    struct Release(Option<std::sync::mpsc::Sender<()>>);

    impl Drop for Release {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test]
    async fn cancelled_waiter_keeps_writer_permit_and_author_until_worker_finishes()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let author = Arc::new(super::super::store::lock(&fixture.0)?);
        let cache = storage::Cache::open(&fixture.0, author.clone(), &"a".repeat(64))?;
        let io = Io {
            cache,
            capacity: Arc::new(Semaphore::new(1)),
        };
        let capacity = io.capacity.clone();
        let (started, began) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let release = Release(Some(release));
        let waiter = tokio::spawn(async move {
            io.work(move |_cache| {
                let _ = started.send(());
                wait.recv()
                    .map_err(|_| io::Error::other("test release dropped"))
            })
            .await
        });
        timeout(Duration::from_secs(5), began)
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        waiter.abort();
        assert!(waiter.await.is_err_and(|error| error.is_cancelled()));
        drop(author);
        assert_eq!(capacity.available_permits(), 0);
        assert_eq!(
            super::super::store::lock(&fixture.0)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        drop(release);
        let permit = timeout(Duration::from_secs(5), capacity.acquire())
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        drop(permit);
        drop(super::super::store::lock(&fixture.0)?);
        Ok(())
    }

    #[test]
    fn renewal_arithmetic_handles_short_and_maximum_intervals() -> io::Result<()> {
        assert_eq!(renew_at(100, 190)?, 160);
        assert_eq!(renew_at(100, 101)?, 100);
        assert!(renew_at(1, 1).is_err());
        assert!(renew_at(10, 9).is_err());
        assert!(renew_at(0, u64::MAX)? < u64::MAX);
        assert_eq!(renew_at(u64::MAX - 3, u64::MAX)?, u64::MAX - 1);
        Ok(())
    }

    #[test]
    fn prepared_reloads_cooldown_before_startup_and_rejects_corrupt_state() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let author = Arc::new(super::super::store::lock(&fixture.0)?);
        let config = Config {
            domain: "retry.example".into(),
            directory: instant_acme::LetsEncrypt::Staging.url().into(),
            production: false,
            contacts: Vec::new(),
            challenge: Challenge::TlsAlpn01,
            http_bind: None,
        };
        let cache = storage::Cache::open(&fixture.0, author.clone(), &namespace(&config))?;
        let due = UnixTime::now().as_secs() + 7200;
        cache.advance_retry(due)?;
        let prepared = Prepared::new(config.clone(), &fixture.0, author.clone())?;
        assert_eq!(prepared.runner.due, due);
        assert_eq!(prepared.runner.client.retry_at(), due);
        let view = serde_json::to_value(prepared.status().view()?).map_err(io::Error::other)?;
        assert_eq!(view["next_attempt_at_unix_s"], due.to_string());
        drop(prepared);
        let corrupt = br#"{"version":2,"not_before_unix_s":0}"#;
        cache.replace("retry.json", corrupt)?;
        assert_eq!(
            Prepared::new(config, &fixture.0, author)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
        assert_eq!(
            cache.load("retry.json")?.as_deref().map(Vec::as_slice),
            Some(corrupt.as_slice())
        );
        Ok(())
    }

    #[test]
    fn dropping_an_unpolled_prepared_runner_stops_only_its_observation() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let author = Arc::new(super::super::store::lock(&fixture.0)?);
        let prepared = Prepared::new(
            Config {
                domain: "status.example".into(),
                directory: instant_acme::LetsEncrypt::Staging.url().into(),
                production: false,
                contacts: Vec::new(),
                challenge: Challenge::TlsAlpn01,
                http_bind: None,
            },
            &fixture.0,
            author,
        )?;
        let status = prepared.status();
        let unpolled = prepared.run(CancellationToken::new());
        drop(unpolled);
        let view = serde_json::to_value(status.view()?).map_err(io::Error::other)?;
        assert_eq!(view["activity"], "stopped");
        assert!(view["certificate"].is_null() && view["next_attempt_at_unix_s"].is_null());
        drop(super::super::store::lock(&fixture.0)?);
        Ok(())
    }
}
