//! One-origin ACME HTTPS exchanges with explicit byte and waiting limits.
//!
//! Only the caller's TLS roots are used. Proxies and redirects are disabled,
//! so signed requests remain bound to their configured origin.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http::{HeaderValue, Request, Version, header};
use http_body_util::{BodyExt as _, LengthLimitError, Limited};
use hyper::body::Body as _;
use instant_acme::{BodyWrapper, BytesResponse};
use rustls::ClientConfig;
use tokio::{sync::OwnedSemaphorePermit, time::timeout};

use super::Io;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_URI_BYTES: usize = 8192;
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Cloneable adapter for one configured ACME origin, not a general HTTP proxy.
/// Idle connections and retries are disabled. Already-submitted cache work may
/// outlive cancellation while retaining its writer permit and process author.
#[derive(Clone)]
pub(super) struct Client {
    origin: url::Origin,
    http: reqwest::Client,
    budget: Duration,
    retry_at: Arc<AtomicU64>,
    persistence: Option<Io>,
}

impl Client {
    /// Pin a canonical HTTPS directory's origin and the supplied TLS policy.
    ///
    /// Userinfo, fragments, zero ports, noncanonical URLs and inputs over 8 KiB
    /// fail before any network I/O. This does not check public reachability or
    /// trust the directory; production CA selection remains the caller's job.
    pub(super) fn new(directory: &str, tls: Arc<ClientConfig>, io: Io) -> io::Result<Self> {
        let retry_at = io.cache.retry_at()?;
        Self::configured(directory, tls, Some(io), retry_at)
    }

    fn configured(
        directory: &str,
        tls: Arc<ClientConfig>,
        persistence: Option<Io>,
        retry_at: u64,
    ) -> io::Result<Self> {
        let origin = canonical_url(directory)?.origin();
        let http = reqwest::Client::builder()
            .use_preconfigured_tls((*tls).clone())
            .https_only(true)
            .http1_only()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|_| failure(io::ErrorKind::Other, "configuration"))?;
        Ok(Self {
            origin,
            http,
            budget: REQUEST_TIMEOUT,
            retry_at: Arc::new(AtomicU64::new(retry_at)),
            persistence,
        })
    }

    /// A CA rate/service limit applies to the next whole attempt, including its
    /// directory/account reads. Clones share the longest advertised not-before.
    pub(super) fn retry_at(&self) -> u64 {
        self.retry_at.load(Ordering::Relaxed)
    }

    fn record_retry(&self, response: &mut reqwest::Response) -> Option<u64> {
        // HTTP-date and delay-seconds are both allowed; do not shorten a CA's
        // limit to the local exponential-backoff maximum.
        // https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3
        let header = response.headers().get(header::RETRY_AFTER)?;
        let time = header
            .to_str()
            .ok()
            .and_then(|value| retry_time(value, SystemTime::now()));
        if let Some(time) = time {
            self.retry_at.fetch_max(time, Ordering::Relaxed);
            // instant-acme adds numeric seconds to SystemTime without checked
            // arithmetic. Pass only a checked absolute HTTP date to the library,
            // including processing (2xx) replies it may otherwise forget.
            let value = UNIX_EPOCH
                .checked_add(Duration::from_secs(time))
                .filter(|until| {
                    // The library also adds the delay to Instant unchecked.
                    // Keep an unrepresentable deadline in our network gate,
                    // but do not expose it to that upstream arithmetic.
                    let wait = until.duration_since(SystemTime::now()).unwrap_or_default();
                    wait <= self.budget && std::time::Instant::now().checked_add(wait).is_some()
                })
                .map(httpdate::fmt_http_date)
                .and_then(|value| HeaderValue::from_str(&value).ok());
            if let Some(value) = value {
                response.headers_mut().insert(header::RETRY_AFTER, value);
                return Some(time);
            }
        }
        response.headers_mut().remove(header::RETRY_AFTER);
        time
    }

    /// Reserve before network activity, then retain the slot until headers are
    /// observed. Every request rechecks the current private record; nonzero max
    /// is flushed again so an earlier cancelled/failed sync is not treated as a
    /// confirmed publication merely because its bytes can be read back.
    async fn reserve_retry(&self) -> io::Result<Option<OwnedSemaphorePermit>> {
        let Some(io) = &self.persistence else {
            return Ok(None);
        };
        let permit = io.reserve().await?;
        let retry_at = self.retry_at.clone();
        io.start_reserved(permit, move |cache, permit| {
            let latest = cache.retry_at()?.max(retry_at.load(Ordering::Relaxed));
            let confirmed = if latest != 0 {
                cache.advance_retry(latest)?
            } else {
                0
            };
            retry_at.fetch_max(confirmed, Ordering::Relaxed);
            Ok(permit)
        })
        .await
        .map_err(|_| failure(io::ErrorKind::Other, "retry_worker"))?
        .map(Some)
        .map_err(|error| failure(error.kind(), "retry_state"))
    }

    /// Validate locally produced request bytes before opening a socket. The
    /// concrete BodyWrapper has an exact local size hint, not a remote stream.
    fn prepare(&self, request: &mut Request<BodyWrapper<Bytes>>) -> io::Result<()> {
        let url = canonical_url(&request.uri().to_string())?;
        if url.origin() != self.origin {
            return Err(failure(io::ErrorKind::InvalidInput, "origin"));
        }
        if request
            .body()
            .size_hint()
            .upper()
            .is_none_or(|length| length > MAX_REQUEST_BYTES)
        {
            return Err(failure(io::ErrorKind::InvalidInput, "request_limit"));
        }
        *request.version_mut() = Version::HTTP_11;
        request.headers_mut().remove(header::HOST);
        // https://www.rfc-editor.org/rfc/rfc8555.html#section-6.1
        request.headers_mut().insert(
            header::USER_AGENT,
            HeaderValue::from_static(concat!(
                "vproxy/",
                env!("CARGO_PKG_VERSION"),
                " instant-acme/0.8.5"
            )),
        );
        Ok(())
    }

    /// Preflight, DNS/connect/TLS/header/body and persistence waiting share one
    /// deadline. Cancellation closes the exchange, not dispatched cache
    /// work or an OS DNS lookup; it cannot forcibly kill blocking operations.
    async fn exchange(&self, request: Request<BodyWrapper<Bytes>>) -> io::Result<BytesResponse> {
        timeout(self.budget, self.once(request))
            .await
            .map_err(|_| failure(io::ErrorKind::TimedOut, "timeout"))?
    }

    async fn once(&self, mut request: Request<BodyWrapper<Bytes>>) -> io::Result<BytesResponse> {
        self.prepare(&mut request)?;
        let mut reservation = self.reserve_retry().await?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| failure(io::ErrorKind::InvalidData, "clock"))?;
        let wait = Duration::from_secs(self.retry_at()).saturating_sub(now);
        if wait >= self.budget {
            return Err(failure(io::ErrorKind::WouldBlock, "retry_after"));
        }
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        let (parts, body) = request.into_parts();
        let body = body
            .collect()
            .await
            .map_err(|_| failure(io::ErrorKind::Other, "request"))?
            .to_bytes();
        let mut response = self
            .http
            .request(parts.method, parts.uri.to_string())
            .version(parts.version)
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map_err(|_| failure(io::ErrorKind::Other, "http"))?;
        let hint = self.record_retry(&mut response);
        if let (Some(_), Some(permit), Some(io)) =
            (hint, reservation.take(), self.persistence.as_ref())
        {
            let retry_at = self.retry_at.clone();
            let candidate = self.retry_at();
            // No await occurs between reading the header and this actual
            // submission. Cancellation can drop only the waiter, not the
            // worker's reserved permit, Cache clone or process author.
            let worker = io.start_reserved(permit, move |cache, _permit| {
                let confirmed = cache.advance_retry(candidate)?;
                retry_at.fetch_max(confirmed, Ordering::Relaxed);
                Ok(())
            });
            worker
                .await
                .map_err(|_| failure(io::ErrorKind::Other, "retry_worker"))?
                .map_err(|error| failure(error.kind(), "retry_persist"))?;
        }
        // ACME resource URLs are obtained from the configured directory,
        // not by following HTTP redirects. Preserve Location on e.g. 201.
        // https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4
        if response.status().is_redirection() {
            return Err(failure(io::ErrorKind::InvalidData, "redirect"));
        }
        let (parts, body) = http::Response::<reqwest::Body>::from(response).into_parts();
        let body = Limited::new(body, MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|error| {
                if error.is::<LengthLimitError>() {
                    failure(io::ErrorKind::InvalidData, "response_limit")
                } else {
                    failure(io::ErrorKind::Other, "body")
                }
            })?
            .to_bytes();
        Ok(BytesResponse {
            parts,
            body: Box::new(body),
        })
    }
}

fn retry_time(value: &str, now: SystemTime) -> Option<u64> {
    let value = value.trim_matches([' ', '\t']);
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        let seconds = value.parse::<u64>().ok()?;
        let until = now.checked_add(Duration::from_secs(seconds))?;
        let elapsed = until.duration_since(UNIX_EPOCH).ok()?;
        let time = elapsed
            .as_secs()
            .checked_add(u64::from(elapsed.subsec_nanos() != 0))?;
        // httpdate's formatter accepts only years 1970..=9999. Bounding before
        // formatting avoids both an upstream SystemTime overflow and a panic.
        return (time <= super::storage::MAX_RETRY_AT).then_some(time);
    }
    let time = httpdate::parse_http_date(value)
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    (time <= super::storage::MAX_RETRY_AT).then_some(time)
}

impl instant_acme::HttpClient for Client {
    fn request(
        &self,
        request: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let client = self.clone();
        Box::pin(async move {
            client
                .exchange(request)
                .await
                .map_err(|error| instant_acme::Error::Other(Box::new(error)))
        })
    }
}

fn canonical_url(value: &str) -> io::Result<url::Url> {
    let invalid = || failure(io::ErrorKind::InvalidInput, "origin");
    if value.len() > MAX_URI_BYTES || value.chars().any(char::is_control) {
        return Err(invalid());
    }
    let url = url::Url::parse(value).map_err(|_| invalid())?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
        || url.as_str() != value
    {
        return Err(invalid());
    }
    Ok(url)
}

/// Only fixed local labels enter diagnostics. Source errors can contain a
/// request URI, arbitrary peer body or headers, so never retain them as sources.
fn failure(kind: io::ErrorKind, stage: &'static str) -> io::Error {
    io::Error::new(kind, format!("ACME transport failed ({stage})"))
}

#[cfg(test)]
mod tests {
    //! In-memory test identities and owned loopback sockets only. No public ACME,
    //! persistent keys, environment changes or trust-store operations.

    use rustls::{RootCertStore, ServerConfig, crypto::aws_lc_rs};
    use rustls_pki_types::PrivatePkcs8KeyDer;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
        sync::Notify,
        task::JoinSet,
    };
    use tokio_rustls::TlsAcceptor;

    use super::*;

    const TEST_WAIT: Duration = Duration::from_secs(5);
    const PRIVATE_RESPONSE: &str = "peer-private-body-must-not-enter-diagnostics";

    struct DiskFixture(std::path::PathBuf);

    impl DiskFixture {
        fn new() -> io::Result<Self> {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(|_| io::Error::other("fixture entropy failed"))?;
            let path = std::env::temp_dir().join(format!(
                "vproxy-acme-retry-{:032x}",
                u128::from_ne_bytes(random)
            ));
            super::super::super::files::create_directory(&path)?;
            Ok(Self(path))
        }

        fn io(&self) -> io::Result<Io> {
            let author = Arc::new(super::super::super::store::lock(&self.0)?);
            Ok(Io {
                cache: super::super::storage::Cache::open(&self.0, author, &"a".repeat(64))?,
                capacity: Arc::new(tokio::sync::Semaphore::new(1)),
            })
        }
    }

    impl Drop for DiskFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn retry_header_worker_owns_authority_after_cancel_and_keeps_a_buffered_response()
    -> io::Result<()> {
        // A single blocking thread lets the fixture queue the real publication
        // after headers without adding a production hook or sleeping on a race.
        // Runtime drop precedes private-directory removal and drains workers.
        for (cancel, truncated) in [(false, false), (true, false), (false, true)] {
            let fixture = DiskFixture::new()?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .max_blocking_threads(1)
                .build()?;
            runtime.block_on(async {
                let mut tasks: JoinSet<io::Result<()>> = JoinSet::new();
                let outcome: io::Result<()> = async {
                    let (server, tls) = identity()?;
                    let ready = Arc::new(Notify::new());
                    let proceed = Arc::new(Notify::new());
                    let bytes = if truncated {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nRetry-After: 3600\r\n\r\nx".to_vec()
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nRetry-After: 3600\r\n\r\ninvalid-extra".to_vec()
                    };
                    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
                    let origin = format!("https://{}", listener.local_addr()?);
                    let (closed, closure) = tokio::sync::oneshot::channel();
                    let peer_ready = ready.clone();
                    let peer_proceed = proceed.clone();
                    tasks.spawn(async move {
                        let (socket, _) = listener.accept().await?;
                        let mut stream = TlsAcceptor::from(server).accept(socket).await?;
                        let mut head = Vec::new();
                        while !head.ends_with(b"\r\n\r\n") {
                            head.push(stream.read_u8().await?);
                        }
                        peer_ready.notify_one();
                        peer_proceed.notified().await;
                        stream.write_all(&bytes).await?;
                        stream.flush().await?;
                        if truncated { stream.shutdown().await?; }
                        let mut buffer = [0; 1024];
                        while matches!(stream.read(&mut buffer).await, Ok(n) if n != 0) {}
                        let _ = closed.send(());
                        Ok(())
                    });
                    let io = fixture.io()?;
                    let capacity = io.capacity.clone();
                    let client = Client::new(&format!("{}/directory", origin), tls.clone(), io.clone())?;
                    let shared_retry = client.retry_at.clone();
                    let requesting = client.clone();
                    let outgoing = request(&format!("{}/resource", origin))?;
                    let task = tokio::spawn(async move {
                        requesting.exchange(outgoing).await.map(|response| response.parts.status)
                    });
                    timeout(TEST_WAIT, ready.notified()).await.map_err(io::Error::other)?;
                    let (started, began) = tokio::sync::oneshot::channel();
                    let (release, wait) = std::sync::mpsc::channel();
                    let blocker = tokio::task::spawn_blocking(move || {
                        let _ = started.send(());
                        wait.recv().map_err(|_| io::Error::other("fixture release dropped"))
                    });
                    timeout(TEST_WAIT, began).await.map_err(io::Error::other)?.map_err(io::Error::other)?;
                    proceed.notify_one();
                    timeout(TEST_WAIT, async {
                        while shared_retry.load(Ordering::Relaxed) == 0 {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    }).await.map_err(io::Error::other)?;
                    let task = if cancel {
                        task.abort();
                        assert!(task.await.is_err_and(|error| error.is_cancelled()));
                        None
                    } else { Some(task) };
                    drop(client);
                    drop(io);
                    assert_eq!(capacity.available_permits(), 0);
                    assert_eq!(super::super::super::store::lock(&fixture.0).err().map(|error| error.kind()), Some(io::ErrorKind::WouldBlock));
                    release.send(()).map_err(io::Error::other)?;
                    timeout(TEST_WAIT, blocker).await.map_err(io::Error::other)?.map_err(io::Error::other)??;
                    let permit = timeout(TEST_WAIT, capacity.acquire()).await.map_err(io::Error::other)?.map_err(io::Error::other)?;
                    drop(permit);
                    if let Some(task) = task {
                        let result = timeout(TEST_WAIT, task).await.map_err(io::Error::other)?.map_err(io::Error::other)?;
                        if truncated {
                            // Finishing the driver must not turn an incomplete
                            // body into success while its hint is being saved.
                            rejected(result, "body")?;
                        } else {
                            assert_eq!(result?, http::StatusCode::OK);
                        }
                    }
                    timeout(TEST_WAIT, closure).await.map_err(io::Error::other)?.map_err(io::Error::other)?;
                    // Permit release precedes the worker's Cache/author drop.
                    // On this one-thread blocking pool, a joined barrier proves
                    // that worker has returned before claiming a fresh author.
                    tokio::task::spawn_blocking(|| ()).await.map_err(io::Error::other)?;
                    let io = fixture.io()?;
                    let persisted = io.work(|cache| cache.retry_at()).await?;
                    assert_eq!(persisted, shared_retry.load(Ordering::Relaxed));
                    assert!(persisted > SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_secs());
                    let restarted = Client::new(&format!("{}/directory", origin), tls, io)?;
                    assert_eq!(restarted.retry_at(), persisted);
                    rejected(restarted.exchange(request(&format!("{}/resource", origin))?).await, "retry_after")?;
                    Ok(())
                }.await;
                tasks.shutdown().await;
                outcome
            })?;
        }
        Ok(())
    }

    fn identity() -> io::Result<(Arc<ServerConfig>, Arc<ClientConfig>)> {
        let identity = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()])
            .map_err(io::Error::other)?;
        let mut roots = RootCertStore::empty();
        roots
            .add(identity.cert.der().clone())
            .map_err(io::Error::other)?;
        let key = PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der());
        let mut server =
            ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(io::Error::other)?
                .with_no_client_auth()
                .with_single_cert(vec![identity.cert.der().clone()], key.into())
                .map_err(io::Error::other)?;
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut client =
            ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(io::Error::other)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        client.enable_early_data = false;
        client.resumption = rustls::client::Resumption::disabled();
        Ok((Arc::new(server), Arc::new(client)))
    }

    fn request(uri: &str) -> io::Result<Request<BodyWrapper<Bytes>>> {
        Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/jose+json")
            .body(Vec::<u8>::new().into())
            .map_err(io::Error::other)
    }

    fn rejected<T>(result: io::Result<T>, stage: &str) -> io::Result<()> {
        let error = result
            .err()
            .ok_or_else(|| io::Error::other("expected transport rejection"))?;
        assert_eq!(
            error.to_string(),
            format!("ACME transport failed ({stage})")
        );
        assert!(!format!("{error:?}").contains(PRIVATE_RESPONSE));
        Ok(())
    }
}
