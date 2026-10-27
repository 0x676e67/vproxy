//! One-origin ACME HTTPS exchanges with explicit byte and waiting limits.
//!
//! Only the caller's TLS roots are used. Direct sockets do not consult proxy
//! environment variables, and redirects cannot move signed requests elsewhere.

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
use http::{HeaderValue, Request, Uri, Version, header};
use http_body_util::BodyExt as _;
use hyper::body::Body as _;
use hyper_util::rt::TokioIo;
use instant_acme::{BodyWrapper, BytesResponse};
use rustls::{ClientConfig, ProtocolVersion};
use rustls_pki_types::ServerName;
use tokio::{net::TcpStream, sync::OwnedSemaphorePermit, time::timeout};
use tokio_rustls::TlsConnector;

use super::Io;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_URI_BYTES: usize = 8192;
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Cloneable adapter for one configured ACME origin, not a general HTTP proxy.
/// Each request owns its socket and driver. Already-submitted cache work may
/// outlive cancellation while retaining its writer permit and process author.
#[derive(Clone)]
pub(super) struct Client {
    origin: Arc<Origin>,
    tls: Arc<ClientConfig>,
    budget: Duration,
    retry_at: Arc<AtomicU64>,
    persistence: Option<Io>,
}

/// The validated directory's authority also pins every later ACME resource.
/// Resource paths may differ; scheme, host and port may not.
struct Origin {
    value: String,
    host: String,
    authority: HeaderValue,
    port: u16,
    server_name: ServerName<'static>,
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

    /// Protocol-only tests need no disk owner. Production callers cannot choose
    /// this mode: every real client receives the namespace's shared Io owner.
    #[cfg(test)]
    pub(super) fn memory(directory: &str, tls: Arc<ClientConfig>) -> io::Result<Self> {
        Self::configured(directory, tls, None, 0)
    }

    fn configured(
        directory: &str,
        tls: Arc<ClientConfig>,
        persistence: Option<Io>,
        retry_at: u64,
    ) -> io::Result<Self> {
        let url = canonical_url(directory)?;
        let value = url.origin().ascii_serialization();
        let authority = value
            .strip_prefix("https://")
            .ok_or_else(|| failure(io::ErrorKind::InvalidInput, "origin"))?;
        let authority = HeaderValue::from_str(authority)
            .map_err(|_| failure(io::ErrorKind::InvalidInput, "origin"))?;
        let (host, server_name) = match url.host() {
            Some(url::Host::Domain(host)) => (
                host.to_owned(),
                ServerName::try_from(host.to_owned())
                    .map_err(|_| failure(io::ErrorKind::InvalidInput, "origin"))?,
            ),
            Some(url::Host::Ipv4(ip)) => (ip.to_string(), ServerName::IpAddress(ip.into())),
            Some(url::Host::Ipv6(ip)) => (ip.to_string(), ServerName::IpAddress(ip.into())),
            None => return Err(failure(io::ErrorKind::InvalidInput, "origin")),
        };
        let port = url
            .port_or_known_default()
            .ok_or_else(|| failure(io::ErrorKind::InvalidInput, "origin"))?;
        Ok(Self {
            origin: Arc::new(Origin {
                value,
                host,
                authority,
                port,
                server_name,
            }),
            tls,
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

    fn record_retry(&self, response: &mut http::Response<hyper::body::Incoming>) -> Option<u64> {
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
        if url.origin().ascii_serialization() != self.origin.value {
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
        let path = request.uri().path_and_query().cloned();
        *request.uri_mut() = path.map(Uri::from).unwrap_or_else(|| Uri::from_static("/"));
        *request.version_mut() = Version::HTTP_11;
        request
            .headers_mut()
            .insert(header::HOST, self.origin.authority.clone());
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
    /// deadline. Cancellation drops the socket/driver, not dispatched cache
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
        let stream = TcpStream::connect((self.origin.host.as_str(), self.origin.port))
            .await
            .map_err(|error| failure(error.kind(), "connect"))?;
        let stream = TlsConnector::from(self.tls.clone())
            .connect(self.origin.server_name.clone(), stream)
            .await
            .map_err(|error| failure(error.kind(), "tls"))?;
        if stream.get_ref().1.alpn_protocol() != Some(&b"http/1.1"[..])
            || stream.get_ref().1.protocol_version() != Some(ProtocolVersion::TLSv1_3)
        {
            return Err(failure(io::ErrorKind::InvalidData, "negotiation"));
        }
        let mut builder = hyper::client::conn::http1::Builder::new();
        builder.max_buf_size(16 * 1024).max_headers(64);
        let (mut sender, connection) = builder
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|_| failure(io::ErrorKind::Other, "http"))?;
        let exchange = async {
            let mut response = sender
                .send_request(request)
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
            let (parts, mut body) = response.into_parts();
            let mut bytes = Vec::with_capacity(MAX_RESPONSE_BYTES);
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| failure(io::ErrorKind::Other, "body"))?;
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                bytes
                    .len()
                    .checked_add(data.len())
                    .filter(|length| *length <= MAX_RESPONSE_BYTES)
                    .ok_or_else(|| failure(io::ErrorKind::InvalidData, "response_limit"))?;
                bytes.extend_from_slice(&data);
            }
            Ok(BytesResponse {
                parts,
                body: Box::new(Bytes::from(bytes)),
            })
        };
        tokio::pin!(exchange);
        {
            tokio::pin!(connection);
            tokio::select! {
                biased;
                result = &mut exchange => return result,
                _ = &mut connection => {},
            }
        }
        // Drop the completed driver before awaiting its queued response/body.
        // A complete response may only be waiting on its persistence worker;
        // an incomplete body instead observes the driver's closed sender. Both
        // remain inside the unchanged whole-exchange 20-second deadline.
        exchange.await
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

    use std::{
        panic::AssertUnwindSafe,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use futures_util::FutureExt as _;
    use instant_acme::HttpClient as _;
    use rustls::{RootCertStore, ServerConfig, crypto::aws_lc_rs};
    use rustls_pki_types::PrivatePkcs8KeyDer;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
        sync::Notify,
        task::JoinSet,
    };
    use tokio_rustls::{TlsAcceptor, server::TlsStream};
    use zeroize::Zeroizing;

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

    struct Release(Option<std::sync::mpsc::Sender<()>>);

    impl Drop for Release {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[test]
    fn retry_after_accepts_http_date_and_unsigned_delay_without_overflow() {
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert_eq!(retry_time(" 120\t", now), Some(1_800_000_120));
        assert_eq!(
            retry_time(&httpdate::fmt_http_date(now), now),
            Some(1_800_000_000)
        );
        for value in [
            "",
            "+3",
            "-3",
            "1.5",
            "18446744073709551615",
            "invalid date",
        ] {
            assert_eq!(retry_time(value, now), None);
        }
    }

    #[test]
    fn persistent_preflight_reloads_max_after_restart_and_corruption_sends_no_network()
    -> io::Result<()> {
        let fixture = DiskFixture::new()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let origin = format!("https://{}", listener.local_addr()?);
            let (_, tls) = identity(true)?;
            let io = fixture.io()?;
            let client = Client::new(&format!("{origin}/directory"), tls.clone(), io.clone())?;
            assert_eq!(client.retry_at(), 0);
            let due = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_secs()
                + 7200;
            io.work(move |cache| cache.advance_retry(due)).await?;
            rejected(
                timeout(
                    TEST_WAIT,
                    client.exchange(request(&format!("{origin}/resource"), vec![])?),
                )
                .await
                .map_err(io::Error::other)?,
                "retry_after",
            )?;
            assert_eq!(client.retry_at(), due);
            assert!(
                timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err()
            );
            drop(client);
            drop(io);

            let io = fixture.io()?;
            let client = Client::new(&format!("{origin}/directory"), tls.clone(), io.clone())?;
            assert_eq!(client.retry_at(), due);
            rejected(
                client
                    .exchange(request(&format!("{origin}/resource"), vec![])?)
                    .await,
                "retry_after",
            )?;
            io.replace(
                "retry.json",
                Zeroizing::new(br#"{"version":2,"not_before_unix_s":0}"#.to_vec()),
            )
            .await?;
            rejected(
                client
                    .exchange(request(&format!("{origin}/resource"), vec![])?)
                    .await,
                "retry_state",
            )?;
            assert!(
                timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err()
            );
            assert_eq!(
                Client::new(&format!("{origin}/directory"), tls, io)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::InvalidData)
            );
            Ok(())
        })
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
                let mut tasks = JoinSet::new();
                let outcome = AssertUnwindSafe(async {
                    let (server, tls) = identity(true)?;
                    let ready = Arc::new(Notify::new());
                    let proceed = Arc::new(Notify::new());
                    let bytes = if truncated {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nRetry-After: 3600\r\n\r\nx".to_vec()
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nRetry-After: 3600\r\n\r\ninvalid-extra".to_vec()
                    };
                    let remote = peer(&mut tasks, server, Reply::RawAfter {
                        bytes, close: truncated,
                        ready: ready.clone(), proceed: proceed.clone(),
                    }).await?;
                    let io = fixture.io()?;
                    let capacity = io.capacity.clone();
                    let client = Client::new(&format!("{}/directory", remote.origin), tls.clone(), io.clone())?;
                    let shared_retry = client.retry_at.clone();
                    let requesting = client.clone();
                    let outgoing = request(&format!("{}/resource", remote.origin), vec![])?;
                    let task = tokio::spawn(async move {
                        requesting.exchange(outgoing).await.map(|response| response.parts.status)
                    });
                    timeout(TEST_WAIT, ready.notified()).await.map_err(io::Error::other)?;
                    let (started, began) = tokio::sync::oneshot::channel();
                    let (release, wait) = std::sync::mpsc::channel();
                    let release = Release(Some(release));
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
                    drop(release);
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
                    wait_closed(&remote).await?;
                    // Permit release precedes the worker's Cache/author drop.
                    // On this one-thread blocking pool, a joined barrier proves
                    // that worker has returned before claiming a fresh author.
                    tokio::task::spawn_blocking(|| ()).await.map_err(io::Error::other)?;
                    let io = fixture.io()?;
                    let persisted = io.work(|cache| cache.retry_at()).await?;
                    assert_eq!(persisted, shared_retry.load(Ordering::Relaxed));
                    assert!(persisted > SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_secs());
                    let restarted = Client::new(&format!("{}/directory", remote.origin), tls, io)?;
                    assert_eq!(restarted.retry_at(), persisted);
                    rejected(restarted.exchange(request(&format!("{}/resource", remote.origin), vec![])?).await, "retry_after")?;
                    Ok(())
                }).catch_unwind().await;
                finish(&mut tasks, outcome).await
            })?;
        }
        Ok(())
    }

    fn identity(alpn: bool) -> io::Result<(Arc<ServerConfig>, Arc<ClientConfig>)> {
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
        if alpn {
            server.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
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

    fn request(uri: &str, body: Vec<u8>) -> io::Result<Request<BodyWrapper<Bytes>>> {
        Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/jose+json")
            .body(body.into())
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

    #[derive(Default)]
    struct Observed {
        http_bytes: AtomicUsize,
        request: Mutex<Vec<u8>>,
        sent: Notify,
        closed: AtomicBool,
        closure: Notify,
    }

    struct Peer {
        origin: String,
        observed: Arc<Observed>,
    }

    enum Reply {
        Data {
            body: Vec<u8>,
            chunked: bool,
            close: bool,
        },
        Raw(Vec<u8>),
        RawAfter {
            bytes: Vec<u8>,
            close: bool,
            ready: Arc<Notify>,
            proceed: Arc<Notify>,
        },
        Partial,
        NoHeaders,
        NoHandshake,
    }

    fn closed(observed: &Observed) {
        observed.closed.store(true, Ordering::SeqCst);
        observed.closure.notify_one();
    }

    async fn read_request(
        stream: &mut TlsStream<TcpStream>,
        observed: &Observed,
    ) -> io::Result<bool> {
        let mut bytes = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => {
                    closed(observed);
                    return Ok(false);
                }
                Ok(length) => {
                    observed.http_bytes.fetch_add(length, Ordering::SeqCst);
                    bytes.extend_from_slice(&buffer[..length]);
                    if bytes.len() > 80 * 1024 {
                        return Err(io::Error::other("test request exceeds fixture limit"));
                    }
                }
            }
            let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
                continue;
            };
            let text = std::str::from_utf8(&bytes[..header_end]).map_err(io::Error::other)?;
            let length = text
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>())
                .transpose()
                .map_err(io::Error::other)?
                .unwrap_or(0);
            if bytes.len() >= header_end + 4 + length {
                *observed.request.lock().unwrap() = bytes;
                return Ok(true);
            }
        }
    }

    async fn peer(
        tasks: &mut JoinSet<io::Result<()>>,
        tls: Arc<ServerConfig>,
        reply: Reply,
    ) -> io::Result<Peer> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let origin = format!("https://{}", listener.local_addr()?);
        let observed = Arc::new(Observed::default());
        let counters = observed.clone();
        let account = format!("{origin}/account/1");
        tasks.spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            if matches!(reply, Reply::NoHandshake) {
                let mut buffer = [0; 8192];
                while matches!(socket.read(&mut buffer).await, Ok(length) if length != 0) {}
                closed(&counters);
                return Ok(());
            }
            let mut stream = match TlsAcceptor::from(tls).accept(socket).await {
                Ok(stream) => stream,
                Err(_) => { closed(&counters); return Ok(()); }
            };
            if !read_request(&mut stream, &counters).await? {
                return Ok(());
            }
            let write = async {
                match &reply {
                    Reply::Data { body, chunked, close } => {
                        let framing = if *chunked {
                            "Transfer-Encoding: chunked\r\n".to_owned()
                        } else {
                            format!("Content-Length: {}\r\n", body.len())
                        };
                        let connection = if *close { "close" } else { "keep-alive" };
                        let head = format!("HTTP/1.1 201 Created\r\nReplay-Nonce: nonce-1\r\nLocation: {account}\r\nRetry-After: 7\r\nConnection: {connection}\r\n{framing}\r\n");
                        stream.write_all(head.as_bytes()).await?;
                        if *chunked {
                            for chunk in body.chunks(4096) {
                                stream.write_all(format!("{:x}\r\n", chunk.len()).as_bytes()).await?;
                                stream.write_all(chunk).await?;
                                stream.write_all(b"\r\n").await?;
                            }
                            stream.write_all(b"0\r\n\r\n").await?;
                        } else {
                            stream.write_all(body).await?;
                        }
                    }
                    Reply::Raw(bytes) => stream.write_all(bytes).await?,
                    Reply::RawAfter { bytes, ready, proceed, .. } => {
                        ready.notify_one();
                        proceed.notified().await;
                        stream.write_all(bytes).await?;
                    }
                    Reply::Partial => {
                        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nx").await?;
                    }
                    Reply::NoHeaders | Reply::NoHandshake => {}
                }
                stream.flush().await
            }.await;
            counters.sent.notify_one();
            if write.is_err() {
                closed(&counters);
                return Ok(());
            }
            if matches!(reply, Reply::Data { close: true, .. } | Reply::RawAfter { close: true, .. }) {
                let _ = stream.shutdown().await;
            }
            let mut buffer = [0; 1024];
            while matches!(stream.read(&mut buffer).await, Ok(length) if length != 0) {}
            closed(&counters);
            Ok(())
        });
        Ok(Peer { origin, observed })
    }

    async fn wait_closed(peer: &Peer) -> io::Result<()> {
        timeout(TEST_WAIT, async {
            while !peer.observed.closed.load(Ordering::SeqCst) {
                peer.observed.closure.notified().await;
            }
        })
        .await
        .map_err(|_| io::Error::other("fixture did not observe client closure"))
    }

    /// Reap every owned fixture even when the assertion panics. Resume the
    /// original panic only after cancelled children have been observed.
    async fn finish(
        tasks: &mut JoinSet<io::Result<()>>,
        outcome: std::thread::Result<io::Result<()>>,
    ) -> io::Result<()> {
        tasks.abort_all();
        let mut cleanup_error = None;
        while let Some(joined) = tasks.join_next().await {
            let error = match joined {
                Ok(Err(error)) => Some(error),
                Err(error) if !error.is_cancelled() => {
                    Some(io::Error::other("fixture task failed"))
                }
                _ => None,
            };
            if cleanup_error.is_none() {
                cleanup_error = error;
            }
        }
        match outcome {
            Ok(result) => result.and(cleanup_error.map_or(Ok(()), Err)),
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    #[test]
    fn request_validation_pins_origin_and_checks_local_bytes_before_network() -> io::Result<()> {
        let (_, tls) = identity(true)?;
        for directory in [
            "http://example.com/directory",
            "https://user@example.com/directory",
            "https://@example.com/directory",
            "https://example.com:443/directory",
            "https://EXAMPLE.com/directory",
            "https://example.com:0/directory",
            "https://example.com/directory#fragment",
            "https://example.com/\nprivate",
        ] {
            rejected(Client::memory(directory, tls.clone()), "origin")?;
        }
        let client = Client::memory("https://example.com/directory", tls)?;
        for resource in [
            "http://example.com/new-order",
            "https://other.example.com/new-order",
            "https://example.com:8443/new-order",
            "/new-order",
        ] {
            rejected(client.prepare(&mut request(resource, vec![])?), "origin")?;
        }
        rejected(
            client.prepare(&mut request(
                "https://example.com/order",
                vec![0; 64 * 1024 + 1],
            )?),
            "request_limit",
        )?;
        let mut accepted = request("https://example.com/order?exact=%2F", vec![0; 64 * 1024])?;
        accepted
            .headers_mut()
            .insert(header::HOST, HeaderValue::from_static("not-the-ca.example"));
        client.prepare(&mut accepted)?;
        assert_eq!(accepted.uri().to_string(), "/order?exact=%2F");
        assert_eq!(accepted.headers()[header::HOST], "example.com");
        Ok(())
    }

    #[tokio::test]
    async fn returns_bounded_complete_response_without_waiting_for_keepalive_eof() -> io::Result<()>
    {
        let (server, tls) = identity(true)?;
        let mut tasks = JoinSet::new();
        let outcome = AssertUnwindSafe(async {
            for (chunked, close) in [(false, false), (false, true), (true, true)] {
                let expected = vec![b'x'; MAX_RESPONSE_BYTES];
                let remote = peer(
                    &mut tasks,
                    server.clone(),
                    Reply::Data {
                        body: expected.clone(),
                        chunked,
                        close,
                    },
                )
                .await?;
                let client = Client::memory(&format!("{}/directory", remote.origin), tls.clone())?;
                let mut result = client
                    .request(request(
                        &format!("{}/new-order?literal=%2F", remote.origin),
                        vec![b'j'; 64 * 1024],
                    )?)
                    .await
                    .map_err(io::Error::other)?;
                assert_eq!(result.parts.status, http::StatusCode::CREATED);
                assert_eq!(result.parts.headers["replay-nonce"], "nonce-1");
                assert_eq!(
                    result.parts.headers["location"],
                    format!("{}/account/1", remote.origin)
                );
                assert!(
                    httpdate::parse_http_date(
                        result.parts.headers["retry-after"]
                            .to_str()
                            .map_err(io::Error::other)?
                    )
                    .is_ok()
                );
                assert!(
                    client.retry_at()
                        >= SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map_err(io::Error::other)?
                            .as_secs()
                );
                let body = result.body.into_bytes().await.map_err(io::Error::other)?;
                assert_eq!(body.as_ref(), expected);
                wait_closed(&remote).await?;
                let wire = remote.observed.request.lock().unwrap();
                let header_end = wire
                    .windows(4)
                    .position(|part| part == b"\r\n\r\n")
                    .unwrap();
                assert!(wire.starts_with(b"POST /new-order?literal=%2F HTTP/1.1\r\n"));
                assert_eq!(wire.len() - header_end - 4, 64 * 1024);
            }
            Ok(())
        })
        .catch_unwind()
        .await;
        finish(&mut tasks, outcome).await
    }

    #[tokio::test]
    async fn refuses_oversized_chunked_bodies_headers_and_redirects_without_peer_details()
    -> io::Result<()> {
        let (server, tls) = identity(true)?;
        let mut tasks = JoinSet::new();
        let outcome = AssertUnwindSafe(async {
            let mut header_count = String::from("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n");
            for index in 0..65 {
                header_count.push_str(&format!("X-Item-{index}: value\r\n"));
            }
            header_count.push_str("\r\n");
            let large_header = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Large: {}\r\n\r\n", "x".repeat(17 * 1024));
            let redirect = format!("HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:1/{PRIVATE_RESPONSE}\r\nContent-Length: {}\r\n\r\n{PRIVATE_RESPONSE}", PRIVATE_RESPONSE.len());
            for (reply, stage) in [
                (Reply::Data { body: vec![b'x'; MAX_RESPONSE_BYTES + 1], chunked: true, close: true }, "response_limit"),
                (Reply::Raw(header_count.into_bytes()), "http"),
                (Reply::Raw(large_header.into_bytes()), "http"),
                (Reply::Raw(redirect.into_bytes()), "redirect"),
            ] {
                let remote = peer(&mut tasks, server.clone(), reply).await?;
                let client = Client::memory(&format!("{}/directory", remote.origin), tls.clone())?;
                rejected(client.exchange(request(&format!("{}/resource", remote.origin), vec![])?).await, stage)?;
                wait_closed(&remote).await?;
            }
            Ok(())
        }).catch_unwind().await;
        finish(&mut tasks, outcome).await
    }

    #[tokio::test]
    async fn tls_trust_and_alpn_fail_before_any_http_bytes() -> io::Result<()> {
        let (server, _) = identity(true)?;
        let (_, unrelated_roots) = identity(true)?;
        let (no_alpn, correct_roots) = identity(false)?;
        let mut tasks = JoinSet::new();
        let outcome = AssertUnwindSafe(async {
            for (server, tls, stage) in [
                (server, unrelated_roots, "tls"),
                (no_alpn, correct_roots, "negotiation"),
            ] {
                let remote = peer(&mut tasks, server, Reply::NoHeaders).await?;
                let client = Client::memory(&format!("{}/directory", remote.origin), tls)?;
                rejected(
                    client
                        .exchange(request(&format!("{}/resource", remote.origin), vec![])?)
                        .await,
                    stage,
                )?;
                wait_closed(&remote).await?;
                assert_eq!(remote.observed.http_bytes.load(Ordering::SeqCst), 0);
            }
            Ok(())
        })
        .catch_unwind()
        .await;
        finish(&mut tasks, outcome).await
    }

    #[tokio::test]
    async fn one_budget_bounds_handshake_headers_and_body_and_closes_socket() -> io::Result<()> {
        let (server, tls) = identity(true)?;
        let mut tasks = JoinSet::new();
        let outcome = AssertUnwindSafe(async {
            for reply in [Reply::NoHandshake, Reply::NoHeaders, Reply::Partial] {
                let remote = peer(&mut tasks, server.clone(), reply).await?;
                let mut client =
                    Client::memory(&format!("{}/directory", remote.origin), tls.clone())?;
                client.budget = Duration::from_millis(500);
                rejected(
                    client
                        .exchange(request(&format!("{}/resource", remote.origin), vec![])?)
                        .await,
                    "timeout",
                )?;
                wait_closed(&remote).await?;
            }
            Ok(())
        })
        .catch_unwind()
        .await;
        finish(&mut tasks, outcome).await
    }

    #[tokio::test]
    async fn processing_retry_after_is_shared_and_extreme_values_never_reach_the_library()
    -> io::Result<()> {
        let (server, tls) = identity(true)?;
        let mut tasks = JoinSet::new();
        let outcome = AssertUnwindSafe(async {
            for (value, limited) in [("86400", true), ("18446744073709551615", false)] {
                let wire =
                    format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nRetry-After: {value}\r\n\r\n");
                let remote =
                    peer(&mut tasks, server.clone(), Reply::Raw(wire.into_bytes())).await?;
                let client = Client::memory(&format!("{}/directory", remote.origin), tls.clone())?;
                let response = client
                    .exchange(request(&format!("{}/order/1", remote.origin), vec![])?)
                    .await?;
                assert!(!response.parts.headers.contains_key(header::RETRY_AFTER));
                wait_closed(&remote).await?;
                if limited {
                    let cloned = client.clone();
                    assert_eq!(cloned.retry_at(), client.retry_at());
                    timeout(Duration::from_millis(500), async {
                        rejected(
                            cloned
                                .exchange(request(&format!("{}/order/1", remote.origin), vec![])?)
                                .await,
                            "retry_after",
                        )
                    })
                    .await
                    .map_err(io::Error::other)??;
                } else {
                    assert_eq!(client.retry_at(), 0);
                }
            }
            Ok(())
        })
        .catch_unwind()
        .await;
        finish(&mut tasks, outcome).await
    }

    #[tokio::test]
    async fn dropping_an_inflight_exchange_closes_its_socket_without_a_detached_driver()
    -> io::Result<()> {
        let (server, tls) = identity(true)?;
        let mut tasks = JoinSet::new();
        let outcome = AssertUnwindSafe(async {
            let remote = peer(&mut tasks, server, Reply::Partial).await?;
            let client = Client::memory(&format!("{}/directory", remote.origin), tls)?;
            {
                let exchange = client.exchange(request(&format!("{}/resource", remote.origin), vec![])?);
                tokio::pin!(exchange);
                timeout(TEST_WAIT, async {
                    tokio::select! {
                        _ = remote.observed.sent.notified() => Ok(()),
                        _ = &mut exchange => Err(io::Error::other("partial response completed unexpectedly")),
                    }
                }).await.map_err(io::Error::other)??;
            }
            wait_closed(&remote).await
        }).catch_unwind().await;
        finish(&mut tasks, outcome).await
    }
}
