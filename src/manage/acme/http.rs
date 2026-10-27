//! Dedicated HTTP-01 responder, never a plaintext management entry point.
//!
//! Only an explicitly installed in-memory challenge is readable. This listener
//! has no administrator/session state, certificate issuer, proxy connector or
//! static Web fallback. RFC 8555 section 8.3 defines the public port-80 resource:
//! <https://www.rfc-editor.org/rfc/rfc8555.html#section-8.3>.

use std::{
    convert::Infallible,
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ::http::{Method, Request, Response, StatusCode, header};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{net::TcpListener, net::TcpStream, sync::Semaphore, task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;

const PREFIX: &str = "/.well-known/acme-challenge/";
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

struct Challenge {
    token: String,
    key_authorization: String,
}

type Current = Arc<Mutex<Option<Arc<Challenge>>>>;

/// One locally configured DNS domain, not a host learned from an HTTP request.
#[derive(Clone)]
pub(in crate::manage) struct Http {
    domain: Arc<str>,
    current: Current,
}

/// Removing a challenge is generation-specific. Dropping a superseded guard
/// cannot erase a newer order, including one that happens to reuse the token.
#[must_use = "keep the challenge guard until validation finishes"]
pub(super) struct Guard {
    current: Current,
    challenge: Arc<Challenge>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Ok(mut current) = self.current.lock()
            && current
                .as_ref()
                .is_some_and(|challenge| Arc::ptr_eq(challenge, &self.challenge))
        {
            *current = None;
        }
    }
}

impl Http {
    /// The caller supplies its already validated ASCII DNS domain, without a
    /// scheme, port or path. Binding/public reachability remain caller policy.
    pub(super) fn new(domain: String) -> Self {
        Self {
            domain: Arc::from(domain),
            current: Arc::new(Mutex::new(None)),
        }
    }

    /// Install one bounded response before telling the CA validation is ready.
    /// Tokens are raw base64url ASCII, never decoded from paths or reflected
    /// from requests. Key authorization must be nonempty printable ASCII.
    /// Poisoned state fails closed and never restores an older challenge.
    pub(super) fn challenge(&self, token: &str, key_authorization: &str) -> io::Result<Guard> {
        if token.is_empty()
            || token.len() > 256
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
            || key_authorization.is_empty()
            || key_authorization.len() > 512
            || !key_authorization.is_ascii()
            || key_authorization
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ACME HTTP challenge response",
            ));
        }
        let challenge = Arc::new(Challenge {
            token: token.to_owned(),
            key_authorization: key_authorization.to_owned(),
        });
        *self
            .current
            .lock()
            .map_err(|_| io::Error::other("ACME HTTP challenge state is unavailable"))? =
            Some(challenge.clone());
        Ok(Guard {
            current: self.current.clone(),
            challenge,
        })
    }

    /// Serve an already-bound challenge-only socket under the management
    /// supervisor's cancellation owner. At most 128 connections (including
    /// incomplete headers) live for 30 seconds each; headers have five seconds.
    /// Shutdown closes admission, drains five seconds, then aborts and joins
    /// remaining connection tasks. This installs no logger or signal handler.
    pub(in crate::manage) async fn serve(
        self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> io::Result<()> {
        let connections_shutdown = shutdown.child_token();
        let mut connections = JoinSet::new();
        let capacity = Arc::new(Semaphore::new(128));
        let mut last_accept_warning: Option<Instant> = None;
        let result = loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break Ok(()),
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        tracing::debug!(cancelled = error.is_cancelled(), "ACME HTTP connection task ended");
                    }
                }
                incoming = listener.accept() => {
                    let (stream, _) = match incoming {
                        Ok(connection) => connection,
                        Err(error) if super::super::api::retryable_accept_error(&error) => {
                            let now = Instant::now();
                            if last_accept_warning.is_none_or(|last| now.saturating_duration_since(last) >= Duration::from_secs(60)) {
                                tracing::warn!(kind = ?error.kind(), code = error.raw_os_error(), "ACME HTTP accept temporarily unavailable; retrying");
                                last_accept_warning = Some(now);
                            }
                            tokio::select! {
                                _ = shutdown.cancelled() => break Ok(()),
                                _ = tokio::time::sleep(Duration::from_millis(200)) => continue,
                            }
                        }
                        Err(error) => break Err(error),
                    };
                    let Ok(permit) = capacity.clone().try_acquire_owned() else { continue; };
                    let http = self.clone();
                    let shutdown = connections_shutdown.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        let _ = timeout(CONNECTION_TIMEOUT, http.serve_connection(stream, shutdown)).await;
                    });
                }
            }
        };
        drop(listener);
        connections_shutdown.cancel();
        if timeout(SHUTDOWN_TIMEOUT, async {
            while connections.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        }
        result
    }

    async fn serve_connection(self, stream: TcpStream, shutdown: CancellationToken) {
        let service = service_fn(move |request: Request<Incoming>| {
            let response = self.response(request);
            async move { Ok::<_, Infallible>(response) }
        });
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_TIMEOUT)
            .max_buf_size(16 * 1024)
            .max_headers(64);
        let connection = builder.serve_connection(TokioIo::new(stream), service);
        tokio::pin!(connection);
        tokio::select! {
            _ = connection.as_mut() => {},
            _ = shutdown.cancelled() => {
                connection.as_mut().graceful_shutdown();
                let _ = connection.await;
            }
        }
    }

    fn response(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let uri = request.uri();
        let mut hosts = request.headers().get_all(header::HOST).iter();
        let host = hosts.next().and_then(|host| host.to_str().ok());
        if request.method() != Method::GET
            || uri.scheme().is_some()
            || uri.authority().is_some()
            || uri.query().is_some()
            || hosts.next().is_some()
            || !host.is_some_and(|host| {
                host.eq_ignore_ascii_case(self.domain.as_ref())
                    || host
                        .strip_suffix(":80")
                        .is_some_and(|host| host.eq_ignore_ascii_case(self.domain.as_ref()))
            })
        {
            return response(StatusCode::NOT_FOUND, Bytes::new());
        }
        let Some(token) = uri.path().strip_prefix(PREFIX) else {
            return response(StatusCode::NOT_FOUND, Bytes::new());
        };
        // Clone only the public response owner, releasing the short lock before
        // constructing or sending HTTP. An internal state failure is not a
        // claim that the requested challenge does not exist.
        let challenge = match self.current.lock() {
            Ok(current) => current
                .as_ref()
                .filter(|challenge| challenge.token == token)
                .cloned(),
            Err(_) => return response(StatusCode::SERVICE_UNAVAILABLE, Bytes::new()),
        };
        match challenge {
            Some(challenge) => response(
                StatusCode::OK,
                Bytes::copy_from_slice(challenge.key_authorization.as_bytes()),
            ),
            None => response(StatusCode::NOT_FOUND, Bytes::new()),
        }
    }
}

fn response(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Running {
        address: SocketAddr,
        shutdown: CancellationToken,
        tasks: JoinSet<io::Result<()>>,
    }

    impl Running {
        async fn new(http: Http) -> io::Result<Self> {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let shutdown = CancellationToken::new();
            let mut tasks = JoinSet::new();
            tasks.spawn(http.serve(listener, shutdown.clone()));
            Ok(Self {
                address,
                shutdown,
                tasks,
            })
        }

        async fn request(&self, wire: &str) -> io::Result<Vec<u8>> {
            timeout(Duration::from_secs(3), async {
                let mut stream = TcpStream::connect(self.address).await?;
                stream.write_all(wire.as_bytes()).await?;
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await?;
                Ok(response)
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "test HTTP request timed out"))?
        }

        async fn finish(mut self) -> io::Result<()> {
            self.shutdown.cancel();
            let joined = timeout(Duration::from_secs(7), self.tasks.join_next())
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "test listener stop timed out")
                })?
                .ok_or_else(|| io::Error::other("test listener task missing"))?;
            joined.map_err(|_| io::Error::other("test listener task failed"))??;
            assert!(self.tasks.is_empty());
            // This uses exactly the port owned by this fixture, not an assumed
            // fixed test port or a listener belonging to another process.
            let listener = TcpListener::bind(self.address).await?;
            drop(listener);
            Ok(())
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            self.shutdown.cancel();
            self.tasks.abort_all();
        }
    }

    fn wire(method: &str, target: &str, host: &str) -> String {
        format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
    }

    fn body(response: &[u8]) -> &[u8] {
        let start = response
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap();
        &response[start + 4..]
    }

    #[test]
    fn challenge_bounds_and_raw_ascii_are_checked() {
        let http = Http::new("example.test".into());
        let excessive_token = "a".repeat(257);
        for token in [
            "",
            "x=",
            "x/y",
            "x%2Fy",
            "x y",
            "é",
            excessive_token.as_str(),
        ] {
            assert!(http.challenge(token, "token.authorization").is_err());
        }
        let excessive_authorization = "a".repeat(513);
        for authorization in [
            "",
            "a\rb",
            "a\nb",
            "a\tb",
            "a\0b",
            "é",
            excessive_authorization.as_str(),
        ] {
            assert!(http.challenge("token", authorization).is_err());
        }
        let guard = http.challenge(&"a".repeat(256), &"b".repeat(512)).unwrap();
        drop(guard);
    }

    #[tokio::test]
    async fn loopback_serves_only_the_exact_challenge_domain_path_and_method() -> io::Result<()> {
        let http = Http::new("example.test".into());
        let _guard = http.challenge("token_-9", "token_-9.account_thumbprint")?;
        let server = Running::new(http).await?;
        for host in ["example.test", "EXAMPLE.TEST:80"] {
            let response = server
                .request(&wire("GET", "/.well-known/acme-challenge/token_-9", host))
                .await?;
            assert!(response.starts_with(b"HTTP/1.1 200 "));
            assert_eq!(body(&response), b"token_-9.account_thumbprint");
            let headers = String::from_utf8_lossy(&response).to_ascii_lowercase();
            assert!(headers.contains("content-type: text/plain\r\n"));
            assert!(!headers.contains("set-cookie:"));
        }
        let with_untrusted_credentials = "GET /.well-known/acme-challenge/token_-9 HTTP/1.1\r\nHost: example.test\r\nCookie: __Host-vproxy-session=not-a-session\r\nAuthorization: Bearer not-a-key\r\nConnection: close\r\n\r\n";
        assert_eq!(
            body(&server.request(with_untrusted_credentials).await?),
            b"token_-9.account_thumbprint"
        );
        for (method, target, host) in [
            ("GET", "/.well-known/acme-challenge/token_-9", "other.test"),
            (
                "GET",
                "/.well-known/acme-challenge/token_-9",
                "example.test:81",
            ),
            (
                "GET",
                "/.well-known/acme-challenge/token_-9",
                "example.test:443",
            ),
            (
                "GET",
                "/.well-known/acme-challenge/token_-9",
                "example.test.evil",
            ),
            ("GET", "/.well-known/acme-challenge/other", "example.test"),
            (
                "GET",
                "/.well-known/acme-challenge/token_-9/extra",
                "example.test",
            ),
            (
                "GET",
                "/.well-known/acme-challenge/%74oken_-9",
                "example.test",
            ),
            (
                "GET",
                "/.well-known/acme-challenge/token_-9?x=1",
                "example.test",
            ),
            (
                "GET",
                "http://example.test/.well-known/acme-challenge/token_-9",
                "example.test",
            ),
            (
                "POST",
                "/.well-known/acme-challenge/token_-9",
                "example.test",
            ),
            (
                "HEAD",
                "/.well-known/acme-challenge/token_-9",
                "example.test",
            ),
            ("GET", "/api/v1/auth/session", "example.test"),
            ("GET", "/", "example.test"),
        ] {
            let response = server.request(&wire(method, target, host)).await?;
            assert!(
                response.starts_with(b"HTTP/1.1 404 "),
                "{method} {target} {host}"
            );
            assert!(body(&response).is_empty());
        }
        server.finish().await
    }

    #[tokio::test]
    async fn old_guard_drop_cannot_clear_a_new_generation_or_same_token() -> io::Result<()> {
        let http = Http::new("example.test".into());
        let old = http.challenge("old", "old.authorization")?;
        let current = http.challenge("current", "current.authorization")?;
        drop(old);
        let server = Running::new(http.clone()).await?;
        let path = "/.well-known/acme-challenge/current";
        let request = wire("GET", path, "example.test");
        assert_eq!(
            body(&server.request(&request).await?),
            b"current.authorization"
        );
        let same_token = http.challenge("current", "current.new-authorization")?;
        drop(current);
        assert_eq!(
            body(&server.request(&request).await?),
            b"current.new-authorization"
        );
        assert!(
            server
                .request(&wire(
                    "GET",
                    "/.well-known/acme-challenge/old",
                    "example.test"
                ))
                .await?
                .starts_with(b"HTTP/1.1 404 ")
        );
        drop(same_token);
        assert!(
            server
                .request(&request)
                .await?
                .starts_with(b"HTTP/1.1 404 ")
        );
        server.finish().await
    }

    #[tokio::test]
    async fn cancellation_drains_incomplete_headers_and_releases_the_listener() -> io::Result<()> {
        let server = Running::new(Http::new("example.test".into())).await?;
        let mut incomplete = TcpStream::connect(server.address).await?;
        incomplete.write_all(b"GET / HTTP/1.1\r\nHost: ").await?;
        server.finish().await?;
        let mut remaining = Vec::new();
        match timeout(
            Duration::from_secs(1),
            incomplete.read_to_end(&mut remaining),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) => {}
            _ => {
                return Err(io::Error::other(
                    "cancelled challenge connection stayed open",
                ));
            }
        }
        Ok(())
    }
}
