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
