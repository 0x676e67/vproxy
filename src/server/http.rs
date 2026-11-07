pub mod accept;
pub mod tls;

mod auth;
mod error;
pub(super) mod genca;

use std::{
    io::{self},
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{StatusCode, header, uri::Authority};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{
    Method, Request, Response,
    body::{Body, Frame, Incoming, SizeHint},
    service::service_fn,
    upgrade::Upgraded,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_util::task::TaskTracker;
use tracing::{Level, instrument};

use self::{
    accept::{Accept, DefaultAcceptor},
    auth::Authenticator,
    error::Error,
    tls::{RustlsAcceptor, RustlsConfig},
};
use super::{Acceptor, Connector, Context, Handle, Server, drain_connections, drain_permits};
use crate::server::auth::{Authenticated, Service};

#[cfg(feature = "management")]
use crate::traffic::{Data, Direction, Io, Meter};

#[cfg(feature = "management")]
type Payload = Data<Bytes>;
#[cfg(not(feature = "management"))]
type Payload = Bytes;

/// HTTP acceptor.
#[derive(Clone)]
pub struct HttpAcceptor<A = DefaultAcceptor> {
    acceptor: A,
    timeout: Duration,
    handler: Handler,
    builder: Builder<TokioExecutor>,
    // One TCP admission, shared with independent HTTP/2 service futures and
    // upgraded tunnels. It must not be released with only the HTTP head.
    connection_permit: Option<Arc<OwnedSemaphorePermit>>,
}

/// HTTP server.
pub struct HttpServer<A = DefaultAcceptor> {
    listener: TcpListener,
    inner: HttpAcceptor<A>,
    limit: Arc<Semaphore>,
    capacity: u32,
}

// ===== impl HttpAcceptor =====

impl HttpAcceptor {
    /// Create a new [`HttpAcceptor`] instance.
    pub fn new(ctx: Context) -> HttpAcceptor {
        let acceptor = DefaultAcceptor::new();
        let timeout = Duration::from_secs(ctx.connect_timeout);
        let handler = Handler::from(ctx);

        let mut builder = Builder::new(TokioExecutor::new());
        builder
            .http1()
            .title_case_headers(true)
            .preserve_header_case(true);
        // Queue DATA until the actual write accepts it. Flatten/pipeline flush
        // can advance a body Buf during encoding, before any successful write.
        #[cfg(feature = "management")]
        builder.http1().writev(true).pipeline_flush(false);

        HttpAcceptor {
            acceptor,
            timeout,
            handler,
            builder,
            connection_permit: None,
        }
    }

    /// Enable HTTPS with TLS certificate and private key files.
    pub fn with_https<P>(
        self,
        tls_cert: P,
        tls_key: P,
    ) -> std::io::Result<HttpAcceptor<RustlsAcceptor>>
    where
        P: Into<Option<PathBuf>>,
    {
        let config = match (tls_cert.into(), tls_key.into()) {
            (Some(cert), Some(key)) => RustlsConfig::from_pem_chain_file(cert, key),
            _ => {
                let (cert, key) = genca::get_self_signed_cert().map_err(io::Error::other)?;
                RustlsConfig::from_pem(cert, key)
            }
        }?;

        Ok(self.with_config(config))
    }

    #[cfg(feature = "management")]
    pub(crate) fn with_identity(
        self,
        identity: crate::server::tls::Identity,
    ) -> io::Result<HttpAcceptor<RustlsAcceptor>> {
        Ok(self.with_config(RustlsConfig::from_identity(identity)?))
    }

    fn with_config(mut self, config: RustlsConfig) -> HttpAcceptor<RustlsAcceptor> {
        let acceptor = RustlsAcceptor::new(config, self.timeout);
        self.handler.service = Service::Https;
        HttpAcceptor {
            acceptor,
            timeout: self.timeout,
            handler: self.handler,
            builder: self.builder,
            connection_permit: self.connection_permit,
        }
    }
}

// ===== impl HttpServer =====

#[cfg(test)]
impl<A> HttpServer<A> {
    /// Inspect the bound socket for fixtures that request port zero.
    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

impl HttpServer {
    /// Managed startup transfers a checked identity instead of mutable paths.
    /// Listener ownership, connection admission and HTTP policy are unchanged.
    #[cfg(feature = "management")]
    pub(crate) fn with_identity(
        self,
        identity: crate::server::tls::Identity,
    ) -> io::Result<HttpServer<RustlsAcceptor>> {
        self.inner.with_identity(identity).map(|inner| HttpServer {
            listener: self.listener,
            inner,
            limit: self.limit,
            capacity: self.capacity,
        })
    }

    /// Create a new [`HttpServer`] instance.
    pub fn new(ctx: Context) -> std::io::Result<HttpServer<DefaultAcceptor>> {
        let capacity = ctx.concurrent;
        let limit = super::connection_limit(ctx.concurrent)?;
        let socket = if ctx.bind.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };

        socket.set_nodelay(true)?;
        socket.set_reuseaddr(true)?;
        socket.bind(ctx.bind)?;
        socket.listen(ctx.concurrent).map(|listener| HttpServer {
            listener,
            inner: HttpAcceptor::new(ctx),
            limit,
            capacity,
        })
    }

    /// Enable HTTPS with TLS certificate and private key files.
    pub fn with_https<P>(
        self,
        tls_cert: P,
        tls_key: P,
    ) -> std::io::Result<HttpServer<RustlsAcceptor>>
    where
        P: Into<Option<PathBuf>>,
    {
        self.inner
            .with_https(tls_cert, tls_key)
            .map(|inner| HttpServer {
                listener: self.listener,
                inner,
                limit: self.limit,
                capacity: self.capacity,
            })
    }
}

impl<A> Server for HttpServer<A>
where
    A: Accept<TcpStream> + Clone + Send + Sync + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send,
    A::Future: Send,
{
    async fn start(mut self, handle: Handle) -> std::io::Result<()> {
        tracing::info!(
            "Http(s) proxy server listening on {}",
            self.listener.local_addr()?
        );
        let mut connections = tokio::task::JoinSet::new();
        let mut result = Ok(());

        loop {
            tokio::select! {
                biased;
                _ = handle.wait_graceful_shutdown() => break,
                joined = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = joined {
                        result = Err(io::Error::other(error));
                        break;
                    }
                }
                incoming = HttpServer::<A>::incoming(&mut self.listener, &self.limit) => {
                    let (conn, permit) = match incoming {
                        Ok(incoming) => incoming,
                        Err(error) => {
                            result = Err(error);
                            break;
                        }
                    };
                    connections.spawn_on(
                        self.inner.clone().with_connection_permit(permit).accept(conn, handle.clone()),
                        handle.runtime_handle(),
                    );
                }
            }
        }
        // Release the listening socket before waiting for existing work. A
        // fatal accept error must also notify its still-running connections.
        drop(self.listener);
        if result.is_err() {
            handle.request_graceful_shutdown();
        }
        let connections = drain_connections(&mut connections, "HTTP", &handle).await;
        let upgrades = self.inner.shutdown(&handle).await;
        // H2 service/body owners may outlive the outer connection future. This
        // cold barrier reuses their original TCP slots, not a new flow counter.
        let permits = drain_permits(&self.limit, self.capacity, &handle).await;
        result.and(connections).and(upgrades).and(permits)
    }
}

impl<A> Acceptor for HttpAcceptor<A>
where
    A: Accept<TcpStream> + Clone + Send + Sync + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send,
    A::Future: Send,
{
    async fn accept(self, (stream, socket_addr): (TcpStream, SocketAddr), handle: Handle) {
        let acceptor = self.acceptor.clone();
        let builder = self.builder.clone();
        let handler = self.handler.clone();
        let connection_permit = self.connection_permit;

        let stream = tokio::select! {
            _ = handle.wait_graceful_shutdown() => return,
            stream = acceptor.accept(stream) => match stream {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!("[HTTP] failed to accept connection: {error}");
                    return;
                }
            },
        };
        let connection = builder.serve_connection_with_upgrades(
            TokioIo::new(stream),
            service_fn(|request: Request<Incoming>| {
                // Hyper requires a 'static service future. Capture an owned
                // worker only for CONNECT instead of cloning the whole shutdown
                // handle on every ordinary HTTP request.
                let worker =
                    (request.method() == Method::CONNECT).then(|| handle.runtime_handle().clone());
                <Handler as Clone>::clone(&handler).proxy(
                    socket_addr,
                    request,
                    worker,
                    connection_permit.clone(),
                )
            }),
        );
        tokio::pin!(connection);
        let mut shutting_down = false;

        loop {
            tokio::select! {
                result = connection.as_mut() => {
                    if let Err(error) = result {
                        tracing::debug!("[HTTP] failed to serve connection: {error}");
                    }
                    return;
                }
                _ = handle.wait_graceful_shutdown(), if !shutting_down => {
                    shutting_down = true;
                    connection.as_mut().graceful_shutdown();
                }
            }
        }
    }
}

impl<A> HttpAcceptor<A> {
    /// Attach the listener's already acquired TCP slot, without reacquiring it.
    /// Auto detection uses this after peeking; failures, cancellation, and the
    /// final HTTP/body/upgrade owner all release the same one permit by RAII.
    pub(super) fn with_connection_permit(mut self, permit: OwnedSemaphorePermit) -> Self {
        self.connection_permit = Some(Arc::new(permit));
        self
    }

    /// Maintenance waits for CONNECT task ownership without aborting it. A
    /// later process stop uses the runtime's original deadline; timeout alone
    /// does not mean those tasks finished or cancel their work.
    pub(super) async fn shutdown(&self, handle: &Handle) -> io::Result<()> {
        self.handler.tasks.close();
        handle
            .wait_for_drain(self.handler.tasks.wait(), Duration::ZERO)
            .await
    }
}

#[cfg(feature = "management")]
impl HttpAcceptor<RustlsAcceptor> {
    /// The configured HTTPS branch's actual leaf, without loading any path.
    pub(super) fn certificate_leaf(&self) -> Option<&[u8]> {
        self.acceptor.certificate_leaf()
    }
}

#[cfg(feature = "management")]
impl HttpServer<RustlsAcceptor> {
    pub(super) fn certificate_leaf(&self) -> Option<&[u8]> {
        self.inner.certificate_leaf()
    }
}

#[derive(Clone)]
struct Handler {
    authenticator: Arc<Authenticator>,
    service: Service,
    connector: Connector,
    tasks: TaskTracker,
}

impl From<Context> for Handler {
    fn from(ctx: Context) -> Self {
        let authenticator = Authenticator(ctx.auth);

        Handler {
            authenticator: Arc::new(authenticator),
            service: Service::Http,
            connector: ctx.connector,
            tasks: TaskTracker::new(),
        }
    }
}

impl Handler {
    #[instrument(skip(self, req, worker, connection_permit), fields(method = %req.method()), level = Level::DEBUG)]
    async fn proxy(
        self,
        socket: SocketAddr,
        mut req: Request<Incoming>,
        worker: Option<tokio::runtime::Handle>,
        connection_permit: Option<Arc<OwnedSemaphorePermit>>,
    ) -> Result<Response<BoxBody<Payload, hyper::Error>>, Error> {
        // CONNECT's request target is only host:port, with no default port.
        // Reject malformed targets before authentication, logging or dialing.
        // https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6
        let target = if req.method() == Method::CONNECT {
            match connect_target(req.uri()) {
                Some(authority) => Some(authority),
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(full("CONNECT requires a host and explicit valid port"))?);
                }
            }
        } else {
            None
        };
        // Check if the client is authorized
        let authenticated = match self
            .authenticator
            .authenticate(req.headers(), self.service)
            .await
        {
            Ok(authenticated) => authenticated,
            // If the client is not authorized, return an error response
            Err(err) => {
                let resp = match err {
                    Error::ProxyAuthenticationRequired => Response::builder()
                        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                        .header(
                            header::PROXY_AUTHENTICATE,
                            "Basic realm=\"Proxy\", charset=\"UTF-8\"",
                        )
                        .body(empty()),
                    Error::Forbidden => Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(empty()),
                    Error::ServiceUnavailable => Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .body(empty()),
                    _ => Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(empty()),
                }?;

                return Ok(resp);
            }
        };

        // These credentials belong to this proxy, never the origin. There is no
        // cooperative upstream proxy chain here (RFC 9110 §11.7.2).
        // https://www.rfc-editor.org/rfc/rfc9110.html#section-11.7.2
        req.headers_mut().remove(header::PROXY_AUTHORIZATION);

        let connector = self.connector.with_source(authenticated.source);
        if connector.require_profile(authenticated.extension).is_err() {
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(empty())?);
        }

        if let Some(authority) = target {
            let worker = worker.ok_or(Error::ServiceUnavailable)?;
            // Existing TCP attempt deadlines do not include lookup_host. Bound
            // the complete CONNECT setup, including DNS, with the configured
            // budget, then send 2xx only after a target stream actually exists.
            // https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6
            let server = match tokio::time::timeout(
                connector.connect_timeout(),
                connector
                    .tcp(authenticated.extension)
                    .connect(authority.clone()),
            )
            .await
            {
                Ok(Ok(server)) => server,
                Ok(Err(error)) => {
                    tracing::debug!(kind = ?error.kind(), os_error = error.raw_os_error(), %error,
                        "[HTTP] CONNECT target setup failed");
                    return Ok(Response::builder()
                        .status(connect_failure_status(&error))
                        .body(empty())?);
                }
                Err(_) => {
                    tracing::debug!("[HTTP] CONNECT target setup timed out");
                    return Ok(Response::builder()
                        .status(StatusCode::GATEWAY_TIMEOUT)
                        .body(empty())?);
                }
            };
            self.tasks.spawn_on(
                async move {
                    // Admission and the established stream survive the HTTP
                    // response; an upgrade failure drops both without redialing.
                    let _authenticated = authenticated;
                    let _connection_permit = connection_permit;
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            if let Err(error) =
                                tunnel(socket, authority, upgraded, server, &_authenticated).await
                            {
                                tracing::debug!("[HTTP] server io error: {error}");
                            }
                        }
                        Err(error) => tracing::debug!("[HTTP] upgrade error: {error}"),
                    }
                },
                &worker,
            );
            Ok(Response::new(empty()))
        } else {
            connector
                .http(authenticated.extension)
                .send_request(req.map(|body| {
                    LeaseBody::new(
                        body,
                        &authenticated,
                        #[cfg(feature = "management")]
                        Direction::Upload,
                    )
                    .with_connection_permit(connection_permit.clone())
                }))
                .await
                .map(|res| {
                    res.map(|body| {
                        LeaseBody::new(
                            body,
                            &authenticated,
                            #[cfg(feature = "management")]
                            Direction::Download,
                        )
                        .with_connection_permit(connection_permit)
                        .boxed()
                    })
                })
                .map_err(Into::into)
        }
    }
}

fn connect_target(uri: &http::Uri) -> Option<Authority> {
    if uri.scheme().is_some() || uri.path_and_query().is_some() {
        return None;
    }
    let authority = uri.authority()?;
    if authority.host().is_empty()
        || authority.as_str().contains('@')
        || authority.port().is_none_or(|port| {
            port.as_str().is_empty() || !port.as_str().bytes().all(|byte| byte.is_ascii_digit())
        })
        || authority.port_u16().is_none_or(|port| port == 0)
    {
        return None;
    }
    if authority.host().starts_with('[')
        && authority
            .host()
            .strip_prefix('[')?
            .strip_suffix(']')?
            .parse::<std::net::Ipv6Addr>()
            .is_err()
    {
        return None;
    }
    Some(authority.clone())
}

fn connect_failure_status(error: &io::Error) -> StatusCode {
    // A timeout or transport refusal can be attributed to target setup. The
    // connector also returns local bind, resource and preset errors: uncertain
    // failures must not all be presented as a bad upstream response.
    // https://www.rfc-editor.org/rfc/rfc9110.html#section-15.6
    match error.kind() {
        io::ErrorKind::TimedOut => StatusCode::GATEWAY_TIMEOUT,
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable => StatusCode::BAD_GATEWAY,
        io::ErrorKind::AddrInUse
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::NetworkDown
        | io::ErrorKind::PermissionDenied
        | io::ErrorKind::WouldBlock
        | io::ErrorKind::OutOfMemory
        | io::ErrorKind::Unsupported => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Body ownership, not response headers, determines the end of HTTP admission.
/// The request and response share one lease, so early responses cannot free a
/// slot while an upload remains active. Frames pass through without copying.
struct LeaseBody<B> {
    inner: B,
    connection_permit: Option<Arc<OwnedSemaphorePermit>>,
    #[cfg(feature = "management")]
    lease: Option<Arc<crate::access::FlowLease>>,
    #[cfg(feature = "management")]
    meter: Option<Meter>,
}

impl<B: Body> LeaseBody<B> {
    fn new(
        inner: B,
        _authenticated: &Authenticated,
        #[cfg(feature = "management")] direction: Direction,
    ) -> Self {
        Self {
            connection_permit: None,
            #[cfg(feature = "management")]
            lease: if inner.is_end_stream() {
                None
            } else {
                _authenticated.lease.clone()
            },
            #[cfg(feature = "management")]
            meter: _authenticated.meter(direction),
            inner,
        }
    }

    /// An independently driven HTTP/2 body can outlive its service future or
    /// outer connection future. Share its existing slot only until body EOF,
    /// error, or drop; frames do not clone the permit or wrap the TCP stream.
    fn with_connection_permit(mut self, permit: Option<Arc<OwnedSemaphorePermit>>) -> Self {
        if !self.inner.is_end_stream() {
            self.connection_permit = permit;
        }
        self
    }
}

impl<B: Body<Data = Bytes> + Unpin> Body for LeaseBody<B> {
    type Data = Payload;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_frame(cx);
        #[cfg(feature = "management")]
        let result = result.map(|frame| {
            frame.map(|frame| {
                frame.map(|frame| frame.map_data(|data| Data::new(data, this.meter.clone())))
            })
        });
        if matches!(&result, Poll::Ready(None | Some(Err(_)))) || this.inner.is_end_stream() {
            this.connection_permit = None;
            #[cfg(feature = "management")]
            {
                this.lease = None;
            }
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn empty() -> BoxBody<Payload, hyper::Error> {
    Empty::<Payload>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Payload, hyper::Error> {
    let chunk = chunk.into();
    #[cfg(feature = "management")]
    let chunk = Data::new(chunk, None);
    Full::new(chunk).map_err(|never| match never {}).boxed()
}

/// Forward an already established target stream after the successful CONNECT
/// response. The caller owns admission across both setup and this upgrade wait.
async fn tunnel(
    source: SocketAddr,
    target: Authority,
    upgraded: Upgraded,
    mut server: TcpStream,
    _authenticated: &Authenticated,
) -> std::io::Result<()> {
    tracing::info!("[HTTP] {source} -> {target} forwarding connection");

    #[cfg(target_os = "linux")]
    let res =
        match hyper_util::server::conn::auto::upgrade::downcast::<TokioIo<TcpStream>>(upgraded) {
            Ok(io) => {
                let mut client = io.io.into_inner();
                let res =
                    copy_prefetched(&mut client, &mut server, &io.read_buf, _authenticated).await;
                client.shutdown().await?;
                res
            }
            Err(upgraded) => {
                let mut client = TokioIo::new(upgraded);
                #[cfg(feature = "management")]
                let mut client = Io::new(&mut client, _authenticated.meter(Direction::Download));
                #[cfg(feature = "management")]
                let mut server = Io::new(&mut server, _authenticated.meter(Direction::Upload));
                tokio::io::copy_bidirectional(&mut client, &mut server).await
            }
        };

    #[cfg(not(target_os = "linux"))]
    let res = {
        let mut client = TokioIo::new(upgraded);
        #[cfg(feature = "management")]
        let mut client = Io::new(&mut client, _authenticated.meter(Direction::Download));
        #[cfg(feature = "management")]
        let mut server = Io::new(&mut server, _authenticated.meter(Direction::Upload));
        tokio::io::copy_bidirectional(&mut client, &mut server).await
    };

    match res {
        Ok((from_client, from_server)) => {
            tracing::info!(
                "[HTTP] client wrote {} bytes and received {} bytes",
                from_client,
                from_server
            );
        }
        Err(err) => {
            tracing::trace!("[HTTP] tunnel error: {}", err);
        }
    }

    server.shutdown().await
}

/// Hyper's upgrade pre-read belongs to the opaque tunnel, not its CONNECT head.
/// Drain it once before giving the bare sockets to splice; otherwise downcasting
/// discards already received payload. Partial writes are metered by the writer.
#[cfg(target_os = "linux")]
async fn copy_prefetched(
    client: &mut TcpStream,
    server: &mut TcpStream,
    prefetched: &[u8],
    _authenticated: &Authenticated,
) -> io::Result<(u64, u64)> {
    #[cfg(feature = "management")]
    let (upload, download) = {
        let mut client = Io::new(client, _authenticated.meter(Direction::Download));
        let mut server = Io::new(server, _authenticated.meter(Direction::Upload));
        server.write_all(prefetched).await?;
        super::io::copy_bidirectional(&mut client, &mut server).await?
    };
    #[cfg(not(feature = "management"))]
    let (upload, download) = {
        server.write_all(prefetched).await?;
        super::io::copy_bidirectional(client, server).await?
    };
    let prefetched = u64::try_from(prefetched.len())
        .map_err(|_| io::Error::other("tunnel byte count exceeds u64"))?;
    let upload = upload
        .checked_add(prefetched)
        .ok_or_else(|| io::Error::other("tunnel byte count overflow"))?;
    Ok((upload, download))
}

#[cfg(test)]
mod connect_tests {
    //! CONNECT setup must finish before a successful HTTP response transfers the
    //! transport into tunnel mode. Tests use only owned loopback sockets.

    use tokio::{io::AsyncReadExt, task::JoinHandle};

    use super::*;
    use crate::{AuthMode, server::auth::Source};

    async fn proxy_with_limit(
        auth: Source,
        limit: Arc<Semaphore>,
    ) -> (
        SocketAddr,
        JoinHandle<()>,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = HttpAcceptor::new(super::Context {
            auth,
            bind: address,
            concurrent: 8,
            connect_timeout: 2,
            connector: Connector::new(
                None,
                None,
                None,
                2,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                None,
                None,
            ),
        });
        let permit = limit.try_acquire_owned().unwrap();
        let (outer_finished, outer_completion) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let incoming = listener.accept().await.unwrap();
            let drain = acceptor.clone();
            let handle = Handle::new();
            acceptor
                .with_connection_permit(permit)
                .accept(incoming, handle.clone())
                .await;
            let _ = outer_finished.send(());
            handle.request_graceful_shutdown();
            drain
                .shutdown(&handle)
                .await
                .expect("CONNECT fixture tasks completed");
        });
        (address, task, outer_completion)
    }

    fn anonymous() -> Source {
        Source::Legacy(AuthMode {
            username: None,
            password: None,
        })
    }

    async fn response_head(client: &mut TcpStream) -> String {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            assert!(head.len() < 4096);
            head.push(client.read_u8().await.unwrap());
        }
        String::from_utf8(head).unwrap()
    }

    #[tokio::test]
    async fn established_connect_preserves_pipelined_payload_and_half_close() {
        tokio::time::timeout(Duration::from_secs(5), async {
        let limit = Arc::new(Semaphore::new(1));
        let (fin_seen, fin_observed) = tokio::sync::oneshot::channel();
        let (release_tail, tail_released) = tokio::sync::oneshot::channel();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.unwrap();
            assert_eq!(payload, b"pipelined-opaque-data");
            fin_seen.send(()).unwrap();
            tail_released.await.unwrap();
            stream.write_all(b"reply-after-client-fin").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let (address, task, outer_finished) = proxy_with_limit(anonymous(), limit.clone()).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(
                format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\npipelined-opaque-data")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let head = response_head(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 200"));
        let head = head.to_ascii_lowercase();
        assert!(!head.contains("content-length:"));
        assert!(!head.contains("transfer-encoding:"));
        outer_finished.await.unwrap();
        assert_eq!(limit.available_permits(), 0, "the upgrade owns the TCP slot after its outer HTTP future ends");
        client.shutdown().await.unwrap();
        fin_observed.await.unwrap();
        // RFC 9293 section 3.6.1 keeps the reverse direction usable. Releasing
        // the slot on this FIN would allow another connection before its tail.
        assert_eq!(limit.available_permits(), 0, "client FIN is not the end of a bidirectional tunnel");
        release_tail.send(()).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"reply-after-client-fin");
        target_task.await.unwrap();
        task.await.unwrap();
        assert_eq!(limit.available_permits(), 1);
    })
    .await
    .expect("CONNECT must preserve prefetched data and the opposite half");
    }
}

#[cfg(test)]
mod security_tests {
    //! Loopback regression for the boundary between proxy and origin credentials.

    use std::{
        convert::Infallible,
        io::{self, Write},
        sync::{Arc, Mutex},
    };

    use base64::Engine;
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::fmt::format::FmtSpan;

    use super::*;
    use crate::AuthMode;

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn unavailable_preset_is_rejected_before_http_or_connect_can_reach_origin() {
        use crate::access::{
            Reader,
            tests::{LOGIN, policy, secret},
        };
        use crate::server::auth::Source;
        use tokio::io::AsyncReadExt as _;

        tokio::time::timeout(Duration::from_secs(5), async {
        for connect in [false, true] {
            let mut data = policy(1, 1);
            data.presets.users[0].default_preset = Some(crate::ebpf::Profile::Linux);
            data.presets.users[0].allowed_presets = vec![crate::ebpf::Profile::Linux];
            let reader = Reader::new(data).unwrap();
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination = origin.local_addr().unwrap();
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = proxy.local_addr().unwrap();
            let context = Context {
                auth: Source::Managed(reader.clone()), bind: address, concurrent: 8, connect_timeout: 1,
                connector: Connector::new(None, None, None, 1,
                    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                    None, None),
            };
            let server = tokio::spawn(async move {
                let stream = proxy.accept().await.unwrap();
                HttpAcceptor::new(context).accept(stream, Handle::new()).await;
            });
            let token = base64::engine::general_purpose::STANDARD.encode([LOGIN.as_bytes(), b":", &secret()].concat());
            let target = if connect { format!("CONNECT {destination}") } else { format!("GET http://{destination}/") };
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(format!("{target} HTTP/1.1\r\nHost: {destination}\r\nProxy-Authorization: Basic {token}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 503"));
            assert!(tokio::time::timeout(Duration::from_millis(30), origin.accept()).await.is_err(), "unavailable backend must not retry native");
            server.await.unwrap();
            assert!(reader.authenticate(LOGIN, &secret(), crate::access::Protocol::Http).is_ok());
        }
    }).await.expect("backend rejection must not wait for an unreachable destination");
    }

    #[derive(Clone)]
    struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    impl Write for LogBuffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| io::Error::other("poisoned test log"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn consumes_proxy_credentials_without_logging_or_forwarding_them() {
        tokio::time::timeout(Duration::from_secs(10), async {
            // tracing-core 0.1.36's single-dispatch callsite optimization consults
            // the registering thread's current subscriber. A parallel HTTP test
            // with no scoped subscriber can otherwise cache `Never` for our shared
            // handler callsite. Keep a second registered (but never installed)
            // dispatcher so registration combines the actual subscriber interests.
            // No global logger or cross-test serialization is needed.
            // https://github.com/tokio-rs/tracing/blob/10a9e838a35e6ded79d66af246be2ee05417136d/tracing-core/src/callsite.rs#L543-L574
            let _parallel_dispatch =
                tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
            // Exercise both authenticated and open proxies: a supplied header must
            // not become an origin credential just because authentication is off.
            for protected in [true, false] {
                let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let origin_address = origin.local_addr().unwrap();
                let origin_task = tokio::spawn(async move {
                    let (stream, _) = origin.accept().await.unwrap();
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(|request: Request<Incoming>| async move {
                                let headers = request.headers();
                                assert!(!headers.contains_key(header::PROXY_AUTHORIZATION));
                                assert_eq!(
                                    headers[header::AUTHORIZATION],
                                    "Bearer origin-only-secret"
                                );
                                assert_eq!(
                                    headers[header::COOKIE],
                                    "origin-session=private-cookie"
                                );
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                    b"ok",
                                ))))
                            }),
                        )
                        .await
                        .unwrap();
                });

                let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let proxy_address = proxy.local_addr().unwrap();
                let log = LogBuffer(Arc::new(Mutex::new(Vec::new())));
                let writer = log.clone();
                let subscriber = tracing_subscriber::fmt()
                    .with_max_level(Level::DEBUG)
                    .with_ansi(false)
                    .without_time()
                    .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
                    .with_writer(move || writer.clone())
                    .finish();
                let context = Context {
                    auth: AuthMode {
                        username: protected.then(|| "gate-user".into()),
                        password: protected.then(|| "sentinel-secret".into()),
                    }
                    .into(),
                    bind: proxy_address,
                    concurrent: 16,
                    connect_timeout: 3,
                    connector: Connector::new(
                        None,
                        None,
                        None,
                        3,
                        #[cfg(any(
                            target_os = "android",
                            target_os = "fuchsia",
                            target_os = "linux"
                        ))]
                        None,
                        None,
                    ),
                };
                let proxy_task = tokio::spawn(
                    async move {
                        let connection = proxy.accept().await.unwrap();
                        HttpAcceptor::new(context)
                            .accept(connection, Handle::new())
                            .await;
                    }
                    .with_subscriber(subscriber),
                );

                let token =
                    base64::engine::general_purpose::STANDARD.encode("gate-user:sentinel-secret");
                let client = crate::oneself::test_http_client_builder()
                    .unwrap()
                    .no_proxy()
                    .proxy(reqwest::Proxy::http(format!("http://{proxy_address}")).unwrap())
                    .build()
                    .unwrap();
                let response = client
                    .get(format!("http://{origin_address}/"))
                    .header(header::PROXY_AUTHORIZATION, format!("Basic {token}"))
                    .header(header::AUTHORIZATION, "Bearer origin-only-secret")
                    .header(header::COOKIE, "origin-session=private-cookie")
                    .header(header::CONNECTION, "close")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.text().await.unwrap(), "ok");
                drop(client);
                proxy_task.await.unwrap();
                origin_task.await.unwrap();

                let output = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
                assert!(
                    output
                        .lines()
                        .any(|line| line.contains("proxy{") && line.contains("method=GET")),
                    "the test must actually capture the handler span"
                );
                for secret in [
                    token.as_str(),
                    "sentinel-secret",
                    "origin-only-secret",
                    "private-cookie",
                ] {
                    assert!(
                        !output.contains(secret),
                        "a credential appeared in debug logs"
                    );
                }
            }
        })
        .await
        .expect("loopback credential regression must finish");
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn managed_http_authentication_and_streaming_response_share_one_user_budget() {
        use crate::access::{
            Protocol, Reader,
            tests::{ROUTED_LOGIN as LOGIN, routed_policy as policy, secret},
        };
        use crate::server::auth::Source;
        use futures_util::stream;
        use http_body_util::StreamBody;
        use tokio_util::sync::CancellationToken;

        tokio::time::timeout(Duration::from_secs(10), async {
        let reader = Reader::new(policy(1, 1)).unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let release = CancellationToken::new();
        let stop = release.clone();
        let origin_task = tokio::spawn(async move {
            let (stream, peer) = origin.accept().await.unwrap();
            assert_eq!(peer.ip(), "127.0.0.2".parse::<std::net::IpAddr>().unwrap());
            hyper::server::conn::http1::Builder::new().serve_connection(
                TokioIo::new(stream), service_fn(move |_request: Request<Incoming>| {
                    let stop = stop.clone();
                    async move {
                        let body = StreamBody::new(stream::once(async move {
                            stop.cancelled().await;
                            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"finished")))
                        }));
                        Ok::<_, Infallible>(Response::new(body))
                    }
                })).await.unwrap();
        });
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let context = Context {
            auth: Source::Managed(reader.clone()), bind: proxy_address, concurrent: 16, connect_timeout: 3,
            connector: Connector::new(Some("192.0.2.1/32".parse().unwrap()), None, None, 3,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))] None, None),
        };
        let acceptor = HttpAcceptor::new(context);
        let mut servers = tokio::task::JoinSet::new();
        servers.spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    result = connections.join_next(), if !connections.is_empty() => { result.unwrap().unwrap(); }
                    incoming = proxy.accept() => {
                        let incoming = incoming.unwrap();
                        connections.spawn(acceptor.clone().accept(incoming, Handle::new()));
                    }
                }
            }
        });
        let client = crate::oneself::test_http_client_builder().unwrap().no_proxy()
            .proxy(reqwest::Proxy::http(format!("http://{proxy_address}")).unwrap()).build().unwrap();
        let target = format!("http://{origin_address}/");
        let token = base64::engine::general_purpose::STANDARD.encode([LOGIN.as_bytes(), b":", &secret()].concat());
        let unauthenticated = client.get(&target).send().await.unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert!(unauthenticated.headers().contains_key(header::PROXY_AUTHENTICATE));
        let response = client.get(&target).header(header::PROXY_AUTHORIZATION, format!("Basic {token}"))
            .header(header::CONNECTION, "close").send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(matches!(reader.authenticate(LOGIN, &secret(), Protocol::Socks5), Err(crate::access::Error::Capacity)));
        let busy = client.get(&target).header(header::PROXY_AUTHORIZATION, format!("Basic {token}"))
            .send().await.unwrap();
        assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!busy.headers().contains_key(header::PROXY_AUTHENTICATE));
        reader.publish({ let mut data = policy(2, 1); data.users[0].active = false; data }).unwrap();
        let denied = client.get(&target).header(header::PROXY_AUTHORIZATION, format!("Basic {token}"))
            .send().await.unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let wrong = client.get(&target).header(header::PROXY_AUTHORIZATION, "Basic d3Jvbmc6d3Jvbmc=")
            .send().await.unwrap();
        assert_eq!(wrong.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        release.cancel();
        assert_eq!(response.text().await.unwrap(), "finished");
        origin_task.await.unwrap();
        reader.publish(policy(3, 1)).unwrap();
        assert!(reader.authenticate(LOGIN, &secret(), Protocol::Http).is_ok());
        reader.fail_closed();
        let unavailable = client.get(&target).header(header::PROXY_AUTHORIZATION, format!("Basic {token}"))
            .send().await.unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        servers.shutdown().await;
    }).await.expect("managed HTTP streaming regression must finish");
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn managed_connect_keeps_admission_until_the_upgraded_tunnel_finishes() {
        use crate::access::{
            Protocol, Reader,
            tests::{ROUTED_LOGIN as LOGIN, routed_policy as policy, secret},
        };
        use crate::server::auth::Source;
        use tokio::io::AsyncReadExt as _;

        tokio::time::timeout(Duration::from_secs(10), async {
        let reader = Reader::new(policy(1, 1)).unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, peer) = origin.accept().await.unwrap();
            assert_eq!(peer.ip(), "127.0.0.2".parse::<std::net::IpAddr>().unwrap());
            let mut received = [0; 4];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"live");
            stream.write_all(&received).await.unwrap();
            assert_eq!(stream.read(&mut received).await.unwrap(), 0);
        });
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let acceptor = HttpAcceptor::new(Context {
            auth: Source::Managed(reader.clone()), bind: proxy_address, concurrent: 16, connect_timeout: 3,
            connector: Connector::new(Some("192.0.2.1/32".parse().unwrap()), None, None, 3,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))] None, None),
        });
        let proxy_task = tokio::spawn(async move {
            let incoming = proxy.accept().await.unwrap();
            let drain = acceptor.clone();
            let handle = Handle::new();
            acceptor.accept(incoming, handle.clone()).await;
            handle.request_graceful_shutdown();
            drain.shutdown(&handle).await.unwrap();
        });
        let token = base64::engine::general_purpose::STANDARD.encode([LOGIN.as_bytes(), b":", &secret()].concat());
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        client.write_all(format!("CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\nProxy-Authorization: Basic {token}\r\n\r\n").as_bytes()).await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            assert!(head.len() < 4096);
            head.push(client.read_u8().await.unwrap());
        }
        assert!(head.starts_with(b"HTTP/1.1 200"));
        assert!(matches!(reader.authenticate(LOGIN, &secret(), Protocol::Socks5), Err(crate::access::Error::Capacity)));
        client.write_all(b"live").await.unwrap();
        let mut echoed = [0; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"live");
        reader.publish(policy(2, 1)).unwrap();
        assert!(matches!(reader.authenticate(LOGIN, &secret(), Protocol::Http), Err(crate::access::Error::Capacity)));
        client.shutdown().await.unwrap();
        drop(client);
        origin_task.await.unwrap();
        proxy_task.await.unwrap();
        assert!(reader.authenticate(LOGIN, &secret(), Protocol::Http).is_ok());
    }).await.expect("managed CONNECT admission must end with its tunnel");
    }
}

#[cfg(all(test, feature = "management"))]
mod traffic_tests {
    //! Real H1 forwarding boundaries, including framing and upgrade pre-read.

    use std::convert::Infallible;

    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{
        access::{
            Reader,
            tests::{LOGIN, policy, secret},
        },
        server::auth::Source,
        traffic::Snapshot,
    };

    fn totals(reader: &Reader) -> Snapshot {
        let series = reader.traffic_registry().snapshot().unwrap();
        series
            .iter()
            .find(|series| series.protocol == crate::access::traffic::Protocol::Http)
            .unwrap()
            .value
    }

    #[tokio::test]
    async fn ordinary_http_counts_payload_not_chunk_headers_trailers_or_rejections() {
        tokio::time::timeout(Duration::from_secs(10), async {
        let reader = Reader::new(policy(1, 8)).unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = origin.accept().await.unwrap();
                hyper::server::conn::http1::Builder::new().serve_connection(
                    TokioIo::new(stream),
                    service_fn(|request: Request<Incoming>| async move {
                        let data = request.into_body().collect().await.unwrap().to_bytes();
                        assert_eq!(data, b"abcdefg".as_slice());
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("x-finished", "yes".parse().unwrap());
                        let body = http_body_util::StreamBody::new(futures_util::stream::iter([
                            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"first"))),
                            Ok(Frame::data(Bytes::from_static(b"-last"))),
                            Ok(Frame::trailers(trailers)),
                        ]));
                        Ok::<_, Infallible>(Response::builder()
                            .header(header::TRAILER, "x-finished")
                            .body(body).unwrap())
                    }),
                ).await.unwrap();
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let acceptor = HttpAcceptor::new(Context {
            auth: Source::Managed(reader.clone()), bind: proxy, concurrent: 16,
            connect_timeout: 3,
            connector: Connector::new(None, None, None, 3,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                None,
                None,
            ),
        });
        let proxy_task = tokio::spawn(async move {
            for _ in 0..3 {
                acceptor.clone().accept(listener.accept().await.unwrap(), Handle::new()).await;
            }
        });
        let token = base64::engine::general_purpose::STANDARD.encode(
            format!("{LOGIN}:{}", std::str::from_utf8(&secret()).unwrap())
        );
        for case in 0..3 {
            let mut client = TcpStream::connect(proxy).await.unwrap();
            let authorization = if case == 0 { "Basic aW52YWxpZDppbnZhbGlk".to_owned() }
                else { format!("Basic {token}") };
            let (framing, body) = if case == 2 {
                ("Transfer-Encoding: chunked\r\nTrailer: x-upload\r\n", "3\r\nabc\r\n4\r\ndefg\r\n0\r\nx-upload: done\r\n\r\n")
            } else { ("Content-Length: 7\r\n", "abcdefg") };
            client.write_all(format!(
                "POST http://{address}/ HTTP/1.1\r\nHost: {address}\r\nProxy-Authorization: {authorization}\r\nConnection: close\r\n{framing}\r\n{body}"
            ).as_bytes()).await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            let response = std::str::from_utf8(&response).unwrap();
            if case == 0 {
                assert!(response.starts_with("HTTP/1.1 407"));
            } else {
                assert!(response.starts_with("HTTP/1.1 200"));
                assert!(response.contains("first") && response.contains("-last"));
            }
            assert_eq!(totals(&reader), Snapshot {
                upload: u64::try_from(case * 7).unwrap(),
                download: u64::try_from(case * 10).unwrap(),
                saturated: false,
            });
        }
        proxy_task.await.unwrap();
        origin_task.await.unwrap();
    }).await.expect("H1 payload accounting must finish");
    }
}

#[cfg(all(test, feature = "management"))]
mod write_tests {
    //! Deterministic accepted-byte guards for the locked Hyper H1 implementation.
    //!
    //! These exercise real `LeaseBody`/`Data` rather than a second counting buffer.
    //! The server cases use the production builder. Client handshake injection can
    //! only guard H1's explicit Queue setting; the socket interop test separately
    //! exercises the production `HttpConnector` configuration.

    use std::{convert::Infallible, io::IoSlice, sync::Mutex};

    use http_body_util::{Either, Full, StreamBody};
    use tokio::io::ReadBuf;

    use super::*;
    use crate::{
        access::{
            Protocol, Reader,
            tests::{LOGIN, policy, secret},
        },
        traffic::Snapshot,
    };

    #[derive(Default)]
    struct Accepted {
        payload: usize,
        vectored: usize,
    }

    /// Limit encoded writes, not DATA advances. Header/chunk bytes can span several
    /// writes; 0xfe cannot occur in the fixed ASCII headers or chunk framing.
    struct PartialWriter {
        accepted: Arc<Mutex<Accepted>>,
    }

    impl PartialWriter {
        fn accept(&self, buffers: &[IoSlice<'_>], vectored: bool) -> io::Result<usize> {
            let mut accepted = self.accepted.lock().unwrap();
            if accepted.payload == 8 {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let mut written = 0;
            for byte in buffers.iter().flat_map(|buffer| buffer.iter()) {
                if written == 3 || accepted.payload == 8 {
                    break;
                }
                accepted.payload += usize::from(*byte == 0xfe);
                written += 1;
            }
            accepted.vectored += usize::from(vectored);
            Ok(written)
        }
    }

    impl AsyncRead for PartialWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            // Keep reads pending so the writer error ends the driver.
            Poll::Pending
        }
    }

    impl AsyncWrite for PartialWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(self.get_mut().accept(&[IoSlice::new(buffer)], false))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            buffers: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(self.get_mut().accept(buffers, true))
        }

        fn is_write_vectored(&self) -> bool {
            // Explicit Queue must remain effective even when automatic strategy
            // selection would flatten, as it can for an accepted TLS transport.
            false
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn admission() -> (Reader, Authenticated) {
        let reader = Reader::new(policy(1, 8)).unwrap();
        let authorized = reader
            .authenticate(LOGIN, &secret(), Protocol::Http)
            .unwrap();
        let authenticated = Authenticated {
            extension: authorized.extension,
            source: authorized.source,
            lease: Some(authorized.lease),
            presets: Some(authorized.presets),
        };
        (reader, authenticated)
    }

    fn assert_totals(reader: &Reader, upload: u64, download: u64) {
        let series = reader.traffic_registry().snapshot().unwrap();
        let actual = series
            .iter()
            .find(|series| series.protocol == crate::access::traffic::Protocol::Http)
            .unwrap()
            .value;
        assert_eq!(
            actual,
            Snapshot {
                upload,
                download,
                saturated: false
            }
        );
    }

    fn assert_partial(accepted: &Mutex<Accepted>) {
        let accepted = accepted.lock().unwrap();
        assert_eq!(accepted.payload, 8);
        assert!(accepted.vectored > 0);
    }

    #[tokio::test]
    async fn h1_upload_keeps_only_the_accepted_prefix_after_error_and_queue_drop() {
        tokio::time::timeout(Duration::from_secs(5), async {
            for exact in [true, false] {
                let (reader, authenticated) = admission();
                let accepted = Arc::new(Mutex::new(Accepted::default()));
                let writer = PartialWriter {
                    accepted: accepted.clone(),
                };
                // This protects the pinned H1 Queue behavior, not construction of
                // the production legacy connector, which cannot inject this IO.
                let mut builder = hyper::client::conn::http1::Builder::new();
                builder.writev(true);
                let (mut sender, connection) =
                    builder.handshake(TokioIo::new(writer)).await.unwrap();
                let driver = tokio::spawn(connection);
                let data = Bytes::from(vec![0xfe; 32]);
                let body = if exact {
                    Either::Left(Full::new(data))
                } else {
                    Either::Right(StreamBody::new(futures_util::stream::iter([Ok::<
                        _,
                        Infallible,
                    >(
                        Frame::data(data),
                    )])))
                };
                let request = Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header(header::HOST, "example.test")
                    .body(LeaseBody::new(body, &authenticated, Direction::Upload))
                    .unwrap();
                drop(authenticated);
                assert!(sender.send_request(request).await.is_err());
                // Hyper may report the I/O failure to the waiter and then finish
                // its driver successfully. Only the request result is contractual.
                let _ = driver.await.unwrap();
                drop(sender);
                assert_partial(&accepted);
                assert_totals(&reader, 8, 0);
            }
        })
        .await
        .expect("partial H1 upload must finish on the writer error");
    }
}
