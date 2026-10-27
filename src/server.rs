mod auth;
mod auto;
mod context;
mod handle;
mod http;
pub(crate) mod io;
mod masque;
mod runtime;
mod socks;
pub(crate) mod tls;

use std::{
    io::{self as std_io, IsTerminal},
    net::SocketAddr,
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};

use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use self::{auto::AutoDetectServer, http::HttpServer, masque::MasqueServer, socks::Socks5Server};
use crate::{AuthMode, BootArgs, Proxy, Result, connect::Connector};

#[cfg(feature = "management")]
pub(crate) use self::runtime::Completion;
pub(crate) use self::{auth::Source, context::Context, handle::Handle, runtime::Runtime};

const CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
// A bounded default that accommodates common QUIC packets without reserving a
// maximum-sized UDP datagram for every active relay.
const MAX_UDP_RELAY_PAYLOAD_SIZE: usize = 1_500;

/// Validate both the OS backlog representation and Tokio's permit bound before
/// binding sockets, loading certificates, or changing any runtime settings.
/// Zero is not an unlimited mode. The same startup range applies to managed
/// listeners and the legacy CLI on 32-bit and 64-bit targets.
pub(crate) fn validate_concurrent(value: u32) -> std_io::Result<usize> {
    let count = usize::try_from(value).map_err(|_| {
        std_io::Error::new(
            std_io::ErrorKind::InvalidInput,
            "invalid proxy connection limit",
        )
    })?;
    if count == 0 || count > Semaphore::MAX_PERMITS || value > i32::MAX as u32 {
        return Err(std_io::Error::new(
            std_io::ErrorKind::InvalidInput,
            "proxy concurrent must be non-zero and fit the socket/semaphore limits",
        ));
    }
    Ok(count)
}

/// One independent budget per listener. Owned permits follow TCP sessions and
/// their remaining HTTP work; MASQUE uses this budget for CONNECT-UDP tunnels.
fn connection_limit(value: u32) -> std_io::Result<Arc<Semaphore>> {
    validate_concurrent(value).map(|count| Arc::new(Semaphore::new(count)))
}

fn is_oversized_datagram_error(error: &std_io::Error) -> bool {
    let Some(code) = error.raw_os_error() else {
        return false;
    };
    #[cfg(windows)]
    {
        code == 10040
    }
    #[cfg(unix)]
    {
        code == libc::EMSGSIZE
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Trait for connection acceptors that handle incoming TCP streams.
pub trait Acceptor {
    /// Accepts and processes an incoming connection.
    async fn accept(self, conn: (TcpStream, SocketAddr), handle: Handle);
}

/// Common interface for starting proxy servers.
pub trait Server {
    /// Starts accepting connections and runs until graceful shutdown begins.
    async fn start(self, handle: Handle) -> std::io::Result<()>;

    /// Reserve capacity before accepting, including before TLS, auto detection
    /// and authentication. Saturation leaves sockets in the OS backlog instead
    /// of creating an unbounded set of accepted tasks waiting for capacity.
    /// Canceling either wait drops the reservation; closing the budget is a
    /// local I/O error, not a protocol response to an unparsed peer.
    #[inline]
    async fn incoming(
        listener: &mut TcpListener,
        limit: &Arc<Semaphore>,
    ) -> std_io::Result<((TcpStream, SocketAddr), OwnedSemaphorePermit)> {
        let permit = limit
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| std_io::Error::other("proxy connection limit closed"))?;
        loop {
            match listener.accept().await {
                Ok(conn) => return Ok((conn, permit)),
                Err(error) => {
                    tracing::trace!("Failed to accept connection: {error}");
                    tokio::time::sleep(Duration::from_millis(50)).await
                }
            }
        }
    }
}

/// Startup-only protocol selection, separate from authentication. Optional TLS
/// files preserve the legacy CLI's self-signed behavior; the managed config
/// loader supplies an owned identity, not paths to reopen at listener bind.
pub(crate) enum ServerKind {
    Http,
    Https { tls: tls::Source },
    Socks5,
    Masque { tls: tls::Source },
    Auto { tls: tls::Source },
}

/// A listener whose socket and TLS state were constructed successfully. Keeping
/// construction separate from acceptance lets managed startup bind every
/// listener atomically with respect to readiness: a later error drops all
/// earlier sockets before any protocol accept loop is spawned.
pub(crate) enum BoundServer {
    Http(Box<HttpServer>),
    Https(Box<HttpServer<http::tls::RustlsAcceptor>>),
    Socks5(Box<Socks5Server>),
    Masque(Box<MasqueServer>),
    Auto(Box<AutoDetectServer>),
}

impl BoundServer {
    /// Inspect only the public leaf installed by the successful constructor.
    /// Plaintext variants have no TLS identity; this never reopens a PEM path.
    #[cfg(feature = "management")]
    pub(crate) fn certificate_leaf(&self) -> Option<&[u8]> {
        match self {
            Self::Http(_) | Self::Socks5(_) => None,
            Self::Https(server) => server.certificate_leaf(),
            Self::Masque(server) => server.certificate_leaf(),
            Self::Auto(server) => server.certificate_leaf(),
        }
    }

    /// Test fixtures observe sockets only after the actual protocol has bound;
    /// probing a TCP port first cannot reserve it or select a free UDP port.
    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> std_io::Result<SocketAddr> {
        match self {
            Self::Http(server) => server.local_addr(),
            Self::Https(server) => server.local_addr(),
            Self::Socks5(server) => server.local_addr(),
            Self::Masque(server) => server.local_addr(),
            Self::Auto(server) => server.local_addr(),
        }
    }

    /// Bind a protocol listener on the current forwarding runtime. File and
    /// socket errors are returned without starting any accept task.
    pub(crate) fn bind(context: Context, kind: ServerKind) -> std_io::Result<Self> {
        match kind {
            ServerKind::Http => HttpServer::new(context).map(Box::new).map(Self::Http),
            ServerKind::Https { tls } => {
                let server = HttpServer::new(context)?;
                let server = match tls {
                    tls::Source::Files { certificate, key } => server.with_https(certificate, key),
                    #[cfg(feature = "management")]
                    tls::Source::Identity(identity) => server.with_identity(identity),
                }?;
                Ok(Self::Https(Box::new(server)))
            }
            ServerKind::Socks5 => Socks5Server::new(context).map(Box::new).map(Self::Socks5),
            ServerKind::Masque { tls } => {
                let server = match tls {
                    tls::Source::Files { certificate, key } => {
                        MasqueServer::new(context, certificate, key)
                    }
                    #[cfg(feature = "management")]
                    tls::Source::Identity(identity) => {
                        MasqueServer::from_identity(context, identity)
                    }
                }?;
                Ok(Self::Masque(Box::new(server)))
            }
            ServerKind::Auto { tls } => {
                let server = match tls {
                    tls::Source::Files { certificate, key } => {
                        AutoDetectServer::new(context, certificate, key)
                    }
                    #[cfg(feature = "management")]
                    tls::Source::Identity(identity) => {
                        AutoDetectServer::from_identity(context, identity)
                    }
                }?;
                Ok(Self::Auto(Box::new(server)))
            }
        }
    }

    /// Accept until the shared shutdown request, then apply the protocol's
    /// existing connection/stream drain rules.
    pub(crate) async fn start(self, handle: Handle) -> std_io::Result<()> {
        match self {
            Self::Http(server) => (*server).start(handle).await,
            Self::Https(server) => (*server).start(handle).await,
            Self::Socks5(server) => (*server).start(handle).await,
            Self::Masque(server) => (*server).start(handle).await,
            Self::Auto(server) => (*server).start(handle).await,
        }
    }
}

/// Reap accepted tasks under the runtime's retained shutdown phase. Aborting
/// remaining work is cleanup, not a successful drain; report it even after all
/// aborted tasks have released their resources. A task failure during this wait
/// is also returned rather than hidden in a debug log.
async fn drain_connections(
    connections: &mut JoinSet<()>,
    protocol: &str,
    handle: &Handle,
) -> std_io::Result<()> {
    let mut failure = None;
    let drained = handle
        .wait_for_drain(
            async {
                while let Some(result) = connections.join_next().await {
                    if let Err(error) = result {
                        tracing::debug!("{protocol} connection task failed: {error}");
                        failure.get_or_insert_with(|| std_io::Error::other(error));
                        handle.request_graceful_shutdown();
                    }
                }
            },
            Duration::ZERO,
        )
        .await;
    if let Err(error) = drained {
        tracing::debug!(kind = ?error.kind(), "{protocol} connection drain did not finish");
        connections.abort_all();
        while let Some(result) = connections.join_next().await {
            log_connection_result(result, protocol);
        }
        return Err(failure.unwrap_or(error));
    }
    failure.map_or(Ok(()), Err)
}

/// After accept and protocol drivers stop, wait for independently owned HTTP
/// bodies and upgraded streams to release the listener's existing slots. This
/// is only a cold-path ownership barrier, not proof of remote data delivery.
/// The original validated capacity must be supplied; available permits alone
/// cannot distinguish outstanding work from the listener's configured limit.
async fn drain_permits(
    limit: &Arc<Semaphore>,
    capacity: u32,
    handle: &Handle,
) -> std_io::Result<()> {
    let permit = handle
        .wait_for_drain(limit.clone().acquire_many_owned(capacity), Duration::ZERO)
        .await?
        .map_err(|_| std_io::Error::other("proxy connection limit closed during shutdown"))?;
    drop(permit);
    Ok(())
}

fn log_connection_result(result: std::result::Result<(), tokio::task::JoinError>, protocol: &str) {
    if let Err(error) = result
        && !error.is_cancelled()
    {
        tracing::debug!("{protocol} connection task failed: {error}");
    }
}

/// Runs the selected proxy server.
pub fn run(args: BootArgs) -> Result<()> {
    validate_concurrent(args.concurrent)?;
    let filter = EnvFilter::from_default_env()
        .add_directive(args.log.into())
        .add_directive("netlink_proto=error".parse()?);

    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_max_level(args.log)
            .with_env_filter(filter)
            .with_ansi(std_io::stderr().is_terminal())
            .finish(),
    )?;

    let workers = match args.workers {
        Some(workers) => NonZeroUsize::new(workers).ok_or_else(|| {
            std_io::Error::new(
                std_io::ErrorKind::InvalidInput,
                "worker count must be non-zero",
            )
        })?,
        None => std::thread::available_parallelism()?,
    };

    let profile_config = args.profile_config()?;
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        // Only an active loader changes process privileges. Perform legacy
        // CIDR preparation first, then restrict before workers inherit them.
        // Native/feature-disabled startup keeps its existing route path below.
        if profile_config.is_active()
            && let Some(cidr) = &args.cidr
        {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    crate::route::sysctl_ipv6_no_local_bind(cidr);
                    crate::route::sysctl_ipv6_all_enable_ipv6(cidr);
                    crate::route::sysctl_route_add_cidr(cidr).await;
                });
        }
        profile_config.restrict_runtime_privileges(
            args.bind.port() != 0 && args.bind.port() < 1024,
            matches!(&args.fallback, Some(crate::connect::Fallback::Interface(_))),
        )?;
    }

    Runtime::new(workers).block_on(move |handle| async move {
        #[cfg(target_os = "linux")]
        if let Some(cidr) = &args.cidr {
            #[cfg(feature = "ebpf")]
            let prepared = profile_config.is_active();
            #[cfg(not(feature = "ebpf"))]
            let prepared = false;
            if !prepared {
                crate::route::sysctl_ipv6_no_local_bind(cidr);
                crate::route::sysctl_ipv6_all_enable_ipv6(cidr);
                crate::route::sysctl_route_add_cidr(cidr).await;
            }
        }

        tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            os = std::env::consts::OS,
            arch = std::env::consts::ARCH,
            threads = workers.get(),
            concurrent_limit = args.concurrent,
            connect_timeout = %format_args!("{} (s)", args.connect_timeout),
            "starting vproxy on {}",
            args.bind,
        );

        let context = move |auth: AuthMode| Context {
            auth: Source::from(auth),
            bind: args.bind,
            concurrent: args.concurrent,
            connect_timeout: args.connect_timeout,
            connector: Connector::new(
                args.cidr,
                args.cidr_range,
                args.fallback,
                args.connect_timeout,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                args.tcp_user_timeout,
                args.reuseaddr,
            )
            .with_profile_config(profile_config),
        };

        let (context, kind) = match args.proxy {
            Proxy::Http { auth } => (context(auth), ServerKind::Http),
            Proxy::Https {
                auth,
                tls_cert,
                tls_key,
            } => (
                context(auth),
                ServerKind::Https {
                    tls: tls::Source::Files {
                        certificate: tls_cert,
                        key: tls_key,
                    },
                },
            ),
            Proxy::Socks5 { auth } => (context(auth), ServerKind::Socks5),
            Proxy::Quic {
                auth,
                tls_cert,
                tls_key,
            } => (
                context(auth),
                ServerKind::Masque {
                    tls: tls::Source::Files {
                        certificate: tls_cert,
                        key: tls_key,
                    },
                },
            ),
            Proxy::Auto {
                auth,
                tls_cert,
                tls_key,
            } => (
                context(auth),
                ServerKind::Auto {
                    tls: tls::Source::Files {
                        certificate: tls_cert,
                        key: tls_key,
                    },
                },
            ),
        };
        BoundServer::bind(context, kind)?
            .start(handle)
            .await
            .map_err(Into::into)
    })
}

#[cfg(test)]
mod admission_tests {
    //! Listener admission owns capacity before accepting any peer, including while
    //! protocol detection or an established SOCKS control connection is pending.

    mod http2 {
        //! HTTP/2 streams share one TCP admission, including through TLS negotiation.

        use std::{
            future::poll_fn,
            sync::{Arc, Mutex},
        };

        use base64::Engine;
        use bytes::Bytes;
        use http::{Method, Request, StatusCode, Version, header};
        use http_body_util::Empty;
        use hyper::{client::conn::http2, upgrade::Upgraded};
        use hyper_util::rt::TokioIo;
        use tokio::io::{AsyncRead, AsyncWrite};
        use tokio_rustls::{TlsConnector, rustls};

        use super::*;

        type Sender = http2::SendRequest<Empty<Bytes>>;
        type Tunnel = TokioIo<Upgraded>;

        /// Hyper executes its transport and upgraded send drivers separately from the
        /// public connection future. Own all of them; never hold this short lock while
        /// awaiting a driver, since that driver can itself submit an upgrade task.
        #[derive(Clone, Default)]
        struct Drivers(Arc<Mutex<DriverState>>);

        #[derive(Default)]
        struct DriverState {
            tasks: JoinSet<io::Result<()>>,
            closed: bool,
        }

        impl<F> hyper::rt::Executor<F> for Drivers
        where
            F: Future<Output = ()> + Send + 'static,
        {
            fn execute(&self, future: F) {
                let mut state = self.0.lock().unwrap();
                if state.closed {
                    // Dropping a driver can release another owner that calls back into
                    // this executor. Never drop its future while holding the lock.
                    drop(state);
                    drop(future);
                    return;
                }
                state.tasks.spawn(async move {
                    future.await;
                    Ok(())
                });
            }
        }

        impl Drivers {
            fn abort_all(&self) {
                let mut state = self.0.lock().unwrap();
                state.closed = true;
                state.tasks.abort_all();
            }

            async fn join(&self, cancelled: bool) -> io::Result<()> {
                let mut result = Ok(());
                while let Some(joined) =
                    poll_fn(|cx| self.0.lock().unwrap().tasks.poll_join_next(cx)).await
                {
                    let next = match joined {
                        Ok(result) => result,
                        Err(error) if cancelled && error.is_cancelled() => Ok(()),
                        Err(error) => Err(io::Error::other(error)),
                    };
                    if result.is_ok() {
                        result = next;
                    }
                }
                result
            }
        }

        fn require(condition: bool, message: &'static str) -> io::Result<()> {
            if condition {
                Ok(())
            } else {
                Err(io::Error::other(message))
            }
        }

        async fn client<I>(stream: I, drivers: &Drivers) -> io::Result<Sender>
        where
            I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        {
            let (sender, connection) =
                http2::handshake::<_, _, Empty<Bytes>>(drivers.clone(), TokioIo::new(stream))
                    .await
                    .map_err(io::Error::other)?;
            drivers
                .0
                .lock()
                .unwrap()
                .tasks
                .spawn(async move { connection.await.map_err(io::Error::other) });
            Ok(sender)
        }

        async fn connect(
            sender: &mut Sender,
            destination: SocketAddr,
            authorization: Option<&str>,
        ) -> io::Result<hyper::Response<hyper::body::Incoming>> {
            let mut request = Request::builder()
                .method(Method::CONNECT)
                .version(Version::HTTP_2)
                .uri(destination.to_string());
            if let Some(authorization) = authorization {
                request = request.header(header::PROXY_AUTHORIZATION, authorization);
            }
            sender.ready().await.map_err(io::Error::other)?;
            sender
                .send_request(request.body(Empty::new()).map_err(io::Error::other)?)
                .await
                .map_err(io::Error::other)
        }

        async fn connected(sender: &mut Sender, destination: SocketAddr) -> io::Result<Tunnel> {
            let response = connect(sender, destination, None).await?;
            require(
                response.status() == StatusCode::OK,
                "H2 CONNECT was not accepted",
            )?;
            Ok(TokioIo::new(
                hyper::upgrade::on(response)
                    .await
                    .map_err(io::Error::other)?,
            ))
        }

        async fn exchange<I>(
            client: &mut I,
            origin: &mut TcpStream,
            upload: &[u8],
            download: &[u8],
        ) -> io::Result<()>
        where
            I: AsyncRead + AsyncWrite + Unpin,
        {
            client.write_all(upload).await?;
            let mut received = vec![0; upload.len()];
            origin.read_exact(&mut received).await?;
            require(
                received == upload,
                "CONNECT upload crossed streams or changed bytes",
            )?;
            origin.write_all(download).await?;
            received.resize(download.len(), 0);
            client.read_exact(&mut received).await?;
            require(
                received == download,
                "CONNECT download crossed streams or changed bytes",
            )
        }

        async fn finish_tunnel<I>(
            client: &mut I,
            origin: &mut TcpStream,
            tail: &[u8],
        ) -> io::Result<()>
        where
            I: AsyncRead + AsyncWrite + Unpin,
        {
            // CONNECT's END_STREAM closes only this direction; the peer can still send
            // its final DATA. https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5
            client.shutdown().await?;
            let mut byte = [0];
            require(
                origin.read(&mut byte).await? == 0,
                "CONNECT half-close did not reach its origin",
            )?;
            origin.write_all(tail).await?;
            origin.shutdown().await?;
            let mut received = Vec::new();
            client.read_to_end(&mut received).await?;
            require(
                received == tail,
                "CONNECT discarded its reverse tail after half-close",
            )
        }

        async fn response_head(client: &mut TcpStream) -> io::Result<Vec<u8>> {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                require(
                    head.len() < 4096,
                    "queued CONNECT response exceeded fixture bound",
                )?;
                head.push(client.read_u8().await?);
            }
            Ok(head)
        }

        #[tokio::test]
        async fn h2_connect_streams_are_independent_and_retain_one_tcp_admission() -> io::Result<()>
        {
            let (address, handle, tasks) = start_fixture(ServerKind::Http)?;
            let drivers = Drivers::default();
            let result = timeout(FIXTURE_TIMEOUT, async {
                let first_origin = TcpListener::bind("127.0.0.1:0").await?;
                let second_origin = TcpListener::bind("127.0.0.1:0").await?;
                let later_origin = TcpListener::bind("127.0.0.1:0").await?;
                let queued_origin = TcpListener::bind("127.0.0.1:0").await?;
                let mut sender = client(TcpStream::connect(address).await?, &drivers).await?;
                let mut first = connected(&mut sender, first_origin.local_addr()?).await?;
                let (mut first_peer, _) = first_origin.accept().await?;
                let mut second = connected(&mut sender, second_origin.local_addr()?).await?;
                let (mut second_peer, _) = second_origin.accept().await?;
                exchange(
                    &mut first,
                    &mut first_peer,
                    b"first-upload",
                    b"first-download",
                )
                .await?;
                exchange(
                    &mut second,
                    &mut second_peer,
                    b"second-upload",
                    b"second-download",
                )
                .await?;

                let mut queued = TcpStream::connect(address).await?;
                let destination = queued_origin.local_addr()?;
                queued
                    .write_all(
                        format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n")
                            .as_bytes(),
                    )
                    .await?;
                no_reply_while_saturated(&mut queued).await?;

                // Drop cancels this independent stream, without claiming a particular
                // RST_STREAM code. The other tunnel and the H2 transport must survive.
                drop(first);
                let mut byte = [0];
                match first_peer.read(&mut byte).await {
                    Ok(0) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::BrokenPipe
                        ) => {}
                    Err(error) => return Err(error),
                    Ok(_) => {
                        return Err(io::Error::other(
                            "cancelled stream produced unexpected origin data",
                        ));
                    }
                }
                drop(first_peer);
                exchange(
                    &mut second,
                    &mut second_peer,
                    b"still-second",
                    b"still-independent",
                )
                .await?;
                finish_tunnel(&mut second, &mut second_peer, b"reply-after-end-stream").await?;
                drop(second);
                drop(second_peer);

                let mut later = connected(&mut sender, later_origin.local_addr()?).await?;
                let (mut later_peer, _) = later_origin.accept().await?;
                exchange(
                    &mut later,
                    &mut later_peer,
                    b"new-stream",
                    b"same-connection",
                )
                .await?;
                finish_tunnel(&mut later, &mut later_peer, b"").await?;
                drop(later);
                drop(later_peer);
                no_reply_while_saturated(&mut queued).await?;

                // Completed streams are not completed TCP admission. Dropping the last
                // sender closes this idle transport; join its real executor tasks too.
                drop(sender);
                drivers.join(false).await?;
                require(
                    response_head(&mut queued)
                        .await?
                        .starts_with(b"HTTP/1.1 200 "),
                    "closing H2 did not restore listener admission",
                )?;
                let (mut queued_peer, _) = queued_origin.accept().await?;
                exchange(
                    &mut queued,
                    &mut queued_peer,
                    b"queued-upload",
                    b"queued-download",
                )
                .await?;
                finish_tunnel(&mut queued, &mut queued_peer, b"queued-tail").await
            })
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "H2 admission fixture stalled",
                ))
            });
            if result.is_err() {
                drivers.abort_all();
            }
            let joined = drivers.join(result.is_err()).await;
            finish_fixture(handle, tasks, result.and(joined)).await
        }

        #[tokio::test]
        async fn explicit_https_h2_negotiation_holds_admission_and_enforces_basic_auth()
        -> io::Result<()> {
            let files = AutoTlsFiles::new()?;
            let certificate = fs::read(files.0.join("cert.pem"))?;
            let mut roots = rustls::RootCertStore::empty();
            for certificate in rustls_pemfile::certs(&mut certificate.as_slice()) {
                roots
                    .add(certificate.map_err(io::Error::other)?)
                    .map_err(io::Error::other)?;
            }
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots)
            .with_no_client_auth();
            config.alpn_protocols = vec![b"h2".to_vec()];
            let connector = TlsConnector::from(Arc::new(config));
            let (address, handle, tasks) = start_fixture_with_auth(
                ServerKind::Https {
                    tls: crate::server::tls::Source::Files {
                        certificate: Some(files.0.join("cert.pem")),
                        key: Some(files.0.join("key.pem")),
                    },
                },
                Source::Legacy(AuthMode {
                    username: Some("admission-user".into()),
                    password: Some("admission-password".into()),
                }),
            )?;
            let drivers = Drivers::default();
            let result = timeout(FIXTURE_TIMEOUT, async {
                let stalled = TcpStream::connect(address).await?;
                let next = TcpStream::connect(address).await?;
                let handshake = connector.connect(
                    rustls::pki_types::ServerName::try_from("localhost")
                        .map_err(io::Error::other)?,
                    next,
                );
                tokio::pin!(handshake);
                // Borrow the same future: timing out this observation must not discard
                // its ClientHello or replace the queued TCP connection on retry.
                require(
                    timeout(Duration::from_millis(100), handshake.as_mut())
                        .await
                        .is_err(),
                    "second TLS connection bypassed saturated admission",
                )?;
                drop(stalled);
                let tls = handshake.await.map_err(io::Error::other)?;
                require(
                    tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()),
                    "explicit certificate listener did not negotiate H2",
                )?;
                let mut sender = client(tls, &drivers).await?;
                let origin = TcpListener::bind("127.0.0.1:0").await?;
                let wrong = format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD
                        .encode("admission-user:wrong-password")
                );
                let denied = connect(&mut sender, origin.local_addr()?, Some(&wrong)).await?;
                require(
                    denied.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                    "wrong H2 proxy password was not challenged",
                )?;
                require(
                    denied.headers().contains_key(header::PROXY_AUTHENTICATE),
                    "H2 407 omitted its proxy challenge",
                )?;
                drop(denied);
                let mut incoming = Box::pin(origin.accept());
                let mut context = TaskContext::from_waker(Waker::noop());
                require(
                    incoming.as_mut().poll(&mut context).is_pending(),
                    "wrong H2 proxy password reached the origin",
                )?;
                drop(incoming);

                let correct = format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD
                        .encode("admission-user:admission-password")
                );
                let response = connect(&mut sender, origin.local_addr()?, Some(&correct)).await?;
                require(
                    response.status() == StatusCode::OK,
                    "correct H2 proxy credentials were rejected",
                )?;
                let mut tunnel = TokioIo::new(
                    hyper::upgrade::on(response)
                        .await
                        .map_err(io::Error::other)?,
                );
                let (mut peer, _) = origin.accept().await?;
                exchange(&mut tunnel, &mut peer, b"tls-upload", b"tls-download").await?;
                finish_tunnel(&mut tunnel, &mut peer, b"tls-tail").await?;
                drop(tunnel);
                drop(peer);
                drop(sender);
                drivers.join(false).await
            })
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTPS H2 admission fixture stalled",
                ))
            });
            if result.is_err() {
                drivers.abort_all();
            }
            let joined = drivers.join(result.is_err()).await;
            finish_fixture(handle, tasks, result.and(joined)).await
        }
    }

    use std::{
        fs::{self, DirBuilder, OpenOptions},
        future::Future,
        io::{self, Write as _},
        net::SocketAddr,
        path::PathBuf,
        pin::Pin,
        task::{Context as TaskContext, Waker},
        time::Duration,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::Semaphore,
        task::JoinSet,
        time::timeout,
    };

    use super::{
        BoundServer, Context, Handle, Server, ServerKind, Source, connection_limit,
        http::{HttpServer, accept::DefaultAcceptor},
        validate_concurrent,
    };
    use crate::{AuthMode, connect::Connector};

    const FIXTURE_TIMEOUT: Duration = Duration::from_secs(10);

    fn assert_pending(future: Pin<&mut impl Future>) {
        let mut context = TaskContext::from_waker(Waker::noop());
        assert!(future.poll(&mut context).is_pending());
    }

    #[test]
    fn concurrent_limits_reject_zero_and_overflow_before_semaphore_creation() -> io::Result<()> {
        let maximum = (i32::MAX as usize).min(Semaphore::MAX_PERMITS);
        let maximum = u32::try_from(maximum).expect("socket bound fits u32");
        for value in [1, 1024, maximum] {
            assert_eq!(validate_concurrent(value)?, value as usize);
            assert_eq!(connection_limit(value)?.available_permits(), value as usize);
        }
        for value in [0, maximum.checked_add(1).expect("bounded by i32"), u32::MAX] {
            assert_eq!(
                validate_concurrent(value)
                    .expect_err("invalid limit")
                    .kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                connection_limit(value)
                    .expect_err("must validate before Semaphore::new")
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn incoming_at_capacity_resumes_only_after_a_permit_is_released() -> io::Result<()> {
        timeout(FIXTURE_TIMEOUT, async {
            let mut listener = TcpListener::bind("127.0.0.1:0").await?;
            let limit = connection_limit(1)?;
            let held = limit.clone().acquire_owned().await.expect("open budget");
            let client = TcpStream::connect(listener.local_addr()?).await?;
            let client_address = client.local_addr()?;
            let mut incoming = Box::pin(HttpServer::<DefaultAcceptor>::incoming(
                &mut listener,
                &limit,
            ));
            assert_pending(incoming.as_mut());
            assert_eq!(limit.available_permits(), 0);

            drop(held);
            let ((accepted, peer), permit) = incoming.await?;
            assert_eq!(peer, client_address);
            assert_eq!(limit.available_permits(), 0);
            drop(accepted);
            drop(client);
            drop(permit);
            assert_eq!(limit.available_permits(), 1);
            Ok(())
        })
        .await
        .expect("owned loopback admission must complete")
    }

    #[tokio::test]
    async fn cancelling_a_capacity_wait_leaves_the_peer_in_the_backlog() -> io::Result<()> {
        timeout(FIXTURE_TIMEOUT, async {
            let mut listener = TcpListener::bind("127.0.0.1:0").await?;
            let limit = connection_limit(1)?;
            let held = limit.clone().acquire_owned().await.expect("open budget");
            let mut client = TcpStream::connect(listener.local_addr()?).await?;
            let peer = client.local_addr()?;
            client.write_all(b"still queued").await?;
            {
                let mut incoming = Box::pin(HttpServer::<DefaultAcceptor>::incoming(
                    &mut listener,
                    &limit,
                ));
                assert_pending(incoming.as_mut());
            }
            assert_eq!(limit.available_permits(), 0);
            drop(held);
            assert_eq!(limit.available_permits(), 1);

            // If incoming accepted before reserving capacity, cancellation would
            // have discarded this exact peer instead of leaving it in the backlog.
            let ((mut accepted, address), permit) =
                HttpServer::<DefaultAcceptor>::incoming(&mut listener, &limit).await?;
            assert_eq!(address, peer);
            let mut data = [0; 12];
            accepted.read_exact(&mut data).await?;
            assert_eq!(&data, b"still queued");
            drop(accepted);
            drop(client);
            drop(permit);
            assert_eq!(limit.available_permits(), 1);
            Ok(())
        })
        .await
        .expect("cancelling admission must not consume the queued peer")
    }

    #[tokio::test]
    async fn cancelling_an_accept_wait_returns_the_reserved_permit() -> io::Result<()> {
        timeout(FIXTURE_TIMEOUT, async {
            let mut listener = TcpListener::bind("127.0.0.1:0").await?;
            let limit = connection_limit(1)?;
            {
                let mut incoming = Box::pin(HttpServer::<DefaultAcceptor>::incoming(
                    &mut listener,
                    &limit,
                ));
                assert_pending(incoming.as_mut());
                assert_eq!(limit.available_permits(), 0);
            }
            assert_eq!(limit.available_permits(), 1);
            let client = TcpStream::connect(listener.local_addr()?).await?;
            let ((accepted, _), permit) =
                HttpServer::<DefaultAcceptor>::incoming(&mut listener, &limit).await?;
            assert_eq!(limit.available_permits(), 0);
            drop(accepted);
            drop(client);
            drop(permit);
            assert_eq!(limit.available_permits(), 1);
            Ok(())
        })
        .await
        .expect("accept cancellation must leave the listener reusable")
    }

    #[tokio::test]
    async fn a_closed_budget_returns_an_error_without_accepting_the_peer() -> io::Result<()> {
        timeout(FIXTURE_TIMEOUT, async {
            let mut listener = TcpListener::bind("127.0.0.1:0").await?;
            let limit = connection_limit(1)?;
            let client = TcpStream::connect(listener.local_addr()?).await?;
            let peer = client.local_addr()?;
            limit.close();
            assert!(
                HttpServer::<DefaultAcceptor>::incoming(&mut listener, &limit)
                    .await
                    .is_err()
            );
            let (accepted, address) = listener.accept().await?;
            assert_eq!(address, peer);
            drop(accepted);
            drop(client);
            Ok(())
        })
        .await
        .expect("a closed admission budget must fail before accept")
    }

    fn start_fixture(
        kind: ServerKind,
    ) -> io::Result<(SocketAddr, Handle, JoinSet<io::Result<()>>)> {
        start_fixture_with_auth(
            kind,
            Source::Legacy(AuthMode {
                username: None,
                password: None,
            }),
        )
    }

    fn start_fixture_with_auth(
        kind: ServerKind,
        auth: Source,
    ) -> io::Result<(SocketAddr, Handle, JoinSet<io::Result<()>>)> {
        let server = BoundServer::bind(
            Context {
                bind: "127.0.0.1:0".parse().expect("loopback socket address"),
                concurrent: 1,
                connect_timeout: 2,
                auth,
                connector: Connector::new(
                    None,
                    None,
                    None,
                    2,
                    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                    None,
                    None,
                ),
            },
            kind,
        )?;
        let address = server.local_addr()?;
        let handle = Handle::new();
        let mut tasks = JoinSet::new();
        tasks.spawn(server.start(handle.clone()));
        Ok((address, handle, tasks))
    }

    async fn finish_fixture(
        handle: Handle,
        mut tasks: JoinSet<io::Result<()>>,
        result: io::Result<()>,
    ) -> io::Result<()> {
        handle.request_graceful_shutdown();
        let stopped = match timeout(FIXTURE_TIMEOUT, tasks.join_next()).await {
            Ok(Some(joined)) => joined.map_err(io::Error::other)?,
            Ok(None) => Err(io::Error::other("fixture server task disappeared")),
            Err(_) => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "fixture server did not stop",
                ))
            }
        };
        stopped?;
        result
    }

    async fn socks_greeting(client: &mut TcpStream) -> io::Result<()> {
        client.write_all(&[5, 1, 0]).await?;
        let mut response = [0; 2];
        client.read_exact(&mut response).await?;
        if response != [5, 0] {
            return Err(io::Error::other("anonymous SOCKS negotiation failed"));
        }
        Ok(())
    }

    async fn no_reply_while_saturated(client: &mut TcpStream) -> io::Result<()> {
        // The first peer has already received a protocol success response. This
        // bounded absence check observes admission; it is not a readiness sleep.
        let mut byte = [0];
        match timeout(Duration::from_millis(100), client.read(&mut byte)).await {
            Err(_) => Ok(()),
            Ok(Err(error)) => Err(error),
            Ok(Ok(_)) => Err(io::Error::other(
                "saturated listener replied to or closed a queued peer",
            )),
        }
    }

    #[tokio::test]
    async fn socks_bind_and_udp_control_sessions_hold_the_listener_budget() -> io::Result<()> {
        for command in [2, 3] {
            let (address, handle, tasks) = start_fixture(ServerKind::Socks5)?;
            let result = timeout(FIXTURE_TIMEOUT, async {
                let mut control = TcpStream::connect(address).await?;
                socks_greeting(&mut control).await?;
                // RFC 1928 section 6: BIND waits after its first success reply;
                // UDP ASSOCIATE keeps the association until this TCP control ends.
                // https://www.rfc-editor.org/rfc/rfc1928.html#section-6
                control
                    .write_all(&[5, command, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await?;
                let mut reply = [0; 10];
                control.read_exact(&mut reply).await?;
                if reply[..4] != [5, 0, 0, 1] || reply[8..] == [0, 0] {
                    return Err(io::Error::other(
                        "SOCKS control command did not establish a listener",
                    ));
                }

                let mut queued = TcpStream::connect(address).await?;
                queued.write_all(&[5, 1, 0]).await?;
                no_reply_while_saturated(&mut queued).await?;
                drop(control);
                let mut response = [0; 2];
                queued.read_exact(&mut response).await?;
                if response != [5, 0] {
                    return Err(io::Error::other(
                        "closing the SOCKS control did not restore admission",
                    ));
                }
                // Shutdown must also interrupt the next capacity wait while this
                // admitted peer is still waiting to send its SOCKS command.
                handle.request_graceful_shutdown();
                drop(queued);
                Ok(())
            })
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "SOCKS admission fixture stalled",
                ))
            });
            finish_fixture(handle, tasks, result).await?;
        }
        Ok(())
    }

    /// Explicit proxy-only fixture files prevent auto construction from touching
    /// the legacy application's global self-signed-certificate directory.
    struct AutoTlsFiles(PathBuf);

    impl AutoTlsFiles {
        fn new() -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "vproxy-admission-{}-{:016x}",
                std::process::id(),
                crate::rand::random_u64()
            ));
            let builder = DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder.create(&path)?;
            let files = Self(path);
            let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .map_err(io::Error::other)?;
            files.write("cert.pem", identity.cert.pem().as_bytes())?;
            files.write("key.pem", identity.signing_key.serialize_pem().as_bytes())?;
            Ok(files)
        }

        fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(self.0.join(name))?.write_all(bytes)
        }

        fn kind(&self) -> ServerKind {
            ServerKind::Auto {
                tls: super::tls::Source::Files {
                    certificate: Some(self.0.join("cert.pem")),
                    key: Some(self.0.join("key.pem")),
                },
            }
        }
    }

    impl Drop for AutoTlsFiles {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.0.join("key.pem"));
            let _ = fs::remove_file(self.0.join("cert.pem"));
            let _ = fs::remove_dir(&self.0);
        }
    }

    #[tokio::test]
    async fn auto_protocols_share_capacity_through_the_http_upgrade_lifetime() -> io::Result<()> {
        let files = AutoTlsFiles::new()?;
        let (address, handle, tasks) = start_fixture(files.kind())?;
        let result = timeout(FIXTURE_TIMEOUT, async {
            let target = TcpListener::bind("127.0.0.1:0").await?;
            let destination = target.local_addr()?;
            let mut control = TcpStream::connect(address).await?;
            socks_greeting(&mut control).await?;

            let mut tunnel = TcpStream::connect(address).await?;
            tunnel
                .write_all(
                    format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n")
                        .as_bytes(),
                )
                .await?;
            no_reply_while_saturated(&mut tunnel).await?;
            drop(control);
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                if head.len() >= 4096 {
                    return Err(io::Error::other("fixture CONNECT head exceeded limit"));
                }
                head.push(tunnel.read_u8().await?);
            }
            if !head.starts_with(b"HTTP/1.1 200 ") {
                return Err(io::Error::other("auto HTTP CONNECT did not succeed"));
            }
            let (mut origin, _) = target.accept().await?;
            tunnel.write_all(b"upgrade retained").await?;
            let mut payload = [0; 16];
            origin.read_exact(&mut payload).await?;
            if &payload != b"upgrade retained" {
                return Err(io::Error::other("auto CONNECT payload changed"));
            }

            let mut queued = TcpStream::connect(address).await?;
            queued.write_all(&[5, 1, 0]).await?;
            no_reply_while_saturated(&mut queued).await?;
            drop(tunnel);
            drop(origin);
            let mut response = [0; 2];
            queued.read_exact(&mut response).await?;
            if response != [5, 0] {
                return Err(io::Error::other(
                    "finishing the auto upgrade did not restore admission",
                ));
            }
            handle.request_graceful_shutdown();
            drop(queued);
            Ok(())
        })
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "auto admission fixture stalled",
            ))
        });
        finish_fixture(handle, tasks, result).await
    }
}

#[cfg(test)]
mod shutdown_tests {
    //! Shutdown reports forced cancellation separately from natural completion.

    use std::{future::pending, io, sync::Arc, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::oneshot,
        task::{JoinHandle, JoinSet},
        time::{Instant, timeout},
    };

    use super::{
        BoundServer, Context, Handle, ServerKind, Source, connection_limit, drain_connections,
        drain_permits,
    };
    use crate::{AuthMode, connect::Connector};

    #[tokio::test]
    async fn connection_shutdown_reports_timeout_after_reaping_cancelled_owners() {
        let mut connections = JoinSet::new();
        let (entered, ready) = oneshot::channel();
        let (dropped, finished) = oneshot::channel();
        struct DropNotice(Option<oneshot::Sender<()>>);
        impl Drop for DropNotice {
            fn drop(&mut self) {
                if let Some(notice) = self.0.take() {
                    let _ = notice.send(());
                }
            }
        }
        connections.spawn(async move {
            let _owner = DropNotice(Some(dropped));
            entered.send(()).unwrap();
            pending::<()>().await;
        });
        ready.await.unwrap();
        let handle = Handle::new();
        handle.request_shutdown_at(Instant::now() + Duration::from_millis(20));
        let error = drain_connections(&mut connections, "fixture", &handle)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(connections.is_empty());
        finished.await.unwrap();
    }

    #[tokio::test]
    async fn connection_shutdown_returns_task_failure_and_reaps_other_tasks() {
        let handle = Handle::new();
        handle.request_quiesce();
        let mut connections = JoinSet::new();
        connections.spawn(async { panic!("owned fixture task failed") });
        let waiting = handle.clone();
        connections.spawn(async move { waiting.wait_stopping().await });
        let error = drain_connections(&mut connections, "fixture", &handle)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(connections.is_empty());
        assert!(
            !handle.is_quiescing(),
            "a task failure escalates maintenance to process stop"
        );
    }

    #[tokio::test]
    async fn connection_shutdown_returns_success_only_for_naturally_finished_tasks() {
        let handle = Handle::new();
        handle.request_quiesce();
        let mut connections = JoinSet::new();
        connections.spawn(async { tokio::task::yield_now().await });
        drain_connections(&mut connections, "fixture", &handle)
            .await
            .unwrap();
        assert!(connections.is_empty());
        assert!(
            handle.is_quiescing(),
            "normal quiescence must not become a timed stop"
        );
    }

    #[tokio::test]
    async fn connection_ownership_shutdown_waits_for_all_original_slots() {
        let limit = connection_limit(2).unwrap();
        let first = Arc::new(limit.clone().acquire_owned().await.unwrap());
        let second = limit.clone().acquire_owned().await.unwrap();
        let body_owner = first.clone();
        drop(first);
        let handle = Handle::new();
        handle.request_shutdown_at(Instant::now() + Duration::from_millis(20));
        assert_eq!(
            drain_permits(&limit, 2, &handle).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        // A cancelled acquire_many must return any partial reservation.
        drop(second);
        assert_eq!(limit.available_permits(), 1);
        drop(body_owner);
        drain_permits(&limit, 2, &handle).await.unwrap();
        assert_eq!(limit.available_permits(), 2);

        limit.close();
        assert_eq!(
            drain_permits(&limit, 2, &handle).await.unwrap_err().kind(),
            io::ErrorKind::Other
        );
    }

    fn socks_fixture() -> (std::net::SocketAddr, Handle, JoinHandle<io::Result<()>>) {
        let server = BoundServer::bind(
            Context {
                bind: "127.0.0.1:0".parse().unwrap(),
                concurrent: 1,
                connect_timeout: 2,
                auth: Source::Legacy(AuthMode {
                    username: None,
                    password: None,
                }),
                connector: Connector::new(
                    None,
                    None,
                    None,
                    2,
                    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                    None,
                    None,
                ),
            },
            ServerKind::Socks5,
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let handle = Handle::new();
        let task = tokio::spawn(server.start(handle.clone()));
        (address, handle, task)
    }

    async fn socks_negotiate(client: &mut TcpStream) {
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
    }

    async fn socks_first_reply(client: &mut TcpStream) {
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    }

    #[tokio::test]
    async fn socks_shutdown_reports_held_auth_bind_and_udp_sessions_as_incomplete() {
        timeout(Duration::from_secs(10), async {
            let mut checks = JoinSet::new();
            for command in [0, 2, 3] {
                checks.spawn(async move {
                    let (address, handle, server) = socks_fixture();
                    let mut client = TcpStream::connect(address).await.unwrap();
                    // Negotiation confirms the server owns this accepted session.
                    // command=0 then leaves the request head incomplete; there is
                    // no managed lease, but the connection is still outstanding.
                    socks_negotiate(&mut client).await;
                    if command != 0 {
                        client
                            .write_all(&[5, command, 0, 1, 0, 0, 0, 0, 0, 0])
                            .await
                            .unwrap();
                        socks_first_reply(&mut client).await;
                    }
                    assert!(handle.request_quiesce());
                    tokio::task::yield_now().await;
                    assert!(
                        !server.is_finished(),
                        "maintenance must not abort held SOCKS sessions"
                    );
                    handle.request_shutdown_at(Instant::now() + Duration::from_millis(20));
                    assert_eq!(
                        server.await.unwrap().unwrap_err().kind(),
                        io::ErrorKind::TimedOut,
                        "held SOCKS command {command} must not report a completed drain"
                    );
                    let mut byte = [0];
                    assert_eq!(client.read(&mut byte).await.unwrap(), 0);
                    assert!(TcpStream::connect(address).await.is_err());
                });
            }
            while let Some(result) = checks.join_next().await {
                result.unwrap();
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn socks_shutdown_preserves_half_closed_connect_and_delayed_reverse_payload() {
        timeout(Duration::from_secs(10), async {
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = origin.local_addr().unwrap();
            let (address, handle, server) = socks_fixture();
            let mut client = TcpStream::connect(address).await.unwrap();
            socks_negotiate(&mut client).await;
            let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
            request.extend_from_slice(&target.port().to_be_bytes());
            // Payload prefetched with the request must remain part of the tunnel.
            request.extend_from_slice(b"upload before FIN");
            client.write_all(&request).await.unwrap();
            socks_first_reply(&mut client).await;
            let (mut remote, _) = origin.accept().await.unwrap();
            client.shutdown().await.unwrap();
            let mut upload = Vec::new();
            remote.read_to_end(&mut upload).await.unwrap();
            assert_eq!(upload, b"upload before FIN");
            assert!(handle.request_quiesce());
            assert!(!server.is_finished());
            remote.write_all(b"reverse after FIN").await.unwrap();
            remote.shutdown().await.unwrap();
            let mut download = Vec::new();
            client.read_to_end(&mut download).await.unwrap();
            assert_eq!(download, b"reverse after FIN");
            server.await.unwrap().unwrap();
            assert!(handle.is_quiescing());
            assert!(TcpStream::connect(address).await.is_err());
        })
        .await
        .unwrap();
    }
}
