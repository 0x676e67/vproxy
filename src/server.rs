mod auto;
mod context;
mod handle;
mod http;
mod io;
mod masque;
mod runtime;
mod socks;

use std::{
    io::{self as std_io, IsTerminal},
    net::SocketAddr,
    num::NonZeroUsize,
    time::Duration,
};

use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use self::{
    auto::AutoDetectServer, context::Context, handle::Handle, http::HttpServer,
    masque::MasqueServer, runtime::Runtime, socks::Socks5Server,
};
use crate::{AuthMode, BootArgs, Proxy, Result, connect::Connector};

const CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Trait for connection acceptors that handle incoming TCP streams.
pub trait Acceptor {
    /// Accepts and processes an incoming connection.
    async fn accept(self, conn: (TcpStream, SocketAddr), handle: Handle);
}

/// Common interface for starting proxy servers.
pub trait Server {
    /// Starts accepting connections and runs until graceful shutdown begins.
    async fn start(self, handle: Handle) -> std::io::Result<()>;

    /// Accepts incoming TCP connections with retry on temporary failures.
    #[inline]
    async fn incoming(listener: &mut TcpListener) -> (TcpStream, SocketAddr) {
        loop {
            match listener.accept().await {
                Ok(conn) => return conn,
                Err(error) => {
                    tracing::trace!("Failed to accept connection: {error}");
                    tokio::time::sleep(Duration::from_millis(50)).await
                }
            }
        }
    }
}

async fn drain_connections(connections: &mut JoinSet<()>, protocol: &str) {
    if timeout(CONNECTION_DRAIN_TIMEOUT, async {
        while let Some(result) = connections.join_next().await {
            log_connection_result(result, protocol);
        }
    })
    .await
    .is_err()
    {
        tracing::debug!("{protocol} connection drain timed out");
        connections.abort_all();
        while let Some(result) = connections.join_next().await {
            log_connection_result(result, protocol);
        }
    }
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

    Runtime::new(workers).block_on(move |handle| async move {
        #[cfg(target_os = "linux")]
        if let Some(cidr) = &args.cidr {
            crate::route::sysctl_ipv6_no_local_bind(cidr);
            crate::route::sysctl_ipv6_all_enable_ipv6(cidr);
            crate::route::sysctl_route_add_cidr(cidr).await;
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
            auth,
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
            ),
        };

        match args.proxy {
            Proxy::Http { auth } => HttpServer::new(context(auth))?.start(handle).await,
            Proxy::Https {
                auth,
                tls_cert,
                tls_key,
            } => {
                HttpServer::new(context(auth))?
                    .with_https(tls_cert, tls_key)?
                    .start(handle)
                    .await
            }
            Proxy::Socks5 { auth } => Socks5Server::new(context(auth))?.start(handle).await,
            Proxy::Quic {
                auth,
                tls_cert,
                tls_key,
            } => {
                MasqueServer::new(context(auth), tls_cert, tls_key)?
                    .start(handle)
                    .await
            }
            Proxy::Auto {
                auth,
                tls_cert,
                tls_key,
            } => {
                AutoDetectServer::new(context(auth), tls_cert, tls_key)?
                    .start(handle)
                    .await
            }
        }
        .map_err(Into::into)
    })
}
