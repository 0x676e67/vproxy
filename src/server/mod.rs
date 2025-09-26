mod auto;
mod connect;
mod context;
mod extension;
mod http;
mod socks;

use std::{net::SocketAddr, time::Duration};

use tokio::net::{TcpListener, TcpStream};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use self::{
    auto::AutoDetectServer, connect::Connector, context::Context, http::HttpServer,
    socks::Socks5Server,
};
use crate::{AuthMode, Proxy, Result, ServerArgs};

/// Trait for connection acceptors that handle incoming TCP streams.
pub trait Acceptor {
    /// Accepts and processes an incoming connection.
    async fn accept(self, conn: (TcpStream, SocketAddr));
}

/// The [`Server`] trait defines a common interface for starting HTTP and SOCKS5 servers.
///
/// This trait is intended to be implemented by types that represent server configurations
/// for HTTP and SOCKS5 proxy servers. The `start` method is used to start the server and
/// handle incoming connections.
pub trait Server {
    /// Starts the proxy server and runs until shutdown.
    ///
    /// This method binds to the configured address, begins accepting connections,
    /// and handles them according to the proxy protocol (HTTP/HTTPS/SOCKS5).
    /// It runs indefinitely until an error occurs or a shutdown signal is received.
    async fn start(self) -> std::io::Result<()>;

    /// Accepts incoming TCP connections with retry on temporary failures.
    ///
    /// This method continuously attempts to accept connections from the listener.
    /// If a temporary error occurs (e.g., resource temporarily unavailable),
    /// it waits 50ms before retrying to avoid busy-waiting.
    #[inline]
    async fn incoming(listener: &mut TcpListener) -> (TcpStream, SocketAddr) {
        loop {
            match listener.accept().await {
                Ok(value) => return value,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    }
}

/// Run the server with the provided boot arguments.
pub fn run(args: ServerArgs) -> Result<()> {
    // Initialize the logger with a filter that ignores WARN level logs for netlink_proto
    let filter = EnvFilter::from_default_env()
        .add_directive(args.log.into())
        .add_directive("netlink_proto=error".parse()?);

    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_max_level(args.log)
            .with_env_filter(filter)
            .finish(),
    )?;

    let cpu_cores = std::thread::available_parallelism()?;

    tracing::info!("OS: {}", std::env::consts::OS);
    tracing::info!("Arch: {}", std::env::consts::ARCH);
    tracing::info!("CPU cores: {}", cpu_cores);
    tracing::info!("Version: {}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Concurrent: {}", args.concurrent);
    tracing::info!("Connect timeout: {:?}s", args.connect_timeout);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(cpu_cores.into())
        .build()?
        .block_on(async {
            #[cfg(target_os = "linux")]
            if let Some(cidr) = &args.cidr {
                crate::route::sysctl_ipv6_no_local_bind(cidr);
                crate::route::sysctl_ipv6_all_enable_ipv6(cidr);
                crate::route::sysctl_route_add_cidr(cidr).await;
            }

            let context = Context {
                auth: args.auth,
                bind: args.bind,
                concurrent: args.concurrent,
                connect_timeout: args.connect_timeout,
                connector: Connector::new(
                    args.cidr,
                    args.cidr_range,
                    args.fallback,
                    args.connect_timeout,
                    args.reuseaddr,
                    #[cfg(all(
                        unix,
                        not(target_os = "solaris"),
                        not(target_os = "illumos"),
                        not(target_os = "cygwin"),
                    ))]
                    args.reuseport,
                ),
            };

            tokio::select! {
                result = async {
                     match args.proxy {
                        Proxy::Http => {
                            HttpServer::new(context)?.start().await
                        }
                        Proxy::Https {  tls_cert, tls_key } => {
                            HttpServer::new(context)?
                                .with_https(tls_cert, tls_key)?
                                .start()
                                .await
                        }
                        Proxy::Socks5  => {
                            Socks5Server::new(context)?.start().await
                        }
                        Proxy::Auto { tls_cert, tls_key } => {
                            AutoDetectServer::new(context, tls_cert, tls_key)?
                                .start()
                                .await
                        }
                    }
                } => result,
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Shutdown signal received, shutting down gracefully...");
                    Ok(())
                },
            }
        })?;

    Ok(())
}
