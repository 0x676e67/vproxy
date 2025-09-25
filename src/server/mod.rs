mod connect;
mod context;
mod extension;
mod http;
mod socks;

use tracing_subscriber::{EnvFilter, FmtSubscriber};

use self::{
    connect::Connector,
    context::Context,
    http::{HttpServer, HttpsServer},
    socks::Socks5Server,
};
use crate::{AuthMode, BootArgs, Proxy, Result};

/// The `Serve` trait defines a common interface for starting HTTP and SOCKS5 servers.
///
/// This trait is intended to be implemented by types that represent server configurations
/// for HTTP and SOCKS5 proxy servers. The `serve` method is used to start the server and
/// handle incoming connections.
pub trait Serve {
    /// Starts the server and handles incoming connections.
    async fn run(self) -> std::io::Result<()>;
}

/// Run the server with the provided boot arguments.
pub fn run(args: BootArgs) -> Result<()> {
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

            let shutdown_signal = async {
                tokio::signal::ctrl_c()
                    .await
                    .expect("failed to listen for shutdown signal");
                tracing::info!("Shutdown signal received, shutting down gracefully...");
            };

            let server = Server::new(args)?;

            tokio::select! {
                _ = server.run() => Ok(()),
                _ = shutdown_signal => {
                    Ok(())
                }
            }
        })
}

/// The `Server` enum represents different types of servers that can be created and run.
///
/// This enum includes variants for HTTP, HTTPS, and SOCKS5 servers. Each variant holds
/// an instance of the corresponding server type.
enum Server {
    /// Represents an HTTP server.
    Http(HttpServer),

    /// Represents an HTTPS server.
    Https(HttpsServer),

    /// Represents a SOCKS5 server.
    Socks5(Socks5Server),
}

impl Server {
    /// Creates a new `Server` instance based on the provided `BootArgs`.
    ///
    /// This method initializes the appropriate server type (HTTP, HTTPS, or SOCKS5)
    /// based on the `proxy` field in the `BootArgs`. It constructs the server context
    /// using the provided authentication mode and other configuration parameters.
    fn new(args: BootArgs) -> std::io::Result<Server> {
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
            ),
        };

        match args.proxy {
            Proxy::Http { auth } => HttpServer::new(context(auth)).map(Server::Http),
            Proxy::Https {
                auth,
                tls_cert,
                tls_key,
            } => HttpServer::new(context(auth))
                .and_then(|s| s.with_https(tls_cert, tls_key))
                .map(Server::Https),
            Proxy::Socks5 { auth } => Socks5Server::new(context(auth)).map(Server::Socks5),
        }
    }
}

impl Serve for Server {
    async fn run(self) -> std::io::Result<()> {
        match self {
            Server::Http(server) => server.run().await,
            Server::Https(server) => server.run().await,
            Server::Socks5(server) => server.run().await,
        }
    }
}
