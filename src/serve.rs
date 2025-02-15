use crate::{
    connect::Connector,
    http::{HttpServer, HttpsServer},
    socks::Socks5Server,
    AuthMode, BootArgs, Proxy, Result,
};
use std::net::SocketAddr;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

/// The `Serve` trait defines a common interface for starting HTTP and SOCKS5 servers.
///
/// This trait is intended to be implemented by types that represent server configurations
/// for HTTP and SOCKS5 proxy servers. The `serve` method is used to start the server and
/// handle incoming connections.
///
/// # Example
///
/// ```rust
/// struct MyServer;
///
/// impl Serve for MyServer {
///     async fn serve(self) -> std::io::Result<()> {
///         // Server implementation
///         Ok(())
///     }
/// }
///
/// let server = MyServer;
/// server.serve().await?;
/// ```
pub trait Serve {
    /// Starts the server and handles incoming connections.
    ///
    /// This method is responsible for starting the server, accepting incoming connections,
    /// and processing requests. It should be implemented by types that represent server
    /// configurations for HTTP and SOCKS5 proxy servers.
    ///
    /// # Returns
    ///
    /// A `std::io::Result<()>` indicating the result of the server operation.
    /// If the server starts and runs successfully, it returns `Ok(())`.
    /// If an error occurs, it returns the encountered error.
    ///
    /// # Example
    ///
    /// ```rust
    /// struct MyServer;
    ///
    /// impl Serve for MyServer {
    ///     async fn serve(self) -> std::io::Result<()> {
    ///         // Server implementation
    ///         Ok(())
    ///     }
    /// }
    ///
    /// let server = MyServer;
    /// server.serve().await?;
    /// ```
    async fn serve(self) -> std::io::Result<()>;
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
    let blocking_threads = (cpu_cores.get() as f64 * 1.5).round() as usize;

    tracing::info!("OS: {}", std::env::consts::OS);
    tracing::info!("Arch: {}", std::env::consts::ARCH);
    tracing::info!("CPU cores: {}", cpu_cores);
    tracing::info!("Version: {}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Concurrent: {}", args.concurrent);
    tracing::info!("Connect timeout: {:?}s", args.connect_timeout);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(cpu_cores.into())
        .max_blocking_threads(blocking_threads)
        .build()?
        .block_on(async {
            #[cfg(target_os = "linux")]
            if let Some(cidr) = &args.cidr {
                crate::route::sysctl_ipv6_no_local_bind(cidr);
                crate::route::sysctl_ipv6_all_enable_ipv6(cidr);
                crate::route::sysctl_route_add_cidr(cidr).await;
            }

            let server = Server::new(args)?;
            server.serve().await.map_err(Into::into)
        })
}

/// Run the server with the provided boot arguments.
pub struct Context {
    /// Bind address
    pub bind: SocketAddr,

    /// Number of concurrent connections
    pub concurrent: usize,

    /// Connect timeout
    pub connect_timeout: u64,

    /// Authentication type
    pub auth: AuthMode,

    /// Connector
    pub connector: Connector,
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
    ///
    /// # Arguments
    ///
    /// * `args` - The boot arguments used to configure the server.
    ///
    /// # Returns
    ///
    /// A `std::io::Result<Server>` representing the result of the server creation.
    /// If successful, it returns `Ok(Server)`. If an error occurs, it returns the
    /// encountered error.
    ///
    /// # Example
    ///
    /// ```
    /// let args = BootArgs {
    ///     bind: "127.0.0.1:8080".parse().unwrap(),
    ///     concurrent: 100,
    ///     connect_timeout: 5000,
    ///     auth: AuthMode::NoAuth,
    ///     proxy: Proxy::Http { auth: AuthMode::NoAuth },
    ///     cidr: None,
    ///     cidr_range: None,
    ///     fallback: None,
    /// };
    /// let server = Server::new(args)?;
    /// ```
    fn new(args: BootArgs) -> std::io::Result<Server> {
        let ctx = move |auth: AuthMode| Context {
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
            Proxy::Http { auth } => HttpServer::new(ctx(auth)).map(Server::Http),
            Proxy::Https {
                auth,
                tls_cert,
                tls_key,
            } => HttpsServer::new(ctx(auth), tls_cert, tls_key).map(Server::Https),
            Proxy::Socks5 { auth } => Socks5Server::new(ctx(auth)).map(Server::Socks5),
        }
    }
}

impl Serve for Server {
    async fn serve(self) -> std::io::Result<()> {
        match self {
            Server::Http(server) => server.serve().await,
            Server::Https(server) => server.serve().await,
            Server::Socks5(server) => server.serve().await,
        }
    }
}
