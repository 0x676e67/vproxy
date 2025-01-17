mod connect;
mod extension;
mod http;
mod murmur;
#[cfg(target_os = "linux")]
mod route;
mod socks;

use crate::{AuthMode, BootArgs, Proxy, Result};
use connect::Connector;
use std::net::SocketAddr;
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

struct Context {
    /// Bind address
    pub bind: SocketAddr,
    /// Number of concurrent connections
    pub concurrent: usize,
    /// Authentication type
    pub auth: AuthMode,
    /// Connector
    pub connector: Connector,
}

pub fn run(args: BootArgs) -> Result<()> {
    // Initialize the logger with a filter that ignores WARN level logs for netlink_proto
    let filter = EnvFilter::from_default_env()
        .add_directive(
            if args.debug {
                Level::DEBUG
            } else {
                Level::INFO
            }
            .into(),
        )
        .add_directive(
            "netlink_proto=error"
                .parse()
                .expect("failed to parse directive"),
        );

    tracing::subscriber::set_global_default(
        FmtSubscriber::builder().with_env_filter(filter).finish(),
    )?;

    tracing::info!("OS: {}", std::env::consts::OS);
    tracing::info!("Arch: {}", std::env::consts::ARCH);
    tracing::info!("Version: {}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Concurrent: {}", args.concurrent);
    tracing::info!("Connect timeout: {:?}s", args.connect_timeout);

    let ctx = move |auth: AuthMode| Context {
        auth,
        bind: args.bind,
        concurrent: args.concurrent,
        connector: Connector::new(
            args.cidr,
            args.cidr_range,
            args.fallback,
            args.connect_timeout,
        ),
    };

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(args.concurrent)
        .build()?
        .block_on(async {
            #[cfg(target_os = "linux")]
            if let Some(cidr) = &args.cidr {
                route::sysctl_ipv6_no_local_bind();
                route::sysctl_route_add_cidr(&cidr).await;
            }
            match args.proxy {
                Proxy::Http { auth } => http::http_proxy(ctx(auth)).await,
                Proxy::Https {
                    auth,
                    tls_cert,
                    tls_key,
                } => http::https_proxy(ctx(auth), tls_cert, tls_key).await,
                Proxy::Socks5 { auth } => socks::proxy(ctx(auth)).await,
            }
        })
}
