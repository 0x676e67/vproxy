mod auth;
mod connect;
mod http;
mod murmur;
#[cfg(target_os = "linux")]
mod route;
mod socks5;

use crate::{AuthMode, BootArgs, Proxy};
pub use socks5::Error;
use std::net::{IpAddr, SocketAddr};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

struct ProxyContext {
    /// Bind address
    pub bind: SocketAddr,
    /// Number of concurrent connections
    pub concurrent: usize,
    /// Authentication type
    pub auth: AuthMode,
    /// Ip whitelist
    pub whitelist: Vec<IpAddr>,
    /// Connector
    pub connector: connect::Connector,
}

#[tokio::main(flavor = "multi_thread")]
pub async fn run(args: BootArgs) -> crate::Result<()> {
    if args.debug {
        std::env::set_var("RUST_LOG", "debug");
    } else {
        std::env::set_var("RUST_LOG", "info");
    }

    // Init tracing logger
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "RUST_LOG=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("OS: {}", std::env::consts::OS);
    tracing::info!("Arch: {}", std::env::consts::ARCH);
    tracing::info!("Version: {}", env!("CARGO_PKG_VERSION"));

    #[cfg(target_os = "linux")]
    if let Some(cidr) = &args.cidr {
        route::sysctl_ipv6_no_local_bind();
        route::sysctl_route_add_cidr(&cidr).await;
    }

    let ctx = move |auth: AuthMode| ProxyContext {
        bind: args.bind,
        concurrent: args.concurrent,
        auth,
        whitelist: args.whitelist,
        connector: connect::Connector::new(args.cidr, args.fallback, args.connect_timeout),
    };

    match args.proxy {
        Proxy::Http { auth } => http::proxy(ctx(auth)).await,
        Proxy::Socks5 { auth } => socks5::proxy(ctx(auth)).await,
    }
}
