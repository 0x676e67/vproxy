mod auth;
mod connect;
mod http;
mod socks5;

use crate::{AuthMode, BootArgs, Proxy};
pub use socks5::Error;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

struct ProxyContext {
    /// Bind address
    pub bind: SocketAddr,
    /// Number of concurrent connections
    pub concurrent: usize,
    /// Authentication type
    pub auth: AuthMode,
    /// Connector
    pub connector: connect::Connector,
}

#[tokio::main(flavor = "multi_thread")]
pub async fn run(args: BootArgs) -> crate::Result<()> {
    tracing::info!("OS: {}", std::env::consts::OS);
    tracing::info!("Arch: {}", std::env::consts::ARCH);
    tracing::info!("Version: {}", env!("CARGO_PKG_VERSION"));

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

    // Auto set sysctl
    #[cfg(target_os = "linux")]
    args.ipv6_subnet.map(|v6| {
        crate::util::sysctl_ipv6_no_local_bind();
        crate::util::sysctl_route_add_ipv6_subnet(&v6);
    });

    // Init ip whitelist
    auth::init_ip_whitelist(&args);

    match args.proxy {
        Proxy::Http { auth } => {
            http::proxy(ProxyContext {
                bind: args.bind,
                concurrent: args.concurrent,
                auth,
                connector: connect::Connector::new(args.ipv6_subnet, args.fallback),
            })
            .await
        }
        Proxy::Socks5 { auth } => {
            socks5::proxy(ProxyContext {
                bind: args.bind,
                concurrent: args.concurrent,
                auth,
                connector: connect::Connector::new(args.ipv6_subnet, args.fallback),
            })
            .await
        }
    }
}
