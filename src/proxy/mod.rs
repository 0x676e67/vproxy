mod auth;
mod http;
mod socks5;

use std::net::{IpAddr, SocketAddr};

pub use socks5::Error;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{AuthMode, BootArgs, Proxy};

struct ProxyContext {
    pub bind: SocketAddr,
    pub auth: AuthMode,
    /// Ipv6 subnet, e.g. 2001:db8::/32
    pub ipv6_subnet: Option<cidr::Ipv6Cidr>,
    /// Fallback address
    pub fallback: Option<IpAddr>,
}

#[tokio::main(flavor = "multi_thread")]
pub async fn run(args: BootArgs) -> crate::Result<()> {
    if args.debug {
        std::env::set_var("RUST_LOG", "debug");
    } else {
        std::env::set_var("RUST_LOG", "info");
    }
    // Init tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "RUST_LOG=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Init ip whitelist
    auth::init_ip_whitelist(&args);

    // Auto set sysctl
    #[cfg(target_os = "linux")]
    args.ipv6_subnet.map(|v6| {
        crate::util::sysctl_ipv6_no_local_bind();
        crate::util::sysctl_route_add_ipv6_subnet(&v6);
    });

    tracing::info!("OS: {}", std::env::consts::OS);
    tracing::info!("Arch: {}", std::env::consts::ARCH);
    tracing::info!("Version: {}", env!("CARGO_PKG_VERSION"));

    match args.proxy {
        Proxy::Http { auth } => {
            http::run(ProxyContext {
                auth,
                ipv6_subnet: args.ipv6_subnet,
                fallback: args.fallback,
                bind: args.bind,
            })
            .await
        }
        Proxy::Socks5 { auth } => {
            socks5::run(ProxyContext {
                auth,
                ipv6_subnet: args.ipv6_subnet,
                fallback: args.fallback,
                bind: args.bind,
            })
            .await
        }
    }
}
