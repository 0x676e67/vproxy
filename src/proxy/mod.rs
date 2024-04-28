mod auth;
mod http;
pub(crate) mod socks5;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use self::{http::HttpContext, socks5::Socks5Context};
use crate::BootArgs;

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
    tracing::info!("Listening on {}", args.bind);

    // Choose proxy type
    match args.proxy {
        crate::Proxy::Http { auth } => {
            http::run(HttpContext {
                auth,
                ipv6_subnet: args.ipv6_subnet,
                fallback: args.fallback,
                bind: args.bind,
            })
            .await
        }
        crate::Proxy::Socks5 {
            auth,
            timeout,
            resolve_dns: dns_resolve,
            allow_udp: udp_support,
            execute_command,
        } => {
            socks5::run(Socks5Context {
                auth: auth.clone(),
                ipv6_subnet: args.ipv6_subnet,
                fallback: args.fallback,
                bind: args.bind,
                timeout,
                dns_resolve,
                udp_support,
                execute_command,
            })
            .await
        }
    }
}
