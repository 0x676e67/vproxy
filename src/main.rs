#![deny(unused)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, deny(warnings))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod connect;
#[cfg(target_family = "unix")]
mod daemon;
mod error;
mod ext;
mod io;
mod oneself;
mod rand;
#[cfg(target_os = "linux")]
mod route;
mod server;

use std::{net::SocketAddr, path::PathBuf};

use cidr::IpCidr;
use clap::{Args, Parser, Subcommand};
use tracing::Level;

use crate::connect::Fallback;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(feature = "tcmalloc")]
#[global_allocator]
static ALLOC: tcmalloc::TCMalloc = tcmalloc::TCMalloc;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "snmalloc")]
#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

#[cfg(feature = "rpmalloc")]
#[global_allocator]
static ALLOC: rpmalloc::RpMalloc = rpmalloc::RpMalloc;

type Result<T, E = error::Error> = std::result::Result<T, E>;

#[derive(Parser)]
#[clap(author, version, about, arg_required_else_help = true)]
#[command(args_conflicts_with_subcommands = true)]
struct Opt {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run server
    Run(BootArgs),

    /// Start server daemon
    #[cfg(target_family = "unix")]
    Start(BootArgs),

    /// Restart server daemon
    #[cfg(target_family = "unix")]
    Restart(BootArgs),

    /// Stop server daemon
    #[cfg(target_family = "unix")]
    Stop,

    /// Show server daemon process
    #[cfg(target_family = "unix")]
    PS,

    /// Show server daemon log
    #[cfg(target_family = "unix")]
    Log,

    /// Modify server installation
    #[clap(name = "self")]
    Oneself {
        #[command(subcommand)]
        command: Oneself,
    },
}

/// Choose the authentication type
#[derive(Args, Clone)]
pub struct AuthMode {
    /// Authentication username
    #[arg(short, long, requires = "password")]
    username: Option<String>,

    /// Authentication password
    #[arg(short, long, requires = "username")]
    password: Option<String>,
}

#[derive(Subcommand, Clone)]
pub enum Proxy {
    /// Http server
    Http {
        /// Authentication type
        #[command(flatten)]
        auth: AuthMode,
    },

    /// Https server
    Https {
        /// Authentication type
        #[command(flatten)]
        auth: AuthMode,

        /// TLS certificate file
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,

        /// TLS private key file
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
    },

    /// Socks5 server
    Socks5 {
        /// Authentication type
        #[command(flatten)]
        auth: AuthMode,
    },

    /// Auto detect server (SOCKS5, HTTP, HTTPS)
    Auto {
        /// Authentication type
        #[command(flatten)]
        auth: AuthMode,

        /// TLS certificate file
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,

        /// TLS private key file
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
    },
}

#[derive(Args, Clone)]
pub struct BootArgs {
    /// Log level (trace / debug / info / warn / error). Default: info.
    /// Can be overridden by environment variable VPROXY_LOG.
    #[arg(
        long,
        short = 'L',
        env = "VPROXY_LOG",
        default_value = "info",
        global = true,
        verbatim_doc_comment
    )]
    log: Level,

    /// Worker thread count. Default: number of logical CPU cores.
    /// Too small limits concurrency; too large wastes context switches.
    #[arg(long, short = 'w', verbatim_doc_comment)]
    workers: Option<usize>,

    /// Bind address (listen endpoint).
    /// e.g. 0.0.0.0:1080, [::]:1080, 192.168.1.100:1080
    #[arg(
        long,
        short = 'b',
        default_value = "127.0.0.1:1080",
        verbatim_doc_comment
    )]
    bind: SocketAddr,

    /// Base CIDR block for outbound source address selection.
    /// Used for session, TTL and range extensions.
    /// e.g. 2001:db8::/32 or 10.0.0.0/24
    #[arg(long, short = 'i', verbatim_doc_comment)]
    cidr: Option<IpCidr>,

    /// Sub-range bit width (CIDR range extension).
    /// Carves host bits into per-user fixed allocation.
    /// e.g. 64 (IPv6 only meaningful).
    #[arg(long, short = 'r', verbatim_doc_comment)]
    cidr_range: Option<u8>,

    /// Fallback local source address or interface when CIDR selection fails.
    /// Accepts IPv4 / IPv6 address or interface name.
    /// Interface name works only on Unix platforms.
    /// e.g. 192.168.1.100, 2001:db8::1, eth0.
    #[arg(long, short, verbatim_doc_comment)]
    fallback: Option<Fallback>,

    /// Outbound connection timeout (seconds). Applies to TCP (and TLS handshake).
    /// Recommended: 5–15. Too low may fail on high latency links.
    /// e.g. 5.
    #[arg(long, short = 't', default_value = "10", verbatim_doc_comment)]
    connect_timeout: u64,

    /// Maximum concurrent active connections.
    /// Protects resource exhaustion. Raise cautiously.
    /// e.g. 128.
    #[arg(long, short = 'c', default_value = "1024", verbatim_doc_comment)]
    concurrent: u32,

    /// Enable SO_REUSEADDR for outbound sockets.
    /// Helps mitigate TIME_WAIT port exhaustion.
    /// e.g. true.
    #[arg(long, default_value = "true", verbatim_doc_comment)]
    reuseaddr: Option<bool>,

    #[command(subcommand)]
    proxy: Proxy,
}

#[derive(Subcommand, Clone)]
pub enum Oneself {
    /// Download and install updates to the proxy server
    Update,
    /// Uninstall proxy server
    Uninstall,
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    #[cfg(target_family = "unix")]
    let daemon = daemon::Daemon::default();
    match opt.commands {
        Commands::Run(args) => server::run(args),
        #[cfg(target_family = "unix")]
        Commands::Start(args) => daemon.start(args),
        #[cfg(target_family = "unix")]
        Commands::Restart(args) => daemon.restart(args),
        #[cfg(target_family = "unix")]
        Commands::Stop => daemon.stop(),
        #[cfg(target_family = "unix")]
        Commands::PS => daemon.status(),
        #[cfg(target_family = "unix")]
        Commands::Log => daemon.log(),
        Commands::Oneself { command } => match command {
            Oneself::Update => oneself::update(),
            Oneself::Uninstall => oneself::uninstall(),
        },
    }
}
