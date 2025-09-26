#![deny(unused)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, deny(warnings))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

#[cfg(target_family = "unix")]
mod daemon;
mod error;
mod oneself;
#[cfg(target_os = "linux")]
mod route;
mod server;

use std::{net::SocketAddr, path::PathBuf};

use clap::{Args, Parser, Subcommand};

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
#[command(author, version, about, arg_required_else_help = true)]
#[command(args_conflicts_with_subcommands = true)]
struct Opt {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run server
    Run(ServerArgs),

    /// Start server daemon
    #[cfg(target_family = "unix")]
    Start(ServerArgs),

    /// Restart server daemon
    #[cfg(target_family = "unix")]
    Restart(ServerArgs),

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
    #[command(name = "self")]
    Oneself {
        #[command(subcommand)]
        command: Oneself,
    },
}

/// Choose the authentication type
#[derive(Args, Clone)]
pub struct AuthMode {
    /// Authentication username
    #[arg(short, long, requires = "password", global = true)]
    pub username: Option<String>,

    /// Authentication password
    #[arg(short, long, requires = "username", global = true)]
    pub password: Option<String>,
}

#[derive(Subcommand, Clone)]
pub enum Proxy {
    /// Http server
    Http,

    /// Https server
    Https {
        /// TLS certificate file
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,

        /// TLS private key file
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
    },

    /// Socks5 server
    Socks5,

    /// Auto detect server (SOCKS5, HTTP, HTTPS)
    Auto {
        /// TLS certificate file
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,

        /// TLS private key file
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
    },
}

#[derive(Args, Clone)]
pub struct ServerArgs {
    /// Log level e.g. trace, debug, info, warn, error
    #[arg(long, env = "VPROXY_LOG", default_value = "info", global = true)]
    log: tracing::Level,

    /// Bind address
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    bind: SocketAddr,

    /// Connection timeout in seconds
    #[arg(short = 'T', long, default_value = "10")]
    connect_timeout: u64,

    /// Concurrent connections
    #[arg(short, long, default_value = "1024")]
    concurrent: u32,

    /// Enable SO_REUSEADDR for outbound connections
    #[arg(long)]
    reuseaddr: Option<bool>,

    /// Enable SO_REUSEPORT for outbound connections
    #[cfg(all(
        unix,
        not(target_os = "solaris"),
        not(target_os = "illumos"),
        not(target_os = "cygwin"),
    ))]
    #[arg(long)]
    reuseport: Option<bool>,

    /// IP-CIDR, e.g. 2001:db8::/32
    #[arg(short = 'i', long)]
    cidr: Option<cidr::IpCidr>,

    /// IP-CIDR-Range, e.g. 64
    #[arg(short = 'r', long)]
    cidr_range: Option<u8>,

    /// Fallback address
    #[arg(short, long)]
    fallback: Option<std::net::IpAddr>,

    #[clap(flatten)]
    auth: AuthMode,

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
