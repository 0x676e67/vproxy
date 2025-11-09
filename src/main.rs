#![deny(unused)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, deny(warnings))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

#[cfg(target_family = "unix")]
mod daemon;
mod error;
mod io;
mod oneself;
#[cfg(target_os = "linux")]
mod route;
mod server;

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use cidr::IpCidr;
use clap::{Args, Parser, Subcommand};
use tracing::Level;

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
    pub username: Option<String>,

    /// Authentication password
    #[arg(short, long, requires = "username")]
    pub password: Option<String>,
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

    /// Http/3 server (QUIC)
    Http3 {
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
    /// Log level e.g. trace, debug, info, warn, error
    #[arg(
        long,
        short = 'L',
        env = "VPROXY_LOG",
        default_value = "info",
        global = true
    )]
    log: Level,

    /// Worker threads, default to number of CPU cores
    #[arg(long, short = 'w')]
    workers: Option<usize>,

    /// Bind address
    #[arg(long, short = 'b', default_value = "127.0.0.1:1080")]
    bind: SocketAddr,

    /// IP-CIDR, e.g. 2001:db8::/32
    #[arg(long, short = 'i')]
    cidr: Option<IpCidr>,

    /// IP-CIDR-Range, e.g. 64
    #[arg(long, short = 'r')]
    cidr_range: Option<u8>,

    /// Fallback address
    #[arg(long, short)]
    fallback: Option<IpAddr>,

    /// Connection timeout in seconds
    #[arg(long, short = 't', default_value = "10")]
    connect_timeout: u64,

    /// Maximum concurrent connections in socket queue
    #[arg(long, short = 'c', default_value = "1024")]
    concurrent: u32,

    /// Enable SO_REUSEADDR for outbound connections
    #[arg(long, default_value = "true")]
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
