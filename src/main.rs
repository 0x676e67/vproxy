pub mod alloc;
#[cfg(target_family = "unix")]
mod daemon;
mod error;
mod proxy;
mod update;
mod util;

use std::net::SocketAddr;

use clap::{Args, Parser, Subcommand};

type Result<T, E = error::Error> = std::result::Result<T, E>;

#[derive(Parser)]
#[clap(author, version, about, arg_required_else_help = true)]
#[command(args_conflicts_with_subcommands = true)]
struct Opt {
    #[clap(subcommand)]
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
    /// Show the server daemon process
    #[cfg(target_family = "unix")]
    PS,
    /// Show the server daemon log
    #[cfg(target_family = "unix")]
    Log,
    /// Update the application
    Update,
}

#[derive(Args, Clone, Debug)]
pub struct BootArgs {
    /// Debug mode
    #[clap(short = 'L', long, global = true, env = "VPROXY_DEBUG")]
    debug: bool,
    /// Bind address
    #[clap(short, long, default_value = "0.0.0.0:8100")]
    bind: SocketAddr,
    /// Basic auth username
    #[clap(short = 'u', long)]
    auth_user: Option<String>,
    /// Basic auth password
    #[clap(short = 'p', long)]
    auth_pass: Option<String>,
    /// IP addresses whitelist, e.g. 47.253.53.46,47.253.81.245
    #[clap(short = 'w', long)]
    whitelist: Option<Vec<std::net::IpAddr>>,
    /// Ipv6 subnet, e.g. 2001:db8::/32
    #[clap(short = 'i', long)]
    ipv6_subnet: Option<cidr::Ipv6Cidr>,
    /// Fallback address
    #[clap(short = 'f', long)]
    fallback: Option<std::net::IpAddr>,
    /// Proxy type, e.g. http, https, socks5
    #[clap(short = 'T', long, default_value = "http")]
    typed: ProxyType,
}

#[derive(Clone, Debug)]
pub enum ProxyType {
    Http,
    Socks5,
}

impl std::str::FromStr for ProxyType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "http" => Ok(Self::Http),
            "socks5" => Ok(Self::Socks5),
            _ => Err("".to_string()),
        }
    }
}

// To try this example:
// 1. cargo run --example http_proxy
// 2. config http_proxy in command line $ export http_proxy=http://127.0.0.1:8100
//    $ export https_proxy=http://127.0.0.1:8100
// 3. send requests $ curl -i https://www.some_domain.com/
fn main() -> crate::Result<()> {
    let opt = Opt::parse();

    match opt.commands {
        Commands::Run(args) => proxy::run(args)?,
        #[cfg(target_family = "unix")]
        Commands::Start(args) => daemon::start(args)?,
        #[cfg(target_family = "unix")]
        Commands::Restart(args) => daemon::restart(args)?,
        #[cfg(target_family = "unix")]
        Commands::Stop => daemon::stop()?,
        #[cfg(target_family = "unix")]
        Commands::PS => daemon::status(),
        #[cfg(target_family = "unix")]
        Commands::Log => daemon::log()?,
        Commands::Update => update::update()?,
    };

    Ok(())
}
