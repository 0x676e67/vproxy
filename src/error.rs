#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),

    #[error(transparent)]
    NetworkParse(#[from] cidr::errors::NetworkParseError),

    #[error(transparent)]
    AddressParse(#[from] std::net::AddrParseError),

    #[error(transparent)]
    SelfUpdate(#[from] self_update::errors::Error),

    #[cfg(target_family = "unix")]
    #[error(transparent)]
    Nix(#[from] nix::Error),

    #[error(transparent)]
    Rcgen(#[from] rcgen::Error),

    #[error(transparent)]
    Log(#[from] tracing::subscriber::SetGlobalDefaultError),

    #[error(transparent)]
    LogParse(#[from] tracing_subscriber::filter::ParseError),
}
