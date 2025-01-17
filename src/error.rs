#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error(transparent)]
    NetworkParseError(#[from] cidr::errors::NetworkParseError),

    #[error(transparent)]
    AddressParseError(#[from] std::net::AddrParseError),

    #[error(transparent)]
    SelfUpdateError(#[from] self_update::errors::Error),

    #[cfg(target_family = "unix")]
    #[error(transparent)]
    NixError(#[from] nix::Error),

    #[error(transparent)]
    RcgenError(#[from] rcgen::Error),

    #[error(transparent)]
    LogError(#[from] tracing::subscriber::SetGlobalDefaultError),
}
