use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
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
    #[error(transparent)]
    Socks5Error(#[from] crate::proxy::Error),
}
