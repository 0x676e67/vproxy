use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error")]
    IOError(#[from] std::io::Error),
    #[error("Parse int error")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("Network parse error")]
    NetworkParseError(#[from] cidr::errors::NetworkParseError),
    #[error("Address parse error")]
    AddressParseError(#[from] std::net::AddrParseError),
    #[error("Self update error")]
    SelfUpdateError(#[from] self_update::errors::Error),
    #[error(transparent)]
    SocksError(#[from] crate::proxy::socks5::error::SocksError),
}
