/// The library's error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    FromUtf8(#[from] std::string::FromUtf8Error),

    #[error("Invalid SOCKS version: {0:x}")]
    InvalidVersion(u8),
    #[error("Invalid command: {0:x}")]
    InvalidCommand(u8),
    #[error("Invalid address type: {0:x}")]
    InvalidAtyp(u8),
    #[error("Invalid reserved bytes: {0:x}")]
    InvalidReserved(u8),
    #[error("Invalid authentication status: {0:x}")]
    InvalidAuthStatus(u8),
    #[error("Invalid authentication version of subnegotiation: {0:x}")]
    InvalidAuthSubnegotiation(u8),
    #[error("Invalid fragment id: {0:x}")]
    InvalidFragmentId(u8),

    #[error("Invalid authentication method: {0:?}")]
    InvalidAuthMethod(crate::proxy::socks::proto::Method),

    #[error("SOCKS version is 4 when 5 is expected")]
    WrongVersion,

    #[error("AddrParseError: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error("ParseIntError: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("Utf8Error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error("{0}")]
    String(String),
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::String(s.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::String(s)
    }
}

impl From<&String> for Error {
    fn from(s: &String) -> Self {
        Error::String(s.to_string())
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(e) => e,
            _ => std::io::Error::new(std::io::ErrorKind::Other, e),
        }
    }
}

impl From<tokio::time::error::Elapsed> for Error {
    fn from(e: tokio::time::error::Elapsed) -> Self {
        Error::Io(e.into())
    }
}
