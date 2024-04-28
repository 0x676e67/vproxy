use thiserror::Error;

use super::consts;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum SocksError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("the data for key `{0}` is not available")]
    Redaction(String),
    #[error("invalid header (expected {expected:?}, found {found:?})")]
    InvalidHeader { expected: String, found: String },

    #[error("Auth method unacceptable `{0:?}`.")]
    AuthMethodUnacceptable(Vec<u8>),
    #[error("Unsupported SOCKS version `{0}`.")]
    UnsupportedSocksVersion(u8),
    #[error("Domain exceeded max sequence length")]
    ExceededMaxDomainLen(usize),
    #[error("Authentication failed `{0}`")]
    AuthenticationFailed(String),
    #[error("Authentication rejected `{0}`")]
    AuthenticationRejected(String),

    #[error("Argument input error: `{0}`.")]
    ArgumentInputError(&'static str),

    #[error("Error with reply: {0}.")]
    ReplyError(#[from] ReplyError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// SOCKS5 reply code
#[allow(dead_code)]
#[derive(Error, Debug, Copy, Clone)]
pub enum ReplyError {
    #[error("Succeeded")]
    Succeeded,
    #[error("General failure")]
    GeneralFailure,
    #[error("Connection not allowed by ruleset")]
    ConnectionNotAllowed,
    #[error("Network unreachable")]
    NetworkUnreachable,
    #[error("Host unreachable")]
    HostUnreachable,
    #[error("Connection refused")]
    ConnectionRefused,
    #[error("Connection timeout")]
    ConnectionTimeout,
    #[error("TTL expired")]
    TtlExpired,
    #[error("Command not supported")]
    CommandNotSupported,
    #[error("Address type not supported")]
    AddressTypeNotSupported,
}

impl ReplyError {
    #[inline]
    pub fn as_u8(self) -> u8 {
        match self {
            ReplyError::Succeeded => consts::SOCKS5_REPLY_SUCCEEDED,
            ReplyError::GeneralFailure => consts::SOCKS5_REPLY_GENERAL_FAILURE,
            ReplyError::ConnectionNotAllowed => consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED,
            ReplyError::NetworkUnreachable => consts::SOCKS5_REPLY_NETWORK_UNREACHABLE,
            ReplyError::HostUnreachable => consts::SOCKS5_REPLY_HOST_UNREACHABLE,
            ReplyError::ConnectionRefused => consts::SOCKS5_REPLY_CONNECTION_REFUSED,
            ReplyError::ConnectionTimeout => consts::SOCKS5_REPLY_TTL_EXPIRED,
            ReplyError::TtlExpired => consts::SOCKS5_REPLY_TTL_EXPIRED,
            ReplyError::CommandNotSupported => consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            ReplyError::AddressTypeNotSupported => consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
        }
    }
}
