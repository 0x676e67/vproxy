#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Reply {
    Succeeded            = 0x00,
    GeneralFailure       = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable   = 0x03,
    HostUnreachable      = 0x04,
    ConnectionRefused    = 0x05,
    TtlExpired           = 0x06,
    CommandNotSupported  = 0x07,
    AddressTypeNotSupported = 0x08,
}

impl TryFrom<u8> for Reply {
    type Error = std::io::Error;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        let err = format!("Unsupported reply code {0:#x}", code);
        match code {
            0x00 => Ok(Reply::Succeeded),
            0x01 => Ok(Reply::GeneralFailure),
            0x02 => Ok(Reply::ConnectionNotAllowed),
            0x03 => Ok(Reply::NetworkUnreachable),
            0x04 => Ok(Reply::HostUnreachable),
            0x05 => Ok(Reply::ConnectionRefused),
            0x06 => Ok(Reply::TtlExpired),
            0x07 => Ok(Reply::CommandNotSupported),
            0x08 => Ok(Reply::AddressTypeNotSupported),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, err)),
        }
    }
}

impl From<Reply> for u8 {
    fn from(reply: Reply) -> Self {
        match reply {
            Reply::Succeeded => 0x00,
            Reply::GeneralFailure => 0x01,
            Reply::ConnectionNotAllowed => 0x02,
            Reply::NetworkUnreachable => 0x03,
            Reply::HostUnreachable => 0x04,
            Reply::ConnectionRefused => 0x05,
            Reply::TtlExpired => 0x06,
            Reply::CommandNotSupported => 0x07,
            Reply::AddressTypeNotSupported => 0x08,
        }
    }
}

impl std::fmt::Display for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Reply::Succeeded => "Reply::Succeeded",
            Reply::GeneralFailure => "Reply::GeneralFailure",
            Reply::ConnectionNotAllowed => "Reply::ConnectionNotAllowed",
            Reply::NetworkUnreachable => "Reply::NetworkUnreachable",
            Reply::HostUnreachable => "Reply::HostUnreachable",
            Reply::ConnectionRefused => "Reply::ConnectionRefused",
            Reply::TtlExpired => "Reply::TtlExpired",
            Reply::CommandNotSupported => "Reply::CommandNotSupported",
            Reply::AddressTypeNotSupported => "Reply::AddressTypeNotSupported",
        };
        write!(f, "{}", s)
    }
}
