#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Command {
    Connect      = 0x01,
    Bind         = 0x02,
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for Command {
    type Error = std::io::Error;

    fn try_from(code: u8) -> std::result::Result<Self, Self::Error> {
        let err = format!("Unsupported command code {0:#x}", code);
        match code {
            0x01 => Ok(Command::Connect),
            0x02 => Ok(Command::Bind),
            0x03 => Ok(Command::UdpAssociate),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, err)),
        }
    }
}

impl From<Command> for u8 {
    fn from(cmd: Command) -> Self {
        match cmd {
            Command::Connect => 0x01,
            Command::Bind => 0x02,
            Command::UdpAssociate => 0x03,
        }
    }
}
