mod address;
mod codec;
mod command;
mod reply;
mod udp;

pub mod handshake;

use tokio::io::{AsyncWrite, AsyncWriteExt};

pub use self::{
    address::Address,
    codec::{ClientFrame, ClientFrameKind, MAX_CLIENT_FRAME_LEN, ServerFrame, SocksCodec},
    command::Command,
    handshake::{Method, password::UsernamePassword},
    reply::Reply,
    udp::UdpHeader,
};

pub async fn write_server_frame<W>(stream: &mut W, frame: ServerFrame) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    use tokio_util::codec::Encoder;

    let mut buffer = bytes::BytesMut::new();
    SocksCodec::new().encode(frame, &mut buffer)?;
    stream.write_all(&buffer).await
}

/// SOCKS protocol version, either 4 or 5
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Version {
    V4 = 4,
    V5 = 5,
}

impl TryFrom<u8> for Version {
    type Error = std::io::Error;

    fn try_from(value: u8) -> std::io::Result<Self> {
        match value {
            4 => Ok(Version::V4),
            5 => Ok(Version::V5),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid version",
            )),
        }
    }
}

impl From<Version> for u8 {
    fn from(v: Version) -> Self {
        v as u8
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v: u8 = (*self).into();
        write!(f, "{v}")
    }
}

pub trait StreamOperation {
    fn retrieve_from_stream<R>(stream: &mut R) -> std::io::Result<Self>
    where
        R: std::io::Read,
        Self: Sized;

    fn write_to_buf<B: bytes::BufMut>(&self, buf: &mut B) -> std::io::Result<()>;

    fn len(&self) -> usize;
}
