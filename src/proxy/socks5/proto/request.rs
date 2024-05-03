use crate::proxy::socks5::proto::{
    Address, AsyncStreamOperation, Command, StreamOperation, Version,
};
use tokio::io::{AsyncRead, AsyncReadExt};

/// SOCKS5 request
///
/// ```plain
/// +-----+-----+-------+------+----------+----------+
/// | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +-----+-----+-------+------+----------+----------+
/// |  1  |  1  | X'00' |  1   | Variable |    2     |
/// +-----+-----+-------+------+----------+----------+
/// ```
#[derive(Clone, Debug)]
pub struct Request {
    pub command: Command,
    pub address: Address,
}

impl StreamOperation for Request {
    fn retrieve_from_stream<R: std::io::Read>(stream: &mut R) -> std::io::Result<Self> {
        let mut ver = [0u8; 1];
        stream.read_exact(&mut ver)?;
        let ver = Version::try_from(ver[0])?;

        if ver != Version::V5 {
            let err = format!("Unsupported SOCKS version {0:#x}", u8::from(ver));
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let mut buf = [0; 2];
        stream.read_exact(&mut buf)?;

        let command = Command::try_from(buf[0])?;
        let address = Address::retrieve_from_stream(stream)?;

        Ok(Self { command, address })
    }

    fn write_to_buf<B: bytes::BufMut>(&self, buf: &mut B) {
        buf.put_u8(Version::V5.into());
        buf.put_u8(u8::from(self.command));
        buf.put_u8(0x00);
        self.address.write_to_buf(buf);
    }

    fn len(&self) -> usize {
        3 + self.address.len()
    }
}

impl AsyncStreamOperation for Request {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> std::io::Result<Self>
    where
        R: AsyncRead + Unpin + Send,
    {
        let ver = Version::try_from(r.read_u8().await?)?;

        if ver != Version::V5 {
            let err = format!("Unsupported SOCKS version {0:#x}", u8::from(ver));
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let mut buf = [0; 2];
        r.read_exact(&mut buf).await?;

        let command = Command::try_from(buf[0])?;
        let address = Address::retrieve_from_async_stream(r).await?;

        Ok(Self { command, address })
    }
}
