use crate::proxy::socks::proto::{Address, AsyncStreamOperation, StreamOperation};
use tokio::io::{AsyncRead, AsyncReadExt};

/// SOCKS5 UDP packet header
///
/// ```plain
/// +-----+------+------+----------+----------+----------+
/// | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +-----+------+------+----------+----------+----------+
/// |  2  |  1   |  1   | Variable |    2     | Variable |
/// +-----+------+------+----------+----------+----------+
/// ```
#[derive(Clone, Debug)]
pub struct UdpHeader {
    pub frag: u8,
    pub address: Address,
}

impl UdpHeader {
    pub fn new(frag: u8, address: Address) -> Self {
        Self { frag, address }
    }

    pub const fn max_serialized_len() -> usize {
        3 + Address::max_serialized_len()
    }
}

impl StreamOperation for UdpHeader {
    fn retrieve_from_stream<R: std::io::Read>(stream: &mut R) -> std::io::Result<Self> {
        let mut buf = [0; 3];
        stream.read_exact(&mut buf)?;

        let frag = buf[2];

        let address = Address::retrieve_from_stream(stream)?;
        Ok(Self { frag, address })
    }

    fn write_to_buf<B: bytes::BufMut>(&self, buf: &mut B) {
        buf.put_bytes(0x00, 2);
        buf.put_u8(self.frag);
        self.address.write_to_buf(buf);
    }

    fn len(&self) -> usize {
        3 + self.address.len()
    }
}

impl AsyncStreamOperation for UdpHeader {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> std::io::Result<Self>
    where
        R: AsyncRead + Unpin + Send,
    {
        let mut buf = [0; 3];
        r.read_exact(&mut buf).await?;

        let frag = buf[2];

        let address = Address::retrieve_from_async_stream(r).await?;
        Ok(Self { frag, address })
    }
}
