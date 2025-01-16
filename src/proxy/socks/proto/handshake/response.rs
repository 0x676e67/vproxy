use crate::proxy::socks::proto::{AsyncStreamOperation, Method, StreamOperation, Version};
use tokio::io::{AsyncRead, AsyncReadExt};

/// SOCKS5 handshake response
///
/// ```plain
/// +-----+--------+
/// | VER | METHOD |
/// +-----+--------+
/// |  1  |   1    |
/// +-----+--------+
/// ```
#[derive(Clone, Debug)]
pub struct Response {
    pub method: Method,
}

impl Response {
    pub fn new(method: Method) -> Self {
        Self { method }
    }
}

impl StreamOperation for Response {
    fn retrieve_from_stream<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut ver = [0; 1];
        r.read_exact(&mut ver)?;
        let ver = Version::try_from(ver[0])?;

        if ver != Version::V5 {
            let err = format!("Unsupported SOCKS version {0:#x}", u8::from(ver));
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let mut method = [0; 1];
        r.read_exact(&mut method)?;
        let method = Method::from(method[0]);

        Ok(Self { method })
    }

    fn write_to_buf<B: bytes::BufMut>(&self, buf: &mut B) {
        buf.put_u8(Version::V5.into());
        buf.put_u8(u8::from(self.method));
    }

    fn len(&self) -> usize {
        2
    }
}

impl AsyncStreamOperation for Response {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> std::io::Result<Self>
    where
        R: AsyncRead + Unpin + Send,
    {
        let ver = Version::try_from(r.read_u8().await?)?;

        if ver != Version::V5 {
            let err = format!("Unsupported SOCKS version {0:#x}", u8::from(ver));
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let method = Method::from(r.read_u8().await?);

        Ok(Self { method })
    }
}
