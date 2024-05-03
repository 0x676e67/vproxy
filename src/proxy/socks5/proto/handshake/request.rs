use crate::proxy::socks5::proto::{AsyncStreamOperation, AuthMethod, StreamOperation, Version};
use tokio::io::{AsyncRead, AsyncReadExt};

/// SOCKS5 handshake request
///
/// ```plain
/// +-----+----------+----------+
/// | VER | NMETHODS | METHODS  |
/// +-----+----------+----------+
/// |  1  |    1     | 1 to 255 |
/// +-----+----------+----------|
/// ```
#[derive(Clone, Debug)]
pub struct Request {
    methods: Vec<AuthMethod>,
}

impl Request {
    pub fn evaluate_method(&self, server_method: AuthMethod) -> bool {
        self.methods.iter().any(|&m| m == server_method)
    }
}

impl StreamOperation for Request {
    fn retrieve_from_stream<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut ver = [0; 1];
        r.read_exact(&mut ver)?;
        let ver = Version::try_from(ver[0])?;

        if ver != Version::V5 {
            let err = format!("Unsupported SOCKS version {0:#x}", u8::from(ver));
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let mut mlen = [0; 1];
        r.read_exact(&mut mlen)?;
        let mlen = mlen[0];

        let mut methods = vec![0; mlen as usize];
        r.read_exact(&mut methods)?;

        let methods = methods.into_iter().map(AuthMethod::from).collect();

        Ok(Self { methods })
    }

    fn write_to_buf<B: bytes::BufMut>(&self, buf: &mut B) {
        buf.put_u8(Version::V5.into());
        buf.put_u8(self.methods.len() as u8);

        let methods = self.methods.iter().map(u8::from).collect::<Vec<u8>>();
        buf.put_slice(&methods);
    }

    fn len(&self) -> usize {
        2 + self.methods.len()
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

        let mlen = r.read_u8().await?;
        let mut methods = vec![0; mlen as usize];
        r.read_exact(&mut methods).await?;

        let methods = methods.into_iter().map(AuthMethod::from).collect();

        Ok(Self { methods })
    }
}
