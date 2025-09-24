use tokio::io::{AsyncRead, AsyncReadExt};

use crate::server::socks::proto::{AsyncStreamOperation, StreamOperation, UsernamePassword};

/// SOCKS5 password handshake request
///
/// ```plain
/// +-----+------+----------+------+----------+
/// | VER | ULEN |  UNAME   | PLEN |  PASSWD  |
/// +-----+------+----------+------+----------+
/// |  1  |  1   | 1 to 255 |  1   | 1 to 255 |
/// +-----+------+----------+------+----------+
/// ```

#[derive(Clone, Debug)]
pub struct Request {
    pub user_pass: UsernamePassword,
}

impl StreamOperation for Request {
    fn retrieve_from_stream<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut ver = [0; 1];
        r.read_exact(&mut ver)?;
        let ver = ver[0];

        if ver != super::SUBNEGOTIATION_VERSION {
            let err = format!("Unsupported sub-negotiation version {ver:#x}");
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let mut ulen = [0; 1];
        r.read_exact(&mut ulen)?;
        let ulen = ulen[0];
        let mut buf = vec![0; ulen as usize + 1];
        r.read_exact(&mut buf)?;

        let plen = buf[ulen as usize];
        buf.truncate(ulen as usize);
        let username = String::from_utf8(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut password = vec![0; plen as usize];
        r.read_exact(&mut password)?;
        let pwd = String::from_utf8(password)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let user_pass = UsernamePassword::new(username, pwd);
        Ok(Self { user_pass })
    }

    fn write_to_buf<B: bytes::BufMut>(&self, buf: &mut B) {
        buf.put_u8(super::SUBNEGOTIATION_VERSION);

        let username = self.user_pass.username_bytes();
        buf.put_u8(username.len() as u8);
        buf.put_slice(username);

        let password = self.user_pass.password_bytes();
        buf.put_u8(password.len() as u8);
        buf.put_slice(password);
    }

    #[inline]
    fn len(&self) -> usize {
        3 + self.user_pass.username_bytes().len() + self.user_pass.password_bytes().len()
    }
}

impl AsyncStreamOperation for Request {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> std::io::Result<Self>
    where
        R: AsyncRead + Unpin + Send,
    {
        let ver = r.read_u8().await?;

        if ver != super::SUBNEGOTIATION_VERSION {
            let err = format!("Unsupported sub-negotiation version {ver:#x}");
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let ulen = r.read_u8().await?;
        let mut buf = vec![0; ulen as usize + 1];
        r.read_exact(&mut buf).await?;

        let plen = buf[ulen as usize];
        buf.truncate(ulen as usize);
        let username = String::from_utf8(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut password = vec![0; plen as usize];
        r.read_exact(&mut password).await?;
        let pwd = String::from_utf8(password)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let user_pass = UsernamePassword::new(username, pwd);
        Ok(Self { user_pass })
    }
}
