use super::{proto::AddressType, Result};
use crate::proxy::socks5::{
    error::Error,
    proto::{handshake::Method as AuthMethod, Address, Command, Reply, UsernamePassword, Version},
};
use async_trait::async_trait;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[async_trait]
pub trait Socks5Reader: AsyncReadExt + Unpin {
    async fn read_version(&mut self) -> Result<()> {
        let value = Version::try_from(self.read_u8().await?)?;
        match value {
            Version::V4 => Err(Error::WrongVersion),
            Version::V5 => Ok(()),
        }
    }

    async fn read_method(&mut self) -> Result<AuthMethod> {
        let value = AuthMethod::from(self.read_u8().await?);
        match value {
            AuthMethod::NoAuth | AuthMethod::Password => Ok(value),
            _ => Err(Error::InvalidAuthMethod(value)),
        }
    }

    async fn read_atyp(&mut self) -> Result<AddressType> {
        let value = self.read_u8().await?;
        Ok(AddressType::try_from(value)?)
    }

    async fn read_reserved(&mut self) -> Result<()> {
        let value = self.read_u8().await?;
        match value {
            0x00 => Ok(()),
            _ => Err(Error::InvalidReserved(value)),
        }
    }

    async fn read_reply(&mut self) -> Result<()> {
        let value = self.read_u8().await?;
        match Reply::try_from(value)? {
            Reply::Succeeded => Ok(()),
            reply => Err(format!("{}", reply).into()),
        }
    }

    async fn read_address(&mut self) -> Result<Address> {
        let atyp = self.read_atyp().await?;
        let addr = match atyp {
            AddressType::IPv4 => {
                let mut ip = [0; 4];
                self.read_exact(&mut ip).await?;
                let port = self.read_u16().await?;
                Address::from((Ipv4Addr::from(ip), port))
            }
            AddressType::IPv6 => {
                let mut ip = [0; 16];
                self.read_exact(&mut ip).await?;
                let port = self.read_u16().await?;
                Address::from((Ipv6Addr::from(ip), port))
            }
            AddressType::Domain => {
                let str = self.read_string().await?;
                let port = self.read_u16().await?;
                Address::from((str, port))
            }
        };

        Ok(addr)
    }

    async fn read_string(&mut self) -> Result<String> {
        let len = self.read_u8().await? as usize;
        let mut str = vec![0; len];
        self.read_exact(&mut str).await?;
        let str = String::from_utf8(str)?;
        Ok(str)
    }

    async fn read_auth_version(&mut self) -> Result<()> {
        let value = self.read_u8().await?;
        if value != 0x01 {
            return Err(Error::InvalidAuthSubnegotiation(value));
        }
        Ok(())
    }

    async fn read_auth_status(&mut self) -> Result<()> {
        let value = self.read_u8().await?;
        if value != 0x00 {
            return Err(Error::InvalidAuthStatus(value));
        }
        Ok(())
    }

    async fn read_selection_msg(&mut self) -> Result<AuthMethod> {
        self.read_version().await?;
        self.read_method().await
    }

    async fn read_final(&mut self) -> Result<Address> {
        self.read_version().await?;
        self.read_reply().await?;
        self.read_reserved().await?;
        let addr = self.read_address().await?;
        Ok(addr)
    }
}

#[async_trait]
impl<T: AsyncReadExt + Unpin> Socks5Reader for T {}

#[async_trait]
pub trait Socks5Writer: AsyncWriteExt + Unpin {
    async fn write_version(&mut self) -> Result<()> {
        self.write_u8(0x05).await?;
        Ok(())
    }

    async fn write_method(&mut self, method: AuthMethod) -> Result<()> {
        self.write_u8(u8::from(method)).await?;
        Ok(())
    }

    async fn write_command(&mut self, command: Command) -> Result<()> {
        self.write_u8(u8::from(command)).await?;
        Ok(())
    }

    async fn write_atyp(&mut self, atyp: AddressType) -> Result<()> {
        self.write_u8(u8::from(atyp)).await?;
        Ok(())
    }

    async fn write_reserved(&mut self) -> Result<()> {
        self.write_u8(0x00).await?;
        Ok(())
    }

    async fn write_address(&mut self, address: &Address) -> Result<()> {
        match address {
            Address::SocketAddress(SocketAddr::V4(addr)) => {
                self.write_atyp(AddressType::IPv4).await?;
                self.write_all(&addr.ip().octets()).await?;
                self.write_u16(addr.port()).await?;
            }
            Address::SocketAddress(SocketAddr::V6(addr)) => {
                self.write_atyp(AddressType::IPv6).await?;
                self.write_all(&addr.ip().octets()).await?;
                self.write_u16(addr.port()).await?;
            }
            Address::DomainAddress(domain, port) => {
                self.write_atyp(AddressType::Domain).await?;
                self.write_string(domain).await?;
                self.write_u16(*port).await?;
            }
        }
        Ok(())
    }

    async fn write_string(&mut self, string: &str) -> Result<()> {
        let bytes = string.as_bytes();
        if bytes.len() > 255 {
            return Err("Too long string".into());
        }
        self.write_u8(bytes.len() as u8).await?;
        self.write_all(bytes).await?;
        Ok(())
    }

    async fn write_auth_version(&mut self) -> Result<()> {
        self.write_u8(0x01).await?;
        Ok(())
    }

    async fn write_methods(&mut self, methods: &[AuthMethod]) -> Result<()> {
        self.write_u8(methods.len() as u8).await?;
        for method in methods {
            self.write_method(*method).await?;
        }
        Ok(())
    }

    async fn write_selection_msg(&mut self, methods: &[AuthMethod]) -> Result<()> {
        self.write_version().await?;
        self.write_methods(methods).await?;
        self.flush().await?;
        Ok(())
    }

    async fn write_final(&mut self, command: Command, addr: &Address) -> Result<()> {
        self.write_version().await?;
        self.write_command(command).await?;
        self.write_reserved().await?;
        self.write_address(addr).await?;
        self.flush().await?;
        Ok(())
    }
}

#[async_trait]
impl<T: AsyncWriteExt + Unpin> Socks5Writer for T {}

async fn username_password_auth<S>(stream: &mut S, auth: &UsernamePassword) -> Result<()>
where
    S: Socks5Writer + Socks5Reader + Send,
{
    stream.write_auth_version().await?;
    stream.write_string(&auth.username).await?;
    stream.write_string(&auth.password).await?;
    stream.flush().await?;

    stream.read_auth_version().await?;
    stream.read_auth_status().await
}

async fn init<S, A>(
    stream: &mut S,
    command: Command,
    addr: A,
    auth: Option<UsernamePassword>,
) -> Result<Address>
where
    S: Socks5Writer + Socks5Reader + Send,
    A: Into<Address>,
{
    let addr: Address = addr.into();

    let mut methods = Vec::with_capacity(2);
    methods.push(AuthMethod::NoAuth);
    if auth.is_some() {
        methods.push(AuthMethod::Password);
    }
    stream.write_selection_msg(&methods).await?;
    stream.flush().await?;

    let method: AuthMethod = stream.read_selection_msg().await?;
    match method {
        AuthMethod::NoAuth => {}
        // FIXME: until if let in match is stabilized
        AuthMethod::Password if auth.is_some() => {
            username_password_auth(stream, auth.as_ref().unwrap()).await?;
        }
        _ => return Err(Error::InvalidAuthMethod(method)),
    }

    stream.write_final(command, &addr).await?;
    stream.read_final().await
}

pub async fn connect<S, A>(
    socket: &mut S,
    addr: A,
    auth: Option<UsernamePassword>,
) -> Result<Address>
where
    S: AsyncWriteExt + AsyncReadExt + Send + Unpin,
    A: Into<Address>,
{
    init(socket, Command::Connect, addr, auth).await
}
