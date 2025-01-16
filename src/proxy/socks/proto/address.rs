use crate::proxy::socks::proto::{AsyncStreamOperation, StreamOperation};
use bytes::BufMut;
use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AddressType {
    IPv4 = 0x01,
    Domain = 0x03,
    IPv6 = 0x04,
}

impl TryFrom<u8> for AddressType {
    type Error = std::io::Error;

    fn try_from(code: u8) -> core::result::Result<Self, Self::Error> {
        let err = format!("Unsupported address type code {0:#x}", code);
        match code {
            0x01 => Ok(AddressType::IPv4),
            0x03 => Ok(AddressType::Domain),
            0x04 => Ok(AddressType::IPv6),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, err)),
        }
    }
}

impl From<AddressType> for u8 {
    fn from(addr_type: AddressType) -> Self {
        match addr_type {
            AddressType::IPv4 => 0x01,
            AddressType::Domain => 0x03,
            AddressType::IPv6 => 0x04,
        }
    }
}

/// SOCKS5 Adderss Format
///
/// ```plain
/// +------+----------+----------+
/// | ATYP | DST.ADDR | DST.PORT |
/// +------+----------+----------+
/// |  1   | Variable |    2     |
/// +------+----------+----------+
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Address {
    SocketAddress(SocketAddr),
    DomainAddress(String, u16),
}

impl Address {
    pub fn unspecified() -> Self {
        Address::SocketAddress(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
    }

    pub fn get_type(&self) -> AddressType {
        match self {
            Self::SocketAddress(SocketAddr::V4(_)) => AddressType::IPv4,
            Self::SocketAddress(SocketAddr::V6(_)) => AddressType::IPv6,
            Self::DomainAddress(..) => AddressType::Domain,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::SocketAddress(addr) => addr.port(),
            Self::DomainAddress(_, port) => *port,
        }
    }

    pub fn domain(&self) -> String {
        match self {
            Self::SocketAddress(addr) => addr.ip().to_string(),
            Self::DomainAddress(addr, _) => addr.clone(),
        }
    }

    pub const fn max_serialized_len() -> usize {
        1 + 1 + u8::MAX as usize + 2
    }
}

impl StreamOperation for Address {
    fn retrieve_from_stream<R: std::io::Read>(stream: &mut R) -> std::io::Result<Self> {
        let mut atyp = [0; 1];
        stream.read_exact(&mut atyp)?;
        match AddressType::try_from(atyp[0])? {
            AddressType::IPv4 => {
                let mut buf = [0; 6];
                stream.read_exact(&mut buf)?;
                let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                Ok(Self::SocketAddress(SocketAddr::from((addr, port))))
            }
            AddressType::Domain => {
                let mut len = [0; 1];
                stream.read_exact(&mut len)?;
                let len = len[0] as usize;
                let mut buf = vec![0; len + 2];
                stream.read_exact(&mut buf)?;

                let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
                buf.truncate(len);

                let addr = match String::from_utf8(buf) {
                    Ok(addr) => addr,
                    Err(err) => {
                        let err = format!("Invalid address encoding: {err}");
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, err));
                    }
                };
                Ok(Self::DomainAddress(addr, port))
            }
            AddressType::IPv6 => {
                let mut buf = [0; 18];
                stream.read_exact(&mut buf)?;
                let port = u16::from_be_bytes([buf[16], buf[17]]);
                let mut addr_bytes = [0; 16];
                addr_bytes.copy_from_slice(&buf[..16]);
                Ok(Self::SocketAddress(SocketAddr::from((
                    Ipv6Addr::from(addr_bytes),
                    port,
                ))))
            }
        }
    }

    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::SocketAddress(SocketAddr::V4(addr)) => {
                buf.put_u8(AddressType::IPv4.into());
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::SocketAddress(SocketAddr::V6(addr)) => {
                buf.put_u8(AddressType::IPv6.into());
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::DomainAddress(addr, port) => {
                let addr = addr.as_bytes();
                buf.put_u8(AddressType::Domain.into());
                buf.put_u8(addr.len() as u8);
                buf.put_slice(addr);
                buf.put_u16(*port);
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            Address::SocketAddress(SocketAddr::V4(_)) => 1 + 4 + 2,
            Address::SocketAddress(SocketAddr::V6(_)) => 1 + 16 + 2,
            Address::DomainAddress(addr, _) => 1 + 1 + addr.len() + 2,
        }
    }
}

impl AsyncStreamOperation for Address {
    async fn retrieve_from_async_stream<R>(stream: &mut R) -> std::io::Result<Self>
    where
        R: AsyncRead + Unpin + Send,
    {
        let atyp = stream.read_u8().await?;
        match AddressType::try_from(atyp)? {
            AddressType::IPv4 => {
                let mut addr_bytes = [0; 4];
                stream.read_exact(&mut addr_bytes).await?;
                let mut buf = [0; 2];
                stream.read_exact(&mut buf).await?;
                let addr = Ipv4Addr::from(addr_bytes);
                let port = u16::from_be_bytes(buf);
                Ok(Self::SocketAddress(SocketAddr::from((addr, port))))
            }
            AddressType::Domain => {
                let len = stream.read_u8().await? as usize;
                let mut buf = vec![0; len + 2];
                stream.read_exact(&mut buf).await?;

                let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
                buf.truncate(len);

                let addr = match String::from_utf8(buf) {
                    Ok(addr) => addr,
                    Err(err) => {
                        let err = format!("Invalid address encoding: {err}");
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, err));
                    }
                };
                Ok(Self::DomainAddress(addr, port))
            }
            AddressType::IPv6 => {
                let mut addr_bytes = [0; 16];
                stream.read_exact(&mut addr_bytes).await?;
                let mut buf = [0; 2];
                stream.read_exact(&mut buf).await?;
                let port = u16::from_be_bytes(buf);
                Ok(Self::SocketAddress(SocketAddr::from((
                    Ipv6Addr::from(addr_bytes),
                    port,
                ))))
            }
        }
    }
}

impl ToSocketAddrs for Address {
    type Iter = std::vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        match self {
            Address::SocketAddress(addr) => Ok(vec![*addr].into_iter()),
            Address::DomainAddress(addr, port) => Ok((addr.as_str(), *port).to_socket_addrs()?),
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::DomainAddress(hostname, port) => write!(f, "{hostname}:{port}"),
            Address::SocketAddress(socket_addr) => write!(f, "{socket_addr}"),
        }
    }
}

impl TryFrom<Address> for SocketAddr {
    type Error = std::io::Error;

    fn try_from(address: Address) -> std::result::Result<Self, Self::Error> {
        match address {
            Address::SocketAddress(addr) => Ok(addr),
            Address::DomainAddress(addr, port) => {
                if let Ok(addr) = addr.parse::<Ipv4Addr>() {
                    Ok(SocketAddr::from((addr, port)))
                } else if let Ok(addr) = addr.parse::<Ipv6Addr>() {
                    Ok(SocketAddr::from((addr, port)))
                } else {
                    let err = format!("domain address {addr} is not supported");
                    Err(Self::Error::new(std::io::ErrorKind::Unsupported, err))
                }
            }
        }
    }
}

impl TryFrom<&Address> for SocketAddr {
    type Error = std::io::Error;

    fn try_from(address: &Address) -> std::result::Result<Self, Self::Error> {
        TryFrom::<Address>::try_from(address.clone())
    }
}

impl From<Address> for Vec<u8> {
    fn from(addr: Address) -> Self {
        let mut buf = Vec::with_capacity(addr.len());
        addr.write_to_buf(&mut buf);
        buf
    }
}

impl TryFrom<Vec<u8>> for Address {
    type Error = std::io::Error;

    fn try_from(data: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        let mut rdr = Cursor::new(data);
        Self::retrieve_from_stream(&mut rdr)
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = std::io::Error;

    fn try_from(data: &[u8]) -> std::result::Result<Self, Self::Error> {
        let mut rdr = Cursor::new(data);
        Self::retrieve_from_stream(&mut rdr)
    }
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Address::SocketAddress(addr)
    }
}

impl From<&SocketAddr> for Address {
    fn from(addr: &SocketAddr) -> Self {
        Address::SocketAddress(*addr)
    }
}

impl From<(Ipv4Addr, u16)> for Address {
    fn from((addr, port): (Ipv4Addr, u16)) -> Self {
        Address::SocketAddress(SocketAddr::from((addr, port)))
    }
}

impl From<(Ipv6Addr, u16)> for Address {
    fn from((addr, port): (Ipv6Addr, u16)) -> Self {
        Address::SocketAddress(SocketAddr::from((addr, port)))
    }
}

impl From<(IpAddr, u16)> for Address {
    fn from((addr, port): (IpAddr, u16)) -> Self {
        Address::SocketAddress(SocketAddr::from((addr, port)))
    }
}

impl From<(String, u16)> for Address {
    fn from((addr, port): (String, u16)) -> Self {
        Address::DomainAddress(addr, port)
    }
}

impl From<(&str, u16)> for Address {
    fn from((addr, port): (&str, u16)) -> Self {
        Address::DomainAddress(addr.to_owned(), port)
    }
}

impl From<&Address> for Address {
    fn from(addr: &Address) -> Self {
        addr.clone()
    }
}

impl TryFrom<&str> for Address {
    type Error = crate::proxy::socks::error::Error;

    fn try_from(addr: &str) -> std::result::Result<Self, Self::Error> {
        if let Ok(addr) = addr.parse::<SocketAddr>() {
            Ok(Address::SocketAddress(addr))
        } else {
            let (addr, port) = if let Some(pos) = addr.rfind(':') {
                (&addr[..pos], &addr[pos + 1..])
            } else {
                (addr, "0")
            };
            let port = port.parse::<u16>()?;
            Ok(Address::DomainAddress(addr.to_owned(), port))
        }
    }
}
