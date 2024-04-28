mod auth;
pub mod error;
mod server;
mod util;

use std::{
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr},
};

use anyhow::Context;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    task,
};
use tokio_stream::StreamExt;
use util::addr::{read_address, TargetAddr, ToTargetAddr};

#[allow(dead_code)]
pub mod consts {
    pub const SOCKS5_VERSION: u8 = 0x05;

    pub const SOCKS5_AUTH_METHOD_NONE: u8 = 0x00;
    pub const SOCKS5_AUTH_METHOD_GSSAPI: u8 = 0x01;
    pub const SOCKS5_AUTH_METHOD_PASSWORD: u8 = 0x02;
    pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE: u8 = 0xff;

    pub const SOCKS5_CMD_TCP_CONNECT: u8 = 0x01;
    pub const SOCKS5_CMD_TCP_BIND: u8 = 0x02;
    pub const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;

    pub const SOCKS5_ADDR_TYPE_IPV4: u8 = 0x01;
    pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
    pub const SOCKS5_ADDR_TYPE_IPV6: u8 = 0x04;

    pub const SOCKS5_REPLY_SUCCEEDED: u8 = 0x00;
    pub const SOCKS5_REPLY_GENERAL_FAILURE: u8 = 0x01;
    pub const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED: u8 = 0x02;
    pub const SOCKS5_REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
    pub const SOCKS5_REPLY_HOST_UNREACHABLE: u8 = 0x04;
    pub const SOCKS5_REPLY_CONNECTION_REFUSED: u8 = 0x05;
    pub const SOCKS5_REPLY_TTL_EXPIRED: u8 = 0x06;
    pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

#[derive(Debug, PartialEq)]
pub enum Socks5Command {
    TCPConnect,
    TCPBind,
    UDPAssociate,
}

#[allow(dead_code)]
impl Socks5Command {
    #[inline]
    fn as_u8(&self) -> u8 {
        match self {
            Socks5Command::TCPConnect => consts::SOCKS5_CMD_TCP_CONNECT,
            Socks5Command::TCPBind => consts::SOCKS5_CMD_TCP_BIND,
            Socks5Command::UDPAssociate => consts::SOCKS5_CMD_UDP_ASSOCIATE,
        }
    }

    #[inline]
    fn from_u8(code: u8) -> Option<Socks5Command> {
        match code {
            consts::SOCKS5_CMD_TCP_CONNECT => Some(Socks5Command::TCPConnect),
            consts::SOCKS5_CMD_TCP_BIND => Some(Socks5Command::TCPBind),
            consts::SOCKS5_CMD_UDP_ASSOCIATE => Some(Socks5Command::UDPAssociate),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum AuthenticationMethod {
    None,
    Password { username: String, password: String },
}

impl AuthenticationMethod {
    #[inline]
    fn from_u8(code: u8) -> Option<AuthenticationMethod> {
        match code {
            consts::SOCKS5_AUTH_METHOD_NONE => Some(AuthenticationMethod::None),
            consts::SOCKS5_AUTH_METHOD_PASSWORD => Some(AuthenticationMethod::Password {
                username: "test".to_string(),
                password: "test".to_string(),
            }),
            _ => None,
        }
    }
}

impl fmt::Display for AuthenticationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            AuthenticationMethod::None => f.write_str("AuthenticationMethod::None"),
            AuthenticationMethod::Password { .. } => f.write_str("AuthenticationMethod::Password"),
        }
    }
}

pub type Result<T, E = SocksError> = core::result::Result<T, E>;

/// Generate UDP header
///
/// # UDP Request header structure.
/// ```text
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
///
/// The fields in the UDP request header are:
///
///     o  RSV  Reserved X'0000'
///     o  FRAG    Current fragment number
///     o  ATYP    address type of following addresses:
///        o  IP V4 address: X'01'
///        o  DOMAINNAME: X'03'
///        o  IP V6 address: X'04'
///     o  DST.ADDR       desired destination address
///     o  DST.PORT       desired destination port
///     o  DATA     user data
/// ```
pub fn new_udp_header<T: ToTargetAddr>(target_addr: T) -> Result<Vec<u8>> {
    let mut header = vec![
        0, 0, // RSV
        0, // FRAG
    ];
    header.append(&mut target_addr.to_target_addr()?.to_be_bytes()?);

    Ok(header)
}

/// Parse data from UDP client on raw buffer, return (frag, target_addr,
/// payload).
pub async fn parse_udp_request<'a>(mut req: &'a [u8]) -> Result<(u8, TargetAddr, &'a [u8])> {
    let rsv = read_exact!(req, [0u8; 2]).context("Malformed request")?;

    if !rsv.eq(&[0u8; 2]) {
        return Err(ReplyError::GeneralFailure.into());
    }

    let [frag, atyp] = read_exact!(req, [0u8; 2]).context("Malformed request")?;

    let target_addr = read_address(&mut req, atyp).await.map_err(|e| {
        // print explicit error
        tracing::error!("{:#}", e);
        // then convert it to a reply
        ReplyError::AddressTypeNotSupported
    })?;

    Ok((frag, target_addr, req))
}

use self::{error::SocksError, server::Socks5Socket};
use crate::{
    proxy::socks5::{
        auth::SimpleUserPassword,
        error::ReplyError,
        server::{Config, Socks5Server},
    },
    read_exact, AuthMode,
};

pub struct Socks5Context {
    pub bind: SocketAddr,
    pub auth: AuthMode,
    pub timeout: u64,
    pub dns_resolve: bool,
    pub udp_support: bool,
    pub execute_command: bool,
    /// Ipv6 subnet, e.g. 2001:db8::/32
    pub ipv6_subnet: Option<cidr::Ipv6Cidr>,
    /// Fallback address
    pub fallback: Option<IpAddr>,
}

pub(super) async fn run(ctx: Socks5Context) -> crate::Result<()> {
    let mut config = Config::default();
    config.set_request_timeout(ctx.timeout);
    config.set_dns_resolve(ctx.dns_resolve);
    config.set_udp_support(ctx.udp_support);
    config.set_execute_command(ctx.execute_command);

    let config = match ctx.auth {
        AuthMode::NoAuth => {
            tracing::info!("No auth system has been set.");
            config
        }
        AuthMode::Auth { username, password } => {
            tracing::info!("Auth system has been set.");
            config.with_authentication(SimpleUserPassword { username, password })
        }
    };

    // Bind to the address and start listening for incoming connections
    let server = <Socks5Server>::bind(ctx.bind).await?.with_config(config);

    // Accept connections in a loop
    let mut incoming = server.incoming();

    // Standard TCP loop
    while let Some(socket_res) = incoming.next().await {
        match socket_res {
            Ok(socket) => {
                spawn_and_log_error(socket.upgrade_to_socks5());
            }
            Err(err) => {
                tracing::error!("Accept error = {:?}", err);
            }
        }
    }

    Ok(())
}

fn spawn_and_log_error<F, T>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<Socks5Socket<T, SimpleUserPassword>>> + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin,
{
    task::spawn(async move {
        match fut.await {
            Ok(mut socket) => {
                if let Some(user) = socket.take_credentials() {
                    tracing::info!("User logged in with `{}`", user.username);
                }
            }
            Err(err) => tracing::error!("{:#}", &err),
        }
    })
}
