use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;

pub mod auth;
pub mod connection;

pub use crate::proxy::socks::server::{
    auth::AuthAdaptor,
    connection::{associate::UdpAssociate, ClientConnection, IncomingConnection},
};

pub struct Server {
    listener: TcpListener,
    auth: Arc<AuthAdaptor>,
}

impl Server {
    /// Create a new socks5 server with the given TCP listener and
    /// authentication method.
    #[inline]
    pub fn new(listener: TcpListener, auth: AuthAdaptor) -> Self {
        Self {
            listener,
            auth: Arc::new(auth),
        }
    }

    /// Create a new socks5 server on the given socket address, authentication
    /// method, and concurrency level.
    #[inline]
    pub async fn bind_with_concurrency(
        addr: SocketAddr,
        concurrent: u32,
        auth: AuthAdaptor,
    ) -> std::io::Result<Self> {
        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(true)?;
        socket.bind(addr)?;
        let listener = socket.listen(concurrent)?;
        Ok(Self::new(listener, auth))
    }

    /// The connection may not be a valid socks5 connection. You need to call
    /// to hand-shake it into a proper socks5 connection.
    #[inline]
    pub async fn accept(&self) -> std::io::Result<(IncomingConnection, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        Ok((IncomingConnection::new(stream, self.auth.clone()), addr))
    }
}
