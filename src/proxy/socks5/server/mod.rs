use std::{
    net::SocketAddr,
    task::{Context, Poll},
};
use tokio::net::TcpListener;

pub mod auth;
pub mod connection;

pub use crate::proxy::socks5::server::{
    auth::AuthAdaptor,
    connection::{associate::UdpAssociate, ClientConnection, IncomingConnection},
};

pub struct Server<O> {
    listener: TcpListener,
    auth: AuthAdaptor<O>,
}

impl<O: 'static + std::marker::Send> Server<O> {
    /// Create a new socks5 server with the given TCP listener and
    /// authentication method.
    #[inline]
    pub fn new(listener: TcpListener, auth: AuthAdaptor<O>) -> Self {
        Self { listener, auth }
    }

    /// Create a new socks5 server on the given socket address, authentication
    /// method, and concurrency level.
    #[inline]
    pub async fn bind_with_concurrency(
        addr: SocketAddr,
        concurrent: u32,
        auth: AuthAdaptor<O>,
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
    pub async fn accept(&self) -> std::io::Result<(IncomingConnection<O>, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        Ok((IncomingConnection::new(stream, self.auth.clone()), addr))
    }

    /// The connection is only a freshly created TCP connection and may not be a
    /// valid SOCKS5 connection. You should call
    /// to perform a SOCKS5 authentication handshake.
    ///
    /// If there is no connection to accept, Poll::Pending is returned, and the
    /// current task will be notified by a waker. Note that on multiple
    /// calls to poll_accept, only the Waker from the Context passed to the most
    /// recent call is scheduled to receive a wakeup.
    #[inline]
    pub fn poll_accept(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<(IncomingConnection<O>, SocketAddr)>> {
        self.listener
            .poll_accept(cx)
            .map_ok(|(stream, addr)| (IncomingConnection::new(stream, self.auth.clone()), addr))
    }

    /// Get the local socket address bound to this server
    #[inline]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

impl<O> From<(TcpListener, AuthAdaptor<O>)> for Server<O> {
    #[inline]
    fn from((listener, auth): (TcpListener, AuthAdaptor<O>)) -> Self {
        Self { listener, auth }
    }
}

impl<O> From<Server<O>> for (TcpListener, AuthAdaptor<O>) {
    #[inline]
    fn from(server: Server<O>) -> Self {
        (server.listener, server.auth)
    }
}
