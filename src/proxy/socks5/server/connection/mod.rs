use std::{net::SocketAddr, time::Duration};

use tokio::{io::AsyncWriteExt, net::TcpStream};

use self::{associate::UdpAssociate, bind::Bind, connect::Connect};
use crate::proxy::{
    socks5::{
        proto::{self, handshake, Address, AsyncStreamOperation, AuthMethod, Command},
        server::AuthAdaptor,
    },
    Error,
};

pub mod associate;
pub mod bind;
pub mod connect;

/// An incoming connection. This may not be a valid socks5 connection. You need
/// to call [`handshake()`](#method.handshake) to perform the socks5 handshake.
/// It will be converted to a proper socks5 connection after the handshake
/// succeeds.
pub struct IncomingConnection<O> {
    stream: TcpStream,
    auth: AuthAdaptor<O>,
}

impl<O: 'static> IncomingConnection<O> {
    #[inline]
    pub(crate) fn new(stream: TcpStream, auth: AuthAdaptor<O>) -> Self {
        IncomingConnection { stream, auth }
    }

    /// Returns the local address that this stream is bound to.
    #[inline]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    /// Returns the remote address that this stream is connected to.
    #[inline]
    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    /// Shutdown the TCP stream.
    #[inline]
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.stream.shutdown().await
    }

    /// Reads the linger duration for this socket by getting the `SO_LINGER`
    /// option.
    ///
    /// For more information about this option, see
    /// [set_linger](https://docs.rs/socks5-impl/latest/socks5_impl/server/connection/struct.IncomingConnection.html#method.set_linger).
    #[inline]
    pub fn linger(&self) -> std::io::Result<Option<Duration>> {
        self.stream.linger()
    }

    /// Sets the linger duration of this socket by setting the `SO_LINGER`
    /// option.
    ///
    /// This option controls the action taken when a stream has unsent messages
    /// and the stream is closed. If `SO_LINGER` is set, the system shall
    /// block the process until it can transmit the data or until the time
    /// expires.
    ///
    /// If `SO_LINGER` is not specified, and the stream is closed, the system
    /// handles the call in a way that allows the process to continue as
    /// quickly as possible.
    #[inline]
    pub fn set_linger(&self, dur: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_linger(dur)
    }

    /// Gets the value of the `TCP_NODELAY` option on this socket.
    ///
    /// For more information about this option, see
    /// [set_nodelay](https://docs.rs/socks5-impl/latest/socks5_impl/server/connection/struct.IncomingConnection.html#method.set_nodelay).
    #[inline]
    pub fn nodelay(&self) -> std::io::Result<bool> {
        self.stream.nodelay()
    }

    /// Sets the value of the `TCP_NODELAY` option on this socket.
    ///
    /// If set, this option disables the Nagle algorithm. This means that
    /// segments are always sent as soon as possible, even if there is only
    /// a small amount of data. When not set, data is buffered until there is a
    /// sufficient amount to send out, thereby avoiding the frequent sending
    /// of small packets.
    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        self.stream.set_nodelay(nodelay)
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    ///
    /// For more information about this option, see
    /// [set_ttl](https://docs.rs/socks5-impl/latest/socks5_impl/server/connection/struct.IncomingConnection.html#method.set_ttl).
    pub fn ttl(&self) -> std::io::Result<u32> {
        self.stream.ttl()
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent
    /// from this socket.
    pub fn set_ttl(&self, ttl: u32) -> std::io::Result<()> {
        self.stream.set_ttl(ttl)
    }

    /// Perform a SOCKS5 authentication handshake using the given
    /// [`AuthExecutor`](https://docs.rs/socks5-impl/latest/socks5_impl/server/auth/trait.AuthExecutor.html) adapter.
    ///
    /// If the handshake succeeds, an [`Authenticated`](https://docs.rs/socks5-impl/latest/socks5_impl/server/connection/struct.Authenticated.html)
    /// alongs with the output of the [`AuthExecutor`](https://docs.rs/socks5-impl/latest/socks5_impl/server/auth/trait.AuthExecutor.html) adapter is returned.
    /// Otherwise, the error and the original [`TcpStream`](https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html) is returned.
    ///
    /// Note that this method will not implicitly close the connection even if
    /// the handshake failed.
    pub async fn authenticate(mut self) -> std::io::Result<(Authenticated, O)> {
        let request = handshake::Request::retrieve_from_async_stream(&mut self.stream).await?;
        if let Some(method) = self.evaluate_request(&request) {
            let response = handshake::Response::new(method);
            response.write_to_async_stream(&mut self.stream).await?;
            let output = self.auth.execute(&mut self.stream).await;
            Ok((Authenticated::new(self.stream), output))
        } else {
            let response = handshake::Response::new(AuthMethod::NoAcceptableMethods);
            response.write_to_async_stream(&mut self.stream).await?;
            let err = "No available handshake method provided by client";
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err))
        }
    }

    fn evaluate_request(&self, req: &handshake::Request) -> Option<AuthMethod> {
        let method = self.auth.auth_method();
        if req.evaluate_method(method) {
            Some(method)
        } else {
            None
        }
    }
}

impl<O> std::fmt::Debug for IncomingConnection<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncomingConnection")
            .field("stream", &self.stream)
            .finish()
    }
}

impl<O> From<IncomingConnection<O>> for TcpStream {
    #[inline]
    fn from(conn: IncomingConnection<O>) -> Self {
        conn.stream
    }
}

/// A TCP stream that has been authenticated.
///
/// To get the command from the SOCKS5 client, use
/// [`wait_request`](https://docs.rs/socks5-impl/latest/socks5_impl/server/connection/struct.Authenticated.html#method.wait_request).
///
/// It can also be converted back into a raw [`tokio::TcpStream`](https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html) with `From` trait.
pub struct Authenticated(TcpStream);

impl Authenticated {
    #[inline]
    fn new(stream: TcpStream) -> Self {
        Self(stream)
    }

    /// Waits the SOCKS5 client to send a request.
    ///
    /// This method will return a [`Command`](https://docs.rs/socks5-impl/latest/socks5_impl/server/connection/enum.Command.html)
    /// if the client sends a valid command.
    ///
    /// When encountering an error, the stream will be returned alongside the
    /// error.
    ///
    /// Note that this method will not implicitly close the connection even if
    /// the client sends an invalid request.
    pub async fn wait_request(mut self) -> Result<ClientConnection, Error> {
        let req = proto::Request::retrieve_from_async_stream(&mut self.0).await?;

        match req.command {
            Command::UdpAssociate => Ok(ClientConnection::UdpAssociate(
                UdpAssociate::<associate::NeedReply>::new(self.0),
                req.address,
            )),
            Command::Bind => Ok(ClientConnection::Bind(
                Bind::<bind::NeedFirstReply>::new(self.0),
                req.address,
            )),
            Command::Connect => Ok(ClientConnection::Connect(
                Connect::<connect::NeedReply>::new(self.0),
                req.address,
            )),
        }
    }

    /// Causes the other peer to receive a read of length 0, indicating that no
    /// more data will be sent. This only closes the stream in one direction.
    #[inline]
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.0.shutdown().await
    }

    /// Returns the local address that this stream is bound to.
    #[inline]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.local_addr()
    }

    /// Returns the remote address that this stream is connected to.
    #[inline]
    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.peer_addr()
    }

    /// Reads the linger duration for this socket by getting the `SO_LINGER`
    /// option.
    ///
    /// For more information about this option, see
    /// [set_linger](https://docs.rs/socks5-impl/latest/socks5_impl/server/connection/struct.Authenticated.html#method.set_linger).
    #[inline]
    pub fn linger(&self) -> std::io::Result<Option<Duration>> {
        self.0.linger()
    }

    /// Sets the linger duration of this socket by setting the `SO_LINGER`
    /// option.
    ///
    /// This option controls the action taken when a stream has unsent messages
    /// and the stream is closed. If `SO_LINGER` is set, the system shall
    /// block the process until it can transmit the data or until the time
    /// expires.
    ///
    /// If `SO_LINGER` is not specified, and the stream is closed, the system
    /// handles the call in a way that allows the process to continue as
    /// quickly as possible.
    #[inline]
    pub fn set_linger(&self, dur: Option<Duration>) -> std::io::Result<()> {
        self.0.set_linger(dur)
    }

    /// Gets the value of the `TCP_NODELAY` option on this socket.
    ///
    /// For more information about this option, see
    /// [set_nodelay](https://docs.rs/socks5-impl/latest/socks5_impl/server/connection/struct.Authenticated.html#method.set_nodelay).
    #[inline]
    pub fn nodelay(&self) -> std::io::Result<bool> {
        self.0.nodelay()
    }

    /// Sets the value of the `TCP_NODELAY` option on this socket.
    ///
    /// If set, this option disables the Nagle algorithm. This means that
    /// segments are always sent as soon as possible, even if there is only
    /// a small amount of data. When not set, data is buffered until there is a
    /// sufficient amount to send out, thereby avoiding the frequent sending
    /// of small packets.
    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        self.0.set_nodelay(nodelay)
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    ///
    /// For more information about this option, see
    /// [set_ttl](https://docs.rs/socks5-impl/latest/socks5_impl/server/connection/struct.Authenticated.html#method.set_ttl).
    pub fn ttl(&self) -> std::io::Result<u32> {
        self.0.ttl()
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent
    /// from this socket.
    pub fn set_ttl(&self, ttl: u32) -> std::io::Result<()> {
        self.0.set_ttl(ttl)
    }
}

impl From<Authenticated> for TcpStream {
    #[inline]
    fn from(conn: Authenticated) -> Self {
        conn.0
    }
}

/// After the socks5 handshake succeeds, the connection may become:
///
/// - Associate
/// - Bind
/// - Connect
#[derive(Debug)]
pub enum ClientConnection {
    UdpAssociate(UdpAssociate<associate::NeedReply>, Address),
    Bind(Bind<bind::NeedFirstReply>, Address),
    Connect(Connect<connect::NeedReply>, Address),
}
