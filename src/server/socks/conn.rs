pub mod associate;
pub mod bind;
pub mod connect;

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};
use tokio_util::codec::{Framed, FramedParts};

use self::{associate::UdpAssociate, bind::Bind, connect::Connect};
use super::proto;
use super::{
    auth::{Auth, AuthAdaptor},
    error::Error,
    proto::{
        Address, ClientFrame, ClientFrameKind, Command, MAX_CLIENT_FRAME_LEN, Method, Reply,
        ServerFrame, SocksCodec, handshake::password::Status,
    },
};
use crate::ext::Extension;

fn poll_read_with_pending(
    stream: &mut TcpStream,
    pending: &mut Bytes,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> Poll<std::io::Result<()>> {
    if !pending.is_empty() && buf.remaining() != 0 {
        let len = pending.len().min(buf.remaining());
        let chunk = pending.split_to(len);
        buf.put_slice(&chunk);
        if pending.is_empty() {
            *pending = Bytes::new();
        }
        Poll::Ready(Ok(()))
    } else {
        Pin::new(stream).poll_read(cx, buf)
    }
}

async fn reject_request(
    stream: &mut TcpStream,
    reply: Reply,
    address: Address,
) -> std::io::Result<()> {
    if reply == Reply::Succeeded {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a SOCKS5 rejection requires a nonzero reply code",
        ));
    }

    // RFC 1928 section 6 requires the server to close shortly after a failure
    // reply. Closing immediately also prevents a failed typestate transition
    // from being used as a ready data stream.
    // https://www.rfc-editor.org/rfc/rfc1928.html#section-6
    proto::write_server_frame(stream, ServerFrame::Reply(reply, address)).await?;
    stream.shutdown().await
}

/// Error returned while negotiating a SOCKS5 authentication method.
#[derive(Debug, thiserror::Error)]
pub enum AuthenticationError {
    /// The client supplied credentials or methods that the server rejected.
    #[error("{0}")]
    Rejected(#[source] std::io::Error),

    /// The negotiation failed before an authentication decision was made.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// An incoming connection before SOCKS5 method negotiation and authentication.
///
/// Call [`authenticate`](Self::authenticate) to obtain an authenticated stream.
pub struct IncomingConnection {
    framed: Framed<TcpStream, SocksCodec>,
    auth: Arc<AuthAdaptor>,
}

impl IncomingConnection {
    #[inline]
    pub(crate) fn new(stream: TcpStream, auth: Arc<AuthAdaptor>) -> Self {
        IncomingConnection {
            framed: Framed::with_capacity(stream, SocksCodec::new(), MAX_CLIENT_FRAME_LEN),
            auth,
        }
    }

    /// Returns the local address that this stream is bound to.
    #[inline]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.framed.get_ref().local_addr()
    }

    /// Returns the remote address that this stream is connected to.
    #[inline]
    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.framed.get_ref().peer_addr()
    }

    /// Shutdown the TCP stream.
    #[inline]
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.framed.get_mut().shutdown().await
    }

    /// Reads the linger duration for this socket by getting the `SO_LINGER`
    #[inline]
    pub fn linger(&self) -> std::io::Result<Option<Duration>> {
        self.framed.get_ref().linger()
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
        socket2::SockRef::from(self.framed.get_ref()).set_linger(dur)
    }

    /// Gets the value of the `TCP_NODELAY` option on this socket.
    #[inline]
    pub fn nodelay(&self) -> std::io::Result<bool> {
        self.framed.get_ref().nodelay()
    }

    /// Sets the value of the `TCP_NODELAY` option on this socket.
    ///
    /// If set, this option disables the Nagle algorithm. This means that
    /// segments are always sent as soon as possible, even if there is only
    /// a small amount of data. When not set, data is buffered until there is a
    /// sufficient amount to send out, thereby avoiding the frequent sending
    /// of small packets.
    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        self.framed.get_ref().set_nodelay(nodelay)
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    pub fn ttl(&self) -> std::io::Result<u32> {
        self.framed.get_ref().ttl()
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent
    /// from this socket.
    pub fn set_ttl(&self, ttl: u32) -> std::io::Result<()> {
        self.framed.get_ref().set_ttl(ttl)
    }

    /// Performs SOCKS5 method negotiation and authentication.
    ///
    /// Authentication failures are reported to the client before the
    /// connection is closed, as required by RFC 1929 section 2.
    pub async fn authenticate(
        mut self,
    ) -> Result<(AuthenticatedStream, Extension), AuthenticationError> {
        let method = self.auth.method();
        let Some(ClientFrame::Methods(methods)) = self.framed.next().await.transpose()? else {
            return Err(AuthenticationError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed during SOCKS5 method negotiation",
            )));
        };
        if !methods.contains(&method) {
            self.framed
                .send(ServerFrame::Method(Method::NoAcceptableMethods))
                .await?;
            self.framed.get_mut().shutdown().await?;
            return Err(AuthenticationError::Rejected(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "no acceptable SOCKS5 authentication method",
            )));
        }

        self.framed.send(ServerFrame::Method(method)).await?;
        let credentials = if method == Method::Password {
            self.framed.codec_mut().expect(ClientFrameKind::Password);
            let Some(ClientFrame::Password(credentials)) = self.framed.next().await.transpose()?
            else {
                return Err(AuthenticationError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "client closed during SOCKS5 password authentication",
                )));
            };
            Some(credentials)
        } else {
            None
        };

        let output = self.auth.authenticate(credentials).await;
        if method == Method::Password {
            self.framed
                .send(ServerFrame::Password(if output.is_ok() {
                    Status::Succeeded
                } else {
                    Status::Failed
                }))
                .await?;
        }
        let extension = match output {
            Ok(extension) => extension,
            Err(error) => {
                // RFC 1929 section 2 requires closing after a failed status.
                // https://www.rfc-editor.org/rfc/rfc1929.html#section-2
                self.framed.get_mut().shutdown().await?;
                let rejected = error.is_rejected();
                let error = std::io::Error::from(error);
                return Err(if rejected {
                    AuthenticationError::Rejected(error)
                } else {
                    AuthenticationError::Io(error)
                });
            }
        };
        self.framed.codec_mut().expect(ClientFrameKind::Request);
        Ok((AuthenticatedStream::new(self.framed), extension))
    }
}

impl AuthenticationError {
    #[inline]
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected(_))
    }

    #[inline]
    pub fn into_io_error(self) -> std::io::Error {
        match self {
            Self::Rejected(error) | Self::Io(error) => error,
        }
    }
}

impl std::fmt::Debug for IncomingConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncomingConnection")
            .field("stream", self.framed.get_ref())
            .finish()
    }
}

impl From<IncomingConnection> for FramedParts<TcpStream, SocksCodec> {
    fn from(connection: IncomingConnection) -> Self {
        connection.framed.into_parts()
    }
}

/// A TCP stream that has been authenticated.
pub struct AuthenticatedStream(Framed<TcpStream, SocksCodec>);

impl AuthenticatedStream {
    #[inline]
    fn new(framed: Framed<TcpStream, SocksCodec>) -> Self {
        Self(framed)
    }

    /// Waits the SOCKS5 client to send a request.
    ///
    /// Invalid commands and address types receive their RFC 1928 failure reply
    /// before the connection is closed.
    pub async fn wait_request(mut self) -> Result<ClientConnection, Error> {
        let frame = self.0.next().await.transpose()?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed before sending a SOCKS5 request",
            )
        })?;
        let (command, address) = match frame {
            ClientFrame::Request { command, address } => (command, address),
            ClientFrame::RequestRejected(reply) => {
                self.0
                    .send(ServerFrame::Reply(reply, Address::unspecified()))
                    .await?;
                self.0.get_mut().shutdown().await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "SOCKS5 request was rejected",
                )
                .into());
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected SOCKS5 frame",
                )
                .into());
            }
        };
        self.0.codec_mut().expect(ClientFrameKind::Done);
        let parts = self.0.into_parts();
        let pending = if parts.read_buf.is_empty() {
            Bytes::new()
        } else {
            parts.read_buf.freeze()
        };

        match command {
            Command::UdpAssociate => Ok(ClientConnection::UdpAssociate(
                UdpAssociate::<associate::NeedReply>::new(parts.io, pending),
                address,
            )),
            Command::Bind => Ok(ClientConnection::Bind(
                Bind::<bind::NeedFirstReply>::new(parts.io, pending),
                address,
            )),
            Command::Connect => Ok(ClientConnection::Connect(
                Connect::<connect::NeedReply>::new(parts.io, pending),
                address,
            )),
        }
    }

    /// Causes the other peer to receive a read of length 0, indicating that no
    /// more data will be sent. This only closes the stream in one direction.
    #[inline]
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.0.get_mut().shutdown().await
    }

    /// Returns the local address that this stream is bound to.
    #[inline]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.get_ref().local_addr()
    }

    /// Returns the remote address that this stream is connected to.
    #[inline]
    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.get_ref().peer_addr()
    }

    /// Reads the linger duration for this socket by getting the `SO_LINGER`
    /// option.
    #[inline]
    pub fn linger(&self) -> std::io::Result<Option<Duration>> {
        self.0.get_ref().linger()
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
        socket2::SockRef::from(self.0.get_ref()).set_linger(dur)
    }

    /// Gets the value of the `TCP_NODELAY` option on this socket.
    #[inline]
    pub fn nodelay(&self) -> std::io::Result<bool> {
        self.0.get_ref().nodelay()
    }

    /// Sets the value of the `TCP_NODELAY` option on this socket.
    ///
    /// If set, this option disables the Nagle algorithm. This means that
    /// segments are always sent as soon as possible, even if there is only
    /// a small amount of data. When not set, data is buffered until there is a
    /// sufficient amount to send out, thereby avoiding the frequent sending
    /// of small packets.
    #[inline]
    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        self.0.get_ref().set_nodelay(nodelay)
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    #[inline]
    pub fn ttl(&self) -> std::io::Result<u32> {
        self.0.get_ref().ttl()
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent
    /// from this socket.
    #[inline]
    pub fn set_ttl(&self, ttl: u32) -> std::io::Result<()> {
        self.0.get_ref().set_ttl(ttl)
    }
}

impl From<AuthenticatedStream> for FramedParts<TcpStream, SocksCodec> {
    fn from(connection: AuthenticatedStream) -> Self {
        connection.0.into_parts()
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

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::*;

    #[tokio::test]
    async fn non_utf8_rfc1929_credentials_receive_failure_status_then_close() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let result = IncomingConnection::new(
                stream,
                Arc::new(AuthAdaptor::password("expected", "secret")),
            )
            .authenticate()
            .await;
            assert!(matches!(result, Err(AuthenticationError::Rejected(_))));
        });

        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x05, 0x02]);

        client
            .write_all(&[0x01, 0x01, 0xff, 0x06, b's', b'e', b'c', b'r', b'e', b't'])
            .await
            .unwrap();
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x01, 0xff]);
        assert_eq!(client.read(&mut response).await.unwrap(), 0);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_rfc1929_frame_is_not_reported_as_credential_rejection() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let result = IncomingConnection::new(
                stream,
                Arc::new(AuthAdaptor::password("expected", "secret")),
            )
            .authenticate()
            .await;
            assert!(matches!(result, Err(AuthenticationError::Io(_))));
        });

        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x05, 0x02]);
        client.write_all(&[0x02, 0x01]).await.unwrap();

        server.await.unwrap();
    }
}
