use std::{
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{
        TcpStream,
        tcp::{ReadHalf, WriteHalf},
    },
};

use crate::socks::proto::{Address, AsyncStreamOperation, Reply, Response};

/// Socks5 command type `Bind`
/// you may get a `Bind<NeedFirstReply>`. After replying the client 2 times
/// you will get a `Bind<Ready>`, which can be used as a regular async TCP
/// stream.
///
/// A `Bind<S>` can be converted to a regular tokio [`TcpStream`](https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html) by using the `From` trait.
#[derive(Debug)]
pub struct Bind<S> {
    stream: TcpStream,
    _state: PhantomData<S>,
}

/// Marker type indicating that the connection needs its first reply.
#[derive(Debug, Default)]
pub struct NeedFirstReply;

/// Marker type indicating that the connection needs its second reply.
#[derive(Debug, Default)]
pub struct NeedSecondReply;

/// Marker type indicating that the connection is ready to use as a regular TCP
/// stream.
#[derive(Debug, Default)]
pub struct Ready;

impl Bind<NeedFirstReply> {
    #[inline]
    pub(super) fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            _state: PhantomData,
        }
    }

    /// Reply to the SOCKS5 client with the given reply and address.
    ///
    /// If encountered an error while writing the reply, the error alongside the
    /// original `TcpStream` is returned.
    pub async fn reply(
        mut self,
        reply: Reply,
        addr: Address,
    ) -> std::io::Result<Bind<NeedSecondReply>> {
        let resp = Response::new(reply, addr);
        resp.write_to_async_stream(&mut self.stream).await?;
        Ok(Bind::<NeedSecondReply>::new(self.stream))
    }

    /// Causes the other peer to receive a read of length 0, indicating that no
    /// more data will be sent. This only closes the stream in one direction.
    #[inline]
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.stream.shutdown().await
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

    /// Reads the linger duration for this socket by getting the `SO_LINGER`
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
}

impl Bind<NeedSecondReply> {
    #[inline]
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            _state: PhantomData,
        }
    }

    /// Reply to the SOCKS5 client with the given reply and address.
    ///
    /// If encountered an error while writing the reply, the error alongside the
    /// original `TcpStream` is returned.
    pub async fn reply(
        mut self,
        reply: Reply,
        addr: Address,
    ) -> Result<Bind<Ready>, (std::io::Error, TcpStream)> {
        let resp = Response::new(reply, addr);

        if let Err(err) = resp.write_to_async_stream(&mut self.stream).await {
            return Err((err, self.stream));
        }

        Ok(Bind::<Ready>::new(self.stream))
    }

    /// Causes the other peer to receive a read of length 0, indicating that no
    /// more data will be sent. This only closes the stream in one direction.
    #[inline]
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.stream.shutdown().await
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

    /// Reads the linger duration for this socket by getting the `SO_LINGER`
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
}

impl Bind<Ready> {
    #[inline]
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            _state: PhantomData,
        }
    }

    /// Split the connection into a read and a write half.
    #[inline]
    pub fn split(&mut self) -> (ReadHalf<'_>, WriteHalf<'_>) {
        self.stream.split()
    }
}

impl std::ops::Deref for Bind<Ready> {
    type Target = TcpStream;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl std::ops::DerefMut for Bind<Ready> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

impl AsyncRead for Bind<Ready> {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Bind<Ready> {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl<S> From<Bind<S>> for TcpStream {
    #[inline]
    fn from(conn: Bind<S>) -> Self {
        conn.stream
    }
}
