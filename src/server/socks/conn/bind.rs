use std::{
    io::IoSlice,
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};

use super::{
    poll_read_with_pending,
    proto::{Address, Reply, ServerFrame, write_server_frame},
    reject_request,
};

/// A SOCKS5 BIND connection.
///
/// A `Bind<NeedFirstReply>` becomes `Bind<Ready>` after the two replies
/// required by RFC 1928 have been sent. The ready state can be used as a
/// regular asynchronous TCP stream.
/// https://www.rfc-editor.org/rfc/rfc1928.html#section-6
///
/// A `Bind<S>` can be converted into its raw tokio
/// [`TcpStream`](https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html)
/// and any prefetched application data by using the `From` trait.
#[derive(Debug)]
pub struct Bind<S> {
    stream: TcpStream,
    pending: Bytes,
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
    /// Create a new [`Bind<NeedFirstReply>`] from a [`TcpStream`].
    #[inline]
    pub(super) fn new(stream: TcpStream, pending: Bytes) -> Self {
        Self {
            stream,
            pending,
            _state: PhantomData,
        }
    }

    /// Sends the first successful BIND reply.
    pub async fn succeed(mut self, addr: Address) -> std::io::Result<Bind<NeedSecondReply>> {
        write_server_frame(&mut self.stream, ServerFrame::Reply(Reply::Succeeded, addr)).await?;
        Ok(Bind::<NeedSecondReply>::new(self.stream, self.pending))
    }

    /// Sends a failed first BIND reply and closes the control connection.
    pub async fn reject(mut self, reply: Reply, addr: Address) -> std::io::Result<()> {
        reject_request(&mut self.stream, reply, addr).await
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
        socket2::SockRef::from(&self.stream).set_linger(dur)
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
    #[inline]
    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        self.stream.set_nodelay(nodelay)
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    #[inline]
    pub fn ttl(&self) -> std::io::Result<u32> {
        self.stream.ttl()
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent
    /// from this socket.
    #[inline]
    pub fn set_ttl(&self, ttl: u32) -> std::io::Result<()> {
        self.stream.set_ttl(ttl)
    }
}

impl Bind<NeedSecondReply> {
    #[inline]
    fn new(stream: TcpStream, pending: Bytes) -> Self {
        Self {
            stream,
            pending,
            _state: PhantomData,
        }
    }

    /// Reads data that arrives while the server waits for the BIND peer.
    ///
    /// The handler keeps these bytes in order and forwards them only after the
    /// second successful BIND reply.
    pub(in crate::server::socks) async fn read_early_data(
        &mut self,
        buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        self.stream.read(buffer).await
    }

    /// Returns application data that the request codec read ahead.
    #[inline]
    pub(in crate::server::socks) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Sends the second successful BIND reply and enables the data stream.
    ///
    /// If writing the reply fails, the error and connection state are returned.
    pub async fn succeed(
        mut self,
        addr: Address,
    ) -> Result<Bind<Ready>, (std::io::Error, Bind<NeedSecondReply>)> {
        if let Err(err) =
            write_server_frame(&mut self.stream, ServerFrame::Reply(Reply::Succeeded, addr)).await
        {
            return Err((err, self));
        }

        Ok(Bind::<Ready>::new(self.stream, self.pending))
    }

    /// Sends a failed second BIND reply and closes the control connection.
    pub async fn reject(mut self, reply: Reply, addr: Address) -> std::io::Result<()> {
        reject_request(&mut self.stream, reply, addr).await
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
        socket2::SockRef::from(&self.stream).set_linger(dur)
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
    fn new(stream: TcpStream, pending: Bytes) -> Self {
        Self {
            stream,
            pending,
            _state: PhantomData,
        }
    }

    /// Takes application data read together with the SOCKS5 request.
    #[inline]
    pub fn take_pending_data(&mut self) -> Bytes {
        std::mem::take(&mut self.pending)
    }

    /// Returns the raw transport after all codec-prefetched data is handled.
    pub fn transport_mut(&mut self) -> std::io::Result<&mut TcpStream> {
        if self.pending.is_empty() {
            Ok(&mut self.stream)
        } else {
            Err(std::io::Error::other(
                "SOCKS5 prefetched data must be forwarded first",
            ))
        }
    }
}

impl AsyncRead for Bind<Ready> {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        poll_read_with_pending(&mut this.stream, &mut this.pending, cx, buf)
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
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
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

impl<S> From<Bind<S>> for (TcpStream, Bytes) {
    fn from(connection: Bind<S>) -> Self {
        (connection.stream, connection.pending)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::{Bind, Ready};

    #[tokio::test]
    async fn ready_stream_reads_prefetched_data_before_transport_data() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut client = TcpStream::connect(listener_addr).await.unwrap();
            client.write_all(b"transport").await.unwrap();
        });
        let (stream, _) = listener.accept().await.unwrap();
        let mut bind = Bind::<Ready>::new(stream, Bytes::from_static(b"prefetched-"));
        let mut received = [0; 20];

        bind.read_exact(&mut received).await.unwrap();

        assert_eq!(&received, b"prefetched-transport");
        client.await.unwrap();
    }
}
