use std::{
    net::SocketAddr,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpStream, ToSocketAddrs, UdpSocket},
};

use crate::proxy::socks5::proto::{
    Address, AsyncStreamOperation, Reply, Response, StreamOperation, UdpHeader,
};

/// Socks5 connection type `UdpAssociate`
#[derive(Debug)]
pub struct UdpAssociate<S> {
    stream: TcpStream,
    _state: S,
}

impl<S: Default> UdpAssociate<S> {
    #[inline]
    pub(super) fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            _state: S::default(),
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
    ) -> std::io::Result<UdpAssociate<Ready>> {
        let resp = Response::new(reply, addr);
        resp.write_to_async_stream(&mut self.stream).await?;
        Ok(UdpAssociate::<Ready>::new(self.stream))
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
    /// option.
    ///
    /// For more information about this option, see
    /// [set_linger](https://docs.rs/socks5-impl/latest/socks5_impl/server/connection/struct.Connect.html#method.set_linger).
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
    /// [set_nodelay](https://docs.rs/socks5-impl/latest/socks5_impl/server/connection/struct.Connect.html#method.set_nodelay).
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
    /// [set_ttl](https://docs.rs/socks5-impl/latest/socks5_impl/server/connection/struct.Connect.html#method.set_ttl).
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

#[derive(Debug, Default)]
pub struct NeedReply;

#[derive(Debug, Default)]
pub struct Ready;

impl UdpAssociate<Ready> {
    /// Wait until the client closes this TCP connection.
    ///
    /// Socks5 protocol defines that when the client closes the TCP connection
    /// used to send the associate command, the server should release the
    /// associated UDP socket.
    pub async fn wait_until_closed(&mut self) -> std::io::Result<()> {
        loop {
            match self.stream.read(&mut [0]).await {
                Ok(0) => break Ok(()),
                Ok(_) => {}
                Err(err) => break Err(err),
            }
        }
    }
}

impl std::ops::Deref for UdpAssociate<Ready> {
    type Target = TcpStream;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl std::ops::DerefMut for UdpAssociate<Ready> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

impl AsyncRead for UdpAssociate<Ready> {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for UdpAssociate<Ready> {
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

impl<S> From<UdpAssociate<S>> for TcpStream {
    #[inline]
    fn from(conn: UdpAssociate<S>) -> Self {
        conn.stream
    }
}

/// This is a helper for managing the associated UDP socket.
///
/// It will add the socks5 UDP header to every UDP packet it sends, also try to
/// parse the socks5 UDP header from any UDP packet received.
///
/// The receiving buffer size for each UDP packet can be set with
/// [`set_recv_buffer_size()`](#method.set_recv_buffer_size), and be read with
/// [`get_max_packet_size()`](#method.get_recv_buffer_size).
///
/// You can create this struct by using
/// [`AssociatedUdpSocket::from::<(UdpSocket,
/// usize)>()`](#impl-From<UdpSocket>), the first element of the tuple is the
/// UDP socket, the second element is the receiving buffer size.
///
/// This struct can also be revert into a raw tokio UDP socket with
/// [`UdpSocket::from::<AssociatedUdpSocket>()`](#
/// impl-From<AssociatedUdpSocket>).
///
/// [`AssociatedUdpSocket`](https://docs.rs/socks5-impl/latest/socks5_impl/server/connection/associate/struct.AssociatedUdpSocket.html)
/// can be used as the associated UDP socket.
#[derive(Debug)]
pub struct AssociatedUdpSocket {
    socket: UdpSocket,
    buf_size: AtomicUsize,
}

impl AssociatedUdpSocket {
    /// Connects the UDP socket setting the default destination for send() and
    /// limiting packets that are read via recv from the address specified in
    /// addr.
    #[inline]
    pub async fn connect<A: ToSocketAddrs>(&self, addr: A) -> std::io::Result<()> {
        self.socket.connect(addr).await
    }

    /// Get the maximum UDP packet size, with socks5 UDP header included.
    pub fn get_max_packet_size(&self) -> usize {
        self.buf_size.load(Ordering::Relaxed)
    }

    /// Set the maximum UDP packet size, with socks5 UDP header included, for
    /// adjusting the receiving buffer size.
    pub fn set_max_packet_size(&self, size: usize) {
        self.buf_size.store(size, Ordering::Release);
    }

    /// Receives a socks5 UDP relay packet on the socket from the remote address
    /// to which it is connected. On success, returns the packet itself, the
    /// fragment number and the remote target address.
    ///
    /// The [`connect`](#method.connect) method will connect this socket to a
    /// remote address. This method will fail if the socket is not
    /// connected.
    pub async fn recv(&self) -> std::io::Result<(Bytes, u8, Address)> {
        loop {
            let max_packet_size = self.buf_size.load(Ordering::Acquire);
            let mut buf = vec![0; max_packet_size];
            let len = self.socket.recv(&mut buf).await?;
            buf.truncate(len);
            let pkt = Bytes::from(buf);

            if let Ok(header) = UdpHeader::retrieve_from_async_stream(&mut pkt.as_ref()).await {
                let pkt = pkt.slice(header.len()..);
                return Ok((pkt, header.frag, header.address));
            }
        }
    }

    /// Receives a socks5 UDP relay packet on the socket from the any remote
    /// address. On success, returns the packet itself, the fragment number,
    /// the remote target address and the source address.
    pub async fn recv_from(&self) -> std::io::Result<(Bytes, u8, Address, SocketAddr)> {
        loop {
            let max_packet_size = self.buf_size.load(Ordering::Acquire);
            let mut buf = vec![0; max_packet_size];
            let (len, src_addr) = self.socket.recv_from(&mut buf).await?;
            buf.truncate(len);
            let pkt = Bytes::from(buf);

            if let Ok(header) = UdpHeader::retrieve_from_async_stream(&mut pkt.as_ref()).await {
                let pkt = pkt.slice(header.len()..);
                return Ok((pkt, header.frag, header.address, src_addr));
            }
        }
    }

    /// Sends a UDP relay packet to the remote address to which it is connected.
    /// The socks5 UDP header will be added to the packet.
    pub async fn send<P: AsRef<[u8]>>(
        &self,
        pkt: P,
        frag: u8,
        from_addr: Address,
    ) -> std::io::Result<usize> {
        let header = UdpHeader::new(frag, from_addr);
        let mut buf = BytesMut::with_capacity(header.len() + pkt.as_ref().len());
        header.write_to_buf(&mut buf);
        buf.extend_from_slice(pkt.as_ref());

        self.socket.send(&buf).await.map(|len| len - header.len())
    }

    /// Sends a UDP relay packet to a specified remote address to which it is
    /// connected. The socks5 UDP header will be added to the packet.
    pub async fn send_to<P: AsRef<[u8]>>(
        &self,
        pkt: P,
        frag: u8,
        from_addr: Address,
        to_addr: SocketAddr,
    ) -> std::io::Result<usize> {
        let header = UdpHeader::new(frag, from_addr);
        let mut buf = BytesMut::with_capacity(header.len() + pkt.as_ref().len());
        header.write_to_buf(&mut buf);
        buf.extend_from_slice(pkt.as_ref());

        self.socket
            .send_to(&buf, to_addr)
            .await
            .map(|len| len - header.len())
    }
}

impl From<(UdpSocket, usize)> for AssociatedUdpSocket {
    #[inline]
    fn from(from: (UdpSocket, usize)) -> Self {
        AssociatedUdpSocket {
            socket: from.0,
            buf_size: AtomicUsize::new(from.1),
        }
    }
}

impl From<AssociatedUdpSocket> for UdpSocket {
    #[inline]
    fn from(from: AssociatedUdpSocket) -> Self {
        from.socket
    }
}

impl AsRef<UdpSocket> for AssociatedUdpSocket {
    #[inline]
    fn as_ref(&self) -> &UdpSocket {
        &self.socket
    }
}

impl AsMut<UdpSocket> for AssociatedUdpSocket {
    #[inline]
    fn as_mut(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }
}
