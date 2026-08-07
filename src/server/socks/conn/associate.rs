use std::{
    io::IoSlice,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpStream, ToSocketAddrs, UdpSocket},
};

use super::{
    poll_read_with_pending,
    proto::{Address, Reply, ServerFrame, StreamOperation, UdpHeader, write_server_frame},
    reject_request,
};

/// Socks5 connection type `UdpAssociate`
#[derive(Debug)]
pub struct UdpAssociate<S> {
    stream: TcpStream,
    pending: Bytes,
    _state: S,
}

impl<S: Default> UdpAssociate<S> {
    #[inline]
    pub(super) fn new(stream: TcpStream, pending: Bytes) -> Self {
        Self {
            stream,
            pending,
            _state: S::default(),
        }
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

#[derive(Debug, Default)]
pub struct NeedReply;

#[derive(Debug, Default)]
pub struct Ready;

impl UdpAssociate<NeedReply> {
    /// Sends a successful UDP ASSOCIATE reply.
    pub async fn succeed(mut self, addr: Address) -> std::io::Result<UdpAssociate<Ready>> {
        write_server_frame(&mut self.stream, ServerFrame::Reply(Reply::Succeeded, addr)).await?;
        Ok(UdpAssociate::<Ready>::new(self.stream, self.pending))
    }

    /// Sends a failed UDP ASSOCIATE reply and closes the control connection.
    pub async fn reject(mut self, reply: Reply, addr: Address) -> std::io::Result<()> {
        reject_request(&mut self.stream, reply, addr).await
    }
}

impl UdpAssociate<Ready> {
    /// Wait until the client closes this TCP connection.
    ///
    /// Socks5 protocol defines that when the client closes the TCP connection
    /// used to send the associate command, the server should release the
    /// associated UDP socket.
    pub async fn wait_until_closed(&mut self, buffer: &mut [u8]) -> std::io::Result<()> {
        self.pending = Bytes::new();
        loop {
            match self.stream.read(buffer).await {
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
        let this = &mut *self;
        poll_read_with_pending(&mut this.stream, &mut this.pending, cx, buf)
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

impl<S> From<UdpAssociate<S>> for (TcpStream, Bytes) {
    fn from(connection: UdpAssociate<S>) -> Self {
        (connection.stream, connection.pending)
    }
}

/// This is a helper for managing the associated UDP socket.
///
/// It encodes and decodes the RFC 1928 UDP header. Receive methods borrow a
/// caller-provided buffer so the relay loop can reuse storage without a heap
/// allocation for every datagram.
#[derive(Debug)]
pub struct AssociatedUdpSocket {
    socket: UdpSocket,
}

impl AssociatedUdpSocket {
    #[inline]
    pub fn new(socket: UdpSocket) -> Self {
        Self { socket }
    }

    /// Connects the UDP socket setting the default destination for send() and
    /// limiting packets that are read via recv from the address specified in
    /// addr.
    #[inline]
    pub async fn connect<A: ToSocketAddrs>(&self, addr: A) -> std::io::Result<()> {
        self.socket.connect(addr).await
    }

    /// Receives a socks5 UDP relay packet on the socket from the remote address
    /// to which it is connected. On success, returns the packet itself, the
    /// fragment number and the remote target address.
    ///
    /// The [`connect`](#method.connect) method will connect this socket to a
    /// remote address. This method will fail if the socket is not
    /// connected.
    pub async fn recv<'a>(&self, buffer: &'a mut [u8]) -> std::io::Result<(&'a [u8], u8, Address)> {
        loop {
            let len = self.socket.recv(buffer).await?;
            if let Ok((header, header_len)) = UdpHeader::decode(&buffer[..len]) {
                return Ok((&buffer[header_len..len], header.frag, header.address));
            }
        }
    }

    /// Receives a socks5 UDP relay packet on the socket from the any remote
    /// address. On success, returns the packet itself, the fragment number,
    /// the remote target address and the source address.
    pub async fn recv_from<'a>(
        &self,
        buffer: &'a mut [u8],
    ) -> std::io::Result<(&'a [u8], u8, Address, SocketAddr)> {
        loop {
            let (len, src_addr) = self.socket.recv_from(buffer).await?;
            if let Ok((header, header_len)) = UdpHeader::decode(&buffer[..len]) {
                return Ok((
                    &buffer[header_len..len],
                    header.frag,
                    header.address,
                    src_addr,
                ));
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
        from_addr.validate_for_serialization()?;
        let header = UdpHeader::new(frag, from_addr);
        let capacity = header
            .len()
            .checked_add(pkt.as_ref().len())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "SOCKS5 UDP datagram length overflow",
                )
            })?;
        let mut buf = BytesMut::with_capacity(capacity);
        header.write_to_buf(&mut buf)?;
        buf.extend_from_slice(pkt.as_ref());

        self.socket
            .send(&buf)
            .await?
            .checked_sub(header.len())
            .ok_or_else(|| std::io::Error::other("UDP socket sent less than the SOCKS5 header"))
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
        let mut buffer = BytesMut::new();
        self.send_to_buffered(pkt, frag, from_addr, to_addr, &mut buffer)
            .await
    }

    /// Sends a UDP relay packet using caller-owned storage.
    ///
    /// Reusing the buffer avoids allocating for every response in the relay
    /// loop.
    pub(in crate::server::socks) async fn send_to_buffered<P: AsRef<[u8]>>(
        &self,
        pkt: P,
        frag: u8,
        from_addr: Address,
        to_addr: SocketAddr,
        buffer: &mut BytesMut,
    ) -> std::io::Result<usize> {
        from_addr.validate_for_serialization()?;
        let header = UdpHeader::new(frag, from_addr);
        let capacity = header
            .len()
            .checked_add(pkt.as_ref().len())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "SOCKS5 UDP datagram length overflow",
                )
            })?;
        buffer.clear();
        buffer.reserve(capacity);
        header.write_to_buf(buffer)?;
        buffer.extend_from_slice(pkt.as_ref());

        self.socket
            .send_to(buffer, to_addr)
            .await?
            .checked_sub(header.len())
            .ok_or_else(|| std::io::Error::other("UDP socket sent less than the SOCKS5 header"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_send_rejects_domain_longer_than_rfc1928_allows() {
        let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let socket = AssociatedUdpSocket::new(socket);

        let error = socket
            .send(
                [],
                0,
                Address::DomainAddress("a".repeat(u8::MAX as usize + 1), 53),
            )
            .await
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
