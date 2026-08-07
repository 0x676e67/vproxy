use std::{
    io::IoSlice,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};

use super::{
    poll_read_with_pending,
    proto::{Address, Reply, ServerFrame, write_server_frame},
    reject_request,
};

/// Socks5 connection type `Connect`
///
/// This connection can be used as a regular async TCP stream after replying to
/// the client.
#[derive(Debug)]
pub struct Connect<S> {
    stream: TcpStream,
    pending: Bytes,
    _state: S,
}

impl<S: Default> Connect<S> {
    #[inline]
    pub(super) fn new(stream: TcpStream, pending: Bytes) -> Self {
        Self {
            stream,
            pending,
            _state: S::default(),
        }
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
}

#[derive(Debug, Default)]
pub struct NeedReply;

#[derive(Debug, Default)]
pub struct Ready;

impl Connect<NeedReply> {
    /// Sends a successful CONNECT reply and enables the data stream.
    #[inline]
    pub async fn succeed(mut self, addr: Address) -> std::io::Result<Connect<Ready>> {
        write_server_frame(&mut self.stream, ServerFrame::Reply(Reply::Succeeded, addr)).await?;
        Ok(Connect::<Ready>::new(self.stream, self.pending))
    }

    /// Sends a failed CONNECT reply and closes the control connection.
    #[inline]
    pub async fn reject(mut self, reply: Reply, addr: Address) -> std::io::Result<()> {
        reject_request(&mut self.stream, reply, addr).await
    }
}

impl Connect<Ready> {
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

impl AsyncRead for Connect<Ready> {
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

impl AsyncWrite for Connect<Ready> {
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

impl<S> From<Connect<S>> for (TcpStream, Bytes) {
    fn from(connection: Connect<S>) -> Self {
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

    use super::{Connect, Ready};

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
        let mut connect = Connect::<Ready>::new(stream, Bytes::from_static(b"prefetched-"));
        let mut received = [0; 20];

        connect.read_exact(&mut received).await.unwrap();

        assert_eq!(&received, b"prefetched-transport");
        client.await.unwrap();
    }
}
