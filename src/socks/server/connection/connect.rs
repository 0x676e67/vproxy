use crate::socks::proto::{Address, AsyncStreamOperation, Reply, Response};
use std::{
    io::IoSlice,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, WriteHalf},
    },
};

/// Socks5 connection type `Connect`
///
/// This connection can be used as a regular async TCP stream after replying to
/// the client.
#[derive(Debug)]
pub struct Connect<S> {
    stream: TcpStream,
    _state: S,
}

impl<S: Default> Connect<S> {
    #[inline]
    pub(super) fn new(stream: TcpStream) -> Self {
        Self {
            stream,
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
    /// Reply to the client.
    #[inline]
    pub async fn reply(mut self, reply: Reply, addr: Address) -> std::io::Result<Connect<Ready>> {
        let resp = Response::new(reply, addr);
        resp.write_to_async_stream(&mut self.stream).await?;
        Ok(Connect::<Ready>::new(self.stream))
    }
}

impl Connect<Ready> {
    /// Returns the read/write half of the stream.
    #[inline]
    pub fn split(&mut self) -> (ReadHalf, WriteHalf) {
        self.stream.split()
    }

    /// Returns the owned read/write half of the stream.
    #[inline]
    pub fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        self.stream.into_split()
    }
}

impl std::ops::Deref for Connect<Ready> {
    type Target = TcpStream;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl std::ops::DerefMut for Connect<Ready> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

impl AsyncRead for Connect<Ready> {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
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

impl<S> From<Connect<S>> for TcpStream {
    #[inline]
    fn from(conn: Connect<S>) -> Self {
        conn.stream
    }
}
