use std::{path::PathBuf, sync::Arc};

use tokio::{
    io::ReadBuf,
    net::{TcpListener, TcpSocket},
    sync::Semaphore,
};

use super::{
    Acceptor, Context, Handle, Server, drain_connections, drain_permits,
    http::{HttpAcceptor, accept::DefaultAcceptor, tls::RustlsAcceptor},
    socks::Socks5Acceptor,
};

/// A server that automatically detects and handles multiple protocols (SOCKS5, HTTP, HTTPS).
///
/// This server listens on a single port and automatically routes incoming connections
/// to the appropriate protocol handler based on the first few bytes of the connection.
pub struct AutoDetectServer {
    listener: TcpListener,
    limit: Arc<Semaphore>,
    capacity: u32,
    acceptor: (
        Socks5Acceptor,
        HttpAcceptor<DefaultAcceptor>,
        HttpAcceptor<RustlsAcceptor>,
    ),
}

impl AutoDetectServer {
    /// Inspect the actual HTTPS branch while leaving the plaintext branches
    /// and per-connection protocol detection unchanged.
    #[cfg(feature = "management")]
    pub(super) fn certificate_leaf(&self) -> Option<&[u8]> {
        self.acceptor.2.certificate_leaf()
    }

    /// Inspect the bound socket for fixtures that request port zero.
    #[cfg(test)]
    pub(super) fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Creates a new [`AutoDetectServer`] with the given context.
    pub fn new<P>(ctx: Context, tls_cert: P, tls_key: P) -> std::io::Result<AutoDetectServer>
    where
        P: Into<Option<PathBuf>>,
    {
        Self::with_acceptor(ctx, move |http| http.with_https(tls_cert, tls_key))
    }

    /// Keep all three detection branches on their original socket/capacity,
    /// using the managed HTTPS identity already prepared before runtime start.
    #[cfg(feature = "management")]
    pub(crate) fn from_identity(
        ctx: Context,
        identity: super::tls::Identity,
    ) -> std::io::Result<Self> {
        Self::with_acceptor(ctx, move |http| http.with_identity(identity))
    }

    fn with_acceptor(
        ctx: Context,
        https: impl FnOnce(
            HttpAcceptor<DefaultAcceptor>,
        ) -> std::io::Result<HttpAcceptor<RustlsAcceptor>>,
    ) -> std::io::Result<Self> {
        let capacity = ctx.concurrent;
        let limit = super::connection_limit(ctx.concurrent)?;
        let socket = if ctx.bind.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };

        socket.set_nodelay(true)?;
        socket.set_reuseaddr(true)?;
        socket.bind(ctx.bind)?;
        socket.listen(ctx.concurrent).and_then(|listener| {
            https(HttpAcceptor::new(ctx.clone())).map(|https_acceptor| AutoDetectServer {
                listener,
                limit,
                capacity,
                acceptor: (
                    Socks5Acceptor::new(ctx.clone()),
                    HttpAcceptor::new(ctx),
                    https_acceptor,
                ),
            })
        })
    }
}

impl Server for AutoDetectServer {
    async fn start(mut self, handle: Handle) -> std::io::Result<()> {
        tracing::info!(
            "Http(s)/Socks5 proxy server listening on {}",
            self.listener.local_addr()?
        );
        let mut connections = tokio::task::JoinSet::new();

        let result = loop {
            tokio::select! {
                biased;
                _ = handle.wait_graceful_shutdown() => break Ok(()),
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = result {
                        break Err(std::io::Error::other(error));
                    }
                }
                conn = AutoDetectServer::incoming(&mut self.listener, &self.limit) => {
                    let (conn, permit) = match conn {
                        Ok(conn) => conn,
                        Err(error) => break Err(error),
                    };
                    let acceptor = self.acceptor.clone();
                    let connection_handle = handle.clone();
                    connections.spawn_on(async move {
                        // Peek the first byte to determine the protocol
                        // SOCKS5 always starts with version byte 0x05
                        // TLS/HTTPS starts with binary data (< 0x41)
                        // HTTP methods start with ASCII letters (>= 0x41: GET, POST, CONNECT, etc.)
                        let mut protocol = [0u8; 1];
                        let mut buf = ReadBuf::new(&mut protocol);
                        let peeked = tokio::select! {
                            _ = connection_handle.wait_graceful_shutdown() => return,
                            result = std::future::poll_fn(|cx| conn.0.poll_peek(cx, &mut buf)) => result,
                        };
                        if peeked.is_ok() {
                            match protocol[0] {
                                0x05 => {
                                    let _permit = permit;
                                    acceptor.0.accept(conn, connection_handle).await;
                                }
                                0x00..0x41 => acceptor.2.with_connection_permit(permit)
                                    .accept(conn, connection_handle).await,
                                _ => acceptor.1.with_connection_permit(permit)
                                    .accept(conn, connection_handle).await,
                            }
                        }
                    }, handle.runtime_handle());
                }
            }
        };
        drop(self.listener);
        if result.is_err() {
            handle.request_graceful_shutdown();
        }
        let connections = drain_connections(&mut connections, "auto", &handle).await;
        let (http, https) = tokio::join!(
            self.acceptor.1.shutdown(&handle),
            self.acceptor.2.shutdown(&handle),
        );
        let permits = drain_permits(&self.limit, self.capacity, &handle).await;
        result.and(connections).and(http).and(https).and(permits)
    }
}
