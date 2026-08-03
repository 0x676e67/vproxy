use std::path::PathBuf;

use tokio::{
    io::ReadBuf,
    net::{TcpListener, TcpSocket},
};

use super::{
    Acceptor, Context, Handle, Server, drain_connections,
    http::{HttpAcceptor, accept::DefaultAcceptor, tls::RustlsAcceptor},
    log_connection_result,
    socks::Socks5Acceptor,
};

/// A server that automatically detects and handles multiple protocols (SOCKS5, HTTP, HTTPS).
///
/// This server listens on a single port and automatically routes incoming connections
/// to the appropriate protocol handler based on the first few bytes of the connection.
pub struct AutoDetectServer {
    listener: TcpListener,
    acceptor: (
        Socks5Acceptor,
        HttpAcceptor<DefaultAcceptor>,
        HttpAcceptor<RustlsAcceptor>,
    ),
}

impl AutoDetectServer {
    /// Creates a new [`AutoDetectServer`] with the given context.
    pub fn new<P>(ctx: Context, tls_cert: P, tls_key: P) -> std::io::Result<AutoDetectServer>
    where
        P: Into<Option<PathBuf>>,
    {
        let socket = if ctx.bind.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };

        socket.set_nodelay(true)?;
        socket.set_reuseaddr(true)?;
        socket.bind(ctx.bind)?;
        socket.listen(ctx.concurrent).and_then(|listener| {
            HttpAcceptor::new(ctx.clone())
                .with_https(tls_cert, tls_key)
                .map(|https_acceptor| AutoDetectServer {
                    listener,
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

        loop {
            tokio::select! {
                _ = handle.wait_graceful_shutdown() => break,
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(result) = result {
                        log_connection_result(result, "auto");
                    }
                }
                conn = AutoDetectServer::incoming(&mut self.listener) => {
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
                                0x05 => acceptor.0.accept(conn, connection_handle).await,
                                0x00..0x41 => acceptor.2.accept(conn, connection_handle).await,
                                _ => acceptor.1.accept(conn, connection_handle).await,
                            }
                        }
                    }, &pingora_runtime::current_handle());
                }
            }
        }
        drain_connections(&mut connections, "auto").await;
        self.acceptor.1.shutdown().await;
        self.acceptor.2.shutdown().await;
        Ok(())
    }
}
