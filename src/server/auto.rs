use std::path::PathBuf;

use tokio::{
    io::ReadBuf,
    net::{TcpListener, TcpSocket},
};

use super::{
    Acceptor, Context, Server,
    http::{HTTP, HTTPS, HttpAcceptor, accept::DefaultAcceptor, tls::RustlsAcceptor},
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
        HttpAcceptor<DefaultAcceptor, HTTP>,
        HttpAcceptor<RustlsAcceptor, HTTPS>,
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
            HttpAcceptor::<DefaultAcceptor, HTTP>::new(ctx.clone())
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
    async fn start(mut self) -> std::io::Result<()> {
        tracing::info!(
            "Http(s)/Socks5 proxy server listening on {}",
            self.listener.local_addr()?
        );

        loop {
            // Accept a new connection
            let conn = AutoDetectServer::incoming(&mut self.listener).await;
            let acceptor = self.acceptor.clone();

            tokio::spawn(async move {
                // Peek the first byte to determine the protocol
                // SOCKS5 always starts with version byte 0x05
                // TLS/HTTPS starts with binary data (< 0x41)
                // HTTP methods start with ASCII letters (>= 0x41: GET, POST, CONNECT, etc.)
                let mut protocol = [0u8; 1];
                let mut buf = ReadBuf::new(&mut protocol);
                if std::future::poll_fn(|cx| conn.0.poll_peek(cx, &mut buf))
                    .await
                    .is_ok()
                {
                    match protocol[0] {
                        0x05 => {
                            // ASCII '5', assuming socks5
                            acceptor.0.accept(conn).await;
                        }
                        0x00..0x41 => {
                            // ASCII < 'A', assuming https
                            acceptor.2.accept(conn).await;
                        }
                        _ => {
                            // ASCII >= 'A', assuming http
                            acceptor.1.accept(conn).await;
                        }
                    }
                }
            });
        }
    }
}
