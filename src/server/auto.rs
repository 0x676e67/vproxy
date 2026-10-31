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

#[cfg(all(test, feature = "management"))]
mod traffic_tests {
    use super::*;
    use crate::{
        access::{
            Reader,
            tests::{LOGIN, policy, secret},
            traffic::Protocol,
        },
        server::{Connector, auth::Source},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use tokio::{
        io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
        net::TcpStream,
    };

    async fn tunnel<S: AsyncRead + AsyncWrite + Unpin>(
        mut stream: S,
        destination: std::net::SocketAddr,
        payload: &[u8],
        reply: &[u8],
    ) {
        let token = STANDARD.encode([LOGIN.as_bytes(), b":", &secret()].concat());
        stream.write_all(format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\nProxy-Authorization: Basic {token}\r\n\r\n").as_bytes()).await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            assert!(head.len() < 8192);
            head.push(stream.read_u8().await.unwrap());
        }
        assert!(head.starts_with(b"HTTP/1.1 200"));
        stream.write_all(payload).await.unwrap();
        let mut received = vec![0; reply.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, reply);
        stream.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn auto_detected_connect_counts_proxy_transport_not_destination_or_http_framing() {
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            let reader = Reader::new(policy(1, 8)).unwrap();
            let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let leaf = certificate.cert.der().clone();
            let key = rustls_pki_types::PrivateKeyDer::Pkcs8(
                rustls_pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()),
            );
            let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).unwrap();
            let identity = super::super::tls::Identity::new(rustls::sign::CertifiedKey::new(
                vec![leaf.clone()],
                signer,
            ))
            .unwrap();
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination = origin.local_addr().unwrap();
            let server = AutoDetectServer::from_identity(
                Context {
                    auth: Source::Managed(reader.clone()),
                    bind: "127.0.0.1:0".parse().unwrap(),
                    concurrent: 8,
                    connect_timeout: 3,
                    connector: Connector::new(
                        None,
                        None,
                        None,
                        3,
                        #[cfg(any(
                            target_os = "android",
                            target_os = "fuchsia",
                            target_os = "linux"
                        ))]
                        None,
                        None,
                    ),
                },
                identity,
            )
            .unwrap();
            let proxy = server.local_addr().unwrap();
            let handle = Handle::new();
            let mut tasks = tokio::task::JoinSet::new();
            tasks.spawn(server.start(handle.clone()));
            tasks.spawn(async move {
                for (payload, reply) in [
                    (b"http".as_slice(), b"one".as_slice()),
                    (b"secure".as_slice(), b"three".as_slice()),
                ] {
                    let (mut stream, _) = origin.accept().await?;
                    let mut received = vec![0; payload.len()];
                    stream.read_exact(&mut received).await?;
                    assert_eq!(received, payload);
                    stream.write_all(reply).await?;
                    stream.shutdown().await?;
                }
                Ok(())
            });
            tunnel(
                TcpStream::connect(proxy).await.unwrap(),
                destination,
                b"http",
                b"one",
            )
            .await;
            let mut roots = rustls::RootCertStore::empty();
            roots.add(leaf).unwrap();
            let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            client.alpn_protocols = vec![b"http/1.1".to_vec()];
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
            let encrypted = connector
                .connect(
                    "localhost".try_into().unwrap(),
                    TcpStream::connect(proxy).await.unwrap(),
                )
                .await
                .unwrap();
            tunnel(encrypted, destination, b"secure", b"three").await;
            handle.request_graceful_shutdown();
            while let Some(result) = tasks.join_next().await {
                result.unwrap().unwrap();
            }
            let rows = reader.traffic_registry().snapshot().unwrap();
            for (protocol, upload, download) in [
                (Protocol::Http, 4, 3),
                (Protocol::Https, 6, 5),
                (Protocol::HttpLegacy, 0, 0),
            ] {
                let value = rows
                    .iter()
                    .find(|row| row.protocol == protocol)
                    .unwrap()
                    .value;
                assert_eq!(
                    (value.upload, value.download, value.saturated),
                    (upload, download, false)
                );
            }
        })
        .await
        .expect("auto transport accounting must finish");
    }
}
