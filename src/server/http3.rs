use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use h3::server::Connection;
use h3_quinn::quinn::{self, Endpoint, ServerConfig};

use super::{
    Server,
    connect::Connector,
    context::Context,
    http::{auth::Authenticator, error::Error, genca},
};

type Certificate = Vec<u8>;
type PrivateKey = Vec<u8>;

/// HTTP/3 server using QUIC transport.
pub struct Http3Server {
    endpoint: Endpoint,
    handler: Handler,
}

impl Http3Server {
    /// Create a new [`Http3Server`] instance.
    pub async fn new<P>(ctx: Context, tls_cert: P, tls_key: P) -> std::io::Result<Http3Server>
    where
        P: Into<Option<PathBuf>>,
    {
        let bind_addr = ctx.bind;
        
        // Configure QUIC/TLS  - using quinn-proto types directly
        let (cert_chain, priv_key) = match (tls_cert.into(), tls_key.into()) {
            (Some(cert), Some(key)) => build_tls_config_from_files(cert, key)?,
            _ => {
                let (cert, key) = genca::get_self_signed_cert().map_err(io::Error::other)?;
                build_tls_config_from_pem(cert, key)?
            }
        };

        // Use the raw certificate parsing from quinn
        let mut server_crypto = rustls_0_21::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(
                cert_chain.into_iter().map(rustls_0_21::Certificate).collect(),
                rustls_0_21::PrivateKey(priv_key),
            )
            .map_err(io::Error::other)?;
        
        server_crypto.alpn_protocols = vec![b"h3".to_vec()];

        let mut server_config = ServerConfig::with_crypto(Arc::new(server_crypto));

        // Configure transport config
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(100_u8.into());
        transport_config.max_concurrent_uni_streams(100_u8.into());
        server_config.transport = Arc::new(transport_config);

        let endpoint = Endpoint::server(server_config, bind_addr)?;

        let handler = Handler::from(ctx);

        Ok(Http3Server { endpoint, handler })
    }
}

impl Server for Http3Server {
    async fn start(self) -> std::io::Result<()> {
        tracing::info!(
            "HTTP/3 proxy server listening on {}",
            self.endpoint.local_addr()?
        );

        while let Some(conn) = self.endpoint.accept().await {
            let handler = self.handler.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_connection(conn, handler).await {
                    tracing::debug!("[HTTP/3] connection error: {:?}", err);
                }
            });
        }

        Ok(())
    }
}

async fn handle_connection(
    conn: quinn::Connecting,
    handler: Handler,
) -> Result<(), Box<dyn std::error::Error>> {
    let remote_addr = conn.remote_address();
    let conn = conn.await?;
    
    tracing::debug!("[HTTP/3] new connection from {}", remote_addr);

    let mut h3_conn = Connection::new(h3_quinn::Connection::new(conn)).await?;

    loop {
        match h3_conn.accept().await {
            Ok(Some((req, mut stream))) => {
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_request(remote_addr, req, &mut stream, handler).await {
                        tracing::debug!("[HTTP/3] request error: {:?}", err);
                    }
                });
            }
            Ok(None) => break,
            Err(err) => {
                tracing::debug!("[HTTP/3] accept error: {:?}", err);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_request(
    socket: SocketAddr,
    req: Request<()>,
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    handler: Handler,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::debug!("[HTTP/3] {} {} from {}", req.method(), req.uri(), socket);

    // Check authentication
    let _extension = match handler.authenticator.authenticate(req.headers()).await {
        Ok(extension) => extension,
        Err(err) => {
            let status = match err {
                Error::ProxyAuthenticationRequired => StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                Error::Forbidden => StatusCode::FORBIDDEN,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            let resp = Response::builder().status(status).body(())?;
            stream.send_response(resp).await?;
            stream.finish().await?;
            return Ok(());
        }
    };

    // HTTP/3 doesn't support CONNECT method tunneling in the same way
    // as HTTP/1.1 and HTTP/2. For now, return method not allowed for CONNECT.
    if req.method() == Method::CONNECT {
        let resp = Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(())?;
        stream.send_response(resp).await?;
        stream.finish().await?;
        return Ok(());
    }

    // Send a simple response
    // Full request forwarding would be implemented here
    let resp = Response::builder()
        .status(StatusCode::OK)
        .body(())?;
    stream.send_response(resp).await?;
    stream.send_data(Bytes::from("HTTP/3 proxy - basic support enabled")).await?;
    stream.finish().await?;

    Ok(())
}

#[derive(Clone)]
struct Handler {
    authenticator: Arc<Authenticator>,
    #[allow(dead_code)]
    connector: Connector,
}

impl From<Context> for Handler {
    fn from(ctx: Context) -> Self {
        let authenticator = match (ctx.auth.username, ctx.auth.password) {
            (Some(username), Some(password)) => Authenticator::Password { username, password },
            _ => Authenticator::None,
        };

        Handler {
            authenticator: Arc::new(authenticator),
            connector: ctx.connector,
        }
    }
}

fn build_tls_config_from_pem(
    cert: Vec<u8>,
    key: Vec<u8>,
) -> io::Result<(Vec<Certificate>, PrivateKey)> {
    use rustls_pemfile::Item;

    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut cert.as_ref())
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|c| c.to_vec())
        .collect();

    let mut keys: Vec<Vec<u8>> = Vec::new();
    for item in rustls_pemfile::read_all(&mut key.as_ref()) {
        match item? {
            Item::Pkcs1Key(key) => keys.push(key.secret_pkcs1_der().to_vec()),
            Item::Pkcs8Key(key) => keys.push(key.secret_pkcs8_der().to_vec()),
            Item::Sec1Key(key) => keys.push(key.secret_sec1_der().to_vec()),
            _ => {}
        }
    }

    if keys.len() != 1 {
        return Err(io::Error::other("expected exactly one private key"));
    }

    Ok((certs, keys.into_iter().next().unwrap()))
}

fn build_tls_config_from_files(
    cert_path: impl AsRef<std::path::Path>,
    key_path: impl AsRef<std::path::Path>,
) -> io::Result<(Vec<Certificate>, PrivateKey)> {
    let cert = std::fs::read(cert_path)?;
    let key = std::fs::read(key_path)?;
    build_tls_config_from_pem(cert, key)
}
