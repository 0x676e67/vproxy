pub mod future;

use self::future::RustlsAcceptorFuture;
use crate::{
    http::accept::{Accept, DefaultAcceptor},
    http::server::io_other,
};
use rustls_pemfile::Item;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::time::Duration;
use std::{fmt, io, path::Path, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{rustls::ServerConfig, server::TlsStream};

/// Tls acceptor using rustls.
#[derive(Clone)]
pub struct RustlsAcceptor<A = DefaultAcceptor> {
    inner: A,
    config: RustlsConfig,
    handshake_timeout: Duration,
}

impl RustlsAcceptor {
    /// Create a new rustls acceptor.
    pub fn new(config: RustlsConfig, timeout: u64) -> Self {
        let inner = DefaultAcceptor::new();
        let handshake_timeout = Duration::from_secs(timeout);

        Self {
            inner,
            config,
            handshake_timeout,
        }
    }
}

impl<A, I> Accept<I> for RustlsAcceptor<A>
where
    A: Accept<I>,
    A::Stream: AsyncRead + AsyncWrite + Unpin,
{
    type Stream = TlsStream<A::Stream>;
    type Future = RustlsAcceptorFuture<A::Future, A::Stream>;

    fn accept(&self, stream: I) -> Self::Future {
        let inner_future = self.inner.accept(stream);
        let config = self.config.clone();

        RustlsAcceptorFuture::new(inner_future, config, self.handshake_timeout)
    }
}

impl<A> fmt::Debug for RustlsAcceptor<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RustlsAcceptor").finish()
    }
}

/// Rustls configuration.
#[derive(Clone)]
pub struct RustlsConfig {
    inner: Arc<ServerConfig>,
}

impl RustlsConfig {
    /// Get  inner `Arc<`[`ServerConfig`]`>`.
    pub fn get_inner(&self) -> Arc<ServerConfig> {
        self.inner.clone()
    }

    /// Create config from PEM formatted data.
    ///
    /// Certificate and private key must be in PEM format.
    pub fn from_pem(cert: Vec<u8>, key: Vec<u8>) -> io::Result<Self> {
        let server_config = config_from_pem(cert, key)?;
        let inner = Arc::new(server_config);

        Ok(Self { inner })
    }

    /// This helper will establish a TLS server based on strong cipher suites
    /// from a PEM-formatted certificate chain and key.
    pub fn from_pem_chain_file(chain: impl AsRef<Path>, key: impl AsRef<Path>) -> io::Result<Self> {
        let server_config = config_from_pem_chain_file(chain, key)?;
        let inner = Arc::new(server_config);

        Ok(Self { inner })
    }
}

impl fmt::Debug for RustlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RustlsConfig").finish()
    }
}

fn config_from_der(cert: Vec<Vec<u8>>, key: Vec<u8>) -> io::Result<ServerConfig> {
    let cert = cert.into_iter().map(CertificateDer::from).collect();
    let key = PrivateKeyDer::try_from(key).map_err(io_other)?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .map_err(io_other)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(config)
}

fn config_from_pem(cert: Vec<u8>, key: Vec<u8>) -> io::Result<ServerConfig> {
    let cert = rustls_pemfile::certs(&mut cert.as_ref())
        .map(|it| it.map(|it| it.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    // Check the entire PEM file for the key in case it is not first section
    let mut key_vec: Vec<Vec<u8>> = rustls_pemfile::read_all(&mut key.as_ref())
        .filter_map(|i| match i.ok()? {
            Item::Sec1Key(key) => Some(key.secret_sec1_der().to_vec()),
            Item::Pkcs1Key(key) => Some(key.secret_pkcs1_der().to_vec()),
            Item::Pkcs8Key(key) => Some(key.secret_pkcs8_der().to_vec()),
            _ => None,
        })
        .collect();

    // Make sure file contains only one key
    if key_vec.len() != 1 {
        return Err(io_other("private key format not supported"));
    }

    config_from_der(cert, key_vec.pop().unwrap())
}

fn config_from_pem_chain_file(
    cert: impl AsRef<Path>,
    chain: impl AsRef<Path>,
) -> io::Result<ServerConfig> {
    let cert = std::fs::read(cert.as_ref())?;
    let cert = rustls_pemfile::certs(&mut cert.as_ref())
        .map(|it| it.map(|it| CertificateDer::from(it.to_vec())))
        .collect::<Result<Vec<_>, _>>()?;
    let key = std::fs::read(chain.as_ref())?;
    let key_cert: PrivateKeyDer = match rustls_pemfile::read_one(&mut key.as_ref())?
        .ok_or_else(|| io_other("could not parse pem file"))?
    {
        Item::Pkcs8Key(key) => Ok(key.into()),
        Item::Sec1Key(key) => Ok(key.into()),
        Item::Pkcs1Key(key) => Ok(key.into()),
        x => Err(io_other(format!(
            "invalid certificate format, received: {x:?}"
        ))),
    }?;

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, key_cert)
        .map_err(|_| io_other("invalid certificate"))
}
