pub mod future;

use std::{io, io::Error, path::Path, sync::Arc, time::Duration};

use rustls_pemfile::Item;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{rustls::ServerConfig, server::TlsStream};

use self::future::RustlsAcceptorFuture;
use super::accept::{Accept, DefaultAcceptor};

/// Tls acceptor using rustls.
#[derive(Clone)]
pub struct RustlsAcceptor<A = DefaultAcceptor> {
    inner: A,
    config: RustlsConfig,
    handshake_timeout: Duration,
}

impl RustlsAcceptor {
    /// Create a new rustls acceptor.
    pub fn new(config: RustlsConfig, handshake_timeout: Duration) -> Self {
        let inner = DefaultAcceptor::new();
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

/// Rustls configuration.
#[derive(Clone)]
pub struct RustlsConfig {
    inner: Arc<LoadedConfig>,
}

/// Public metadata belongs to the same immutable owner as the installed
/// configuration. Acceptor clones still increment only their existing Arc;
/// collecting an identity never creates another per-connection metadata lease.
struct LoadedConfig {
    config: Arc<ServerConfig>,
    #[cfg(feature = "management")]
    leaf: Option<CertificateDer<'static>>,
}

impl RustlsConfig {
    /// Construct HTTP TLS from the exact prepared signer. This is the same
    /// protocol policy as file-based HTTPS; no original path is consulted.
    #[cfg(feature = "management")]
    pub(crate) fn from_identity(identity: crate::server::tls::Identity) -> io::Result<Self> {
        let leaf = identity.leaf().cloned();
        let mut config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(Error::other)?
        .with_no_client_auth()
        .with_cert_resolver(identity.resolver());
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            inner: Arc::new(LoadedConfig {
                config: Arc::new(config),
                leaf,
            }),
        })
    }

    /// Get  inner `Arc<`[`ServerConfig`]`>`.
    pub fn get_inner(&self) -> Arc<ServerConfig> {
        self.inner.config.clone()
    }

    /// Borrow the leaf from the chain that successfully constructed this exact
    /// TLS configuration, not from a subsequent read of its original PEM path.
    #[cfg(feature = "management")]
    fn certificate_leaf(&self) -> Option<&[u8]> {
        self.inner.leaf.as_ref().map(|leaf| leaf.as_ref())
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

fn config_from_der(cert: Vec<Vec<u8>>, key: Vec<u8>) -> io::Result<LoadedConfig> {
    let cert = cert
        .into_iter()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    #[cfg(feature = "management")]
    let leaf = cert.first().cloned();
    let key = PrivateKeyDer::try_from(key).map_err(Error::other)?;

    let mut config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(Error::other)?
    .with_no_client_auth()
    .with_single_cert(cert, key)
    .map_err(Error::other)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(LoadedConfig {
        config: Arc::new(config),
        #[cfg(feature = "management")]
        leaf,
    })
}

fn config_from_pem(cert: Vec<u8>, key: Vec<u8>) -> io::Result<LoadedConfig> {
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
        return Err(Error::other("private key format not supported"));
    }

    config_from_der(cert, key_vec.pop().unwrap())
}

fn config_from_pem_chain_file(
    cert: impl AsRef<Path>,
    chain: impl AsRef<Path>,
) -> io::Result<LoadedConfig> {
    let cert = std::fs::read(cert.as_ref())?;
    let cert = rustls_pemfile::certs(&mut cert.as_ref())
        .map(|it| it.map(|it| CertificateDer::from(it.to_vec())))
        .collect::<Result<Vec<_>, _>>()?;
    #[cfg(feature = "management")]
    let leaf = cert.first().cloned();
    let key = std::fs::read(chain.as_ref())?;
    let key_cert: PrivateKeyDer = match rustls_pemfile::read_one(&mut key.as_ref())?
        .ok_or_else(|| Error::other("could not parse pem file"))?
    {
        Item::Pkcs8Key(key) => Ok(key.into()),
        Item::Sec1Key(key) => Ok(key.into()),
        Item::Pkcs1Key(key) => Ok(key.into()),
        x => Err(Error::other(format!(
            "invalid certificate format, received: {x:?}"
        ))),
    }?;

    let mut config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(Error::other)?
    .with_no_client_auth()
    .with_single_cert(cert, key_cert)
    .map_err(|_| Error::other("invalid certificate"))?;

    // File and in-memory identities serve the same HTTP versions. HTTPS H2
    // requires ALPN, not an unnegotiated client preface (RFC 9113 section 3.2).
    // https://www.rfc-editor.org/rfc/rfc9113.html#section-3.2
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(LoadedConfig {
        config: Arc::new(config),
        #[cfg(feature = "management")]
        leaf,
    })
}

#[cfg(feature = "management")]
impl<A> RustlsAcceptor<A> {
    /// Cold inspection only; handshake futures continue using `get_inner`.
    pub(super) fn certificate_leaf(&self) -> Option<&[u8]> {
        self.config.certificate_leaf()
    }
}

#[cfg(all(test, feature = "management"))]
mod tests {
    use super::*;

    #[test]
    fn in_memory_identity_capture_uses_the_installed_chain_without_changing_alpn() -> io::Result<()>
    {
        let identity =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(Error::other)?;
        let config = RustlsConfig::from_pem(
            identity.cert.pem().into_bytes(),
            identity.signing_key.serialize_pem().into_bytes(),
        )?;
        assert_eq!(
            config.certificate_leaf(),
            Some(identity.cert.der().as_ref())
        );
        assert_eq!(
            config.get_inner().alpn_protocols,
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert!(
            RustlsConfig::from_pem(
                identity.cert.pem().into_bytes(),
                b"not a private key".to_vec()
            )
            .is_err()
        );
        Ok(())
    }
}
