//! Cold listener identity selection. Legacy listeners load paths at bind time;
//! managed listeners move the already checked signer into their TLS resolver.

use std::path::PathBuf;

/// Files and a loaded identity are exclusive: a managed listener never falls
/// back to a mutable path or a generated certificate after preparation.
pub(crate) enum Source {
    Files {
        certificate: Option<PathBuf>,
        key: Option<PathBuf>,
    },
    #[cfg(feature = "management")]
    Identity(Identity),
}

/// An owned, matching chain/signer, without Debug or retained PEM bytes. TLS
/// versions, ALPN and transport policy are still chosen by each protocol.
#[cfg(feature = "management")]
#[derive(Clone)]
pub(crate) struct Identity {
    resolver: std::sync::Arc<dyn rustls::server::ResolvesServerCert>,
    leaf: Option<rustls_pki_types::CertificateDer<'static>>,
}

#[cfg(feature = "management")]
impl Identity {
    /// Check the exact signer before handing it to a resolver. Filesystem,
    /// byte bounds and private-key permissions belong to the owning loader.
    pub(crate) fn new(key: rustls::sign::CertifiedKey) -> std::io::Result<Self> {
        Self::shared(std::sync::Arc::new(key))
    }

    /// Share one already-loaded signer without duplicating its certificate
    /// chain. Matching is still checked here; protocol TLS policy stays local.
    pub(crate) fn shared(key: std::sync::Arc<rustls::sign::CertifiedKey>) -> std::io::Result<Self> {
        key.keys_match().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "proxy TLS certificate and private key do not match",
            )
        })?;
        Ok(Self {
            leaf: key.cert.first().cloned(),
            resolver: std::sync::Arc::new(rustls::sign::SingleCertAndKey::from(key)),
        })
    }

    /// A renewable owner supplies its normal-only resolver and the actual leaf
    /// captured with it. This constructor grants no trust or issuance authority;
    /// the owning loader must validate each publication and never select an
    /// ACME challenge identity. The captured leaf is bind-time metadata only.
    pub(crate) fn renewable(
        resolver: std::sync::Arc<dyn rustls::server::ResolvesServerCert>,
        leaf: rustls_pki_types::CertificateDer<'static>,
    ) -> Self {
        Self {
            resolver,
            leaf: Some(leaf),
        }
    }

    pub(crate) fn leaf(&self) -> Option<&rustls_pki_types::CertificateDer<'static>> {
        self.leaf.as_ref()
    }

    /// Transfer the selected fixed/normal-only resolver to the protocol's TLS
    /// configuration; no path lookup or PEM parse enters a handshake.
    pub(crate) fn resolver(self) -> std::sync::Arc<dyn rustls::server::ResolvesServerCert> {
        self.resolver
    }
}
