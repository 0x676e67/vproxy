//! Separate TLS identities for administrators and mutually authenticated nodes.
//!
//! Administrator authentication belongs to the HTTP session layer, not to TLS
//! client certificates. Nodes use a distinct mandatory-mTLS configuration and
//! explicit CA roots; successful TLS authentication still grants no permission
//! until the application matches the actual leaf DER to a current registration.

use std::{
    fs::{self, OpenOptions},
    io::{self, Read},
    path::Path,
    sync::Arc,
};

use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    client::{Resumption, verify_server_cert_signed_by_trust_anchor, verify_server_name},
    crypto::aws_lc_rs,
    server::{NoServerSessionStorage, ParsedCertificate, WebPkiClientVerifier},
    sign::{CertifiedKey, SingleCertAndKey},
};
use rustls_pemfile::Item;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const MAX_CERTIFICATE_BYTES: usize = 256 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 64 * 1024;
const MAX_LEAF_BYTES: usize = 16 * 1024;

/// Hash the RFC 5280 DER SubjectPublicKeyInfo derived from one private PEM key.
///
/// This is the same complete SPKI representation used by rustls to compare a
/// leaf certificate to its signing key, not a hash of PEM, raw key or certificate
/// bytes. Recovery uses it to bind newly issued certificates to the generated
/// key. It neither trusts a certificate nor grants permission to start a node.
/// SPKI is defined by RFC 5280 §4.1.2.7:
/// <https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.7>.
///
/// File bounds, private Unix modes, symlink rejection and Windows/ancestor ACL
/// limitations are those of [`admin_server_config`]. This synchronous cold-path
/// operation accepts exactly one unencrypted PKCS#8, PKCS#1 or SEC1 key. Missing,
/// malformed, unsupported or excessive input fails without logging key bytes;
/// PEM/decoded-key owners are zeroized, and the provider owns its signing key.
pub(super) fn node_key_sha256(private_key: &Path) -> io::Result<[u8; 32]> {
    let pem = read_bounded(private_key, MAX_PRIVATE_KEY_BYTES, true)?;
    key_pem_sha256(&pem)
}

/// Hash public SPKI from already captured bounded private-key bytes. This does
/// not reread the input path or expose the PEM/decoded secret in a diagnostic.
pub(super) fn key_pem_sha256(pem: &[u8]) -> io::Result<[u8; 32]> {
    if pem.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(invalid("private key exceeds its input limit"));
    }
    let key = private_key_der(pem)?;
    let signer = aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|_| invalid("unsupported or invalid node TLS private key"))?;
    let public_key = signer
        .public_key()
        .ok_or_else(|| invalid("node TLS key has no supported public SPKI representation"))?;
    Ok(Sha256::digest(public_key.as_ref()).into())
}

/// Loads a bounded PEM chain and its matching key for the administrator HTTPS API.
///
/// The chain must contain only certificates, leaf first. The key file must
/// supply exactly one unencrypted PKCS#8, PKCS#1 or SEC1 key. Other recognized
/// PEM items are rejected; unrecognized sections and preambles follow the
/// upstream PEM parser's skip behavior and cannot supply a signing identity.
/// All certificates are parsed and the leaf/key match is checked, but this does
/// not establish browser trust, SAN coverage, validity dates or issuer-chain
/// trust: clients must still verify the deployed identity.
///
/// Only TLS 1.3 and HTTP/1.1 are enabled. No client certificate is requested:
/// browser sessions authenticate administrators; node mTLS is a distinct entry
/// point. File I/O and parsing are synchronous and belong in startup, never on
/// a proxy worker or inside an HTTP handler. The caller bounds TLS handshakes.
///
/// Symlink leaves and non-regular files are rejected. On Unix the key must have
/// no group/other permission bits, checked on the opened descriptor; ancestors
/// must be trusted because this is not a descriptor-relative directory walk.
/// Unix modes are not an ACL audit. On Windows this checks file type but does
/// not audit inherited ACLs or prevent ancestor reparse-point replacement; the
/// operator must provision a private, trusted directory before startup.
///
/// # Errors
///
/// Returns filesystem errors, `PermissionDenied` for non-private Unix keys, or
/// `InvalidData` for excessive input, unsupported/malformed PEM or DER, an empty
/// chain, multiple keys, or a mismatched key. Errors never include PEM, DER or
/// private-key bytes. Owned input and accepted decoded-key buffers are zeroized
/// when dropped; the cryptographic provider owns the active signing key.
pub(super) fn admin_server_config(
    certificate: &Path,
    private_key: &Path,
) -> io::Result<Arc<ServerConfig>> {
    admin_identity(certificate, private_key).map(|(config, _)| config)
}

/// Load the ordinary administrator identity and derive public metadata from
/// that exact CertifiedKey before it moves into the active resolver. Monitoring
/// failure is represented by Unavailable; it adds no date, SAN or trust gate to
/// the existing manual TLS loader. Paths are read only once by this operation.
pub(super) fn admin_identity(
    certificate: &Path,
    private_key: &Path,
) -> io::Result<(Arc<ServerConfig>, super::certificates::State)> {
    configured_admin(loaded_identity(certificate, private_key)?)
}

/// Validate manual management TLS from exact captured private buffers. A fixed
/// description also checks its declared origin name before any witness write.
pub(super) fn captured_admin_identity(
    certificate: &[u8],
    private_key: &[u8],
    reference: &str,
) -> io::Result<(Arc<ServerConfig>, super::certificates::State)> {
    let identity = identity_pem(certificate, private_key)?;
    let leaf = identity
        .end_entity_cert()
        .map_err(|_| invalid("management TLS identity has no leaf"))?;
    verify_peer_name(leaf, reference)?;
    configured_admin(identity)
}

fn configured_admin(
    identity: CertifiedKey,
) -> io::Result<(Arc<ServerConfig>, super::certificates::State)> {
    configured_admin_shared(Arc::new(identity))
}

fn configured_admin_shared(
    identity: Arc<CertifiedKey>,
) -> io::Result<(Arc<ServerConfig>, super::certificates::State)> {
    let descriptor = identity
        .end_entity_cert()
        .map_or(super::certificates::State::Unavailable, |leaf| {
            super::certificates::State::from_leaf(leaf.as_ref())
        });
    let mut config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| invalid("cannot configure management TLS 1.3"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(identity)));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.max_early_data_size = 0;
    Ok((Arc::new(config), descriptor))
}

/// Load manual management/proxy identities once from the same bounded inputs.
/// Sharing the signer does not share TLS versions, ALPN or client permissions.
pub(super) fn admin_proxy_identity(
    certificate: &Path,
    private_key: &Path,
) -> io::Result<(
    Arc<ServerConfig>,
    super::certificates::State,
    crate::server::tls::Identity,
)> {
    let key = Arc::new(loaded_identity(certificate, private_key)?);
    let proxy = crate::server::tls::Identity::shared(key.clone())?;
    let (config, state) = configured_admin_shared(key)?;
    Ok((config, state, proxy))
}

/// Prepare a managed proxy's actual chain/signer, using the same bounded,
/// zeroizing private-file loader as administrator TLS, but no admin TLS policy.
/// The listener takes this owner; later path replacement cannot select a new key.
pub(super) fn proxy_identity(
    certificate: &Path,
    private_key: &Path,
) -> io::Result<crate::server::tls::Identity> {
    crate::server::tls::Identity::new(loaded_identity(certificate, private_key)?)
}

fn loaded_identity(certificate: &Path, private_key: &Path) -> io::Result<CertifiedKey> {
    let certificate_pem = read_bounded(certificate, MAX_CERTIFICATE_BYTES, false)?;
    let private_key_pem = read_bounded(private_key, MAX_PRIVATE_KEY_BYTES, true)?;
    identity_pem(&certificate_pem, &private_key_pem)
}

/// Prepare a proxy signer from the same bounded bytes owned by a configuration
/// capture. The caller validates private-file provenance; this never reopens it.
pub(super) fn captured_proxy_identity(
    certificate: &[u8],
    private_key: &[u8],
) -> io::Result<crate::server::tls::Identity> {
    crate::server::tls::Identity::new(identity_pem(certificate, private_key)?)
}

fn identity_pem(certificate: &[u8], private_key: &[u8]) -> io::Result<CertifiedKey> {
    if certificate.len() > MAX_CERTIFICATE_BYTES || private_key.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(invalid("captured TLS material exceeds its bounds"));
    }
    let chain = certificates(certificate)?;
    let key = private_key_der(private_key)?;

    // The borrowed-key API avoids an extra owned DER copy whose lifetime would
    // otherwise be hidden by `with_single_cert`. The active signer necessarily
    // retains the key in the provider's representation for future handshakes.
    let signer = aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|_| invalid("unsupported or invalid management TLS private key"))?;
    let identity = CertifiedKey::new(chain, signer);
    identity
        .keys_match()
        .map_err(|_| invalid("management TLS certificate and private key do not match"))?;
    Ok(identity)
}

/// Build an ordinary management HTTPS client using only this explicit CA bundle.
///
/// This trust domain is separate from node mTLS: no local node certificate,
/// private key, registration, ownership state or database is loaded. Normal
/// WebPKI chain/time/server-name verification still applies, using the reference
/// name from the configured management origin when connecting. There is no
/// system-root or insecure fallback. The caller must check negotiated ALPN and
/// bound DNS/connect/handshake/HTTP waits.
///
/// CA loading is synchronous startup work with the same bounded regular-file
/// and trusted-ancestor rules as the server loaders. Resumption and early data
/// are disabled; each new connection uses TLS 1.3 and advertises HTTP/1.1 only.
pub(super) fn admin_client_config(ca: &Path) -> io::Result<Arc<ClientConfig>> {
    let roots = root_store(ca)
        .map_err(|error| io::Error::new(error.kind(), "cannot load management API CA bundle"))?;
    let mut config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| invalid("cannot configure management API client TLS 1.3"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

/// Loads the separate node listener identity and only explicitly configured CA
/// roots. Client certificates are mandatory; normal WebPKI verification checks
/// their chain, time and client-auth usage, not their application registration.
/// The local identity must satisfy the dual-use node profile and chain to these
/// roots at startup. Its public endpoint name is checked separately by callers.
///
/// Only TLS 1.3/HTTP/1.1 is advertised; callers must also check negotiated ALPN
/// after the handshake, since an omitted client ALPN can otherwise succeed.
/// Tickets, stateful resumption, 0-RTT and half-RTT application data are disabled.
/// https://www.rfc-editor.org/rfc/rfc8446.html#section-2.3
///
/// File I/O is synchronous startup work. PEM, key privacy, trusted ancestors and
/// Windows ACL limitations are the same as [`admin_server_config`]. Errors do
/// not expose certificate/key bytes. This is not the browser authentication domain.
#[cfg(test)]
pub(super) fn node_server_config(
    ca: &Path,
    certificate: &Path,
    private_key: &Path,
) -> io::Result<Arc<ServerConfig>> {
    node_identity(ca, certificate, private_key)?.server_config()
}

/// A single validated in-memory node chain/key shared by both TLS roles.
///
/// Name checks and the recovery SPKI pin apply to this actual signing identity,
/// not a second filesystem read that could differ from the active resolver.
/// Cloning shares immutable roots/signer and copies public metadata; it does
/// not reload paths, reauthorize a peer or grant an independent runtime lease.
#[derive(Clone)]
pub(super) struct NodeIdentity {
    roots: Arc<RootCertStore>,
    identity: Arc<CertifiedKey>,
    certificate: super::certificates::State,
}

impl NodeIdentity {
    /// Public metadata of the exact once-loaded identity shared by the server
    /// and client resolvers. No path or private key is re-read for monitoring.
    pub(super) fn certificate(&self) -> super::certificates::State {
        self.certificate.clone()
    }

    /// Hash this resolver's SPKI. keys_match has already compared it byte-for-byte
    /// to the actual leaf certificate's RFC 5280 §4.1.2.7 SubjectPublicKeyInfo.
    pub(super) fn key_sha256(&self) -> io::Result<[u8; 32]> {
        let public_key =
            self.identity.key.public_key().ok_or_else(|| {
                invalid("node TLS key has no supported public SPKI representation")
            })?;
        Ok(Sha256::digest(public_key.as_ref()).into())
    }

    /// Check a locally configured endpoint name against the already-loaded leaf.
    /// Chain, time, dual usage and key matching were validated during loading.
    pub(super) fn verify_name(&self, reference: &str) -> io::Result<()> {
        let leaf = self
            .identity
            .end_entity_cert()
            .map_err(|_| invalid("node TLS identity has no leaf certificate"))?;
        verify_peer_name(leaf, reference)
    }

    /// Build the mandatory-mTLS server using this exact identity and CA roots.
    pub(super) fn server_config(&self) -> io::Result<Arc<ServerConfig>> {
        let provider = Arc::new(aws_lc_rs::default_provider());
        let verifier =
            WebPkiClientVerifier::builder_with_provider(self.roots.clone(), provider.clone())
                .build()
                .map_err(|_| {
                    invalid("cannot configure mandatory node TLS client authentication")
                })?;
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| invalid("cannot configure node TLS 1.3"))?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(self.identity.clone())));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        config.send_half_rtt_data = false;
        // The builder's stateless ticketer is disabled by default; do not replace it
        // with a ticket producer when every connection must revalidate credentials.
        Ok(Arc::new(config))
    }

    /// Build the outbound node client using the same loaded chain/key and roots.
    pub(super) fn client_config(&self) -> io::Result<Arc<ClientConfig>> {
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| invalid("cannot configure node TLS 1.3"))?
                .with_root_certificates(self.roots.clone())
                .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(self.identity.clone())));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.resumption = Resumption::disabled();
        config.enable_early_data = false;
        Ok(Arc::new(config))
    }
}

/// Loads a node client identity with fixed CA trust, mandatory normal server
/// certificate/name verification, TLS 1.3 and HTTP/1.1. The reference name passed
/// to the TLS connector must come from local trusted endpoint configuration.
/// Verify the registered leaf DER and negotiated ALPN before sending HTTP data.
///
/// The local certificate follows the same explicit dual-use profile as the node
/// server. Resumption and early data are disabled so each new connection performs
/// a fresh authenticated handshake. Loading/error/privacy rules match the node
/// server configuration; no system-root or insecure fallback is provided.
#[cfg(test)]
pub(super) fn node_client_config(
    ca: &Path,
    certificate: &Path,
    private_key: &Path,
) -> io::Result<Arc<ClientConfig>> {
    node_identity(ca, certificate, private_key)?.client_config()
}

/// Imports a leaf-first PEM chain for offline registration, returning only its
/// exact bounded leaf DER. All chain elements must parse; the leaf must satisfy
/// the explicit node profile, both normal TLS usages, current validity and the
/// operator-supplied SAN, chaining to the explicit CA bundle. It does not prove
/// possession of the peer's private key or grant/store authorization.
///
/// Call in bounded blocking/startup work, not on an async worker. A mismatched
/// name, unsupported identity, invalid chain or excessive leaf returns InvalidData;
/// an invalid reference name returns InvalidInput. No input is logged.
pub(super) fn load_peer_certificate(
    ca: &Path,
    certificate: &Path,
    expected_san: &str,
) -> io::Result<Vec<u8>> {
    let roots = root_store(ca)?;
    let pem = read_bounded(certificate, MAX_CERTIFICATE_BYTES, false)?;
    let chain = certificates(&pem)?;
    verify_node_chain(&chain, &roots)?;
    let leaf = checked_leaf(Some(&chain))?;
    verify_peer_name(&leaf, expected_san)?;
    Ok(leaf)
}

/// Reads the exact bounded leaf DER without trusting it. Intended for identifying
/// a previously registered certificate during permanent revocation, including an
/// expired or now-untrusted one. The bounded leaf-first PEM chain must parse, but
/// no chain, validity, name or usage check is performed and no permission is granted.
/// Registration must use [`load_peer_certificate`] instead. File I/O is blocking.
pub(super) fn read_certificate_leaf(certificate: &Path) -> io::Result<Vec<u8>> {
    let pem = read_bounded(certificate, MAX_CERTIFICATE_BYTES, false)?;
    let chain = certificates(&pem)?;
    checked_leaf(Some(&chain))
}

/// Applies an additional registered SAN constraint to a bounded leaf certificate.
/// This only checks naming: it must follow normal TLS chain/time/usage verification
/// (or offline registration verification), never replace it. Client-certificate
/// SAN checking is this project's added identity policy, not general TLS client
/// authentication behavior. The reference must come from local registration.
/// https://www.rfc-editor.org/rfc/rfc9525.html#section-1.4.2
pub(super) fn verify_peer_name(der: &[u8], expected_san: &str) -> io::Result<()> {
    if der.is_empty() || der.len() > MAX_LEAF_BYTES {
        return Err(invalid("node TLS leaf certificate exceeds its bounds"));
    }
    let name = ServerName::try_from(expected_san).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid node TLS reference name",
        )
    })?;
    let der = CertificateDer::from(der);
    let parsed = ParsedCertificate::try_from(&der)
        .map_err(|_| invalid("invalid node TLS leaf certificate"))?;
    verify_server_name(&parsed, &name)
        .map_err(|_| invalid("node TLS certificate does not match its registered name"))
}

/// Copies only the authenticated handshake's leaf, bounded to the database's
/// 16-KiB identity limit. Missing/empty/oversized input fails closed. This helper
/// neither verifies a chain nor establishes authorization: callers must use it
/// only after a successful TLS handshake and still query current registration.
pub(super) fn checked_leaf(chain: Option<&[CertificateDer<'_>]>) -> io::Result<Vec<u8>> {
    let leaf = chain
        .and_then(|chain| chain.first())
        .ok_or_else(|| invalid("node TLS peer certificate is missing"))?;
    if leaf.is_empty() || leaf.len() > MAX_LEAF_BYTES {
        return Err(invalid("node TLS leaf certificate exceeds its bounds"));
    }
    Ok(leaf.as_ref().to_vec())
}

/// Load one bounded node identity, validating explicit roots, both certificate
/// usages, current validity and the exact DER SPKI leaf/key match.
///
/// No path is re-read by the returned identity's TLS builders. Caller-selected
/// endpoint SAN and recovery-pin checks must use that returned identity, not a
/// separately parsed certificate. Private-file/ancestor/Windows limitations and
/// zeroization follow [`admin_server_config`]; errors never expose input bytes.
pub(super) fn node_identity(
    ca: &Path,
    certificate: &Path,
    private_key: &Path,
) -> io::Result<NodeIdentity> {
    node_identity_at(ca, certificate, private_key, UnixTime::now())
}

/// Check a historical archive at its recorded capture time and return only
/// public SPKI. No TLS client/server configuration escapes this path; live
/// construction always uses the current clock through node_identity.
pub(super) fn archived_node_identity(
    ca: &Path,
    certificate: &Path,
    private_key: &Path,
    reference: &str,
    captured_unix_s: u64,
) -> io::Result<[u8; 32]> {
    let identity = node_identity_at(
        ca,
        certificate,
        private_key,
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(captured_unix_s)),
    )?;
    identity.verify_name(reference)?;
    identity.key_sha256()
}

fn node_identity_at(
    ca: &Path,
    certificate: &Path,
    private_key: &Path,
    now: UnixTime,
) -> io::Result<NodeIdentity> {
    let roots = root_store(ca)?;
    let certificate_pem = read_bounded(certificate, MAX_CERTIFICATE_BYTES, false)?;
    let chain = certificates(&certificate_pem)?;
    verify_node_chain_at(&chain, &roots, now)?;
    let key_pem = read_bounded(private_key, MAX_PRIVATE_KEY_BYTES, true)?;
    complete_node_identity(roots, chain, &key_pem)
}

/// Use the exact bounded captured bytes for a live witness client, not a second
/// read of mutable source paths. Current validity/dual EKU/key matching remain
/// identical to node_identity; archived-time validation never grants a client.
pub(super) fn captured_node_identity(
    ca: &[u8],
    certificate: &[u8],
    private_key: &[u8],
) -> io::Result<NodeIdentity> {
    if ca.len() > MAX_CERTIFICATE_BYTES
        || certificate.len() > MAX_CERTIFICATE_BYTES
        || private_key.len() > MAX_PRIVATE_KEY_BYTES
    {
        return Err(invalid("captured node TLS material exceeds its bounds"));
    }
    let roots = root_store_pem(ca)?;
    let chain = certificates(certificate)?;
    verify_node_chain(&chain, &roots)?;
    complete_node_identity(roots, chain, private_key)
}

fn complete_node_identity(
    roots: Arc<RootCertStore>,
    chain: Vec<CertificateDer<'static>>,
    key_pem: &[u8],
) -> io::Result<NodeIdentity> {
    let key = private_key_der(key_pem)?;
    let signer = aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|_| invalid("unsupported or invalid node TLS private key"))?;
    let identity = CertifiedKey::new(chain, signer);
    identity
        .keys_match()
        .map_err(|_| invalid("node TLS certificate and private key do not match"))?;
    let certificate = identity
        .end_entity_cert()
        .map_or(super::certificates::State::Unavailable, |leaf| {
            super::certificates::State::from_leaf(leaf.as_ref())
        });
    Ok(NodeIdentity {
        roots,
        identity: Arc::new(identity),
        certificate,
    })
}

/// Root trust is an explicit operator decision, never inferred from the peer's
/// transmitted chain. Require CA basic constraints instead of accepting a leaf
/// as an unrestricted root; PKIX does not require checking a trust anchor's own
/// signature or expiry. Its directory follows the trusted-ancestor file policy.
fn root_store(ca: &Path) -> io::Result<Arc<RootCertStore>> {
    let pem = read_bounded(ca, MAX_CERTIFICATE_BYTES, false)?;
    root_store_pem(&pem)
}

fn root_store_pem(pem: &[u8]) -> io::Result<Arc<RootCertStore>> {
    let mut roots = RootCertStore::empty();
    for der in certificates(pem)? {
        let (remainder, parsed) = x509_parser::parse_x509_certificate(&der)
            .map_err(|_| invalid("invalid node TLS CA certificate"))?;
        let constraints = parsed
            .basic_constraints()
            .map_err(|_| invalid("invalid node TLS CA basic constraints"))?;
        if !remainder.is_empty() || !constraints.is_some_and(|value| value.value.ca) {
            return Err(invalid(
                "node TLS trust bundle must contain only CA certificates",
            ));
        }
        roots
            .add(der)
            .map_err(|_| invalid("invalid node TLS trust anchor"))?;
    }
    Ok(Arc::new(roots))
}

/// Enforces this homogeneous node's explicit issuance template, stricter than
/// RFC 5280's allowance for absent EKU. Metadata parsing is not cryptographic
/// verification: the ordinary WebPKI verifier below still checks trust, validity,
/// path constraints and both usages, including normal intermediate constraints.
/// Dual serverAuth/clientAuth usage follows RFC 5280 §4.2.1.12:
/// <https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12>.
fn verify_node_chain(chain: &[CertificateDer<'_>], roots: &Arc<RootCertStore>) -> io::Result<()> {
    verify_node_chain_at(chain, roots, UnixTime::now())
}

fn verify_node_chain_at(
    chain: &[CertificateDer<'_>],
    roots: &Arc<RootCertStore>,
    now: UnixTime,
) -> io::Result<()> {
    let (leaf, intermediates) = chain
        .split_first()
        .ok_or_else(|| invalid("node TLS certificate chain is empty"))?;
    if leaf.is_empty() || leaf.len() > MAX_LEAF_BYTES {
        return Err(invalid("node TLS leaf certificate exceeds its bounds"));
    }
    let (remainder, parsed) = x509_parser::parse_x509_certificate(leaf)
        .map_err(|_| invalid("invalid node TLS leaf certificate"))?;
    let constraints = parsed
        .basic_constraints()
        .map_err(|_| invalid("invalid node TLS leaf basic constraints"))?;
    if !remainder.is_empty() || constraints.is_some_and(|value| value.value.ca) {
        return Err(invalid(
            "node TLS identity must be an end-entity certificate",
        ));
    }
    let usage = parsed
        .extended_key_usage()
        .map_err(|_| invalid("invalid node TLS extended key usage"))?
        .ok_or_else(|| invalid("node TLS identity requires explicit dual extended key usage"))?;
    if !usage.value.client_auth || !usage.value.server_auth {
        return Err(invalid(
            "node TLS identity requires clientAuth and serverAuth",
        ));
    }
    let usage = parsed
        .key_usage()
        .map_err(|_| invalid("invalid node TLS key usage"))?
        .ok_or_else(|| invalid("node TLS identity requires explicit digitalSignature key usage"))?;
    if !usage.value.digital_signature() {
        return Err(invalid(
            "node TLS identity requires digitalSignature key usage",
        ));
    }
    let names = parsed
        .subject_alternative_name()
        .map_err(|_| invalid("invalid node TLS subject alternative names"))?
        .ok_or_else(|| invalid("node TLS identity requires subject alternative names"))?;
    if !names.value.general_names.iter().any(|name| {
        matches!(
            name,
            x509_parser::extensions::GeneralName::DNSName(_)
                | x509_parser::extensions::GeneralName::IPAddress(_)
        )
    }) {
        return Err(invalid(
            "node TLS identity requires a DNS or IP subject alternative name",
        ));
    }
    // RFC 8446 requires digitalSignature when KU is present; requiring that
    // extension and both EKUs explicitly is our issuance-template policy.
    // https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.2.2
    // https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12
    let provider = Arc::new(aws_lc_rs::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(roots.clone(), provider.clone())
        .build()
        .map_err(|_| invalid("cannot configure node TLS client-certificate verification"))?;
    verifier
        .verify_client_cert(leaf, intermediates, now)
        .map_err(|_| invalid("node TLS identity has an invalid client-auth chain or validity"))?;
    let parsed = ParsedCertificate::try_from(leaf)
        .map_err(|_| invalid("invalid node TLS leaf certificate"))?;
    verify_server_cert_signed_by_trust_anchor(
        &parsed,
        roots,
        intermediates,
        now,
        provider.signature_verification_algorithms.all,
    )
    .map_err(|_| invalid("node TLS identity has an invalid server-auth chain or validity"))
}

/// Opens a regular file and reads at most the configured limit plus one byte.
///
/// `O_NONBLOCK` prevents a raced-in FIFO from hanging startup before descriptor
/// metadata can reject it. `O_NOFOLLOW` rejects a substituted Unix symlink leaf;
/// neither flag provides a trusted-ancestor guarantee. No permissions change.
fn read_bounded(path: &Path, limit: usize, private: bool) -> io::Result<Zeroizing<Vec<u8>>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(invalid(
            "management TLS path must be a regular non-symlink file",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(invalid("management TLS path must be a regular file"));
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "management TLS private key must not grant group or other permissions",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    let read_limit = limit
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| invalid("invalid management TLS file limit"))?;
    if metadata.len() >= read_limit {
        return Err(invalid("management TLS file exceeds its input limit"));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit + 1));
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid("management TLS file exceeds its input limit"));
    }
    Ok(bytes)
}

/// Parses every chain element, including intermediates, without logging input.
fn certificates(pem: &[u8]) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = pem;
    let mut chain = Vec::new();
    for item in rustls_pemfile::read_all(&mut reader) {
        let Item::X509Certificate(certificate) =
            item.map_err(|_| invalid("invalid management TLS certificate PEM"))?
        else {
            return Err(invalid(
                "management TLS chain must contain only certificates",
            ));
        };
        ParsedCertificate::try_from(&certificate)
            .map_err(|_| invalid("invalid management TLS certificate DER"))?;
        chain.push(certificate);
    }
    if chain.is_empty() {
        return Err(invalid("management TLS certificate chain is empty"));
    }
    Ok(chain)
}

/// Decodes exactly one key and keeps its DER allocation in a zeroizing owner.
fn private_key_der(pem: &[u8]) -> io::Result<Zeroizing<PrivateKeyDer<'static>>> {
    let mut reader = pem;
    let mut private_key = None;
    for item in rustls_pemfile::read_all(&mut reader) {
        let key: PrivateKeyDer<'static> =
            match item.map_err(|_| invalid("invalid management TLS private key PEM"))? {
                Item::Pkcs8Key(key) => key.into(),
                Item::Pkcs1Key(key) => key.into(),
                Item::Sec1Key(key) => key.into(),
                _ => return Err(invalid("unsupported management TLS private key format")),
            };
        let key = Zeroizing::new(key);
        if private_key.is_some() {
            return Err(invalid(
                "management TLS key file must contain exactly one private key",
            ));
        }
        private_key = Some(key);
    }
    private_key.ok_or_else(|| invalid("management TLS private key is missing"))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::{fs::DirBuilder, io::Write, path::PathBuf, time::Duration};

    use rcgen::generate_simple_self_signed;
    use rustls::{ClientConfig, RootCertStore};
    use rustls_pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;

    /// Owns only an exclusively created random temporary leaf and its fixtures.
    pub(super) struct TestDirectory(pub(super) PathBuf);

    impl TestDirectory {
        pub(super) fn new() -> io::Result<Self> {
            let mut random = [0; 16];
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("test entropy unavailable"))?;
            let suffix = u128::from_be_bytes(random);
            let path = std::env::temp_dir().join(format!("vproxy-management-tls-{suffix:032x}"));
            let builder = DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder.create(&path)?;
            Ok(Self(path))
        }

        pub(super) fn write(&self, name: &str, value: &[u8]) -> io::Result<PathBuf> {
            let path = self.0.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(&path)?.write_all(value)?;
            Ok(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn admin_https_negotiates_tls13_http11_without_a_client_certificate() -> io::Result<()> {
        let directory = TestDirectory::new()?;
        let identity =
            generate_simple_self_signed(vec!["localhost".into()]).map_err(io::Error::other)?;
        let certificate = directory.write("cert.pem", identity.cert.pem().as_bytes())?;
        let key = directory.write("key.pem", identity.signing_key.serialize_pem().as_bytes())?;
        let server = admin_server_config(&certificate, &key)?;
        assert_eq!(server.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert_eq!(server.max_early_data_size, 0);
        let mut roots = RootCertStore::empty();
        roots
            .add(identity.cert.der().clone())
            .map_err(io::Error::other)?;
        let mut client =
            ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(io::Error::other)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        client.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        tokio::time::timeout(Duration::from_secs(5), async move {
            let server_handshake = TlsAcceptor::from(server).accept(server_io);
            let connector = TlsConnector::from(Arc::new(client));
            let client_handshake = connector.connect(
                ServerName::try_from("localhost").map_err(io::Error::other)?,
                client_io,
            );
            let (mut server_stream, mut client_stream) =
                tokio::try_join!(server_handshake, client_handshake)?;
            assert_eq!(
                server_stream.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            assert_eq!(
                server_stream.get_ref().1.alpn_protocol(),
                Some(&b"http/1.1"[..])
            );
            assert!(server_stream.get_ref().1.peer_certificates().is_none());
            client_stream.write_all(b"probe").await?;
            client_stream.flush().await?;
            let mut received = [0; 5];
            server_stream.read_exact(&mut received).await?;
            assert_eq!(&received, b"probe");
            Ok::<(), io::Error>(())
        })
        .await
        .map_err(io::Error::other)?
    }

    #[test]
    fn malformed_extra_and_unsupported_identity_input_is_rejected() -> io::Result<()> {
        let identity =
            generate_simple_self_signed(vec!["localhost".into()]).map_err(io::Error::other)?;
        let valid_certificate = identity.cert.pem();
        let valid_key = identity.signing_key.serialize_pem();
        for certificate in [
            "".to_owned(),
            "-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n".to_owned(),
            "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n".to_owned(),
            format!(
                "{valid_certificate}-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"
            ),
            format!("{valid_certificate}{valid_key}"),
        ] {
            assert!(certificates(certificate.as_bytes()).is_err());
        }
        for key in [
            "".to_owned(),
            format!("{valid_key}{valid_key}"),
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----\n"
                .to_owned(),
            "-----BEGIN PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n".to_owned(),
            "-----BEGIN PRIVATE KEY-----\n%%%\n-----END PRIVATE KEY-----\n".to_owned(),
            format!("{valid_key}{valid_certificate}"),
        ] {
            assert!(private_key_der(key.as_bytes()).is_err());
        }
        let directory = TestDirectory::new()?;
        let certificate = directory.write("cert.pem", valid_certificate.as_bytes())?;
        let other_identity =
            generate_simple_self_signed(vec!["localhost".into()]).map_err(io::Error::other)?;
        let other_key = directory.write(
            "other.pem",
            other_identity.signing_key.serialize_pem().as_bytes(),
        )?;
        assert!(admin_server_config(&certificate, &other_key).is_err());
        let invalid_der = directory.write(
            "invalid.pem",
            b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
        )?;
        assert!(admin_server_config(&certificate, &invalid_der).is_err());
        Ok(())
    }

    #[test]
    fn file_input_is_bounded_and_directories_are_rejected() -> io::Result<()> {
        let directory = TestDirectory::new()?;
        let exact = directory.write("exact", b"1234")?;
        assert_eq!(&**read_bounded(&exact, 4, false)?, b"1234");
        assert!(read_bounded(&exact, 3, false).is_err());
        assert!(read_bounded(&directory.0, MAX_CERTIFICATE_BYTES, false).is_err());
        let oversized_certificate =
            directory.write("large-cert", &vec![b'x'; MAX_CERTIFICATE_BYTES + 1])?;
        let oversized_key = directory.write("large-key", &vec![b'x'; MAX_PRIVATE_KEY_BYTES + 1])?;
        assert!(read_bounded(&oversized_certificate, MAX_CERTIFICATE_BYTES, false).is_err());
        assert!(read_bounded(&oversized_key, MAX_PRIVATE_KEY_BYTES, true).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unix_private_keys_reject_public_modes_and_symlinks_without_chmod() -> io::Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = TestDirectory::new()?;
        let key = directory.write("key.pem", b"private fixture")?;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o640))?;
        assert_eq!(
            read_bounded(&key, MAX_PRIVATE_KEY_BYTES, true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(fs::metadata(&key)?.permissions().mode() & 0o777, 0o640);
        assert!(read_bounded(&key, MAX_CERTIFICATE_BYTES, false).is_ok());
        let link = directory.0.join("key-link");
        symlink(&key, &link)?;
        assert!(read_bounded(&link, MAX_PRIVATE_KEY_BYTES, true).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod node_tests {
    //! Node-specific trust/profile and real TLS regressions. PEM/file/admin tests
    //! remain in the parent module and share only their private temporary directory.

    use std::{path::PathBuf, time::Duration};

    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose, date_time_ymd,
    };
    use rustls::{HandshakeKind, client::Resumption};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::{tests::TestDirectory, *};

    struct Authority {
        directory: TestDirectory,
        issuer: CertifiedIssuer<'static, KeyPair>,
        ca: PathBuf,
    }

    struct Identity {
        certificate: PathBuf,
        key: PathBuf,
        der: CertificateDer<'static>,
    }

    impl Authority {
        fn new() -> io::Result<Self> {
            let directory = TestDirectory::new()?;
            let mut parameters =
                CertificateParams::new(Vec::<String>::new()).map_err(io::Error::other)?;
            parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let issuer = CertifiedIssuer::self_signed(
                parameters,
                KeyPair::generate().map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
            let ca = directory.write("ca.pem", issuer.pem().as_bytes())?;
            Ok(Self {
                directory,
                issuer,
                ca,
            })
        }

        fn identity(&self, prefix: &str, parameters: CertificateParams) -> io::Result<Identity> {
            let key_pair = KeyPair::generate().map_err(io::Error::other)?;
            let certificate = parameters
                .signed_by(&key_pair, &self.issuer)
                .map_err(io::Error::other)?;
            Ok(Identity {
                certificate: self
                    .directory
                    .write(&format!("{prefix}-cert.pem"), certificate.pem().as_bytes())?,
                key: self.directory.write(
                    &format!("{prefix}-key.pem"),
                    key_pair.serialize_pem().as_bytes(),
                )?,
                der: certificate.der().clone(),
            })
        }
    }

    fn node_parameters(name: &str) -> io::Result<CertificateParams> {
        let mut parameters =
            CertificateParams::new(vec![name.to_owned()]).map_err(io::Error::other)?;
        parameters.is_ca = IsCa::ExplicitNoCa;
        parameters.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        Ok(parameters)
    }

    #[test]
    fn recovery_key_hash_is_the_actual_leafs_complete_spki() -> io::Result<()> {
        let authority = Authority::new()?;
        let node = authority.identity("pin", node_parameters("node.test")?)?;
        let (_, parsed) =
            x509_parser::parse_x509_certificate(&node.der).map_err(io::Error::other)?;
        let expected: [u8; 32] = Sha256::digest(parsed.public_key().raw).into();
        let loaded = node_identity(&authority.ca, &node.certificate, &node.key)?;
        assert_eq!(loaded.key_sha256()?, expected);
        assert_eq!(node_key_sha256(&node.key)?, expected);
        let other = authority.identity("other-pin", node_parameters("node.test")?)?;
        assert_ne!(node_key_sha256(&other.key)?, expected);
        assert!(node_identity(&authority.ca, &node.certificate, &other.key).is_err());
        let malformed = authority
            .directory
            .write("bad-key.pem", b"not a private key")?;
        assert!(node_key_sha256(&malformed).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn both_tls_roles_keep_the_once_loaded_identity_after_files_change() -> io::Result<()> {
        let authority = Authority::new()?;
        let node = authority.identity("loaded", node_parameters("node.test")?)?;
        let loaded = node_identity(&authority.ca, &node.certificate, &node.key)?;
        let pin = loaded.key_sha256()?;
        let replacement = authority.identity("replacement", node_parameters("other.test")?)?;
        // Only this fixture's private files are replaced. The active resolvers must
        // not re-read paths after name/SPKI verification or disagree across roles.
        fs::write(&node.certificate, fs::read(&replacement.certificate)?)?;
        fs::write(&node.key, fs::read(&replacement.key)?)?;
        assert_eq!(loaded.key_sha256()?, pin);
        assert_ne!(node_key_sha256(&node.key)?, pin);
        loaded.verify_name("node.test")?;
        assert!(loaded.verify_name("other.test").is_err());
        let (server, client) = connect(
            loaded.server_config()?,
            loaded.client_config()?,
            "node.test",
        )
        .await?;
        assert_eq!(
            checked_leaf(server.get_ref().1.peer_certificates())?,
            node.der.as_ref(),
        );
        assert_eq!(
            checked_leaf(client.get_ref().1.peer_certificates())?,
            node.der.as_ref(),
        );
        Ok(())
    }

    fn raw_client(
        authority: &Authority,
        identity: Option<&Identity>,
        versions: &[&'static rustls::SupportedProtocolVersion],
        alpn: &[u8],
    ) -> io::Result<Arc<ClientConfig>> {
        let builder = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_protocol_versions(versions)
            .map_err(io::Error::other)?
            .with_root_certificates(root_store(&authority.ca)?);
        let mut client = match identity {
            Some(identity) => {
                let key = read_bounded(&identity.key, MAX_PRIVATE_KEY_BYTES, true)?;
                builder
                    .with_client_auth_cert(
                        vec![identity.der.clone()],
                        private_key_der(&key)?.clone_key(),
                    )
                    .map_err(io::Error::other)?
            }
            None => builder.with_no_client_auth(),
        };
        if !alpn.is_empty() {
            client.alpn_protocols = vec![alpn.to_vec()];
        }
        client.resumption = Resumption::disabled();
        Ok(Arc::new(client))
    }

    async fn connect(
        server: Arc<ServerConfig>,
        client: Arc<ClientConfig>,
        server_name: &'static str,
    ) -> io::Result<(
        tokio_rustls::server::TlsStream<DuplexStream>,
        tokio_rustls::client::TlsStream<DuplexStream>,
    )> {
        let (client_io, server_io) = tokio::io::duplex(32 * 1024);
        tokio::time::timeout(Duration::from_secs(5), async move {
            let acceptor = TlsAcceptor::from(server);
            let connector = TlsConnector::from(client);
            tokio::try_join!(
                acceptor.accept(server_io),
                connector.connect(
                    ServerName::try_from(server_name).map_err(io::Error::other)?,
                    client_io
                )
            )
        })
        .await
        // A timeout must fail the test, not masquerade as the expected TLS rejection
        // in negative cases that inspect the inner I/O result.
        .expect("TLS handshake test exceeded its deadline")
    }

    #[tokio::test]
    async fn mandatory_node_tls_uses_full_authenticated_handshakes_and_no_resumption()
    -> io::Result<()> {
        let authority = Authority::new()?;
        let server_identity = authority.identity("server", node_parameters("server.test")?)?;
        let client_identity = authority.identity("client", node_parameters("client.test")?)?;
        let server = node_server_config(
            &authority.ca,
            &server_identity.certificate,
            &server_identity.key,
        )?;
        let client = node_client_config(
            &authority.ca,
            &client_identity.certificate,
            &client_identity.key,
        )?;
        assert_eq!(server.send_tls13_tickets, 0);
        assert_eq!(server.max_early_data_size, 0);
        assert!(!server.send_half_rtt_data);
        assert!(!server.ticketer.enabled());
        assert!(!server.session_storage.can_cache());
        assert!(!client.enable_early_data);
        for _ in 0..2 {
            let (mut server_stream, mut client_stream) =
                connect(server.clone(), client.clone(), "server.test").await?;
            assert_eq!(
                server_stream.get_ref().1.handshake_kind(),
                Some(HandshakeKind::Full)
            );
            assert_eq!(
                client_stream.get_ref().1.handshake_kind(),
                Some(HandshakeKind::Full)
            );
            assert_eq!(
                server_stream.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            assert_eq!(
                server_stream.get_ref().1.alpn_protocol(),
                Some(b"http/1.1".as_slice())
            );
            let leaf = checked_leaf(server_stream.get_ref().1.peer_certificates())?;
            assert_eq!(leaf, client_identity.der.as_ref());
            verify_peer_name(&leaf, "client.test")?;
            assert!(verify_peer_name(&leaf, "other.test").is_err());
            client_stream.write_all(b"probe").await?;
            client_stream.flush().await?;
            let mut received = [0; 5];
            server_stream.read_exact(&mut received).await?;
            assert_eq!(&received, b"probe");
        }
        Ok(())
    }

    #[tokio::test]
    async fn node_handshakes_reject_missing_identity_foreign_trust_name_usage_and_tls12()
    -> io::Result<()> {
        let authority = Authority::new()?;
        let other = Authority::new()?;
        let server_identity = authority.identity("server", node_parameters("server.test")?)?;
        let client_identity = authority.identity("client", node_parameters("client.test")?)?;
        let foreign_identity = other.identity("foreign", node_parameters("foreign.test")?)?;
        let server = node_server_config(
            &authority.ca,
            &server_identity.certificate,
            &server_identity.key,
        )?;
        let valid_client = node_client_config(
            &authority.ca,
            &client_identity.certificate,
            &client_identity.key,
        )?;
        assert!(
            connect(server.clone(), valid_client.clone(), "wrong.test")
                .await
                .is_err()
        );
        for client in [
            raw_client(&authority, None, &[&rustls::version::TLS13], b"http/1.1")?,
            raw_client(
                &authority,
                Some(&foreign_identity),
                &[&rustls::version::TLS13],
                b"http/1.1",
            )?,
            raw_client(
                &other,
                Some(&client_identity),
                &[&rustls::version::TLS13],
                b"http/1.1",
            )?,
            raw_client(
                &authority,
                Some(&client_identity),
                &[&rustls::version::TLS12],
                b"http/1.1",
            )?,
            raw_client(
                &authority,
                Some(&client_identity),
                &[&rustls::version::TLS13],
                b"h2",
            )?,
        ] {
            assert!(
                connect(server.clone(), client, "server.test")
                    .await
                    .is_err()
            );
        }
        let mut parameters = node_parameters("server-only.test")?;
        parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_only = authority.identity("server-only", parameters)?;
        let client = raw_client(
            &authority,
            Some(&server_only),
            &[&rustls::version::TLS13],
            b"http/1.1",
        )?;
        assert!(
            connect(server.clone(), client, "server.test")
                .await
                .is_err()
        );
        for (prefix, before, after) in [
            (
                "expired",
                date_time_ymd(2000, 1, 1),
                date_time_ymd(2001, 1, 1),
            ),
            (
                "future",
                date_time_ymd(4090, 1, 1),
                date_time_ymd(4091, 1, 1),
            ),
        ] {
            let mut parameters = node_parameters("server.test")?;
            parameters.not_before = before;
            parameters.not_after = after;
            let identity = authority.identity(prefix, parameters)?;
            let client = raw_client(
                &authority,
                Some(&identity),
                &[&rustls::version::TLS13],
                b"http/1.1",
            )?;
            assert!(
                connect(server.clone(), client, "server.test")
                    .await
                    .is_err()
            );
            let expired_or_future_server =
                admin_server_config(&identity.certificate, &identity.key)?;
            assert!(
                connect(
                    expired_or_future_server,
                    valid_client.clone(),
                    "server.test"
                )
                .await
                .is_err()
            );
        }
        let mut parameters = node_parameters("server.test")?;
        parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_only = authority.identity("client-only", parameters)?;
        let invalid_server = admin_server_config(&client_only.certificate, &client_only.key)?;
        assert!(
            connect(invalid_server, valid_client, "server.test")
                .await
                .is_err()
        );
        // TLS permits an omitted ALPN. The transport must reject this after the
        // handshake, rather than treating a successful handshake as HTTP/1.1.
        let no_alpn = raw_client(
            &authority,
            Some(&client_identity),
            &[&rustls::version::TLS13],
            b"",
        )?;
        let (server_stream, _) = connect(server.clone(), no_alpn, "server.test").await?;
        assert_eq!(server_stream.get_ref().1.alpn_protocol(), None);
        let (mut plaintext, server_io) = tokio::io::duplex(1024);
        plaintext.write_all(b"GET / HTTP/1.1\r\n\r\n").await?;
        plaintext.shutdown().await?;
        assert!(
            tokio::time::timeout(
                Duration::from_secs(5),
                TlsAcceptor::from(server).accept(server_io)
            )
            .await
            .map_err(io::Error::other)?
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn offline_import_and_startup_require_the_explicit_node_profile_and_current_trust()
    -> io::Result<()> {
        let authority = Authority::new()?;
        let other = Authority::new()?;
        let valid = authority.identity("valid", node_parameters("node.test")?)?;
        assert_eq!(
            load_peer_certificate(&authority.ca, &valid.certificate, "node.test")?,
            valid.der.as_ref()
        );
        assert!(load_peer_certificate(&authority.ca, &valid.certificate, "wrong.test").is_err());
        assert!(load_peer_certificate(&other.ca, &valid.certificate, "node.test").is_err());
        assert!(root_store(&valid.certificate).is_err());
        for index in 0..9 {
            let mut parameters = node_parameters("node.test")?;
            match index {
                0 => parameters.extended_key_usages.clear(),
                1 => parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth],
                2 => parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth],
                3 => parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained),
                4 => parameters.key_usages = vec![KeyUsagePurpose::KeyEncipherment],
                5 => parameters.key_usages.clear(),
                6 => {
                    parameters.not_before = date_time_ymd(2000, 1, 1);
                    parameters.not_after = date_time_ymd(2001, 1, 1);
                }
                7 => {
                    parameters.not_before = date_time_ymd(4090, 1, 1);
                    parameters.not_after = date_time_ymd(4091, 1, 1);
                }
                _ => parameters.subject_alt_names.clear(),
            }
            let identity = authority.identity(&format!("invalid-{index}"), parameters)?;
            assert!(
                load_peer_certificate(&authority.ca, &identity.certificate, "node.test").is_err(),
                "profile={index}"
            );
            assert!(
                node_server_config(&authority.ca, &identity.certificate, &identity.key).is_err(),
                "profile={index}"
            );
            assert!(
                node_client_config(&authority.ca, &identity.certificate, &identity.key).is_err(),
                "profile={index}"
            );
            // An invalid/expired former identity still has to be identifiable for
            // permanent revocation; this read grants neither trust nor permission.
            assert_eq!(
                read_certificate_leaf(&identity.certificate)?,
                identity.der.as_ref()
            );
        }
        let combined = authority.directory.write(
            "chain.pem",
            &[fs::read(&valid.certificate)?, fs::read(&authority.ca)?].concat(),
        )?;
        assert_eq!(
            load_peer_certificate(&authority.ca, &combined, "node.test")?,
            valid.der.as_ref()
        );
        assert!(checked_leaf(None).is_err());
        assert!(checked_leaf(Some(&[])).is_err());
        assert!(checked_leaf(Some(&[CertificateDer::from(Vec::<u8>::new())])).is_err());
        assert!(checked_leaf(Some(&[CertificateDer::from(vec![0; MAX_LEAF_BYTES + 1])])).is_err());
        assert!(verify_peer_name(&vec![0; MAX_LEAF_BYTES + 1], "node.test").is_err());
        assert_eq!(
            verify_peer_name(valid.der.as_ref(), "not a reference name")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        Ok(())
    }

    #[test]
    fn a_normal_intermediate_need_not_declare_the_leafs_explicit_ekus() -> io::Result<()> {
        let authority = Authority::new()?;
        let mut parameters =
            CertificateParams::new(Vec::<String>::new()).map_err(io::Error::other)?;
        parameters.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let intermediate = CertifiedIssuer::signed_by(
            parameters,
            KeyPair::generate().map_err(io::Error::other)?,
            &authority.issuer,
        )
        .map_err(io::Error::other)?;
        let key = KeyPair::generate().map_err(io::Error::other)?;
        let leaf = node_parameters("node.test")?
            .signed_by(&key, &intermediate)
            .map_err(io::Error::other)?;
        let chain = authority.directory.write(
            "intermediate-chain.pem",
            format!("{}{}", leaf.pem(), intermediate.pem()).as_bytes(),
        )?;
        let key = authority
            .directory
            .write("intermediate-leaf-key.pem", key.serialize_pem().as_bytes())?;
        assert_eq!(
            load_peer_certificate(&authority.ca, &chain, "node.test")?,
            leaf.der().as_ref()
        );
        node_server_config(&authority.ca, &chain, &key)?;
        node_client_config(&authority.ca, &chain, &key)?;
        Ok(())
    }
}
