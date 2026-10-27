//! Bounded certificate loading and separate HTTPS / ACME TLS handshakes.

use std::{
    io,
    sync::{Arc, Mutex, Weak},
};

use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rustls::{
    RootCertStore, ServerConfig,
    client::{verify_server_cert_signed_by_trust_anchor, verify_server_name},
    crypto::aws_lc_rs,
    server::{NoServerSessionStorage, ParsedCertificate},
    sign::{CertifiedKey, SingleCertAndKey},
};
use rustls_pemfile::Item;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::{io::AsyncWriteExt as _, net::TcpStream};
use tokio_rustls::{LazyConfigAcceptor, server::TlsStream};
use zeroize::Zeroizing;

const MAX_IDENTITY_BYTES: usize = 256 * 1024;
const ACME_ALPN: &[u8] = b"acme-tls/1";
const HTTP_ALPN: &[u8] = b"http/1.1";
const ACME_IDENTIFIER: &str = "1.3.6.1.5.5.7.1.31";

pub(super) struct Identity {
    pub(super) key: Arc<CertifiedKey>,
    pub(super) not_before: u64,
    pub(super) not_after: u64,
}

/// Validate a leaf-first chain and exactly one unencrypted key in bounded PEM.
/// The caller owns (and clears) the borrowed PEM; decoded key owners are cleared
/// here. No system roots, network lookups, publication or persistence are used.
pub(super) fn identity(
    pem: &[u8],
    domain: &str,
    roots: &RootCertStore,
    now: UnixTime,
) -> io::Result<Identity> {
    let name = domain_name(domain)?;
    if pem.len() > MAX_IDENTITY_BYTES {
        return Err(invalid("ACME identity exceeds its input limit"));
    }
    pem_sections(pem)?;
    let mut reader = pem;
    let mut chain = Vec::new();
    let mut private_key = None;
    for item in rustls_pemfile::read_all(&mut reader) {
        let key: PrivateKeyDer<'static> =
            match item.map_err(|_| invalid("invalid ACME identity PEM"))? {
                Item::X509Certificate(certificate) => {
                    ParsedCertificate::try_from(&certificate)
                        .map_err(|_| invalid("invalid ACME identity certificate DER"))?;
                    chain.push(certificate);
                    continue;
                }
                Item::Pkcs8Key(key) => key.into(),
                Item::Pkcs1Key(key) => key.into(),
                Item::Sec1Key(key) => key.into(),
                _ => return Err(invalid("unsupported ACME identity PEM item")),
            };
        let key = Zeroizing::new(key);
        if private_key.is_some() {
            return Err(invalid("ACME identity requires exactly one private key"));
        }
        private_key = Some(key);
    }
    let private_key = private_key.ok_or_else(|| invalid("ACME identity private key is missing"))?;
    let (leaf, intermediates) = chain
        .split_first()
        .ok_or_else(|| invalid("ACME identity certificate chain is empty"))?;
    let (not_before, not_after) = leaf_metadata(leaf, domain)?;
    let parsed =
        ParsedCertificate::try_from(leaf).map_err(|_| invalid("invalid ACME identity leaf"))?;
    let provider = aws_lc_rs::default_provider();
    verify_server_cert_signed_by_trust_anchor(
        &parsed,
        roots,
        intermediates,
        now,
        provider.signature_verification_algorithms.all,
    )
    .map_err(|_| invalid("ACME identity has an invalid server chain or validity"))?;
    verify_server_name(&parsed, &name)
        .map_err(|_| invalid("ACME identity does not match its domain"))?;
    let signer = aws_lc_rs::sign::any_supported_type(&private_key)
        .map_err(|_| invalid("unsupported or invalid ACME identity key"))?;
    let key = CertifiedKey::new(chain, signer);
    key.keys_match()
        .map_err(|_| invalid("ACME identity certificate and key do not match"))?;
    Ok(Identity {
        key: Arc::new(key),
        not_before,
        not_after,
    })
}

struct Normal {
    config: Arc<ServerConfig>,
    key: Arc<CertifiedKey>,
    not_before: u64,
    not_after: u64,
    certificate: crate::manage::certificates::State,
}

struct Challenge {
    generation: Arc<()>,
    config: Arc<ServerConfig>,
    #[cfg(test)]
    certificate: CertificateDer<'static>,
}

#[derive(Default)]
struct State {
    normal: Option<Normal>,
    challenge: Option<Challenge>,
}

#[derive(Clone)]
pub(in crate::manage) struct Tls {
    domain: Arc<str>,
    state: Arc<Mutex<State>>,
}

pub(super) struct ChallengeGuard {
    state: Weak<Mutex<State>>,
    generation: Arc<()>,
}

impl Drop for ChallengeGuard {
    fn drop(&mut self) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        if let Ok(mut state) = state.lock()
            && state
                .challenge
                .as_ref()
                .is_some_and(|challenge| Arc::ptr_eq(&challenge.generation, &self.generation))
        {
            state.challenge = None;
        }
    }
}

impl Tls {
    /// Observe only the currently published normal identity. A TLS-ALPN-01
    /// challenge or unactivated cache is never reported as the server leaf.
    /// Poisoned metadata refuses a healthy observation without changing TLS.
    pub(in crate::manage) fn certificate(&self) -> crate::manage::certificates::State {
        use crate::manage::certificates::State;
        self.state.lock().map_or(State::Unavailable, |state| {
            state
                .normal
                .as_ref()
                .map_or(State::Pending, |normal| normal.certificate.clone())
        })
    }

    pub(super) fn new(domain: String) -> io::Result<Self> {
        domain_name(&domain)?;
        Ok(Self {
            domain: domain.to_ascii_lowercase().into(),
            state: Arc::new(Mutex::new(State::default())),
        })
    }

    /// Publish only after the caller has durably committed the validated cache.
    /// Existing connections keep their selected identity; no lock spans I/O.
    pub(super) fn publish(&self, identity: Identity) -> io::Result<()> {
        let leaf = identity
            .key
            .end_entity_cert()
            .map_err(|_| invalid("ACME identity leaf is missing"))?;
        let validity = leaf_metadata(leaf, &self.domain)?;
        if validity != (identity.not_before, identity.not_after)
            || !valid_at(validity.0, validity.1, UnixTime::now())
        {
            return Err(invalid("ACME identity is not currently valid"));
        }
        identity
            .key
            .keys_match()
            .map_err(|_| invalid("ACME identity certificate and key do not match"))?;
        let certificate = crate::manage::certificates::State::from_leaf(leaf.as_ref());
        let normal = Normal {
            config: config(identity.key.clone(), HTTP_ALPN)?,
            key: identity.key,
            not_before: identity.not_before,
            not_after: identity.not_after,
            certificate,
        };
        self.state
            .lock()
            .map_err(|_| io::Error::other("ACME TLS state is unavailable"))?
            .normal = Some(normal);
        Ok(())
    }

    /// Supply the current normal signer to a managed proxy. Every subsequent
    /// handshake resolves the latest valid normal publication with exact SNI;
    /// no challenge certificate, ACME protocol or key file can be selected.
    /// Absence/expiry/poison is an explicit startup error, not self-signing.
    pub(in crate::manage) fn proxy_identity(&self) -> io::Result<crate::server::tls::Identity> {
        let leaf = {
            let state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("ACME TLS state is unavailable"))?;
            let normal = state
                .normal
                .as_ref()
                .filter(|n| valid_at(n.not_before, n.not_after, UnixTime::now()))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "normal proxy TLS identity is not available",
                    )
                })?;
            normal
                .key
                .cert
                .first()
                .cloned()
                .ok_or_else(|| invalid("normal proxy TLS identity has no leaf"))?
        };
        Ok(crate::server::tls::Identity::renewable(
            Arc::new(ProxyResolver(self.clone())),
            leaf,
        ))
    }

    /// Install a dedicated self-signed TLS-ALPN-01 certificate until guard drop.
    /// A replaced guard cannot clear a newer challenge generation.
    pub(super) fn challenge(&self, digest: &[u8]) -> io::Result<ChallengeGuard> {
        if digest.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ACME challenge digest must contain 32 bytes",
            ));
        }
        let key_pair = Zeroizing::new(
            KeyPair::generate()
                .map_err(|_| io::Error::other("cannot generate ACME challenge key"))?,
        );
        let mut parameters = CertificateParams::new(vec![self.domain.to_string()])
            .map_err(|_| invalid("cannot configure ACME challenge name"))?;
        let now = time::OffsetDateTime::now_utc();
        parameters.not_before = now
            .checked_sub(time::Duration::minutes(1))
            .ok_or_else(|| invalid("ACME challenge validity underflow"))?;
        parameters.not_after = now
            .checked_add(time::Duration::hours(1))
            .ok_or_else(|| invalid("ACME challenge validity overflow"))?;
        // RFC 8737 §3 requires one DNS SAN and a critical DER OCTET STRING.
        // https://www.rfc-editor.org/rfc/rfc8737.html#section-3
        let mut content = Vec::with_capacity(34);
        content.extend_from_slice(&[0x04, 0x20]);
        content.extend_from_slice(digest);
        let mut extension =
            CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 31], content);
        extension.set_criticality(true);
        parameters.custom_extensions.push(extension);
        let certificate = parameters
            .self_signed(&*key_pair)
            .map_err(|_| invalid("cannot generate ACME challenge certificate"))?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialized_der()));
        let signer = aws_lc_rs::sign::any_supported_type(&key_der)
            .map_err(|_| invalid("cannot load ACME challenge key"))?;
        let key = CertifiedKey::new(vec![certificate.der().clone()], signer);
        // Normal WebPKI parsing intentionally rejects this unknown critical
        // extension. Compare its actual DER SPKI without weakening normal TLS.
        let (_, parsed) = x509_parser::parse_x509_certificate(certificate.der())
            .map_err(|_| invalid("invalid ACME challenge certificate"))?;
        if key.key.public_key().as_ref().map(|spki| spki.as_ref()) != Some(parsed.public_key().raw)
        {
            return Err(invalid("ACME challenge certificate and key do not match"));
        }
        let challenge = Challenge {
            generation: Arc::new(()),
            config: config(Arc::new(key), ACME_ALPN)?,
            #[cfg(test)]
            certificate: certificate.der().clone(),
        };
        let guard = ChallengeGuard {
            state: Arc::downgrade(&self.state),
            generation: challenge.generation.clone(),
        };
        self.state
            .lock()
            .map_err(|_| io::Error::other("ACME TLS state is unavailable"))?
            .challenge = Some(challenge);
        Ok(guard)
    }

    /// Accept one TLS connection within the caller's admission/timeout budget.
    /// Dropping this future closes its transport. Challenge connections never
    /// reach HTTP and carry no application data (RFC 8737 §§3–4).
    pub(in crate::manage) async fn accept(
        &self,
        stream: TcpStream,
    ) -> io::Result<Option<TlsStream<TcpStream>>> {
        let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream).await?;
        let hello = start.client_hello();
        if !hello
            .server_name()
            .is_some_and(|name| name.eq_ignore_ascii_case(&self.domain))
        {
            return Err(invalid("ACME TLS requires the configured SNI"));
        }
        let mut protocols = 0usize;
        let mut acme = false;
        let mut http = false;
        if let Some(alpn) = hello.alpn() {
            for protocol in alpn {
                protocols = protocols.saturating_add(1);
                acme |= protocol == ACME_ALPN;
                http |= protocol == HTTP_ALPN;
            }
        }
        if acme && protocols != 1 {
            return Err(invalid("unsupported ACME TLS ALPN offer"));
        }
        // ALPN is optional for ordinary HTTP/1.1 (RFC 7301 §3.1). Only the
        // single acme-tls/1 offer may select the challenge identity (RFC 8737
        // §3). Leave unsupported ordinary offers to rustls so it sends the
        // required no_application_protocol alert instead of silently closing.
        // https://www.rfc-editor.org/rfc/rfc7301.html#section-3.2
        let (config, validity) = {
            let state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("ACME TLS state is unavailable"))?;
            if acme {
                let challenge = state
                    .challenge
                    .as_ref()
                    .ok_or_else(|| invalid("ACME TLS challenge is unavailable"))?;
                (challenge.config.clone(), None)
            } else {
                let normal = state
                    .normal
                    .as_ref()
                    .filter(|normal| valid_at(normal.not_before, normal.not_after, UnixTime::now()))
                    .ok_or_else(|| invalid("ACME HTTPS identity is unavailable or expired"))?;
                (
                    normal.config.clone(),
                    Some((normal.not_before, normal.not_after)),
                )
            }
        };
        let mut stream = start.into_stream(config).await?;
        let expected = if acme {
            Some(ACME_ALPN)
        } else {
            http.then_some(HTTP_ALPN)
        };
        if stream.get_ref().1.alpn_protocol() != expected
            || stream.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        {
            return Err(invalid("ACME TLS negotiated an unexpected protocol"));
        }
        if acme {
            stream.shutdown().await?;
            return Ok(None);
        }
        if validity.is_some_and(|(before, after)| !valid_at(before, after, UnixTime::now())) {
            return Err(invalid("ACME HTTPS identity expired during handshake"));
        }
        Ok(Some(stream))
    }
}

/// Normal-only certificate selection for proxy HTTP/QUIC TLS configurations.
/// Rustls still owns each protocol's ALPN/version negotiation; only selection
/// of the current validated chain/signer is shared with management HTTPS.
struct ProxyResolver(Tls);

impl std::fmt::Debug for ProxyResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProxyResolver")
    }
}

impl rustls::server::ResolvesServerCert for ProxyResolver {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if !hello
            .server_name()
            .is_some_and(|name| name.eq_ignore_ascii_case(&self.0.domain))
        {
            return None;
        }
        let state = self.0.state.lock().ok()?;
        let normal = state
            .normal
            .as_ref()
            .filter(|n| valid_at(n.not_before, n.not_after, UnixTime::now()))?;
        Some(normal.key.clone())
    }
}

fn config(key: Arc<CertifiedKey>, alpn: &[u8]) -> io::Result<Arc<ServerConfig>> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| invalid("cannot configure ACME TLS 1.3"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(key)));
    config.alpn_protocols = vec![alpn.to_vec()];
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    Ok(Arc::new(config))
}

fn domain_name(domain: &str) -> io::Result<ServerName<'_>> {
    match ServerName::try_from(domain) {
        Ok(name @ ServerName::DnsName(_)) if !domain.ends_with('.') => Ok(name),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACME requires a DNS name without a trailing dot",
        )),
    }
}

fn pem_sections(pem: &[u8]) -> io::Result<()> {
    // The upstream decoder skips unknown PEM sections. A combined identity
    // must not silently hide another encrypted/unsupported private-key block.
    let labels: [&[u8]; 4] = [
        b"CERTIFICATE",
        b"PRIVATE KEY",
        b"RSA PRIVATE KEY",
        b"EC PRIVATE KEY",
    ];
    let mut section: Option<&[u8]> = None;
    for line in pem.split(|byte| *byte == b'\n') {
        let line = line.trim_ascii();
        if let Some(label) = section {
            if let Some(end) = line.strip_prefix(b"-----END ") {
                if end.strip_suffix(b"-----") != Some(label) {
                    return Err(invalid("invalid ACME identity PEM boundary"));
                }
                section = None;
            } else if line.starts_with(b"-----") {
                return Err(invalid("invalid ACME identity PEM boundary"));
            }
        } else if !line.is_empty() {
            let label = line
                .strip_prefix(b"-----BEGIN ")
                .and_then(|line| line.strip_suffix(b"-----"))
                .filter(|label| labels.contains(label))
                .ok_or_else(|| invalid("unsupported ACME identity PEM section"))?;
            section = Some(label);
        }
    }
    if section.is_some() {
        return Err(invalid("unterminated ACME identity PEM section"));
    }
    Ok(())
}

fn leaf_metadata(leaf: &CertificateDer<'_>, domain: &str) -> io::Result<(u64, u64)> {
    let (remainder, parsed) = x509_parser::parse_x509_certificate(leaf)
        .map_err(|_| invalid("invalid ACME identity leaf DER"))?;
    if !remainder.is_empty()
        || parsed
            .extensions()
            .iter()
            .any(|extension| extension.oid.to_id_string() == ACME_IDENTIFIER)
        || parsed
            .basic_constraints()
            .map_err(|_| invalid("invalid ACME identity basic constraints"))?
            .is_some_and(|constraints| constraints.value.ca)
    {
        return Err(invalid(
            "ACME HTTPS identity must be an ordinary end entity",
        ));
    }
    let names = parsed
        .subject_alternative_name()
        .map_err(|_| invalid("invalid ACME identity SAN"))?
        .ok_or_else(|| invalid("ACME identity SAN is missing"))?;
    if !names.value.general_names.iter().any(|name| {
        matches!(name, x509_parser::extensions::GeneralName::DNSName(name) if name.eq_ignore_ascii_case(domain))
    }) {
        return Err(invalid("ACME identity requires its exact domain in SAN"));
    }
    let not_before = u64::try_from(parsed.validity().not_before.timestamp())
        .map_err(|_| invalid("ACME identity validity predates the Unix epoch"))?;
    let not_after = u64::try_from(parsed.validity().not_after.timestamp())
        .map_err(|_| invalid("ACME identity validity predates the Unix epoch"))?;
    if not_before >= not_after {
        return Err(invalid("ACME identity validity is empty"));
    }
    Ok((not_before, not_after))
}

fn valid_at(not_before: u64, not_after: u64, now: UnixTime) -> bool {
    not_before <= now.as_secs() && now.as_secs() <= not_after
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use rcgen::{BasicConstraints, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose};
    use rustls::{
        ClientConfig, DigitallySignedStruct, SignatureScheme,
        client::{
            Resumption,
            danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        },
    };
    use tokio::{io::AsyncReadExt as _, net::TcpListener};
    use tokio_rustls::{TlsConnector, client::TlsStream as ClientStream};

    use super::*;

    const DOMAIN: &str = "management.test";

    struct Fixture {
        pem: Zeroizing<String>,
        chain: String,
        certificate: CertificateDer<'static>,
        roots: RootCertStore,
    }

    fn make_fixture(domain: &str, before: u64, after: u64) -> io::Result<Fixture> {
        let ca_key = Zeroizing::new(KeyPair::generate().map_err(io::Error::other)?);
        let mut ca_parameters = CertificateParams::default();
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca_parameters
            .self_signed(&*ca_key)
            .map_err(io::Error::other)?;
        let issuer = Issuer::from_params(&ca_parameters, &*ca_key);
        let key = Zeroizing::new(KeyPair::generate().map_err(io::Error::other)?);
        let mut parameters =
            CertificateParams::new(vec![domain.to_owned()]).map_err(io::Error::other)?;
        parameters.is_ca = IsCa::ExplicitNoCa;
        parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        parameters.not_before = time::OffsetDateTime::from_unix_timestamp(
            i64::try_from(before).map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?;
        parameters.not_after = time::OffsetDateTime::from_unix_timestamp(
            i64::try_from(after).map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?;
        let certificate = parameters
            .signed_by(&*key, &issuer)
            .map_err(io::Error::other)?;
        let chain = format!("{}{}", certificate.pem(), ca.pem());
        let private_pem = Zeroizing::new(key.serialize_pem());
        let pem = Zeroizing::new(format!("{}{chain}", *private_pem));
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).map_err(io::Error::other)?;
        Ok(Fixture {
            pem,
            chain,
            certificate: certificate.der().clone(),
            roots,
        })
    }

    fn current_fixture() -> io::Result<Fixture> {
        let now = UnixTime::now().as_secs();
        make_fixture(
            DOMAIN,
            now.saturating_sub(60),
            now.checked_add(3600)
                .ok_or_else(|| io::Error::other("test clock overflow"))?,
        )
    }

    #[test]
    fn certificate_metadata_tracks_only_successfully_published_normal_identity() -> io::Result<()> {
        use crate::manage::certificates::State;
        let tls = Tls::new(DOMAIN.to_owned())?;
        assert_eq!(tls.certificate(), State::Pending);
        let challenge = tls.challenge(&[7; 32])?;
        assert_eq!(tls.certificate(), State::Pending);
        let fixture = current_fixture()?;
        let expected = State::from_leaf(fixture.certificate.as_ref());
        tls.publish(identity(
            fixture.pem.as_bytes(),
            DOMAIN,
            &fixture.roots,
            UnixTime::now(),
        )?)?;
        assert_eq!(tls.certificate(), expected);
        drop(challenge);
        let _replacement = tls.challenge(&[8; 32])?;
        assert_eq!(tls.certificate(), expected);
        let expired = make_fixture(DOMAIN, 1_700_000_000, 1_700_000_060)?;
        let loaded = identity(
            expired.pem.as_bytes(),
            DOMAIN,
            &expired.roots,
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_030)),
        )?;
        assert!(tls.publish(loaded).is_err());
        assert_eq!(tls.certificate(), expected);
        Ok(())
    }

    fn normal_client(roots: RootCertStore, protocols: &[&[u8]]) -> io::Result<ClientConfig> {
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(io::Error::other)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = protocols.iter().map(|value| value.to_vec()).collect();
        config.resumption = Resumption::disabled();
        config.enable_early_data = false;
        Ok(config)
    }

    fn challenge_certificate(tls: &Tls) -> io::Result<CertificateDer<'static>> {
        let state = tls
            .state
            .lock()
            .map_err(|_| io::Error::other("test lock poisoned"))?;
        Ok(state
            .challenge
            .as_ref()
            .ok_or_else(|| io::Error::other("test challenge missing"))?
            .certificate
            .clone())
    }

    // The challenge deliberately has an unknown critical extension and no CA
    // trust. Pin its exact locally generated DER, then verify the real TLS
    // CertificateVerify signature with that DER's key, never an accept-all hook.
    #[derive(Debug)]
    struct PinnedChallenge(CertificateDer<'static>);

    impl ServerCertVerifier for PinnedChallenge {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            if end_entity != &self.0
                || !intermediates.is_empty()
                || !matches!(server_name, ServerName::DnsName(name) if name.as_ref().eq_ignore_ascii_case(DOMAIN))
            {
                return Err(rustls::Error::General("untrusted challenge fixture".into()));
            }
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _certificate: &CertificateDer<'_>,
            _signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General(
                "TLS 1.2 is disabled for this challenge fixture".into(),
            ))
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            certificate: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            if certificate != &self.0 {
                return Err(rustls::Error::General(
                    "untrusted challenge signing fixture".into(),
                ));
            }
            let (_, parsed) = x509_parser::parse_x509_certificate(certificate)
                .map_err(|_| rustls::Error::General("invalid challenge fixture DER".into()))?;
            let spki = rustls_pki_types::SubjectPublicKeyInfoDer::from(parsed.public_key().raw);
            rustls::crypto::verify_tls13_signature_with_raw_key(
                message,
                &spki,
                signature,
                &aws_lc_rs::default_provider().signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    fn challenge_client(
        certificate: CertificateDer<'static>,
        protocols: &[&[u8]],
    ) -> io::Result<ClientConfig> {
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(io::Error::other)?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedChallenge(certificate)))
                .with_no_client_auth();
        config.alpn_protocols = protocols.iter().map(|value| value.to_vec()).collect();
        config.resumption = Resumption::disabled();
        config.enable_early_data = false;
        Ok(config)
    }

    type Connections = (
        io::Result<Option<TlsStream<TcpStream>>>,
        io::Result<ClientStream<TcpStream>>,
    );

    async fn connect(tls: &Tls, client: ClientConfig, name: &str) -> io::Result<Connections> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let (client_io, (server_io, _)) = tokio::try_join!(
                TcpStream::connect(listener.local_addr()?),
                listener.accept()
            )?;
            let connector = TlsConnector::from(Arc::new(client));
            let name = ServerName::try_from(name.to_owned()).map_err(io::Error::other)?;
            Ok(tokio::join!(
                tls.accept(server_io),
                connector.connect(name, client_io)
            ))
        })
        .await
        .map_err(io::Error::other)?
    }

    /// Reuse one protocol configuration across normal publications. The full
    /// handshake must select the new key without rebuilding the listener, and
    /// must never resolve the simultaneously active challenge identity.
    #[tokio::test]
    async fn proxy_resolver_follows_only_valid_normal_publications() -> io::Result<()> {
        let tls = Tls::new(DOMAIN.into())?;
        let managed = crate::manage::proxy::settings::Tls::Acme(tls.clone());
        let _challenge = tls.challenge(&[6; 32])?;
        assert!(managed.identity().is_err());
        let first = current_fixture()?;
        tls.publish(identity(
            first.pem.as_bytes(),
            DOMAIN,
            &first.roots,
            UnixTime::now(),
        )?)?;
        let resolver = managed.identity()?.resolver();
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(io::Error::other)?
                .with_no_client_auth()
                .with_cert_resolver(resolver);
        config.alpn_protocols = vec![HTTP_ALPN.to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let second = current_fixture()?;
        for fixture in [&first, &second] {
            tls.publish(identity(
                fixture.pem.as_bytes(),
                DOMAIN,
                &fixture.roots,
                UnixTime::now(),
            )?)?;
            assert_eq!(managed.source(), crate::manage::certificates::Source::Acme);
            assert_eq!(
                managed.certificate(),
                crate::manage::certificates::State::from_leaf(fixture.certificate.as_ref())
            );
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let connector = TlsConnector::from(Arc::new(normal_client(
                fixture.roots.clone(),
                &[HTTP_ALPN],
            )?));
            let (client_io, (server_io, _)) = tokio::try_join!(
                TcpStream::connect(listener.local_addr()?),
                listener.accept()
            )?;
            let name = ServerName::try_from(DOMAIN).map_err(io::Error::other)?;
            let (server, client) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(
                    acceptor.accept(server_io),
                    connector.connect(name, client_io)
                )
            })
            .await
            .map_err(io::Error::other)?;
            let _server = server?;
            let client = client?;
            assert_eq!(
                client
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|chain| chain.first()),
                Some(&fixture.certificate)
            );
        }
        // Expiry is checked by the normal-only resolver, not only by clients.
        tls.state
            .lock()
            .map_err(|_| io::Error::other("fixture lock"))?
            .normal
            .as_mut()
            .ok_or_else(|| io::Error::other("normal fixture missing"))?
            .not_after = 0;
        assert!(managed.identity().is_err());
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let connector = TlsConnector::from(Arc::new(normal_client(second.roots, &[HTTP_ALPN])?));
        let (client_io, (server_io, _)) = tokio::try_join!(
            TcpStream::connect(listener.local_addr()?),
            listener.accept()
        )?;
        let name = ServerName::try_from(DOMAIN).map_err(io::Error::other)?;
        let (server, client) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                acceptor.accept(server_io),
                connector.connect(name, client_io)
            )
        })
        .await
        .map_err(io::Error::other)?;
        assert!(server.is_err() && client.is_err());
        Ok(())
    }

    #[test]
    fn identity_checks_pair_name_roots_signature_and_requested_time() -> io::Result<()> {
        let now = 1_800_000_000;
        let fixture = make_fixture(DOMAIN, now - 60, now + 60)?;
        let time = UnixTime::since_unix_epoch(Duration::from_secs(now));
        let loaded = identity(fixture.pem.as_bytes(), DOMAIN, &fixture.roots, time)?;
        assert_eq!((loaded.not_before, loaded.not_after), (now - 60, now + 60));
        assert_eq!(loaded.key.cert[0], fixture.certificate);
        assert!(identity(fixture.pem.as_bytes(), "other.test", &fixture.roots, time).is_err());
        assert!(
            identity(
                fixture.pem.as_bytes(),
                DOMAIN,
                &RootCertStore::empty(),
                time
            )
            .is_err()
        );
        for seconds in [now - 61, now + 61] {
            assert!(
                identity(
                    fixture.pem.as_bytes(),
                    DOMAIN,
                    &fixture.roots,
                    UnixTime::since_unix_epoch(Duration::from_secs(seconds))
                )
                .is_err()
            );
        }
        let other_key = Zeroizing::new(
            KeyPair::generate()
                .map_err(io::Error::other)?
                .serialize_pem(),
        );
        let mismatched = Zeroizing::new(format!("{}{}", fixture.chain, *other_key));
        assert!(identity(mismatched.as_bytes(), DOMAIN, &fixture.roots, time).is_err());
        let mut corrupted = fixture.certificate.as_ref().to_vec();
        *corrupted
            .last_mut()
            .ok_or_else(|| io::Error::other("test DER empty"))? ^= 1;
        let tampered = Zeroizing::new(format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n{}",
            STANDARD.encode(corrupted),
            *fixture.pem,
        ));
        assert!(identity(tampered.as_bytes(), DOMAIN, &fixture.roots, time).is_err());
        Ok(())
    }

    #[test]
    fn identity_rejects_excessive_missing_extra_and_hidden_key_input() -> io::Result<()> {
        let fixture = current_fixture()?;
        for pem in [
            String::new(),
            fixture.chain.clone(),
            format!("{}{}", *fixture.pem, *fixture.pem),
            format!(
                "{}-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----\n",
                *fixture.pem
            ),
            format!(
                "{}-----BEGIN PRIVATE KEY-----\n%%%\n-----END PRIVATE KEY-----\n",
                fixture.chain
            ),
        ] {
            let pem = Zeroizing::new(pem);
            assert!(identity(pem.as_bytes(), DOMAIN, &fixture.roots, UnixTime::now()).is_err());
        }
        assert!(
            identity(
                &vec![b'x'; MAX_IDENTITY_BYTES + 1],
                DOMAIN,
                &fixture.roots,
                UnixTime::now()
            )
            .is_err()
        );
        for domain in [
            "127.0.0.1",
            "*.management.test",
            "management.test.",
            "",
            "münich.test",
        ] {
            assert!(Tls::new(domain.to_owned()).is_err());
        }
        Ok(())
    }

    #[test]
    fn challenge_has_exact_san_critical_digest_and_real_self_signature() -> io::Result<()> {
        let tls = Tls::new(DOMAIN.to_owned())?;
        assert!(tls.challenge(&[0; 31]).is_err());
        let digest = [17; 32];
        let _guard = tls.challenge(&digest)?;
        let certificate = challenge_certificate(&tls)?;
        let (remainder, parsed) =
            x509_parser::parse_x509_certificate(&certificate).map_err(io::Error::other)?;
        assert!(remainder.is_empty());
        assert_eq!(parsed.subject(), parsed.issuer());
        let san = parsed
            .subject_alternative_name()
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::other("test SAN missing"))?;
        assert_eq!(
            san.value.general_names,
            vec![x509_parser::extensions::GeneralName::DNSName(DOMAIN)]
        );
        let extensions: Vec<_> = parsed
            .extensions()
            .iter()
            .filter(|extension| extension.oid.to_id_string() == ACME_IDENTIFIER)
            .collect();
        assert_eq!(extensions.len(), 1);
        assert!(extensions[0].critical);
        assert_eq!(extensions[0].value, [&[0x04, 0x20][..], &digest].concat());
        assert!(
            aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .all
                .iter()
                .any(|algorithm| {
                    algorithm
                        .verify_signature(
                            parsed.public_key().subject_public_key.data.as_ref(),
                            parsed.tbs_certificate.as_ref(),
                            parsed.signature_value.data.as_ref(),
                        )
                        .is_ok()
                })
        );
        assert!(leaf_metadata(&certificate, DOMAIN).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn challenge_isolated_from_http_and_old_guard_cannot_clear_replacement() -> io::Result<()>
    {
        let fixture = current_fixture()?;
        let tls = Tls::new(DOMAIN.to_owned())?;
        tls.publish(identity(
            fixture.pem.as_bytes(),
            DOMAIN,
            &fixture.roots,
            UnixTime::now(),
        )?)?;
        let old = tls.challenge(&[1; 32])?;
        let old_certificate = challenge_certificate(&tls)?;
        let current = tls.challenge(&[2; 32])?;
        let certificate = challenge_certificate(&tls)?;
        assert_ne!(certificate, old_certificate);
        drop(old);
        assert_eq!(challenge_certificate(&tls)?, certificate);
        let (server, client) = connect(
            &tls,
            challenge_client(old_certificate, &[ACME_ALPN])?,
            DOMAIN,
        )
        .await?;
        assert!(server.is_err());
        assert!(client.is_err());
        let (server, client) = connect(
            &tls,
            challenge_client(certificate.clone(), &[ACME_ALPN])?,
            "other.test",
        )
        .await?;
        assert!(server.is_err());
        assert!(client.is_err());
        let (server, client) = connect(
            &tls,
            challenge_client(certificate.clone(), &[ACME_ALPN])?,
            DOMAIN,
        )
        .await?;
        assert!(server?.is_none());
        let mut client = client?;
        assert_eq!(client.get_ref().1.alpn_protocol(), Some(ACME_ALPN));
        assert_eq!(
            client.get_ref().1.peer_certificates(),
            Some(&[certificate.clone()][..])
        );
        let mut byte = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), client.read(&mut byte))
                .await
                .map_err(io::Error::other)??,
            0
        );
        for protocols in [&[ACME_ALPN, HTTP_ALPN][..], &[HTTP_ALPN, ACME_ALPN][..]] {
            let (server, client) = connect(
                &tls,
                challenge_client(certificate.clone(), protocols)?,
                DOMAIN,
            )
            .await?;
            assert!(server.is_err());
            assert!(client.is_err());
        }
        let (server, client) = connect(
            &tls,
            normal_client(fixture.roots.clone(), &[b"h2", HTTP_ALPN])?,
            DOMAIN,
        )
        .await?;
        let mut server = server?.ok_or_else(|| io::Error::other("HTTP was routed to challenge"))?;
        let mut client = client?;
        assert_eq!(
            client
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first()),
            Some(&fixture.certificate)
        );
        assert_eq!(client.get_ref().1.alpn_protocol(), Some(HTTP_ALPN));
        client.write_all(b"HTTP").await?;
        client.flush().await?;
        let mut received = [0; 4];
        tokio::time::timeout(Duration::from_secs(5), server.read_exact(&mut received))
            .await
            .map_err(io::Error::other)??;
        assert_eq!(&received, b"HTTP");
        drop(current);
        let (server, client) =
            connect(&tls, challenge_client(certificate, &[ACME_ALPN])?, DOMAIN).await?;
        assert!(server.is_err());
        assert!(client.is_err());
        let (server, client) =
            connect(&tls, normal_client(fixture.roots, &[HTTP_ALPN])?, DOMAIN).await?;
        assert!(server?.is_some());
        assert!(client.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn http_without_alpn_uses_only_the_valid_normal_identity() -> io::Result<()> {
        let fixture = current_fixture()?;
        let tls = Tls::new(DOMAIN.to_owned())?;
        let challenge = tls.challenge(&[3; 32])?;
        let (server, client) =
            connect(&tls, normal_client(fixture.roots.clone(), &[])?, DOMAIN).await?;
        assert!(server.is_err());
        assert!(client.is_err());
        drop(challenge);
        tls.publish(identity(
            fixture.pem.as_bytes(),
            DOMAIN,
            &fixture.roots,
            UnixTime::now(),
        )?)?;
        for active_challenge in [false, true] {
            let _challenge = if active_challenge {
                Some(tls.challenge(&[4; 32])?)
            } else {
                None
            };
            let (server, client) =
                connect(&tls, normal_client(fixture.roots.clone(), &[])?, DOMAIN).await?;
            let mut server =
                server?.ok_or_else(|| io::Error::other("HTTP was routed to challenge"))?;
            let mut client = client?;
            assert_eq!(server.get_ref().1.alpn_protocol(), None);
            assert_eq!(client.get_ref().1.alpn_protocol(), None);
            assert_eq!(
                client
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|chain| chain.first()),
                Some(&fixture.certificate)
            );
            client.write_all(b"HTTP").await?;
            client.flush().await?;
            let mut received = [0; 4];
            tokio::time::timeout(Duration::from_secs(5), server.read_exact(&mut received))
                .await
                .map_err(io::Error::other)??;
            assert_eq!(&received, b"HTTP");
        }
        Ok(())
    }

    #[tokio::test]
    async fn ordinary_tls_fails_closed_for_sni_unsupported_alpn_missing_or_expired_identity()
    -> io::Result<()> {
        let fixture = current_fixture()?;
        let tls = Tls::new(DOMAIN.to_owned())?;
        let (server, client) = connect(
            &tls,
            normal_client(fixture.roots.clone(), &[HTTP_ALPN])?,
            DOMAIN,
        )
        .await?;
        assert!(server.is_err());
        assert!(client.is_err());
        tls.publish(identity(
            fixture.pem.as_bytes(),
            DOMAIN,
            &fixture.roots,
            UnixTime::now(),
        )?)?;
        for (name, protocols, sni) in [
            ("other.test", vec![HTTP_ALPN], true),
            (DOMAIN, vec![HTTP_ALPN], false),
            (DOMAIN, vec![&b"h2"[..]], true),
        ] {
            let mut config = normal_client(fixture.roots.clone(), &protocols)?;
            config.enable_sni = sni;
            let (server, client) = connect(&tls, config, name).await?;
            assert!(server.is_err());
            assert!(client.is_err());
            if protocols == [b"h2".as_slice()] {
                let error = client
                    .err()
                    .ok_or_else(|| io::Error::other("missing ALPN alert"))?;
                assert!(matches!(
                    error
                        .get_ref()
                        .and_then(|error| error.downcast_ref::<rustls::Error>()),
                    Some(rustls::Error::AlertReceived(
                        rustls::AlertDescription::NoApplicationProtocol
                    ))
                ));
            }
        }
        let expired = make_fixture(DOMAIN, 1_700_000_000, 1_700_000_060)?;
        let loaded = identity(
            expired.pem.as_bytes(),
            DOMAIN,
            &expired.roots,
            UnixTime::since_unix_epoch(Duration::from_secs(1_700_000_030)),
        )?;
        assert!(tls.publish(loaded).is_err());
        let (server, client) = connect(
            &tls,
            normal_client(fixture.roots.clone(), &[HTTP_ALPN])?,
            DOMAIN,
        )
        .await?;
        assert!(server?.is_some());
        assert!(client.is_ok());
        tls.state
            .lock()
            .map_err(|_| io::Error::other("test lock poisoned"))?
            .normal
            .as_mut()
            .ok_or_else(|| io::Error::other("test identity missing"))?
            .not_after = 0;
        let (server, client) =
            connect(&tls, normal_client(fixture.roots, &[HTTP_ALPN])?, DOMAIN).await?;
        assert!(server.is_err());
        assert!(client.is_err());
        Ok(())
    }
}
