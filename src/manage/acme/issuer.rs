//! Restartable ACME issuance. Local intent precedes every non-idempotent order.

use std::{io, time::Duration};

use instant_acme::{
    Account, AuthorizationStatus, ChallengeStatus, ChallengeType, Identifier, Key, NewOrder, Order,
    OrderStatus, RetryPolicy,
};
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, ExtendedKeyUsagePurpose,
    KeyPair, KeyUsagePurpose, PublicKeyData as _, SanType,
};
use rustls::{RootCertStore, crypto::aws_lc_rs};
use rustls_pki_types::{CertificateSigningRequestDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use serde::{Deserialize, Serialize};
use x509_parser::prelude::FromDer as _;
use zeroize::{Zeroize as _, Zeroizing};

use super::{Challenge, Client, Config, Io, Tls};

pub(super) const MAX_WORK_BYTES: usize = 64 * 1024;
const MAX_KEY_BYTES: usize = 16 * 1024;
const MAX_CSR_BYTES: usize = 16 * 1024;
const MAX_URL_BYTES: usize = 8192;
const MAX_IDENTITY_BYTES: usize = 256 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct Secret(String);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Intent,
    Ordered,
    Complete,
    Failed,
}

/// Parse local state using the same key/CSR/domain/CA/URL checks as issuance.
/// This observes only a local phase, not the CA's current order status.
pub(super) fn recovery_phase(bytes: &[u8], config: &Config) -> io::Result<Phase> {
    Ok(Work::decode(bytes, config)?.phase)
}

/// Permit only the complete saved result of this exact Intent. URL validation
/// belongs to Work::decode; equality below additionally forbids substituting a
/// different valid leaf key or CSR. No CA/account history is inferred offline.
pub(super) fn check_order_candidate(
    intent: &[u8],
    candidate: &[u8],
    config: &Config,
) -> io::Result<()> {
    let intent = Work::decode(intent, config)?;
    let candidate = Work::decode(candidate, config)?;
    if intent.phase != Phase::Intent
        || candidate.phase != Phase::Ordered
        || intent.version != candidate.version
        || intent.domain != candidate.domain
        || intent.directory != candidate.directory
        || intent.key_pem.0 != candidate.key_pem.0
        || intent.csr != candidate.csr
    {
        return Err(pause(
            "ACME temporary is not this saved intent's ordered result",
        ));
    }
    Ok(())
}

/// Validate the same supported PKCS8 account format used by the CA client.
/// A valid current key is not proof that this account existed when Intent was
/// written: version 1 Work does not contain a historical account fingerprint.
pub(super) fn account_key(bytes: &[u8]) -> io::Result<Key> {
    if bytes.is_empty() || bytes.len() > MAX_KEY_BYTES {
        return Err(pause("invalid ACME saved account key size"));
    }
    Key::from_pkcs8_der(PrivatePkcs8KeyDer::from(bytes))
        .map_err(|_| pause("invalid ACME saved account key"))
}

/// Named, zeroizing journal buffers used only by isolated recovery fixtures.
#[cfg(test)]
pub(super) struct RecoveryMaterial {
    pub(super) intent: Zeroizing<Vec<u8>>,
    pub(super) ordered: Zeroizing<Vec<u8>>,
}

/// Matching journal stages built with the real leaf-key/CSR encoder. Test
/// material keeps the same zeroizing owners without exposing production Work.
#[cfg(test)]
pub(super) fn recovery_material(config: &Config) -> io::Result<RecoveryMaterial> {
    let mut work = Work::new(config)?;
    let intent = work.encode()?;
    work.phase = Phase::Ordered;
    let directory = url::Url::parse(&config.directory).map_err(|_| pause("invalid test CA"))?;
    work.order_url = Some(format!(
        "{}/order/1",
        directory.origin().ascii_serialization()
    ));
    Ok(RecoveryMaterial {
        intent,
        ordered: work.encode()?,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Work {
    version: u8,
    domain: String,
    directory: String,
    key_pem: Secret,
    csr: Vec<u8>,
    phase: Phase,
    order_url: Option<String>,
}

impl Work {
    fn new(config: &Config) -> io::Result<Self> {
        let key = Zeroizing::new(
            KeyPair::generate().map_err(|_| retry("ACME leaf key generation failed"))?,
        );
        let mut parameters = CertificateParams::new(vec![config.domain.clone()])
            .map_err(|_| pause("invalid ACME CSR domain"))?;
        parameters.distinguished_name = DistinguishedName::new();
        parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let request = parameters
            .serialize_request(&*key)
            .map_err(|_| pause("ACME CSR generation failed"))?;
        Ok(Self {
            version: 1,
            domain: config.domain.clone(),
            directory: config.directory.clone(),
            key_pem: Secret(key.serialize_pem()),
            csr: request.der().to_vec(),
            phase: Phase::Intent,
            order_url: None,
        })
    }

    fn decode(bytes: &[u8], config: &Config) -> io::Result<Self> {
        if bytes.len() > MAX_WORK_BYTES {
            return Err(pause("ACME saved order exceeds its input limit"));
        }
        let work: Self =
            serde_json::from_slice(bytes).map_err(|_| pause("invalid ACME saved order format"))?;
        work.validate(config)?;
        Ok(work)
    }

    fn validate(&self, config: &Config) -> io::Result<()> {
        if self.version != 1
            || self.domain != config.domain
            || self.directory != config.directory
            || self.key_pem.0.len() > MAX_KEY_BYTES
            || self.csr.is_empty()
            || self.csr.len() > MAX_CSR_BYTES
        {
            return Err(pause("ACME saved order does not match its configuration"));
        }
        match (self.phase, self.order_url.as_deref()) {
            (Phase::Intent, None) => {}
            (Phase::Ordered | Phase::Complete | Phase::Failed, Some(url)) => {
                resource_url(url, config)?
            }
            _ => return Err(pause("inconsistent ACME saved order phase")),
        }
        let mut reader = self.key_pem.0.as_bytes();
        if !reader.starts_with(b"-----BEGIN PRIVATE KEY-----") {
            return Err(pause("ACME saved leaf key requires PKCS8 PEM"));
        }
        let Some(rustls_pemfile::Item::Pkcs8Key(key)) = rustls_pemfile::read_one(&mut reader)
            .map_err(|_| pause("invalid ACME saved leaf key"))?
        else {
            return Err(pause("ACME saved leaf key requires PKCS8"));
        };
        let key = Zeroizing::new(key);
        if !reader.iter().all(u8::is_ascii_whitespace) {
            return Err(pause("ACME saved leaf key has extra input"));
        }
        let borrowed_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.secret_pkcs8_der()));
        let signer = aws_lc_rs::sign::any_supported_type(&borrowed_key)
            .map_err(|_| pause("invalid ACME saved leaf key"))?;
        let (remaining, _) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&self.csr)
                .map_err(|_| pause("invalid ACME saved CSR"))?;
        if !remaining.is_empty() {
            return Err(pause("ACME saved CSR has trailing data"));
        }
        // rcgen verifies the CSR signature before exposing its requested SANs.
        let request = CertificateSigningRequestParams::from_der(
            &CertificateSigningRequestDer::from(self.csr.as_slice()),
        )
        .map_err(|_| pause("invalid ACME saved CSR signature or extensions"))?;
        let spki = request.public_key.subject_public_key_info();
        if !matches!(&request.params.subject_alt_names[..], [SanType::DnsName(name)] if name.as_str() == config.domain)
            || signer.public_key().as_ref().map(|value| value.as_ref()) != Some(spki.as_slice())
        {
            return Err(pause("ACME saved CSR does not match its domain and key"));
        }
        Ok(())
    }

    fn resume_url(&self) -> io::Result<Option<&str>> {
        match self.phase {
            Phase::Intent => Err(pause(
                "ACME new order outcome is unknown; saved intent requires review",
            )),
            Phase::Ordered => self
                .order_url
                .as_deref()
                .map(Some)
                .ok_or_else(|| pause("ACME saved order URL is missing")),
            Phase::Complete | Phase::Failed => Ok(None),
        }
    }

    fn encode(&self) -> io::Result<Zeroizing<Vec<u8>>> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(self).map_err(|_| pause("ACME order serialization failed"))?,
        );
        if bytes.len() > MAX_WORK_BYTES {
            return Err(pause("ACME saved order exceeds its output limit"));
        }
        Ok(bytes)
    }
}

enum Installed {
    Tls { _guard: super::tls::ChallengeGuard },
    Http { _guard: super::http::Guard },
}

/// Run under the supervisor's single cancellation/120-second budget. Account
/// registration reuses its durable key; an unfinished order always reuses its
/// durable URL, CSR and leaf key. A URL-less saved intent needs operator review.
/// Only completed issuance or an explicitly invalid order permits fresh work.
/// Returned identities are already durable, but publication belongs to the caller.
pub(super) async fn issue(
    config: &Config,
    client: Client,
    io: &Io,
    tls: &Tls,
    http: &super::http::Http,
    roots: &RootCertStore,
) -> io::Result<super::tls::Identity> {
    validate_config(config)?;
    let account_der = io.load("account.der").await.map_err(cache_error)?;
    let saved_order = io.load("order.json").await.map_err(cache_error)?;
    let saved_identity = io.load("identity.pem").await.map_err(cache_error)?;
    account_state(
        account_der.is_some(),
        saved_order.is_some(),
        saved_identity.is_some(),
    )?;
    let saved_work = saved_order
        .as_ref()
        .map(|bytes| Work::decode(bytes, config))
        .transpose()?;
    if let Some(work) = &saved_work {
        work.resume_url()?;
    }
    drop(saved_order);
    drop(saved_identity);
    let (key, mut key_der) = match account_der {
        Some(mut bytes) => {
            let key = account_key(bytes.as_slice())?;
            (
                key,
                Zeroizing::new(PrivatePkcs8KeyDer::from(std::mem::take(&mut *bytes))),
            )
        }
        None => {
            let (key, key_der) =
                Key::generate_pkcs8().map_err(|_| retry("ACME account key generation failed"))?;
            let key_der = Zeroizing::new(key_der);
            io.create(
                "account.der",
                Zeroizing::new(key_der.secret_pkcs8_der().to_vec()),
            )
            .await
            .map_err(cache_error)?;
            (key, key_der)
        }
    };
    // instant-acme requires ownership and returns opaque credentials containing
    // DER. Its internal key buffers are the library's cleanup boundary; avoid
    // serializing another private credential copy that is not needed to resume.
    let owned_key = std::mem::replace(&mut *key_der, PrivatePkcs8KeyDer::from(Vec::new()));
    let (account, credentials) = Account::builder_with_http(Box::new(client))
        .create_from_key(
            (key, PrivateKeyDer::Pkcs8(owned_key)),
            config.directory.clone(),
        )
        .await
        .map_err(|_| retry("ACME account registration is unavailable"))?;
    drop(credentials);
    let contacts: Vec<_> = config.contacts.iter().map(String::as_str).collect();
    account
        .update_contacts(&contacts)
        .await
        .map_err(|_| retry("ACME contact update is unavailable"))?;

    let had_work = saved_work.is_some();
    let (mut work, mut order) = if let Some(work) = saved_work
        && let Some(url) = work.resume_url()?
    {
        let order = account
            .order(url.to_owned())
            .await
            .map_err(|_| retry("ACME saved order is unavailable"))?;
        (work, order)
    } else {
        let mut work = Work::new(config)?;
        // RFC 8555 §7.4 newOrder is not idempotent. A crash after this commit
        // but before the URL commit must never silently create another order.
        // https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
        if had_work {
            io.replace("order.json", work.encode()?)
                .await
                .map_err(cache_error)?;
        } else {
            io.create("order.json", work.encode()?)
                .await
                .map_err(cache_error)?;
        }
        let identifiers = [Identifier::Dns(config.domain.clone())];
        let order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|_| {
                pause("ACME new order outcome is unknown; saved intent requires review")
            })?;
        resource_url(order.url(), config)?;
        work.order_url = Some(order.url().to_owned());
        work.phase = Phase::Ordered;
        io.replace("order.json", work.encode()?)
            .await
            .map_err(|_| {
                pause("ACME order URL durability is unknown; saved intent requires review")
            })?;
        (work, order)
    };

    if order.state().status == OrderStatus::Invalid {
        return invalid_order(&mut work, io).await;
    }
    let _challenge = authorize(&mut order, config, tls, http).await?;
    let retries = RetryPolicy::new()
        .initial_delay(Duration::from_secs(1))
        .backoff(1.5)
        .timeout(Duration::from_secs(120));
    if order.state().status == OrderStatus::Pending && order.poll_ready(&retries).await.is_err() {
        if order.state().status == OrderStatus::Invalid {
            return invalid_order(&mut work, io).await;
        }
        return Err(retry("ACME order readiness is unavailable"));
    }
    match order.state().status {
        OrderStatus::Invalid => return invalid_order(&mut work, io).await,
        OrderStatus::Ready => {
            if order.finalize_csr(&work.csr).await.is_err() {
                if order.state().status == OrderStatus::Invalid {
                    return invalid_order(&mut work, io).await;
                }
                return Err(retry("ACME order finalization is unavailable"));
            }
        }
        OrderStatus::Processing | OrderStatus::Valid => {}
        _ => return Err(retry("ACME order is not ready")),
    }
    let chain = match order.poll_certificate(&retries).await {
        Ok(chain) => chain,
        Err(_) if order.state().status == OrderStatus::Invalid => {
            return invalid_order(&mut work, io).await;
        }
        Err(_) => return Err(retry("ACME certificate is unavailable")),
    };
    let length = work
        .key_pem
        .0
        .len()
        .checked_add(chain.len())
        .ok_or_else(|| pause("ACME issued identity exceeds its input limit"))?;
    if length > MAX_IDENTITY_BYTES {
        return Err(pause("ACME issued identity exceeds its input limit"));
    }
    let mut pem = Zeroizing::new(Vec::with_capacity(length));
    pem.extend_from_slice(work.key_pem.0.as_bytes());
    pem.extend_from_slice(chain.as_bytes());
    let identity = super::tls::identity(&pem, &config.domain, roots, UnixTime::now())
        .map_err(|_| pause("ACME issued identity failed verification"))?;
    io.replace("identity.pem", pem).await.map_err(cache_error)?;
    work.phase = Phase::Complete;
    io.replace("order.json", work.encode()?)
        .await
        .map_err(cache_error)?;
    Ok(identity)
}

async fn authorize(
    order: &mut Order,
    config: &Config,
    tls: &Tls,
    http: &super::http::Http,
) -> io::Result<Option<Installed>> {
    if order.state().authorizations.len() != 1 {
        return Err(pause("ACME order requires exactly one authorization"));
    }
    let order_status = order.state().status;
    let mut authorizations = order.authorizations();
    let mut authorization = authorizations
        .next()
        .await
        .ok_or_else(|| pause("ACME order authorization is missing"))?
        .map_err(|_| retry("ACME authorization is unavailable"))?;
    let identifier = authorization.identifier();
    if identifier.wildcard
        || !matches!(identifier.identifier, Identifier::Dns(name) if name == &config.domain)
    {
        return Err(pause(
            "ACME authorization does not match its single DNS domain",
        ));
    }
    if authorization.status == AuthorizationStatus::Valid {
        return Ok(None);
    }
    if order_status != OrderStatus::Pending || authorization.status != AuthorizationStatus::Pending
    {
        return Err(pause("ACME authorization is not pending or valid"));
    }
    let challenge_type = match config.challenge {
        Challenge::TlsAlpn01 => ChallengeType::TlsAlpn01,
        Challenge::Http01 => ChallengeType::Http01,
    };
    let mut challenge = authorization
        .challenge(challenge_type)
        .ok_or_else(|| pause("configured ACME challenge is unavailable"))?;
    if challenge.status == ChallengeStatus::Invalid {
        return Err(retry("ACME challenge is invalid; saved order retained"));
    }
    let key_authorization = challenge.key_authorization();
    let installed = match config.challenge {
        Challenge::TlsAlpn01 => Installed::Tls {
            _guard: tls
                .challenge(key_authorization.digest().as_ref())
                .map_err(|_| pause("ACME TLS challenge installation failed"))?,
        },
        Challenge::Http01 => Installed::Http {
            _guard: http
                .challenge(&challenge.token, key_authorization.as_str())
                .map_err(|_| pause("ACME HTTP challenge installation failed"))?,
        },
    };
    if challenge.status == ChallengeStatus::Pending {
        challenge
            .set_ready()
            .await
            .map_err(|_| retry("ACME challenge notification is unavailable"))?;
    }
    Ok(Some(installed))
}

async fn invalid_order(work: &mut Work, io: &Io) -> io::Result<super::tls::Identity> {
    work.phase = Phase::Failed;
    io.replace("order.json", work.encode()?)
        .await
        .map_err(cache_error)?;
    Err(retry(
        "ACME order is explicitly invalid; failure state saved",
    ))
}

fn account_state(account: bool, order: bool, identity: bool) -> io::Result<()> {
    if !account && (order || identity) {
        return Err(pause(
            "ACME account key is missing while saved issuance state exists",
        ));
    }
    Ok(())
}

fn validate_config(config: &Config) -> io::Result<()> {
    if config.domain.len() > 253
        || !config.domain.contains('.')
        || config.domain.parse::<std::net::IpAddr>().is_ok()
        || config.domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(pause(
            "ACME issuer requires one explicit non-wildcard DNS name",
        ));
    }
    resource_url(&config.directory, config)
}

fn resource_url(value: &str, config: &Config) -> io::Result<()> {
    if value.len() > MAX_URL_BYTES || config.directory.len() > MAX_URL_BYTES {
        return Err(pause("ACME resource URL exceeds its input limit"));
    }
    let directory =
        url::Url::parse(&config.directory).map_err(|_| pause("invalid ACME directory URL"))?;
    let url = url::Url::parse(value).map_err(|_| pause("invalid ACME resource URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.origin() != directory.origin()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
        || url.as_str() != value
        || !directory.username().is_empty()
        || directory.password().is_some()
        || directory.fragment().is_some()
    {
        return Err(pause(
            "ACME resource URL is outside its configured HTTPS origin",
        ));
    }
    Ok(())
}

fn cache_error(error: io::Error) -> io::Error {
    match error.kind() {
        io::ErrorKind::PermissionDenied
        | io::ErrorKind::InvalidInput
        | io::ErrorKind::InvalidData
        | io::ErrorKind::AlreadyExists => pause("ACME cache requires operator review"),
        _ => retry("ACME cache persistence is unavailable; saved work retained"),
    }
}

fn pause(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn retry(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        net::{Ipv4Addr, SocketAddr},
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use bytes::Bytes;
    use http::{Request, Response, StatusCode, header};
    use http_body_util::{BodyExt as _, Full, Limited};
    use hyper::{body::Incoming, service::service_fn};
    use hyper_util::rt::TokioIo;
    use rcgen::{BasicConstraints, IsCa, Issuer};
    use rustls::{
        ClientConfig, ServerConfig,
        sign::{CertifiedKey, SingleCertAndKey},
    };
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
        sync::{Notify, Semaphore},
        task::JoinSet,
        time::timeout,
    };
    use tokio_rustls::TlsAcceptor;
    use tokio_util::sync::CancellationToken;

    use super::*;

    fn config() -> Config {
        Config {
            domain: "management.test".to_owned(),
            directory: "https://ca.test/directory".to_owned(),
            contacts: Vec::new(),
            challenge: Challenge::TlsAlpn01,
            http_bind: None,
            production: false,
        }
    }

    #[test]
    fn durable_phases_distinguish_unknown_resume_and_finished_work() -> io::Result<()> {
        let config = config();
        let mut work = Work::new(&config)?;
        assert_eq!(
            work.resume_url().err().map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        let bytes = work.encode()?;
        let restored = Work::decode(&bytes, &config)?;
        assert_eq!(restored.csr, work.csr);
        assert!(restored.key_pem.0 == work.key_pem.0);
        assert!(restored.resume_url().is_err());
        work.phase = Phase::Ordered;
        work.order_url = Some("https://ca.test/order/1".to_owned());
        let restored = Work::decode(&work.encode()?, &config)?;
        assert_eq!(restored.resume_url()?, Some("https://ca.test/order/1"));
        assert_eq!(restored.csr, work.csr);
        for phase in [Phase::Complete, Phase::Failed] {
            work.phase = phase;
            assert_eq!(Work::decode(&work.encode()?, &config)?.resume_url()?, None);
        }
        Ok(())
    }

    #[test]
    fn saved_csr_requires_its_real_signature_exact_domain_and_key() -> io::Result<()> {
        let config = config();
        let mut work = Work::new(&config)?;
        work.validate(&config)?;
        let other = Work::new(&config)?;
        let original = std::mem::replace(&mut work.key_pem, Secret(other.key_pem.0.clone()));
        assert!(work.validate(&config).is_err());
        work.key_pem = original;
        let last = work
            .csr
            .last_mut()
            .ok_or_else(|| io::Error::other("test CSR missing"))?;
        *last ^= 1;
        assert!(work.validate(&config).is_err());
        let mut work = Work::new(&config)?;
        let mut changed = config.clone();
        changed.domain = "other.test".to_owned();
        work.domain = changed.domain.clone();
        assert!(work.validate(&changed).is_err());
        work.csr.push(0);
        assert!(work.validate(&changed).is_err());
        Ok(())
    }

    #[test]
    fn saved_schema_configuration_and_url_fail_closed() -> io::Result<()> {
        let config = config();
        let mut work = Work::new(&config)?;
        let encoded = work.encode()?;
        let mut with_unknown = Zeroizing::new(encoded.to_vec());
        with_unknown.pop();
        with_unknown.extend_from_slice(b",\"unexpected\":true}");
        assert!(Work::decode(&with_unknown, &config).is_err());
        work.version = 2;
        assert!(Work::decode(&work.encode()?, &config).is_err());
        work.version = 1;
        work.phase = Phase::Ordered;
        assert!(Work::decode(&work.encode()?, &config).is_err());
        for url in [
            "http://ca.test/order/1",
            "https://other.test/order/1",
            "https://ca.test/order/1#fragment",
            "https://user@ca.test/order/1",
        ] {
            work.order_url = Some(url.to_owned());
            assert!(Work::decode(&work.encode()?, &config).is_err());
        }
        assert!(Work::decode(&vec![b'x'; MAX_WORK_BYTES + 1], &config).is_err());
        Ok(())
    }

    #[test]
    fn missing_account_never_resets_existing_order_or_identity() {
        for (order, identity) in [(true, false), (false, true), (true, true)] {
            assert_eq!(
                account_state(false, order, identity)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::PermissionDenied)
            );
        }
        assert!(account_state(false, false, false).is_ok());
        assert!(account_state(true, true, true).is_ok());
        assert_eq!(
            cache_error(io::Error::other("fixture")).kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            cache_error(io::Error::from(io::ErrorKind::PermissionDenied)).kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    // This fixture implements only the protocol messages exercised below, not
    // a reusable ACME server. All sockets, roots, keys and cache paths are owned
    // by the test. No public CA, installed trust or external fixture is used.
    struct Authority {
        parameters: CertificateParams,
        key: Zeroizing<KeyPair>,
        certificate: rcgen::Certificate,
    }

    impl Authority {
        fn new() -> io::Result<Self> {
            let key = Zeroizing::new(KeyPair::generate().map_err(io::Error::other)?);
            let mut parameters = CertificateParams::default();
            parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let certificate = parameters.self_signed(&*key).map_err(io::Error::other)?;
            Ok(Self {
                parameters,
                key,
                certificate,
            })
        }

        fn sign(&self, csr: &[u8], domain: &str) -> io::Result<String> {
            let mut request = CertificateSigningRequestParams::from_der(&csr.into())
                .map_err(|_| io::Error::other("fixture CSR signature rejected"))?;
            if !matches!(&request.params.subject_alt_names[..], [SanType::DnsName(name)] if name.as_str() == domain)
            {
                return Err(io::Error::other("fixture CSR SAN rejected"));
            }
            let now = i64::try_from(UnixTime::now().as_secs()).map_err(io::Error::other)?;
            request.params.not_before = time::OffsetDateTime::from_unix_timestamp(
                now.checked_sub(60)
                    .ok_or_else(|| io::Error::other("fixture clock underflow"))?,
            )
            .map_err(io::Error::other)?;
            request.params.not_after = time::OffsetDateTime::from_unix_timestamp(
                now.checked_add(3600)
                    .ok_or_else(|| io::Error::other("fixture clock overflow"))?,
            )
            .map_err(io::Error::other)?;
            let certificate = request
                .signed_by(&Issuer::from_params(&self.parameters, &*self.key))
                .map_err(io::Error::other)?;
            Ok(format!("{}{}", certificate.pem(), self.certificate.pem()))
        }
    }

    #[derive(Default)]
    struct Seen {
        requests: usize,
        new_orders: usize,
        order_reads: usize,
        finalizations: usize,
        http_validations: usize,
        account_hash: Option<[u8; 32]>,
        thumbprint: Option<String>,
        ready: bool,
        certificate: Option<String>,
        csr: Vec<u8>,
    }

    struct Ca {
        origin: String,
        config: Config,
        io: Io,
        http_address: SocketAddr,
        authority: Authority,
        seen: Mutex<Seen>,
        hold_finalize: AtomicBool,
        finalized: Notify,
        release: Notify,
    }

    impl Ca {
        /// The fake CA is an independent read-only observer, not another user
        /// of the client's reserved persistence slot during a network request.
        async fn load(&self, name: &'static str) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
            let cache = self.io.cache.clone();
            tokio::task::spawn_blocking(move || cache.load(name))
                .await
                .map_err(|_| io::Error::other("fixture cache observer failed"))?
        }

        fn order(&self) -> io::Result<Value> {
            let seen = self
                .seen
                .lock()
                .map_err(|_| io::Error::other("fixture state poisoned"))?;
            Ok(json!({
                "status": if seen.certificate.is_some() { "valid" } else if seen.ready { "ready" } else { "pending" },
                "identifiers": [{"type":"dns","value":self.config.domain}],
                "authorizations": [format!("{}/authorization/1", self.origin)],
                "finalize": format!("{}/finalize/1", self.origin),
                "certificate": seen.certificate.as_ref().map(|_| format!("{}/certificate/1", self.origin)),
            }))
        }

        async fn handle(&self, request: Request<Incoming>) -> io::Result<Response<Full<Bytes>>> {
            // Even the very first directory GET must observe the flushed key,
            // proving registration cannot get ahead of local account authority.
            let der = self.load("account.der").await?.ok_or_else(|| {
                io::Error::other("fixture received request before durable account key")
            })?;
            let account_key = Key::from_pkcs8_der(PrivatePkcs8KeyDer::from(der.as_slice()))
                .map_err(|_| io::Error::other("fixture durable account key is invalid"))?;
            drop(account_key);
            let hash: [u8; 32] = Sha256::digest(&*der).into();
            let nonce = {
                let mut seen = self
                    .seen
                    .lock()
                    .map_err(|_| io::Error::other("fixture state poisoned"))?;
                if seen.account_hash.is_some_and(|previous| previous != hash) {
                    return Err(io::Error::other("fixture account key changed"));
                }
                seen.account_hash = Some(hash);
                seen.requests += 1;
                format!("fixture-nonce-{}", seen.requests)
            };
            let path = request.uri().path().to_owned();
            let body = Limited::new(request.into_body(), 64 * 1024)
                .collect()
                .await
                .map_err(|_| io::Error::other("fixture request body failed"))?
                .to_bytes();
            let (protected, payload) = if body.is_empty() {
                (Value::Null, Value::Null)
            } else {
                jws(&body)?
            };
            let mut location = None;
            let mut content_type = "application/json";
            let (status, body) = match path.as_str() {
                "/directory" => (
                    StatusCode::OK,
                    serde_json::to_vec(&json!({
                        "newNonce":format!("{}/nonce", self.origin),
                        "newAccount":format!("{}/account", self.origin),
                        "newOrder":format!("{}/new-order", self.origin),
                    }))
                    .map_err(io::Error::other)?,
                ),
                "/nonce" => (StatusCode::OK, Vec::new()),
                "/account" => {
                    let jwk = &protected["jwk"];
                    let x = jwk["x"]
                        .as_str()
                        .ok_or_else(|| io::Error::other("fixture JWK missing"))?;
                    let y = jwk["y"]
                        .as_str()
                        .ok_or_else(|| io::Error::other("fixture JWK missing"))?;
                    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.as_slice()));
                    let signer =
                        aws_lc_rs::sign::any_supported_type(&key).map_err(io::Error::other)?;
                    let spki = signer
                        .public_key()
                        .ok_or_else(|| io::Error::other("fixture SPKI missing"))?;
                    let (_, public) =
                        x509_parser::x509::SubjectPublicKeyInfo::from_der(spki.as_ref())
                            .map_err(|_| io::Error::other("fixture SPKI invalid"))?;
                    let point = public.subject_public_key.data.as_ref();
                    if point.len() != 65
                        || point[0] != 4
                        || jwk["crv"] != "P-256"
                        || jwk["kty"] != "EC"
                        || URL_SAFE_NO_PAD.encode(&point[1..33]) != x
                        || URL_SAFE_NO_PAD.encode(&point[33..]) != y
                    {
                        return Err(io::Error::other(
                            "fixture JWK does not match durable account key",
                        ));
                    }
                    let thumb = URL_SAFE_NO_PAD.encode(Sha256::digest(
                        format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}")
                            .as_bytes(),
                    ));
                    self.seen
                        .lock()
                        .map_err(|_| io::Error::other("fixture state poisoned"))?
                        .thumbprint = Some(thumb);
                    location = Some(format!("{}/account/1", self.origin));
                    (StatusCode::CREATED, br#"{"status":"valid"}"#.to_vec())
                }
                "/account/1" => (StatusCode::OK, br#"{"status":"valid"}"#.to_vec()),
                "/new-order" => {
                    if payload["identifiers"] != json!([{"type":"dns","value":self.config.domain}])
                    {
                        return Err(io::Error::other("fixture order identifier rejected"));
                    }
                    let bytes = self.load("order.json").await?.ok_or_else(|| {
                        io::Error::other("fixture order arrived before durable intent")
                    })?;
                    let work = Work::decode(&bytes, &self.config)?;
                    if work.phase != Phase::Intent || work.order_url.is_some() {
                        return Err(io::Error::other("fixture expected durable URL-less intent"));
                    }
                    self.seen
                        .lock()
                        .map_err(|_| io::Error::other("fixture state poisoned"))?
                        .new_orders += 1;
                    location = Some(format!("{}/order/1", self.origin));
                    (
                        StatusCode::CREATED,
                        serde_json::to_vec(&self.order()?).map_err(io::Error::other)?,
                    )
                }
                "/order/1" => {
                    self.seen
                        .lock()
                        .map_err(|_| io::Error::other("fixture state poisoned"))?
                        .order_reads += 1;
                    (
                        StatusCode::OK,
                        serde_json::to_vec(&self.order()?).map_err(io::Error::other)?,
                    )
                }
                "/authorization/1" => {
                    let ready = self
                        .seen
                        .lock()
                        .map_err(|_| io::Error::other("fixture state poisoned"))?
                        .ready;
                    (StatusCode::OK, serde_json::to_vec(&json!({
                        "identifier":{"type":"dns","value":self.config.domain},
                        "status":if ready { "valid" } else { "pending" },
                        "wildcard":false,
                        "challenges":[{"type":"http-01","url":format!("{}/challenge/1", self.origin),
                            "status":if ready { "valid" } else { "pending" },"token":"fixture-token-1"}],
                    })).map_err(io::Error::other)?)
                }
                "/challenge/1" => {
                    let thumbprint = self
                        .seen
                        .lock()
                        .map_err(|_| io::Error::other("fixture state poisoned"))?
                        .thumbprint
                        .clone()
                        .ok_or_else(|| io::Error::other("fixture account thumbprint missing"))?;
                    let body = http_challenge(self.http_address, &self.config.domain).await?;
                    if body != format!("fixture-token-1.{thumbprint}").as_bytes() {
                        return Err(io::Error::other(
                            "fixture real HTTP-01 key authorization rejected",
                        ));
                    }
                    {
                        let mut seen = self
                            .seen
                            .lock()
                            .map_err(|_| io::Error::other("fixture state poisoned"))?;
                        seen.http_validations += 1;
                        seen.ready = true;
                    }
                    (
                        StatusCode::OK,
                        serde_json::to_vec(&json!({
                            "type":"http-01","url":format!("{}/challenge/1", self.origin),
                            "status":"valid","token":"fixture-token-1",
                        }))
                        .map_err(io::Error::other)?,
                    )
                }
                "/finalize/1" => {
                    let encoded = payload["csr"]
                        .as_str()
                        .ok_or_else(|| io::Error::other("fixture CSR missing"))?;
                    let csr = URL_SAFE_NO_PAD.decode(encoded).map_err(io::Error::other)?;
                    let bytes = self
                        .load("order.json")
                        .await?
                        .ok_or_else(|| io::Error::other("fixture finalize lacks durable order"))?;
                    let work = Work::decode(&bytes, &self.config)?;
                    if work.phase != Phase::Ordered
                        || work.csr != csr
                        || work.order_url.as_deref()
                            != Some(format!("{}/order/1", self.origin).as_str())
                    {
                        return Err(io::Error::other(
                            "fixture finalize changed durable CSR or order",
                        ));
                    }
                    let certificate = self.authority.sign(&csr, &self.config.domain)?;
                    {
                        let mut seen = self
                            .seen
                            .lock()
                            .map_err(|_| io::Error::other("fixture state poisoned"))?;
                        if !seen.ready {
                            return Err(io::Error::other(
                                "fixture finalized before HTTP validation",
                            ));
                        }
                        seen.finalizations += 1;
                        seen.csr = csr;
                        seen.certificate = Some(certificate);
                    }
                    self.finalized.notify_one();
                    if self.hold_finalize.swap(false, Ordering::SeqCst) {
                        self.release.notified().await;
                    }
                    (
                        StatusCode::OK,
                        serde_json::to_vec(&self.order()?).map_err(io::Error::other)?,
                    )
                }
                "/certificate/1" => {
                    content_type = "application/pem-certificate-chain";
                    let certificate = self
                        .seen
                        .lock()
                        .map_err(|_| io::Error::other("fixture state poisoned"))?
                        .certificate
                        .clone()
                        .ok_or_else(|| io::Error::other("fixture certificate not ready"))?;
                    (StatusCode::OK, certificate.into_bytes())
                }
                _ => return Err(io::Error::other("unexpected fixture resource")),
            };
            let mut response = Response::builder()
                .status(status)
                .header("replay-nonce", nonce)
                .header(header::CONTENT_TYPE, content_type);
            if let Some(location) = location {
                response = response.header(header::LOCATION, location);
            }
            response
                .body(Full::new(Bytes::from(body)))
                .map_err(io::Error::other)
        }
    }

    fn jws(body: &[u8]) -> io::Result<(Value, Value)> {
        let envelope: Value = serde_json::from_slice(body).map_err(io::Error::other)?;
        let decode = |name: &str| -> io::Result<Value> {
            let value = envelope[name]
                .as_str()
                .ok_or_else(|| io::Error::other("fixture JWS missing field"))?;
            if value.is_empty() {
                return Ok(Value::Null);
            }
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(value).map_err(io::Error::other)?)
                .map_err(io::Error::other)
        };
        Ok((decode("protected")?, decode("payload")?))
    }

    async fn http_challenge(address: SocketAddr, domain: &str) -> io::Result<Vec<u8>> {
        timeout(Duration::from_secs(5), async {
            let mut stream = TcpStream::connect(address).await?;
            stream.write_all(format!(
                "GET /.well-known/acme-challenge/fixture-token-1 HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
            ).as_bytes()).await?;
            let mut bytes = Vec::new();
            stream.take(4097).read_to_end(&mut bytes).await?;
            if bytes.len() > 4096 || !bytes.starts_with(b"HTTP/1.1 200 ") {
                return Err(io::Error::other("fixture HTTP-01 response rejected"));
            }
            let end = bytes.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                .ok_or_else(|| io::Error::other("fixture HTTP-01 headers missing"))?;
            Ok(bytes[end + 4..].to_vec())
        }).await.map_err(io::Error::other)?
    }

    struct Running {
        path: Option<PathBuf>,
        config: Config,
        io: Io,
        tls: Tls,
        http: super::super::http::Http,
        client: Client,
        roots: RootCertStore,
        ca: Arc<Ca>,
        shutdown: CancellationToken,
        tasks: JoinSet<io::Result<()>>,
    }

    impl Running {
        async fn new(hold_finalize: bool) -> io::Result<Self> {
            let mut random = [0; 16];
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("fixture entropy unavailable"))?;
            let path = std::env::temp_dir().join(format!(
                "vproxy-acme-issuer-{:032x}",
                u128::from_ne_bytes(random)
            ));
            super::super::super::files::create_directory(&path)?;
            let http_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let ca_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let mut config = config();
            let origin = format!("https://{}", ca_listener.local_addr()?);
            config.directory = format!("{origin}/directory");
            config.challenge = Challenge::Http01;
            config.http_bind = Some(http_listener.local_addr()?);
            let author = Arc::new(super::super::super::store::lock(&path)?);
            let cache = super::super::storage::Cache::open(
                &path,
                author,
                &super::super::namespace(&config),
            )?;
            let io = Io {
                cache,
                capacity: Arc::new(Semaphore::new(1)),
            };
            let http = super::super::http::Http::new(config.domain.clone());
            let tls = Tls::new(config.domain.clone())?;
            let authority = Authority::new()?;
            let mut roots = RootCertStore::empty();
            roots
                .add(authority.certificate.der().clone())
                .map_err(io::Error::other)?;
            let (server, client) = ca_tls(&config.directory, io.clone())?;
            let ca = Arc::new(Ca {
                origin,
                config: config.clone(),
                io: io.clone(),
                http_address: http_listener.local_addr()?,
                authority,
                seen: Mutex::new(Seen::default()),
                hold_finalize: AtomicBool::new(hold_finalize),
                finalized: Notify::new(),
                release: Notify::new(),
            });
            let shutdown = CancellationToken::new();
            let mut tasks = JoinSet::new();
            tasks.spawn(http.clone().serve(http_listener, shutdown.clone()));
            tasks.spawn(serve_ca(ca_listener, server, ca.clone(), shutdown.clone()));
            Ok(Self {
                path: Some(path),
                config,
                io,
                tls,
                http,
                client,
                roots,
                ca,
                shutdown,
                tasks,
            })
        }

        async fn issue(&self) -> io::Result<super::super::tls::Identity> {
            issue(
                &self.config,
                self.client.clone(),
                &self.io,
                &self.tls,
                &self.http,
                &self.roots,
            )
            .await
        }

        async fn assert_durable(&self, identity: &super::super::tls::Identity) -> io::Result<()> {
            let pem = self
                .io
                .load("identity.pem")
                .await?
                .ok_or_else(|| io::Error::other("returned identity is not durable"))?;
            let loaded = super::super::tls::identity(
                &pem,
                &self.config.domain,
                &self.roots,
                UnixTime::now(),
            )?;
            assert_eq!(loaded.key.cert, identity.key.cert);
            let bytes = self
                .io
                .load("order.json")
                .await?
                .ok_or_else(|| io::Error::other("returned order is not durable"))?;
            let work = Work::decode(&bytes, &self.config)?;
            assert_eq!(work.phase, Phase::Complete);
            let seen = self
                .ca
                .seen
                .lock()
                .map_err(|_| io::Error::other("fixture state poisoned"))?;
            assert_eq!(work.csr, seen.csr);
            assert_eq!(seen.new_orders, 1);
            assert_eq!(seen.finalizations, 1);
            assert_eq!(seen.http_validations, 1);
            assert!(seen.account_hash.is_some());
            Ok(())
        }

        async fn finish(mut self) -> io::Result<()> {
            self.shutdown.cancel();
            timeout(Duration::from_secs(7), async {
                while let Some(result) = self.tasks.join_next().await {
                    result.map_err(|_| io::Error::other("fixture task failed"))??;
                }
                Ok::<_, io::Error>(())
            })
            .await
            .map_err(io::Error::other)??;
            let path = self.path.take();
            drop(self);
            if let Some(path) = path {
                // Release every cache/author clone before deleting this test's
                // private leaf, including on Windows where open locks forbid it.
                std::fs::remove_dir_all(path)?;
            }
            Ok(())
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            self.shutdown.cancel();
            self.tasks.abort_all();
            // Only the exclusively created test leaf is removed, after normal
            // finish has joined every listener/connection and cache operation.
            if let Some(path) = &self.path {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }

    fn ca_tls(directory: &str, io: Io) -> io::Result<(Arc<ServerConfig>, Client)> {
        let key = Zeroizing::new(KeyPair::generate().map_err(io::Error::other)?);
        let certificate = CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .map_err(io::Error::other)?
            .self_signed(&*key)
            .map_err(io::Error::other)?;
        let mut roots = RootCertStore::empty();
        roots
            .add(certificate.der().clone())
            .map_err(io::Error::other)?;
        let signer = aws_lc_rs::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(key.serialized_der()),
        ))
        .map_err(io::Error::other)?;
        let mut server =
            ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(io::Error::other)?
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(SingleCertAndKey::from(CertifiedKey::new(
                    vec![certificate.der().clone()],
                    signer,
                ))));
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut client =
            ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(io::Error::other)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        client.resumption = rustls::client::Resumption::disabled();
        Ok((
            Arc::new(server),
            Client::new(directory, Arc::new(client), io)?,
        ))
    }

    async fn serve_ca(
        listener: TcpListener,
        tls: Arc<ServerConfig>,
        ca: Arc<Ca>,
        shutdown: CancellationToken,
    ) -> io::Result<()> {
        let acceptor = TlsAcceptor::from(tls);
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                Some(joined) = connections.join_next(), if !connections.is_empty() => {
                    joined.map_err(|_| io::Error::other("fixture CA connection task failed"))??;
                },
                incoming = listener.accept() => {
                    let (stream, _) = incoming?;
                    let acceptor = acceptor.clone();
                    let ca = ca.clone();
                    connections.spawn(async move {
                        let stream = acceptor.accept(stream).await?;
                        let service = service_fn(move |request| {
                            let ca = ca.clone();
                            async move {
                                let response = ca.handle(request).await.unwrap_or_else(|_| {
                                    let mut response = Response::new(Full::new(Bytes::from_static(b"fixture request rejected")));
                                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                    response
                                });
                                Ok::<_, Infallible>(response)
                            }
                        });
                        // A cancelled request may close before consuming the
                        // already-committed fake-CA result. That is intentional.
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service).await;
                        Ok::<_, io::Error>(())
                    });
                },
            }
        }
        connections.abort_all();
        while let Some(joined) = connections.join_next().await {
            match joined {
                Ok(result) => result?,
                Err(error) if error.is_cancelled() => {}
                Err(_) => return Err(io::Error::other("fixture CA connection task failed")),
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn actual_sdk_https_http01_issues_and_commits_before_return() -> io::Result<()> {
        let fixture = Running::new(false).await?;
        let identity = timeout(Duration::from_secs(15), fixture.issue())
            .await
            .map_err(io::Error::other)??;
        fixture.assert_durable(&identity).await?;
        let requests = fixture
            .ca
            .seen
            .lock()
            .map_err(|_| io::Error::other("fixture state poisoned"))?
            .requests;
        let cache_before = [
            fixture.io.load("account.der").await?,
            fixture.io.load("order.json").await?,
            fixture.io.load("identity.pem").await?,
            fixture.io.load("retry.json").await?,
        ];
        let mut runner = super::super::Runner {
            config: fixture.config.clone(),
            io: fixture.io.clone(),
            client: fixture.client.clone(),
            roots: Arc::new(fixture.roots.clone()),
            tls: Tls::new(fixture.config.domain.clone())?,
            http: fixture.http.clone(),
            due: 0,
            status: super::super::Handle::new(false, fixture.config.challenge, None, 0),
        };
        let status = runner.status.clone();
        let due = runner
            .recover()
            .await?
            .ok_or_else(|| io::Error::other("fixture durable identity was not recovered"))?;
        assert!(due > UnixTime::now().as_secs());
        let recovered = serde_json::to_value(status.view()?).map_err(io::Error::other)?;
        assert_eq!(recovered["certificate"]["available"], true);
        assert!(recovered["last_failure"].is_null());
        let observation = status.observation()?;
        assert_eq!(
            observation.certificate,
            Some((identity.not_before, identity.not_after))
        );
        assert_eq!(observation.activation_seq, 1);
        assert_eq!(observation.result_seq, 0);
        assert!(observation.last_failure.is_none() && !observation.stopped);
        assert_eq!(
            fixture
                .ca
                .seen
                .lock()
                .map_err(|_| io::Error::other("fixture state poisoned"))?
                .requests,
            requests
        );
        runner.due = due;
        let shutdown = CancellationToken::new();
        let mut running = Box::pin(runner.run(shutdown.clone()));
        assert!(
            timeout(Duration::from_millis(40), running.as_mut())
                .await
                .is_err()
        );
        let waiting = serde_json::to_value(status.view()?).map_err(io::Error::other)?;
        assert_eq!(waiting["activity"], "waiting");
        assert_eq!(waiting["next_attempt_at_unix_s"], due.to_string());
        let waiting = status.observation()?;
        assert_eq!(waiting.activation_seq, observation.activation_seq);
        assert_eq!(waiting.result_seq, observation.result_seq);
        shutdown.cancel();
        timeout(Duration::from_secs(5), running.as_mut())
            .await
            .map_err(io::Error::other)??;
        drop(running);
        assert_eq!(
            serde_json::to_value(status.view()?).map_err(io::Error::other)?["activity"],
            "stopped"
        );
        let stopped = status.observation()?;
        assert!(stopped.stopped && stopped.last_failure.is_none());
        assert_eq!(stopped.certificate, observation.certificate);
        assert_eq!(stopped.activation_seq, observation.activation_seq);
        assert_eq!(stopped.result_seq, observation.result_seq);
        assert_eq!(
            fixture
                .ca
                .seen
                .lock()
                .map_err(|_| io::Error::other("fixture state poisoned"))?
                .requests,
            requests
        );
        // These explicit test reads measure the unchanged durable inputs;
        // typed observations above do not touch the cache or fake CA.
        for (name, before) in ["account.der", "order.json", "identity.pem", "retry.json"]
            .into_iter()
            .zip(cache_before)
        {
            let after = fixture.io.load(name).await?;
            assert!(after.as_deref().map(Vec::as_slice) == before.as_deref().map(Vec::as_slice));
        }
        fixture.finish().await
    }

    #[test]
    fn expired_cache_is_historically_verified_but_cannot_be_published() -> io::Result<()> {
        let authority = Authority::new()?;
        let domain = config().domain;
        let key = Zeroizing::new(KeyPair::generate().map_err(io::Error::other)?);
        let mut parameters =
            CertificateParams::new(vec![domain.clone()]).map_err(io::Error::other)?;
        parameters.is_ca = IsCa::ExplicitNoCa;
        parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        parameters.not_before = rcgen::date_time_ymd(2020, 1, 1);
        parameters.not_after = rcgen::date_time_ymd(2021, 1, 1);
        let certificate = parameters
            .signed_by(
                &*key,
                &Issuer::from_params(&authority.parameters, &*authority.key),
            )
            .map_err(io::Error::other)?;
        let private_pem = Zeroizing::new(key.serialize_pem());
        let pem = Zeroizing::new(format!(
            "{}{}{}",
            *private_pem,
            certificate.pem(),
            authority.certificate.pem()
        ));
        let mut roots = RootCertStore::empty();
        roots
            .add(authority.certificate.der().clone())
            .map_err(io::Error::other)?;
        let today = UnixTime::now();
        let identity = super::super::cached_identity(pem.as_bytes(), &domain, &roots, today)?;
        assert!(identity.not_after < today.as_secs());
        assert!(Tls::new(domain.clone())?.publish(identity).is_err());
        assert!(super::super::tls::identity(pem.as_bytes(), &domain, &roots, today).is_err());
        assert!(
            super::super::cached_identity(pem.as_bytes(), "other.test", &roots, today).is_err()
        );
        let mut corrupted = certificate.der().to_vec();
        *corrupted
            .last_mut()
            .ok_or_else(|| io::Error::other("fixture certificate missing"))? ^= 1;
        let tampered = Zeroizing::new(format!(
            "{}-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n{}",
            *private_pem,
            base64::engine::general_purpose::STANDARD.encode(corrupted),
            authority.certificate.pem(),
        ));
        assert!(
            super::super::cached_identity(tampered.as_bytes(), &domain, &roots, today).is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_finalization_resumes_same_order_and_unknown_intent_never_connects()
    -> io::Result<()> {
        let mut fixture = Running::new(true).await?;
        let mut attempt = Box::pin(fixture.issue());
        timeout(Duration::from_secs(10), async {
            tokio::select! {
                _ = fixture.ca.finalized.notified() => Ok(()),
                _ = attempt.as_mut() => Err(io::Error::other("fixture expected a pending finalization response")),
            }
        }).await.map_err(io::Error::other)??;
        assert!(
            timeout(Duration::from_millis(20), attempt.as_mut())
                .await
                .is_err()
        );
        drop(attempt);
        let bytes = fixture
            .io
            .load("order.json")
            .await?
            .ok_or_else(|| io::Error::other("fixture order missing"))?;
        let work = Work::decode(&bytes, &fixture.config)?;
        assert_eq!(work.phase, Phase::Ordered);
        assert_eq!(
            work.order_url.as_deref(),
            Some(format!("{}/order/1", fixture.ca.origin).as_str())
        );
        fixture.ca.release.notify_one();
        let identity = timeout(Duration::from_secs(15), fixture.issue())
            .await
            .map_err(io::Error::other)??;
        fixture.assert_durable(&identity).await?;
        assert!(
            fixture
                .ca
                .seen
                .lock()
                .map_err(|_| io::Error::other("fixture state poisoned"))?
                .order_reads
                > 0
        );
        let mut work = Work::decode(
            &fixture
                .io
                .load("order.json")
                .await?
                .ok_or_else(|| io::Error::other("fixture order missing"))?,
            &fixture.config,
        )?;
        work.phase = Phase::Intent;
        work.order_url = None;
        let intent = work.encode()?;
        fixture
            .io
            .replace("order.json", Zeroizing::new(intent.to_vec()))
            .await?;
        let requests = fixture
            .ca
            .seen
            .lock()
            .map_err(|_| io::Error::other("fixture state poisoned"))?
            .requests;
        let cache_before = [
            fixture.io.load("account.der").await?,
            fixture.io.load("order.json").await?,
            fixture.io.load("identity.pem").await?,
            fixture.io.load("retry.json").await?,
        ];
        assert_eq!(
            fixture.issue().await.err().map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        assert_eq!(
            fixture
                .ca
                .seen
                .lock()
                .map_err(|_| io::Error::other("fixture state poisoned"))?
                .requests,
            requests
        );
        assert!(
            fixture
                .io
                .load("order.json")
                .await?
                .is_some_and(|bytes| *bytes == *intent)
        );
        // The actual runner can recover the saved identity without resolving
        // an unknown order. The failed issuance remains visible while waiting
        // for the recovered identity's exact renewal time; no CA retry occurs.
        let status = super::super::Handle::new(false, fixture.config.challenge, None, 0);
        let runner = super::super::Runner {
            config: fixture.config.clone(),
            io: fixture.io.clone(),
            client: fixture.client.clone(),
            roots: Arc::new(fixture.roots.clone()),
            tls: Tls::new(fixture.config.domain.clone())?,
            http: fixture.http.clone(),
            due: 0,
            status: status.clone(),
        };
        fixture.tasks.spawn(runner.run(fixture.shutdown.clone()));
        let observed = timeout(Duration::from_secs(5), async {
            loop {
                let view = serde_json::to_value(status.view()?).map_err(io::Error::other)?;
                if view["activity"] == "stopped" {
                    return Err(io::Error::other(
                        "fixture runner stopped before observation",
                    ));
                }
                if view["activity"] == "waiting" && view["last_failure"] == "review_required" {
                    return Ok::<_, io::Error>(view);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(io::Error::other);
        let final_requests = fixture
            .ca
            .seen
            .lock()
            .map_err(|_| io::Error::other("fixture state poisoned"))?
            .requests;
        let observation = status.observation();
        let cache_preserved = async {
            for (name, before) in ["account.der", "order.json", "identity.pem", "retry.json"]
                .into_iter()
                .zip(cache_before)
            {
                let after = fixture.io.load(name).await?;
                if after.as_deref().map(Vec::as_slice) != before.as_deref().map(Vec::as_slice) {
                    return Ok(false);
                }
            }
            Ok::<_, io::Error>(true)
        }
        .await;
        let finished = fixture.finish().await;
        let view = observed??;
        assert_eq!(view["certificate"]["available"], true);
        assert!(
            view["next_attempt_at_unix_s"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|due| due > UnixTime::now().as_secs())
        );
        assert_eq!(final_requests, requests);
        let observation = observation?;
        assert_eq!(
            observation.certificate,
            Some((identity.not_before, identity.not_after))
        );
        assert_eq!(observation.activation_seq, 1);
        assert_eq!(observation.result_seq, 1);
        assert!(matches!(
            observation.last_failure,
            Some(super::super::Failure::ReviewRequired)
        ));
        assert!(!observation.stopped);
        assert!(cache_preserved?);
        finished?;
        let stopped = serde_json::to_value(status.view()?).map_err(io::Error::other)?;
        assert_eq!(stopped["activity"], "stopped");
        assert_eq!(stopped["last_failure"], "review_required");
        let stopped = status.observation()?;
        assert!(stopped.stopped);
        assert_eq!(stopped.certificate, observation.certificate);
        assert_eq!(stopped.activation_seq, observation.activation_seq);
        assert_eq!(stopped.result_seq, observation.result_seq);
        Ok(())
    }
}
