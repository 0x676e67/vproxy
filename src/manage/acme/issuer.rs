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
