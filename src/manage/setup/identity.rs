//! Fixed, offline C6 certificate profiles; no file, database or network I/O.
//!
//! CSR signatures prove possession of the requested key, not authorization for
//! a DNS name or node role. The caller separately selects the trusted request,
//! role, name and root fingerprints. Private PEM owners are zeroized; rcgen and
//! its provider retain their own key representations, so this is not a promise
//! that every upstream allocation or process-memory copy is erased.

use std::{collections::BTreeSet, io, net::IpAddr, sync::Arc, time::Duration};

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, PublicKeyData as _, SerialNumber,
};
use rustls::{
    RootCertStore,
    client::{verify_server_cert_signed_by_trust_anchor, verify_server_name},
    crypto::aws_lc_rs,
    server::{ParsedCertificate, WebPkiClientVerifier},
};
use rustls_pemfile::Item;
use rustls_pki_types::{
    CertificateDer, CertificateSigningRequestDer, PrivateKeyDer, ServerName, UnixTime,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use x509_parser::{
    certification_request::X509CertificationRequest,
    cri_attributes::ParsedCriAttribute,
    extensions::X509Extension,
    prelude::{FromDer, X509Certificate},
    x509::{SubjectPublicKeyInfo, X509Name},
};
use zeroize::Zeroizing;

const MAX_PUBLIC_PEM: usize = 16 * 1024;
const MAX_KEY_PEM: usize = 64 * 1024;
const SKEW: u64 = 300;
const CA_SECONDS: u64 = 1_825 * 86_400;
const LEAF_SECONDS: u64 = 90 * 86_400;
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const P256: &str = "1.2.840.10045.3.1.7";
const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const EXTENSION_REQUEST: &str = "1.2.840.113549.1.9.14";
const SAN: &str = "2.5.29.17";
const KU: &str = "2.5.29.15";
const EKU: &str = "2.5.29.37";
const BC: &str = "2.5.29.19";
const SKI: &str = "2.5.29.14";
const AKI: &str = "2.5.29.35";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Role {
    Admin,
    Node,
}

pub(super) struct Generated {
    pub(super) key_pem: Zeroizing<String>,
    pub(super) request_pem: String,
}

pub(super) struct Authority {
    pub(super) key_pem: Zeroizing<String>,
    pub(super) certificate_pem: String,
}

pub(super) struct RootInfo {
    pub(super) role: Role,
    pub(super) der_sha256: String,
    pub(super) spki_sha256: String,
}

pub(super) struct RequestInfo {
    pub(super) der_sha256: String,
    pub(super) spki_sha256: String,
}

struct Root {
    role: Role,
    der: CertificateDer<'static>,
    spki: Vec<u8>,
    not_before: u64,
    not_after: u64,
}

struct Request {
    der: CertificateSigningRequestDer<'static>,
    spki: Vec<u8>,
    parsed: CertificateSigningRequestParams,
}

/// Canonicalize one explicit ASCII DNS hostname or unbracketed IP address.
/// Wildcards, URLs, lists, zone IDs, trailing dots, whitespace and ambiguous
/// dotted numeric addresses are rejected; this does not resolve DNS or prove
/// control of the supplied name. DNS names use lowercase ASCII A-labels.
pub(super) fn name(input: &str) -> io::Result<String> {
    if let Ok(address) = input.parse::<IpAddr>() {
        return Ok(address.to_string());
    }
    if input.is_empty()
        || input.len() > 253
        || input
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(invalid());
    }
    for label in input.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.starts_with(|character: char| character.is_ascii_alphanumeric())
            || !label.ends_with(|character: char| character.is_ascii_alphanumeric())
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(invalid());
        }
    }
    let canonical = input.to_ascii_lowercase();
    ServerName::try_from(canonical.as_str()).map_err(|_| invalid())?;
    Ok(canonical)
}

/// Generate a fresh P-256 root with a five-year lifetime, CA:TRUE/pathLen:0
/// and only keyCertSign. `now` is Unix seconds; all date arithmetic is checked.
/// The caller creates separate Admin and Node roots and compares their SPKIs;
/// generating a root neither installs trust nor authorizes any peer.
pub(super) fn authority(role: Role, now: u64) -> io::Result<Authority> {
    let (not_before, not_after) = period(now, CA_SECONDS)?;
    let key = KeyPair::generate().map_err(|_| invalid())?;
    let mut params = CertificateParams::default();
    params.not_before = not_before;
    params.not_after = not_after;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.serial_number = Some(serial()?);
    params.distinguished_name = distinguished(root_cn(role));
    let certificate = params.self_signed(&key).map_err(|_| invalid())?;
    let certificate_pem = certificate.pem();
    root_info(&certificate_pem, now)?;
    Ok(Authority {
        key_pem: Zeroizing::new(key.serialize_pem()),
        certificate_pem,
    })
}

/// Generate an independent P-256 key and signed PKCS#10 request for one fixed
/// role/name. No certificate is issued. The CA must still authenticate the
/// request's origin: PoP does not prove name ownership (RFC 2986 §§3–4).
/// <https://www.rfc-editor.org/rfc/rfc2986.html#section-3>.
pub(super) fn request(role: Role, requested_name: &str) -> io::Result<Generated> {
    let canonical = name(requested_name)?;
    let params = leaf_parameters(role, &canonical)?;
    let key = KeyPair::generate().map_err(|_| invalid())?;
    let request_pem = params
        .serialize_request(&key)
        .and_then(|request| request.pem())
        .map_err(|_| invalid())?;
    inspect_request(role, &canonical, &request_pem)?;
    Ok(Generated {
        key_pem: Zeroizing::new(key.serialize_pem()),
        request_pem,
    })
}

/// Check one complete, self-signed C6 root certificate and return public pins.
/// CA eligibility, key usage and current validity are checked explicitly;
/// PKIX trust anchors are inputs, not ordinary chain certificates, so WebPKI
/// chain success alone cannot establish these root properties (RFC 5280 §6.1).
/// <https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1>.
pub(super) fn root_info(ca_pem: &str, now: u64) -> io::Result<RootInfo> {
    let root = checked_root(ca_pem, now)?;
    Ok(RootInfo {
        role: root.role,
        der_sha256: hash(root.der.as_ref()),
        spki_sha256: hash(&root.spki),
    })
}

/// Validate one strict C6 CSR: exact role/name, version zero, a single unique
/// extension-request attribute, the fixed non-CA profile and a valid signature.
/// Raw attributes/extensions are checked before rcgen's convenience parser,
/// whose parsed-extension iterator otherwise hides duplicate attributes and
/// whose DER loader accepts an unused remainder.
pub(super) fn inspect_request(
    role: Role,
    requested_name: &str,
    pem: &str,
) -> io::Result<RequestInfo> {
    let request = checked_request(role, &name(requested_name)?, pem)?;
    Ok(RequestInfo {
        der_sha256: hash(request.der.as_ref()),
        spki_sha256: hash(&request.spki),
    })
}

/// Accept only the original recovery CSR template: one node SAN, digitalSignature,
/// serverAuth/clientAuth and no basicConstraints request. The issued leaf still
/// uses the ordinary explicit non-CA C6 template. No broader CSR is imported.
pub(super) fn inspect_recovery_request(name: &str, pem: &str) -> io::Result<RequestInfo> {
    let request = checked_request_for(Role::Node, &self::name(name)?, pem, true)?;
    Ok(RequestInfo {
        der_sha256: hash(request.der.as_ref()),
        spki_sha256: hash(&request.spki),
    })
}

/// Check the CA certificate against its actual P-256 private key without
/// signing a dummy certificate or changing either input.
pub(super) fn verify_authority(ca_pem: &str, key_pem: &str, now: u64) -> io::Result<()> {
    checked_authority(ca_pem, key_pem, now).map(|_| ())
}

/// Validate the CSR before comparing complete DER SubjectPublicKeyInfo with
/// the actual private key. Comparing only its inner BIT STRING would omit the
/// algorithm/curve binding (RFC 5280 §4.1.2.7).
/// <https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.7>.
pub(super) fn verify_request_key(
    role: Role,
    requested_name: &str,
    csr_pem: &str,
    key_pem: &str,
) -> io::Result<RequestInfo> {
    verify_request_key_for(role, requested_name, csr_pem, key_pem, false)
}

/// Recheck the fixed recovery CSR and compare its full SPKI with the retained
/// private key. The caller separately checks the permanent database pin.
pub(super) fn verify_recovery_request_key(
    name: &str,
    csr: &str,
    key: &str,
) -> io::Result<RequestInfo> {
    verify_request_key_for(Role::Node, name, csr, key, true)
}

fn verify_request_key_for(
    role: Role,
    requested_name: &str,
    csr_pem: &str,
    key_pem: &str,
    recovery: bool,
) -> io::Result<RequestInfo> {
    let request = checked_request_for(role, &name(requested_name)?, csr_pem, recovery)?;
    let key = checked_key(key_pem)?;
    if key.subject_public_key_info() != request.spki {
        return Err(invalid());
    }
    Ok(RequestInfo {
        der_sha256: hash(request.der.as_ref()),
        spki_sha256: hash(&request.spki),
    })
}

/// Issue one 90-day certificate using a fresh fixed template, never copying
/// the requester's CertificateParams. The root must cover the entire requested
/// leaf interval; an almost-expired root is rejected instead of silently
/// shortening validity. This does not authorize or enroll the new leaf.
pub(super) fn sign(
    role: Role,
    requested_name: &str,
    csr_pem: &str,
    ca_pem: &str,
    key_pem: &str,
    now: u64,
) -> io::Result<String> {
    sign_for(role, requested_name, csr_pem, ca_pem, key_pem, now, false)
}

/// Sign the checked recovery CSR using the ordinary non-CA node leaf profile;
/// no extension requested by the older CSR is blindly copied into the leaf.
pub(super) fn sign_recovery(
    name: &str,
    csr: &str,
    ca: &str,
    key: &str,
    now: u64,
) -> io::Result<String> {
    sign_for(Role::Node, name, csr, ca, key, now, true)
}

fn sign_for(
    role: Role,
    requested_name: &str,
    csr_pem: &str,
    ca_pem: &str,
    key_pem: &str,
    now: u64,
    recovery: bool,
) -> io::Result<String> {
    let canonical = name(requested_name)?;
    let request = checked_request_for(role, &canonical, csr_pem, recovery)?;
    let (root, key) = checked_authority(ca_pem, key_pem, now)?;
    let (not_before, not_after) = period(now, LEAF_SECONDS)?;
    let mut params = leaf_parameters(role, &canonical)?;
    params.not_before = not_before;
    params.not_after = not_after;
    params.serial_number = Some(serial()?);
    params.use_authority_key_identifier_extension = true;
    if root.role != role
        || timestamp(not_before)? < root.not_before
        || timestamp(not_after)? > root.not_after
        || request.spki == root.spki
    {
        return Err(invalid());
    }
    // Rcgen imports issuer metadata but deliberately does not check CA status,
    // validity or key matching. Those checks have already used the same bytes.
    let issuer = Issuer::from_ca_cert_der(&root.der, key).map_err(|_| invalid())?;
    let certificate = params
        .signed_by(&request.parsed.public_key, &issuer)
        .map_err(|_| invalid())?;
    let pem = certificate.pem();
    checked_leaf(role, &canonical, &root, &pem, &request.spki, now)?;
    Ok(pem)
}

/// Verify the root, signed leaf, CSR and actual private key as one identity.
/// Only the C6 direct-root profile is accepted; intermediate chains and broader
/// external templates are outside this helper. Normal WebPKI chain/time/usage
/// and reference-name verification still run after the fixed-profile checks.
pub(super) fn verify(
    role: Role,
    requested_name: &str,
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
    csr_pem: &str,
    now: u64,
) -> io::Result<()> {
    verify_for(
        role,
        requested_name,
        ca_pem,
        cert_pem,
        key_pem,
        csr_pem,
        now,
        false,
    )
}

/// Verify a newly issued C6 node leaf against the original recovery CSR/key.
/// Root eligibility, current validity, reference name and both EKUs remain the
/// same as ordinary setup; only the CSR's historical template differs.
pub(super) fn verify_recovery(
    name: &str,
    ca: &str,
    cert: &str,
    key: &str,
    csr: &str,
    now: u64,
) -> io::Result<()> {
    verify_for(Role::Node, name, ca, cert, key, csr, now, true)
}

#[allow(clippy::too_many_arguments)]
fn verify_for(
    role: Role,
    requested_name: &str,
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
    csr_pem: &str,
    now: u64,
    recovery: bool,
) -> io::Result<()> {
    let canonical = name(requested_name)?;
    let root = checked_root(ca_pem, now)?;
    let request = checked_request_for(role, &canonical, csr_pem, recovery)?;
    let key = checked_key(key_pem)?;
    if root.role != role
        || key.subject_public_key_info() != request.spki
        || request.spki == root.spki
    {
        return Err(invalid());
    }
    checked_leaf(role, &canonical, &root, cert_pem, &request.spki, now)
}

fn checked_root(pem: &str, now: u64) -> io::Result<Root> {
    let der = certificate_der(pem)?;
    let certificate = parsed_certificate(&der)?;
    let spki = certificate.public_key().raw.to_vec();
    let (not_before, not_after) = validity(&certificate, now, CA_SECONDS)?;
    if certificate.subject() != certificate.issuer() {
        return Err(invalid());
    }
    let role = if subject(certificate.subject(), root_cn(Role::Admin)).is_ok() {
        Role::Admin
    } else if subject(certificate.subject(), root_cn(Role::Node)).is_ok() {
        Role::Node
    } else {
        return Err(invalid());
    };
    let expected = vec![
        expected(KU, true, vec![0x03, 0x02, 0x02, 0x04]),
        expected(
            BC,
            true,
            vec![0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00],
        ),
        expected(SKI, false, key_identifier(&spki)),
    ];
    extensions(certificate.extensions(), &expected)?;
    certificate.verify_signature(None).map_err(|_| invalid())?;
    Ok(Root {
        role,
        der,
        spki,
        not_before,
        not_after,
    })
}

fn checked_authority(ca_pem: &str, key_pem: &str, now: u64) -> io::Result<(Root, KeyPair)> {
    let root = checked_root(ca_pem, now)?;
    let key = checked_key(key_pem)?;
    if key.subject_public_key_info() != root.spki {
        return Err(invalid());
    }
    Ok((root, key))
}

fn checked_request(role: Role, canonical: &str, pem: &str) -> io::Result<Request> {
    checked_request_for(role, canonical, pem, false)
}

fn checked_request_for(
    role: Role,
    canonical: &str,
    pem: &str,
    recovery: bool,
) -> io::Result<Request> {
    if recovery && role != Role::Node {
        return Err(invalid());
    }
    let Item::Csr(der) = single_pem(pem, "CERTIFICATE REQUEST", MAX_PUBLIC_PEM)? else {
        return Err(invalid());
    };
    let (remainder, csr) =
        X509CertificationRequest::from_der(der.as_ref()).map_err(|_| invalid())?;
    if !remainder.is_empty()
        || csr.certification_request_info.version.0 != 0
        || csr.signature_algorithm.algorithm.to_id_string() != ECDSA_SHA256
        || csr.signature_algorithm.parameters.is_some()
        || csr.signature_value.unused_bits != 0
    {
        return Err(invalid());
    }
    subject(&csr.certification_request_info.subject, leaf_cn(role))?;
    supported_spki(&csr.certification_request_info.subject_pki)?;
    let attributes = csr.certification_request_info.attributes();
    if attributes.len() != 1
        || attributes[0].oid.to_id_string() != EXTENSION_REQUEST
        || csr.certification_request_info.attributes_map().is_err()
    {
        return Err(invalid());
    }
    let ParsedCriAttribute::ExtensionRequest(requested) = attributes[0].parsed_attribute() else {
        return Err(invalid());
    };
    // Recovery predates C6 and preserved the operator's DNS letter case. Match
    // that original signed SAN exactly after comparing its canonical name;
    // do not rewrite the CSR or relax extension/DER/PoP checks.
    let requested_name = if recovery {
        let san = requested
            .extensions
            .iter()
            .find(|extension| extension.oid.to_id_string() == SAN)
            .ok_or_else(invalid)?;
        match san.parsed_extension() {
            x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
                match san.general_names.as_slice() {
                    [x509_parser::extensions::GeneralName::DNSName(actual)]
                        if name(actual)? == canonical =>
                    {
                        *actual
                    }
                    [x509_parser::extensions::GeneralName::IPAddress(actual)]
                        if canonical.parse::<IpAddr>().is_ok_and(|ip| match ip {
                            IpAddr::V4(ip) => *actual == ip.octets().as_slice(),
                            IpAddr::V6(ip) => *actual == ip.octets().as_slice(),
                        }) =>
                    {
                        canonical
                    }
                    _ => return Err(invalid()),
                }
            }
            _ => return Err(invalid()),
        }
    } else {
        canonical
    };
    let mut expected_extensions = leaf_extensions(role, requested_name, None, None)?;
    if recovery {
        expected_extensions.retain(|extension| extension.oid != BC);
    }
    extensions(&requested.extensions, &expected_extensions)?;
    // The upstream attribute view describes the first parsed SET value. Compare
    // the complete signed request-info encoding too, so hidden extra values or
    // ignored inner remainders cannot be lost by that convenience projection.
    let request_info = request_info_der(
        csr.certification_request_info.subject.as_raw(),
        csr.certification_request_info.subject_pki.raw,
        &expected_extensions,
    )?;
    if csr.certification_request_info.raw != request_info.as_slice()
        || der.as_ref() != signed_der(&request_info, &csr.signature_value.data)?.as_slice()
    {
        return Err(invalid());
    }
    csr.verify_signature().map_err(|_| invalid())?;
    let spki = csr.certification_request_info.subject_pki.raw.to_vec();
    let parsed = CertificateSigningRequestParams::from_der(&der).map_err(|_| invalid())?;
    // The conversion chooses an algorithm from the signature OID. Requiring
    // exact full SPKI preserves the curve and algorithm from the signed CSR.
    if parsed.public_key.subject_public_key_info() != spki {
        return Err(invalid());
    }
    Ok(Request { der, spki, parsed })
}

fn checked_leaf(
    role: Role,
    canonical: &str,
    root: &Root,
    pem: &str,
    spki: &[u8],
    now: u64,
) -> io::Result<()> {
    let der = certificate_der(pem)?;
    let certificate = parsed_certificate(&der)?;
    let (not_before, not_after) = validity(&certificate, now, LEAF_SECONDS)?;
    if certificate.public_key().raw != spki
        || not_before < root.not_before
        || not_after > root.not_after
    {
        return Err(invalid());
    }
    subject(certificate.subject(), leaf_cn(role))?;
    extensions(
        certificate.extensions(),
        &leaf_extensions(role, canonical, Some(spki), Some(&root.spki))?,
    )?;
    let mut roots = RootCertStore::empty();
    roots.add(root.der.clone()).map_err(|_| invalid())?;
    let roots = Arc::new(roots);
    let provider = Arc::new(aws_lc_rs::default_provider());
    let parsed = ParsedCertificate::try_from(&der).map_err(|_| invalid())?;
    let time = UnixTime::since_unix_epoch(Duration::from_secs(now));
    verify_server_cert_signed_by_trust_anchor(
        &parsed,
        &roots,
        &[],
        time,
        provider.signature_verification_algorithms.all,
    )
    .map_err(|_| invalid())?;
    let reference = ServerName::try_from(canonical).map_err(|_| invalid())?;
    verify_server_name(&parsed, &reference).map_err(|_| invalid())?;
    if role == Role::Node {
        let verifier = WebPkiClientVerifier::builder_with_provider(roots, provider)
            .build()
            .map_err(|_| invalid())?;
        verifier
            .verify_client_cert(&der, &[], time)
            .map_err(|_| invalid())?;
    }
    Ok(())
}

fn parsed_certificate<'a>(der: &'a CertificateDer<'_>) -> io::Result<X509Certificate<'a>> {
    let (remainder, certificate) =
        x509_parser::parse_x509_certificate(der.as_ref()).map_err(|_| invalid())?;
    if !remainder.is_empty()
        || certificate.version().0 != 2
        || certificate.signature_algorithm.algorithm.to_id_string() != ECDSA_SHA256
        || certificate.signature_algorithm.parameters.is_some()
        || certificate.signature_value.unused_bits != 0
        || certificate.tbs_certificate.signature != certificate.signature_algorithm
        || der.as_ref()
            != signed_der(
                certificate.tbs_certificate.as_ref(),
                &certificate.signature_value.data,
            )?
            .as_slice()
    {
        return Err(invalid());
    }
    supported_spki(certificate.public_key())?;
    let serial = certificate.raw_serial();
    if serial.is_empty()
        || serial.len() > 20
        || serial[0] & 0x80 != 0
        || serial.iter().all(|byte| *byte == 0)
    {
        return Err(invalid());
    }
    Ok(certificate)
}

fn supported_spki(spki: &SubjectPublicKeyInfo<'_>) -> io::Result<()> {
    if spki.algorithm.algorithm.to_id_string() != EC_PUBLIC_KEY
        || spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameter| parameter.as_oid().ok())
            .map(|oid| oid.to_id_string())
            .as_deref()
            != Some(P256)
        || spki.subject_public_key.unused_bits != 0
        || spki.subject_public_key.data.len() != 65
        || spki.subject_public_key.data.first() != Some(&4)
    {
        return Err(invalid());
    }
    Ok(())
}

fn checked_key(pem: &str) -> io::Result<KeyPair> {
    let Item::Pkcs8Key(key) = single_pem(pem, "PRIVATE KEY", MAX_KEY_PEM)? else {
        return Err(invalid());
    };
    let key = Zeroizing::new(PrivateKeyDer::Pkcs8(key));
    let parsed = KeyPair::try_from(&*key).map_err(|_| invalid())?;
    if parsed.algorithm() != &PKCS_ECDSA_P256_SHA256 {
        return Err(invalid());
    }
    Ok(parsed)
}

fn certificate_der(pem: &str) -> io::Result<CertificateDer<'static>> {
    let Item::X509Certificate(der) = single_pem(pem, "CERTIFICATE", MAX_PUBLIC_PEM)? else {
        return Err(invalid());
    };
    Ok(der)
}

fn single_pem(pem: &str, label: &str, bound: usize) -> io::Result<Item> {
    if pem.len() > bound {
        return Err(invalid());
    }
    let text = pem.trim_matches(|character: char| character.is_ascii_whitespace());
    let header = format!("-----BEGIN {label}-----");
    let footer = format!("-----END {label}-----");
    let body = text
        .strip_prefix(&header)
        .and_then(|body| body.strip_suffix(&footer))
        .ok_or_else(invalid)?;
    if body.is_empty()
        || !body.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'+' | b'/' | b'=' | b'\r' | b'\n' | b' ' | b'\t')
        })
    {
        return Err(invalid());
    }
    let mut bytes = text.as_bytes();
    let mut items = rustls_pemfile::read_all(&mut bytes);
    let item = items
        .next()
        .transpose()
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    if items.next().is_some() {
        return Err(invalid());
    }
    Ok(item)
}

fn leaf_parameters(role: Role, canonical: &str) -> io::Result<CertificateParams> {
    let mut params = CertificateParams::new(vec![canonical.to_owned()]).map_err(|_| invalid())?;
    params.distinguished_name = distinguished(leaf_cn(role));
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = match role {
        Role::Admin => vec![ExtendedKeyUsagePurpose::ServerAuth],
        Role::Node => vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ],
    };
    Ok(params)
}

struct Expected {
    oid: &'static str,
    critical: bool,
    value: Vec<u8>,
}

fn expected(oid: &'static str, critical: bool, value: Vec<u8>) -> Expected {
    Expected {
        oid,
        critical,
        value,
    }
}

fn extensions(actual: &[X509Extension<'_>], expected: &[Expected]) -> io::Result<()> {
    if actual.len() != expected.len() {
        return Err(invalid());
    }
    let mut seen = BTreeSet::new();
    for extension in actual {
        let oid = extension.oid.to_id_string();
        if !seen.insert(oid.clone()) {
            return Err(invalid());
        }
        let permitted = expected
            .iter()
            .find(|value| value.oid == oid)
            .ok_or_else(invalid)?;
        if extension.critical != permitted.critical || extension.value != permitted.value.as_slice()
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn leaf_extensions(
    role: Role,
    canonical: &str,
    spki: Option<&[u8]>,
    issuer: Option<&[u8]>,
) -> io::Result<Vec<Expected>> {
    // Exact DER for this narrow profile also rejects duplicate EKU values and
    // trailing data inside extnValue that parsed convenience views can hide.
    let mut eku = vec![
        0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
    ];
    if role == Role::Node {
        eku[1] = 0x14;
        eku.extend_from_slice(&[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]);
    }
    let (tag, bytes) = match canonical.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => (0x87, address.octets().to_vec()),
        Ok(IpAddr::V6(address)) => (0x87, address.octets().to_vec()),
        Err(_) => (0x82, canonical.as_bytes().to_vec()),
    };
    let san = small_tlv(0x30, &small_tlv(tag, &bytes)?)?;
    let mut values = vec![
        // Rcgen's PKCS#10 writer orders KU before SAN. Keep the canonical
        // request-info reconstruction aligned with that actual wire encoding;
        // certificate extension validation itself remains order-independent.
        expected(KU, true, vec![0x03, 0x02, 0x07, 0x80]),
        expected(SAN, false, san),
        expected(EKU, false, eku),
        expected(BC, true, vec![0x30, 0x00]),
    ];
    if let Some(spki) = spki {
        values.push(expected(SKI, false, key_identifier(spki)));
    }
    if let Some(issuer) = issuer {
        let mut value = vec![0x30, 0x16, 0x80, 0x14];
        value.extend_from_slice(&Sha256::digest(issuer)[..20]);
        values.push(expected(AKI, false, value));
    }
    Ok(values)
}

/// Encode only this fixed profile's bounded SAN/request-info TLVs, not
/// arbitrary ASN.1. The input package cap and fixed fields fit two length
/// octets; no untrusted length determines a read or unchecked allocation.
fn small_tlv(tag: u8, bytes: &[u8]) -> io::Result<Vec<u8>> {
    let length = u16::try_from(bytes.len()).map_err(|_| invalid())?;
    let mut result = Vec::with_capacity(bytes.len().checked_add(4).ok_or_else(invalid)?);
    result.push(tag);
    match length {
        0..=127 => result.push(u8::try_from(length).map_err(|_| invalid())?),
        128..=255 => {
            result.extend_from_slice(&[0x81, u8::try_from(length).map_err(|_| invalid())?])
        }
        _ => {
            result.push(0x82);
            result.extend_from_slice(&length.to_be_bytes());
        }
    }
    result.extend_from_slice(bytes);
    Ok(result)
}

/// Rebuild the complete three-field certificate/CSR envelope. The upstream
/// sequence parser discards an inner remainder, so an empty outer remainder or
/// a valid TBS signature alone would still allow unsigned fourth fields. This
/// also fixes the DER algorithm and BIT STRING encodings for the C6 profile.
fn signed_der(tbs: &[u8], signature: &[u8]) -> io::Result<Vec<u8>> {
    const ALGORITHM: &[u8] = &[
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    ];
    let mut bits = Vec::with_capacity(signature.len().checked_add(1).ok_or_else(invalid)?);
    bits.push(0);
    bits.extend_from_slice(signature);
    let bits = small_tlv(0x03, &bits)?;
    let capacity = tbs
        .len()
        .checked_add(ALGORITHM.len())
        .and_then(|length| length.checked_add(bits.len()))
        .ok_or_else(invalid)?;
    let mut body = Vec::with_capacity(capacity);
    body.extend_from_slice(tbs);
    body.extend_from_slice(ALGORITHM);
    body.extend_from_slice(&bits);
    small_tlv(0x30, &body)
}

fn request_info_der(subject: &[u8], spki: &[u8], extensions: &[Expected]) -> io::Result<Vec<u8>> {
    let mut encoded = Vec::new();
    for extension in extensions {
        let last = match extension.oid {
            SAN => 0x11,
            KU => 0x0f,
            EKU => 0x25,
            BC => 0x13,
            _ => return Err(invalid()),
        };
        let mut body = vec![0x06, 0x03, 0x55, 0x1d, last];
        if extension.critical {
            body.extend_from_slice(&[0x01, 0x01, 0xff]);
        }
        body.extend_from_slice(&small_tlv(0x04, &extension.value)?);
        encoded.extend_from_slice(&small_tlv(0x30, &body)?);
    }
    let values = small_tlv(0x31, &small_tlv(0x30, &encoded)?)?;
    let mut attribute = vec![
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,
    ];
    attribute.extend_from_slice(&values);
    let attributes = small_tlv(0xa0, &small_tlv(0x30, &attribute)?)?;
    let mut body = vec![0x02, 0x01, 0x00];
    body.extend_from_slice(subject);
    body.extend_from_slice(spki);
    body.extend_from_slice(&attributes);
    small_tlv(0x30, &body)
}

fn key_identifier(spki: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04, 0x14];
    result.extend_from_slice(&Sha256::digest(spki)[..20]);
    result
}

fn subject(actual: &X509Name<'_>, expected: &str) -> io::Result<()> {
    let mut attributes = actual.iter_attributes();
    let attribute = attributes.next().ok_or_else(invalid)?;
    if attributes.next().is_some()
        || attribute.attr_type().to_id_string() != "2.5.4.3"
        || attribute.as_str().map_err(|_| invalid())? != expected
    {
        return Err(invalid());
    }
    Ok(())
}

fn distinguished(cn: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, cn);
    name
}

fn root_cn(role: Role) -> &'static str {
    match role {
        Role::Admin => "vproxy administrator root",
        Role::Node => "vproxy node root",
    }
}
fn leaf_cn(role: Role) -> &'static str {
    match role {
        Role::Admin => "vproxy administrator HTTPS",
        Role::Node => "vproxy node",
    }
}

fn period(now: u64, lifetime: u64) -> io::Result<(OffsetDateTime, OffsetDateTime)> {
    let start = i64::try_from(now.saturating_sub(SKEW)).map_err(|_| invalid())?;
    let end =
        i64::try_from(now.checked_add(lifetime).ok_or_else(invalid)?).map_err(|_| invalid())?;
    Ok((
        OffsetDateTime::from_unix_timestamp(start).map_err(|_| invalid())?,
        OffsetDateTime::from_unix_timestamp(end).map_err(|_| invalid())?,
    ))
}

fn timestamp(value: OffsetDateTime) -> io::Result<u64> {
    u64::try_from(value.unix_timestamp()).map_err(|_| invalid())
}

fn validity(certificate: &X509Certificate<'_>, now: u64, lifetime: u64) -> io::Result<(u64, u64)> {
    let start =
        u64::try_from(certificate.validity().not_before.timestamp()).map_err(|_| invalid())?;
    let end = u64::try_from(certificate.validity().not_after.timestamp()).map_err(|_| invalid())?;
    if start > now
        || end <= now
        || end.checked_sub(start).ok_or_else(invalid)?
            > lifetime.checked_add(SKEW).ok_or_else(invalid)?
    {
        return Err(invalid());
    }
    Ok((start, end))
}

fn serial() -> io::Result<SerialNumber> {
    // Independent random serials avoid rcgen's public-key-derived default,
    // which would reuse an issuer/serial pair when the same key is renewed.
    // RFC 5280 §4.1.2.2 requires positive issuer-unique values <=20 octets.
    // <https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.2>.
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| invalid())?;
    bytes[0] &= 0x7f;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(invalid());
    }
    Ok(SerialNumber::from_slice(&bytes))
}

fn hash(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 15)]));
    }
    result
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "offline setup identity is invalid or does not match its fixed profile",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use rcgen::{Attribute, CustomExtension, PKCS_ECDSA_P384_SHA384, SanType};
    use x509_parser::asn1_rs::{Any, Tag};

    const NOW: u64 = 1_792_454_400;

    fn pem(label: &str, der: &[u8]) -> String {
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            STANDARD.encode(der)
        )
    }

    fn csr(params: &CertificateParams, key: &KeyPair) -> io::Result<String> {
        params
            .serialize_request(key)
            .and_then(|request| request.pem())
            .map_err(|_| invalid())
    }

    fn append_unsigned_outer_field(der: &[u8]) -> io::Result<Vec<u8>> {
        let (remainder, sequence) = Any::from_der(der).map_err(|_| invalid())?;
        if !remainder.is_empty() || sequence.tag() != Tag::Sequence {
            return Err(invalid());
        }
        let mut body = sequence.data.to_vec();
        body.extend_from_slice(&[0x05, 0x00]);
        small_tlv(0x30, &body)
    }

    #[test]
    fn names_are_explicit_canonical_dns_or_ip_and_cannot_supply_extra_sans() -> io::Result<()> {
        assert_eq!(name("Node.Example")?, "node.example");
        assert_eq!(name("2001:0db8:0:0:0:0:0:1")?, "2001:db8::1");
        assert_eq!(name("127.0.0.1")?, "127.0.0.1");
        for bad in [
            "",
            "node.example.",
            "*.example",
            "node,other",
            "https://node.example",
            "[::1]",
            "fe80::1%eth0",
            "node:443",
            " name",
            "name ",
            "n_ame",
            "127.000.0.1",
            "node..example",
            "名称.example",
        ] {
            assert!(name(bad).is_err(), "accepted {bad}");
        }
        let longest = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(longest.len(), 253);
        let generated = request(Role::Node, &longest)?;
        verify_request_key(
            Role::Node,
            &longest,
            &generated.request_pem,
            &generated.key_pem,
        )?;
        assert!(name(&format!("{longest}e")).is_err());
        Ok(())
    }

    #[test]
    fn both_profiles_complete_without_distributing_private_keys_or_trust() -> io::Result<()> {
        let admin = authority(Role::Admin, NOW)?;
        let node = authority(Role::Node, NOW)?;
        let admin_info = root_info(&admin.certificate_pem, NOW)?;
        let node_info = root_info(&node.certificate_pem, NOW)?;
        assert_eq!(admin_info.role, Role::Admin);
        assert_eq!(node_info.role, Role::Node);
        assert_ne!(admin_info.spki_sha256, node_info.spki_sha256);
        assert_ne!(admin_info.der_sha256, node_info.der_sha256);
        for (role, name, ca) in [
            (Role::Admin, "127.0.0.1", &admin),
            (Role::Node, "node.example", &node),
        ] {
            verify_authority(&ca.certificate_pem, &ca.key_pem, NOW)?;
            let generated = request(role, name)?;
            let info = verify_request_key(role, name, &generated.request_pem, &generated.key_pem)?;
            assert_eq!(info.der_sha256.len(), 64);
            assert_eq!(info.spki_sha256.len(), 64);
            let certificate = sign(
                role,
                name,
                &generated.request_pem,
                &ca.certificate_pem,
                &ca.key_pem,
                NOW,
            )?;
            verify(
                role,
                name,
                &ca.certificate_pem,
                &certificate,
                &generated.key_pem,
                &generated.request_pem,
                NOW,
            )?;
            let der = certificate_der(&certificate)?;
            let parsed = parsed_certificate(&der)?;
            assert_eq!(
                parsed.validity().not_before.timestamp(),
                i64::try_from(NOW - SKEW).unwrap()
            );
            assert_eq!(
                parsed.validity().not_after.timestamp(),
                i64::try_from(NOW + LEAF_SECONDS).unwrap()
            );
        }
        Ok(())
    }

    #[test]
    fn wrong_root_role_private_key_request_key_or_name_cannot_issue_or_verify() -> io::Result<()> {
        let admin = authority(Role::Admin, NOW)?;
        let node = authority(Role::Node, NOW)?;
        let first = request(Role::Node, "node.example")?;
        let other = request(Role::Node, "node.example")?;
        assert!(verify_authority(&node.certificate_pem, &admin.key_pem, NOW).is_err());
        assert!(
            verify_request_key(
                Role::Node,
                "node.example",
                &first.request_pem,
                &other.key_pem
            )
            .is_err()
        );
        assert!(
            sign(
                Role::Node,
                "node.example",
                &first.request_pem,
                &admin.certificate_pem,
                &admin.key_pem,
                NOW
            )
            .is_err()
        );
        assert!(
            sign(
                Role::Node,
                "other.example",
                &first.request_pem,
                &node.certificate_pem,
                &node.key_pem,
                NOW
            )
            .is_err()
        );
        assert!(inspect_request(Role::Admin, "node.example", &first.request_pem).is_err());
        let certificate = sign(
            Role::Node,
            "node.example",
            &other.request_pem,
            &node.certificate_pem,
            &node.key_pem,
            NOW,
        )?;
        assert!(
            verify(
                Role::Node,
                "node.example",
                &node.certificate_pem,
                &certificate,
                &first.key_pem,
                &first.request_pem,
                NOW
            )
            .is_err()
        );
        assert!(
            verify(
                Role::Node,
                "node.example",
                &admin.certificate_pem,
                &certificate,
                &other.key_pem,
                &other.request_pem,
                NOW
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn request_signature_and_complete_single_pem_der_are_required() -> io::Result<()> {
        let generated = request(Role::Node, "node.example")?;
        let Item::Csr(der) = single_pem(
            &generated.request_pem,
            "CERTIFICATE REQUEST",
            MAX_PUBLIC_PEM,
        )?
        else {
            return Err(invalid());
        };
        let mut altered = der.as_ref().to_vec();
        *altered.last_mut().unwrap() ^= 1;
        assert!(
            inspect_request(
                Role::Node,
                "node.example",
                &pem("CERTIFICATE REQUEST", &altered)
            )
            .is_err()
        );
        let mut trailing = der.as_ref().to_vec();
        trailing.push(0);
        assert!(
            inspect_request(
                Role::Node,
                "node.example",
                &pem("CERTIFICATE REQUEST", &trailing)
            )
            .is_err()
        );
        for altered in [
            format!("prefix\n{}", generated.request_pem),
            format!("{}suffix", generated.request_pem),
            format!("{}{}", generated.request_pem, generated.request_pem),
            generated
                .request_pem
                .replace("CERTIFICATE REQUEST", "CERTIFICATE"),
            "x".repeat(MAX_PUBLIC_PEM + 1),
        ] {
            assert!(inspect_request(Role::Node, "node.example", &altered).is_err());
        }
        Ok(())
    }

    #[test]
    fn valid_pop_and_self_signatures_do_not_allow_unsigned_outer_fields() -> io::Result<()> {
        let generated = request(Role::Node, "node.example")?;
        let Item::Csr(request_der) = single_pem(
            &generated.request_pem,
            "CERTIFICATE REQUEST",
            MAX_PUBLIC_PEM,
        )?
        else {
            return Err(invalid());
        };
        let malformed = append_unsigned_outer_field(request_der.as_ref())?;
        let (remainder, parsed) =
            X509CertificationRequest::from_der(&malformed).map_err(|_| invalid())?;
        assert!(remainder.is_empty());
        // The signature is still valid: the extra NULL is outside the signed TBS.
        parsed.verify_signature().map_err(|_| invalid())?;
        assert!(
            CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(
                malformed.clone(),
            ))
            .is_ok()
        );
        assert!(
            inspect_request(
                Role::Node,
                "node.example",
                &pem("CERTIFICATE REQUEST", &malformed),
            )
            .is_err()
        );

        let root = authority(Role::Node, NOW)?;
        let root_der = certificate_der(&root.certificate_pem)?;
        let malformed = append_unsigned_outer_field(root_der.as_ref())?;
        let (remainder, parsed) =
            x509_parser::parse_x509_certificate(&malformed).map_err(|_| invalid())?;
        assert!(remainder.is_empty());
        parsed.verify_signature(None).map_err(|_| invalid())?;
        assert!(root_info(&pem("CERTIFICATE", &malformed), NOW).is_err());
        Ok(())
    }

    #[test]
    fn validly_signed_csrs_cannot_escalate_extensions_or_ca_status() -> io::Result<()> {
        let key = KeyPair::generate().map_err(|_| invalid())?;
        for change in 0..6 {
            let mut params = leaf_parameters(Role::Node, "node.example")?;
            match change {
                0 => params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0)),
                1 => params.key_usages.push(KeyUsagePurpose::KeyCertSign),
                2 => params
                    .extended_key_usages
                    .push(ExtendedKeyUsagePurpose::Any),
                3 => params.subject_alt_names.push(SanType::DnsName(
                    "other.example".try_into().map_err(|_| invalid())?,
                )),
                4 => params
                    .custom_extensions
                    .push(CustomExtension::from_oid_content(
                        &[1, 2, 3, 4],
                        vec![0x30, 0],
                    )),
                _ => params
                    .custom_extensions
                    .push(CustomExtension::from_oid_content(
                        &[2, 5, 29, 17],
                        small_tlv(0x30, &small_tlv(0x82, b"other.example")?)?,
                    )),
            }
            assert!(
                inspect_request(Role::Node, "node.example", &csr(&params, &key)?).is_err(),
                "accepted escalation {change}"
            );
        }
        let p384 = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).map_err(|_| invalid())?;
        assert!(
            inspect_request(
                Role::Node,
                "node.example",
                &csr(&leaf_parameters(Role::Node, "node.example")?, &p384)?
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn duplicate_and_unknown_signed_csr_attributes_are_rejected() -> io::Result<()> {
        let key = KeyPair::generate().map_err(|_| invalid())?;
        let params = leaf_parameters(Role::Node, "node.example")?;
        let original = params.serialize_request(&key).map_err(|_| invalid())?;
        let (_, parsed) =
            X509CertificationRequest::from_der(original.der()).map_err(|_| invalid())?;
        let values = parsed.certification_request_info.attributes()[0]
            .value
            .to_vec();
        let duplicate = params
            .serialize_request_with_attributes(
                &key,
                vec![Attribute {
                    oid: &[1, 2, 840, 113549, 1, 9, 14],
                    values,
                }],
            )
            .and_then(|request| request.pem())
            .map_err(|_| invalid())?;
        assert!(inspect_request(Role::Node, "node.example", &duplicate).is_err());
        let unknown = params
            .serialize_request_with_attributes(
                &key,
                vec![Attribute {
                    oid: &[1, 2, 3, 4],
                    values: vec![0x31, 0x02, 0x30, 0x00],
                }],
            )
            .and_then(|request| request.pem())
            .map_err(|_| invalid())?;
        assert!(inspect_request(Role::Node, "node.example", &unknown).is_err());
        // Keep one correctly signed attribute but put two values inside its SET.
        // The narrow profile permits exactly one value; convenience views may
        // project only its first extension sequence.
        let values = parsed.certification_request_info.attributes()[0].value;
        assert_eq!(values[0], 0x31);
        assert!(values[1] < 128);
        let mut duplicate_values = values[2..].to_vec();
        duplicate_values.extend_from_slice(&values[2..]);
        let mut no_generated_extensions = CertificateParams::default();
        no_generated_extensions.distinguished_name = distinguished(leaf_cn(Role::Node));
        let multiple_values = no_generated_extensions
            .serialize_request_with_attributes(
                &key,
                vec![Attribute {
                    oid: &[1, 2, 840, 113549, 1, 9, 14],
                    values: small_tlv(0x31, &duplicate_values)?,
                }],
            )
            .and_then(|request| request.pem())
            .map_err(|_| invalid())?;
        assert!(inspect_request(Role::Node, "node.example", &multiple_values).is_err());
        Ok(())
    }

    fn ca_parameters(now: u64) -> io::Result<CertificateParams> {
        let (not_before, not_after) = period(now, CA_SECONDS)?;
        let mut params = CertificateParams::default();
        params.not_before = not_before;
        params.not_after = not_after;
        params.serial_number = Some(1u64.into());
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.distinguished_name = distinguished(root_cn(Role::Node));
        Ok(params)
    }

    #[test]
    fn root_eligibility_self_signature_and_validity_are_explicit_not_anchor_assumptions()
    -> io::Result<()> {
        let key = KeyPair::generate().map_err(|_| invalid())?;
        for change in 0..5 {
            let mut params = ca_parameters(NOW)?;
            match change {
                0 => params.is_ca = IsCa::ExplicitNoCa,
                1 => params.key_usages = vec![KeyUsagePurpose::DigitalSignature],
                2 => params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained),
                3 => {
                    params.not_after =
                        OffsetDateTime::from_unix_timestamp(i64::try_from(NOW - 1).unwrap())
                            .map_err(|_| invalid())?
                }
                _ => {
                    params.not_before =
                        OffsetDateTime::from_unix_timestamp(i64::try_from(NOW + 1).unwrap())
                            .map_err(|_| invalid())?
                }
            }
            let certificate = params.self_signed(&key).map_err(|_| invalid())?;
            assert!(
                root_info(&certificate.pem(), NOW).is_err(),
                "accepted ineligible root {change}"
            );
        }
        let authority = authority(Role::Node, NOW)?;
        assert!(root_info(&authority.certificate_pem, NOW + CA_SECONDS + 1).is_err());
        let mut der = certificate_der(&authority.certificate_pem)?
            .as_ref()
            .to_vec();
        *der.last_mut().unwrap() ^= 1;
        assert!(root_info(&pem("CERTIFICATE", &der), NOW).is_err());
        Ok(())
    }

    #[test]
    fn explicit_lifetimes_and_renewal_serials_never_use_rcgen_defaults() -> io::Result<()> {
        let ca = authority(Role::Node, NOW)?;
        let generated = request(Role::Node, "node.example")?;
        let first = sign(
            Role::Node,
            "node.example",
            &generated.request_pem,
            &ca.certificate_pem,
            &ca.key_pem,
            NOW,
        )?;
        let second = sign(
            Role::Node,
            "node.example",
            &generated.request_pem,
            &ca.certificate_pem,
            &ca.key_pem,
            NOW,
        )?;
        let first_der = certificate_der(&first)?;
        let second_der = certificate_der(&second)?;
        assert_ne!(
            parsed_certificate(&first_der)?.raw_serial(),
            parsed_certificate(&second_der)?.raw_serial()
        );
        assert!(
            verify(
                Role::Node,
                "node.example",
                &ca.certificate_pem,
                &first,
                &generated.key_pem,
                &generated.request_pem,
                NOW + LEAF_SECONDS + 1
            )
            .is_err()
        );
        let late = NOW + CA_SECONDS - LEAF_SECONDS / 2;
        assert!(root_info(&ca.certificate_pem, late).is_ok());
        assert!(
            sign(
                Role::Node,
                "node.example",
                &generated.request_pem,
                &ca.certificate_pem,
                &ca.key_pem,
                late
            )
            .is_err()
        );
        assert!(authority(Role::Node, u64::MAX).is_err());
        assert!(period(u64::MAX, LEAF_SECONDS).is_err());
        Ok(())
    }
}
