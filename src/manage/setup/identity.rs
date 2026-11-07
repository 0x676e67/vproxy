//! Fixed, offline C6 certificate profiles; no file, database or network I/O.
//!
//! CSR signatures prove possession of the requested key, not authorization for
//! a DNS name or node role. The caller separately selects the trusted request,
//! role, name and root fingerprints. Private PEM owners are zeroized; rcgen and
//! its provider retain their own key representations, so this is not a promise
//! that every upstream allocation or process-memory copy is erased.

use std::{io, net::IpAddr, sync::Arc, time::Duration};

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
use x509_cert::{
    Certificate, SubjectPublicKeyInfo,
    certificate::Version,
    der::{
        Decode, Encode, Reader, SliceReader, Tag, Tagged,
        asn1::{AnyRef, Ia5String, ObjectIdentifier, OctetString},
    },
    ext::{
        Extension,
        pkix::{SubjectAltName, name::GeneralName},
    },
    name::Name,
    request::CertReq,
};
use zeroize::Zeroizing;

const MAX_PUBLIC_PEM: usize = 16 * 1024;
const MAX_KEY_PEM: usize = 64 * 1024;
const SKEW: u64 = 300;
const CA_SECONDS: u64 = 1_825 * 86_400;
const LEAF_SECONDS: u64 = 90 * 86_400;
use x509_cert::der::oid::db::{
    rfc4519::COMMON_NAME,
    rfc5280::{
        ID_CE_AUTHORITY_KEY_IDENTIFIER as AKI, ID_CE_BASIC_CONSTRAINTS as BC,
        ID_CE_EXT_KEY_USAGE as EKU, ID_CE_KEY_USAGE as KU, ID_CE_SUBJECT_ALT_NAME as SAN,
        ID_CE_SUBJECT_KEY_IDENTIFIER as SKI,
    },
    rfc5912::{
        ECDSA_WITH_SHA_256 as ECDSA_SHA256, ID_EC_PUBLIC_KEY as EC_PUBLIC_KEY,
        ID_EXTENSION_REQ as EXTENSION_REQUEST, SECP_256_R_1 as P256,
    },
};

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
    let tbs = certificate.tbs_certificate();
    let spki = tbs
        .subject_public_key_info()
        .to_der()
        .map_err(|_| invalid())?;
    let (not_before, not_after) = validity(&certificate, now, CA_SECONDS)?;
    if tbs.subject() != tbs.issuer() {
        return Err(invalid());
    }
    let role = if subject(tbs.subject(), root_cn(Role::Admin)).is_ok() {
        Role::Admin
    } else if subject(tbs.subject(), root_cn(Role::Node)).is_ok() {
        Role::Node
    } else {
        return Err(invalid());
    };
    let expected = vec![
        expected(KU, true, vec![0x03, 0x02, 0x02, 0x04])?,
        expected(
            BC,
            true,
            vec![0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00],
        )?,
        expected(SKI, false, key_identifier(&spki))?,
    ];
    extensions(tbs.extensions().map_or(&[][..], Vec::as_slice), &expected)?;
    // Verify the original signed bytes, without re-encoding validity times.
    let envelope = AnyRef::from_der(der.as_ref()).map_err(|_| invalid())?;
    let signed = SliceReader::new(envelope.value())
        .and_then(|mut reader| reader.tlv_bytes())
        .map_err(|_| invalid())?;
    ::aws_lc_rs::signature::UnparsedPublicKey::new(
        &::aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        tbs.subject_public_key_info()
            .subject_public_key
            .as_bytes()
            .ok_or_else(invalid)?,
    )
    .verify(
        signed,
        certificate.signature().as_bytes().ok_or_else(invalid)?,
    )
    .map_err(|_| invalid())?;
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
    // The typed DER decoder consumes every sequence/SET value, including the
    // full signed envelope. No reconstruction or second ASN.1 encoder is needed.
    // https://www.rfc-editor.org/rfc/rfc2986.html#section-4
    let csr = CertReq::from_der(der.as_ref()).map_err(|_| invalid())?;
    if csr.algorithm.oid != ECDSA_SHA256
        || csr.algorithm.parameters.is_some()
        || csr.signature.unused_bits() != 0
        || csr.info.attributes.len() != 1
    {
        return Err(invalid());
    }
    subject(&csr.info.subject, leaf_cn(role))?;
    supported_spki(&csr.info.public_key)?;
    let attribute = csr.info.attributes.get(0).ok_or_else(invalid)?;
    if attribute.oid != EXTENSION_REQUEST || attribute.values.len() != 1 {
        return Err(invalid());
    }
    let value = attribute.values.get(0).ok_or_else(invalid)?;
    let requested: Vec<Extension> = value.decode_as().map_err(|_| invalid())?;
    // Recovery retains the original DNS letter case in its signed SAN.
    let requested_name = if recovery {
        let san = requested
            .iter()
            .find(|extension| extension.extn_id == SAN)
            .ok_or_else(invalid)?;
        let names = SubjectAltName::from_der(san.extn_value.as_bytes()).map_err(|_| invalid())?;
        match names.0.as_slice() {
            [GeneralName::DnsName(actual)] if name(actual.as_str())? == canonical => {
                actual.as_str().to_owned()
            }
            [GeneralName::IpAddress(actual)]
                if canonical.parse::<IpAddr>().is_ok_and(|ip| match ip {
                    IpAddr::V4(ip) => actual.as_bytes() == ip.octets(),
                    IpAddr::V6(ip) => actual.as_bytes() == ip.octets(),
                }) =>
            {
                canonical.to_owned()
            }
            _ => return Err(invalid()),
        }
    } else {
        canonical.to_owned()
    };
    let mut expected_extensions = leaf_extensions(role, &requested_name, None, None)?;
    if recovery {
        expected_extensions.retain(|extension| extension.extn_id != BC);
    }
    extensions(&requested, &expected_extensions)?;
    // Keep the original CSR order and omitted DEFAULT critical=false encoding;
    // the library's encoder replaces the former request-info reconstruction.
    if requested
        .iter()
        .zip(&expected_extensions)
        .any(|(actual, expected)| actual.extn_id != expected.extn_id)
        || requested.to_der().map_err(|_| invalid())? != value.to_der().map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let spki = csr.info.public_key.to_der().map_err(|_| invalid())?;
    // Rcgen verifies proof of possession over the original signed request before
    // exposing its signing input. The complete typed parse above bounds its view.
    let parsed = CertificateSigningRequestParams::from_der(&der).map_err(|_| invalid())?;
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
    if certificate
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|_| invalid())?
        != spki
        || not_before < root.not_before
        || not_after > root.not_after
    {
        return Err(invalid());
    }
    subject(certificate.tbs_certificate().subject(), leaf_cn(role))?;
    extensions(
        certificate
            .tbs_certificate()
            .extensions()
            .map_or(&[][..], Vec::as_slice),
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

fn parsed_certificate(der: &CertificateDer<'_>) -> io::Result<Certificate> {
    let certificate = Certificate::from_der(der.as_ref()).map_err(|_| invalid())?;
    let tbs = certificate.tbs_certificate();
    if tbs.version() != Version::V3
        || certificate.signature_algorithm().oid != ECDSA_SHA256
        || certificate.signature_algorithm().parameters.is_some()
        || certificate.signature().unused_bits() != 0
        || tbs.signature() != certificate.signature_algorithm()
    {
        return Err(invalid());
    }
    supported_spki(tbs.subject_public_key_info())?;
    let serial = tbs.serial_number().as_bytes();
    // The library also accepts legacy negative/zero CA serials. C6 keeps its
    // positive, nonzero profile and counts the complete encoded integer value.
    if serial.len() > 20
        || serial.first().is_some_and(|byte| byte & 0x80 != 0)
        || serial.iter().all(|byte| *byte == 0)
    {
        return Err(invalid());
    }
    Ok(certificate)
}

fn supported_spki(spki: &SubjectPublicKeyInfo) -> io::Result<()> {
    let key = spki.subject_public_key.as_bytes().ok_or_else(invalid)?;
    if spki.algorithm.oid != EC_PUBLIC_KEY
        || spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameter| parameter.decode_as::<ObjectIdentifier>().ok())
            .is_none_or(|oid| oid != P256)
        || key.len() != 65
        || key.first() != Some(&4)
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

fn expected(oid: ObjectIdentifier, critical: bool, value: Vec<u8>) -> io::Result<Extension> {
    Ok(Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(value).map_err(|_| invalid())?,
    })
}

fn extensions(actual: &[Extension], expected: &[Extension]) -> io::Result<()> {
    if actual.len() != expected.len()
        || expected
            .iter()
            .any(|wanted| actual.iter().filter(|actual| *actual == wanted).count() != 1)
    {
        return Err(invalid());
    }
    Ok(())
}

fn leaf_extensions(
    role: Role,
    canonical: &str,
    spki: Option<&[u8]>,
    issuer: Option<&[u8]>,
) -> io::Result<Vec<Extension>> {
    // Exact DER for this narrow profile also rejects duplicate EKU values and
    // trailing data inside extnValue that parsed convenience views can hide.
    let mut eku = vec![
        0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
    ];
    if role == Role::Node {
        eku[1] = 0x14;
        eku.extend_from_slice(&[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]);
    }
    let general_name = match canonical.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            GeneralName::IpAddress(OctetString::new(address.octets()).map_err(|_| invalid())?)
        }
        Ok(IpAddr::V6(address)) => {
            GeneralName::IpAddress(OctetString::new(address.octets()).map_err(|_| invalid())?)
        }
        Err(_) => GeneralName::DnsName(Ia5String::new(canonical).map_err(|_| invalid())?),
    };
    let san = SubjectAltName(vec![general_name])
        .to_der()
        .map_err(|_| invalid())?;
    let mut values = vec![
        // Rcgen's PKCS#10 writer orders KU before SAN. Keep the retained CSR
        // template order; certificate extension order remains independent.
        expected(KU, true, vec![0x03, 0x02, 0x07, 0x80])?,
        expected(SAN, false, san)?,
        expected(EKU, false, eku)?,
        expected(BC, true, vec![0x30, 0x00])?,
    ];
    if let Some(spki) = spki {
        values.push(expected(SKI, false, key_identifier(spki))?);
    }
    if let Some(issuer) = issuer {
        let mut value = vec![0x30, 0x16, 0x80, 0x14];
        value.extend_from_slice(&Sha256::digest(issuer)[..20]);
        values.push(expected(AKI, false, value)?);
    }
    Ok(values)
}

fn key_identifier(spki: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04, 0x14];
    result.extend_from_slice(&Sha256::digest(spki)[..20]);
    result
}

fn subject(actual: &Name, expected: &str) -> io::Result<()> {
    let mut attributes = actual.iter();
    let attribute = attributes.next().ok_or_else(invalid)?;
    if attributes.next().is_some()
        || attribute.oid != COMMON_NAME
        || !matches!(
            attribute.value.tag(),
            Tag::NumericString | Tag::PrintableString | Tag::Utf8String | Tag::Ia5String
        )
        || attribute.value.value() != expected.as_bytes()
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

fn validity(certificate: &Certificate, now: u64, lifetime: u64) -> io::Result<(u64, u64)> {
    let validity = certificate.tbs_certificate().validity();
    let start = validity.not_before.to_unix_duration().as_secs();
    let end = validity.not_after.to_unix_duration().as_secs();
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

    use rcgen::{CustomExtension, PKCS_ECDSA_P384_SHA384, SanType};

    const NOW: u64 = 1_792_454_400;

    fn csr(params: &CertificateParams, key: &KeyPair) -> io::Result<String> {
        params
            .serialize_request(key)
            .and_then(|request| request.pem())
            .map_err(|_| invalid())
    }

    #[test]
    fn both_profiles_complete_without_distributing_private_keys_or_trust() -> io::Result<()> {
        let admin = authority(Role::Admin, NOW)?;
        let node = authority(Role::Node, NOW)?;
        let admin_info = root_info(&admin.certificate_pem, NOW)?;
        let node_info = root_info(&node.certificate_pem, NOW)?;
        assert_eq!(admin_info.role, Role::Admin);
        assert_eq!(node_info.role, Role::Node);
        for (role, name, ca) in [
            (Role::Admin, "127.0.0.1", &admin),
            (Role::Node, "node.example", &node),
        ] {
            verify_authority(&ca.certificate_pem, &ca.key_pem, NOW)?;
            let generated = request(role, name)?;
            verify_request_key(role, name, &generated.request_pem, &generated.key_pem)?;
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
            let validity = *parsed_certificate(&der)?.tbs_certificate().validity();
            assert_eq!(validity.not_before.to_unix_duration().as_secs(), NOW - SKEW);
            assert_eq!(
                validity.not_after.to_unix_duration().as_secs(),
                NOW + LEAF_SECONDS
            );
        }
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
                        b"\x30\x0f\x82\x0dother.example".to_vec(),
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
}
