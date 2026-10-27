//! Output-certificate trust for the explicitly selected ACME environment.
//!
//! These roots verify only the management identity returned by the selected CA.
//! They are never used for the ACME HTTPS client, node mTLS, ordinary browsing,
//! or installation into an OS/browser trust store. Staging remains untrusted by
//! ordinary browsers even when its issued certificate passes this local check.

use std::io;

use rustls::RootCertStore;

// Fixed self-signed roots linked by Let's Encrypt's staging documentation:
// https://letsencrypt.org/docs/staging-environment/ (updated 2026-04-10).
// Source PEM hashes identify the downloaded bytes; DER hashes below remain
// stable across harmless checkout line-ending normalization. Updates require
// explicit source/fingerprint review, never a runtime trust-anchor download.
// (STAGING) Pretend Pear X1
// Source: https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem
// Source PEM SHA256: 3a5e1171e5f5c2d41522d438f225602e4236a68fb29c32399a95921a4ae80e73
// Certificate DER SHA256: e70570a989f8565aabdf7cae27abd1621872d6a3f811e3fef27e3dba02912198
//
// (STAGING) Bogus Broccoli X2
// Source: https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x2.pem
// Source PEM SHA256: 497c36c1b50c0daff30870d5908c9b97af29223d5510c5e6c24957d0cc502fb8
// Certificate DER SHA256: 9b2a339fe6a3e85585c4cd75536cb8c1cf7cd603b9a64bec2521858ae48da85d
//
// (STAGING) Yearning Yucca Root YE
// Source: https://letsencrypt.org/certs/staging/gen-y/root-ye.pem
// Source PEM SHA256: bf41a8c5f7fffc181e46d5df1a2b867f0efb6e169df6f0a45bd4064b1d023084
// Certificate DER SHA256: b59bfc0ba52daf849853b7324a91e82f031db3397f35644157352cde6384b56c
//
// (STAGING) Yonder Yam Root YR
// Source: https://letsencrypt.org/certs/staging/gen-y/root-yr.pem
// Source PEM SHA256: 73391ed55a3eb09f1284f8b548e540f5e265149c83ea0b79dd8ae97c016659d7
// Certificate DER SHA256: ef115fb59e040ff39d15fd8f3ef54063c704321d83cb081213272f77d3091672

const STAGING_PEM: &[u8] = include_bytes!("staging-roots.pem");
const STAGING_ROOT_COUNT: usize = 4;

/// Return a fresh, environment-exclusive output-verification store.
/// Production uses the bundled public WebPKI roots; staging uses only the four
/// fixed Let's Encrypt staging self-signed roots, without public-root fallback.
/// Malformed embedded data or an unexpected root count fails closed.
pub(super) fn identity_roots(production: bool) -> io::Result<RootCertStore> {
    if production {
        return Ok(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        });
    }
    let mut roots = RootCertStore::empty();
    let mut pem = STAGING_PEM;
    for certificate in rustls_pemfile::certs(&mut pem) {
        let certificate = certificate.map_err(|_| invalid())?;
        roots.add(certificate).map_err(|_| invalid())?;
    }
    if roots.len() != STAGING_ROOT_COUNT {
        return Err(invalid());
    }
    Ok(roots)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid embedded ACME staging roots",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::aws_lc_rs;
    use sha2::{Digest as _, Sha256};

    const DER_SHA256: [&str; STAGING_ROOT_COUNT] = [
        "e70570a989f8565aabdf7cae27abd1621872d6a3f811e3fef27e3dba02912198",
        "9b2a339fe6a3e85585c4cd75536cb8c1cf7cd603b9a64bec2521858ae48da85d",
        "b59bfc0ba52daf849853b7324a91e82f031db3397f35644157352cde6384b56c",
        "ef115fb59e040ff39d15fd8f3ef54063c704321d83cb081213272f77d3091672",
    ];

    #[test]
    fn production_and_staging_stores_never_mix() -> io::Result<()> {
        let production = identity_roots(true)?;
        let staging = identity_roots(false)?;
        assert_eq!(production.len(), webpki_roots::TLS_SERVER_ROOTS.len());
        assert_eq!(staging.len(), STAGING_ROOT_COUNT);
        for root in &staging.roots {
            assert!(
                !production.roots.iter().any(|public| {
                    public.subject_public_key_info == root.subject_public_key_info
                })
            );
        }
        // Constructing a staging store never mutates the public bundle.
        assert_eq!(identity_roots(true)?.roots, production.roots);
        Ok(())
    }

    #[test]
    fn fixed_roots_parse_and_have_real_aws_lc_verified_self_signatures() -> io::Result<()> {
        let mut pem = STAGING_PEM;
        let certificates = rustls_pemfile::certs(&mut pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        assert_eq!(certificates.len(), STAGING_ROOT_COUNT);
        let provider = aws_lc_rs::default_provider();
        for (index, certificate) in certificates.iter().enumerate() {
            assert_eq!(
                super::super::hex(&Sha256::digest(certificate.as_ref())),
                DER_SHA256[index]
            );
            let (remaining, parsed) =
                x509_parser::parse_x509_certificate(certificate).map_err(|_| invalid())?;
            assert!(remaining.is_empty());
            assert_eq!(parsed.subject(), parsed.issuer());
            assert_eq!(parsed.signature_algorithm, parsed.tbs_certificate.signature);
            let expected_algorithm = if matches!(index, 0 | 3) {
                "1.2.840.113549.1.1.11" // RSA PKCS#1 SHA-256.
            } else {
                "1.2.840.10045.4.3.3" // ECDSA P-384 SHA-384.
            };
            assert_eq!(
                parsed.signature_algorithm.algorithm.to_id_string(),
                expected_algorithm
            );
            assert!(
                parsed
                    .basic_constraints()
                    .map_err(|_| invalid())?
                    .is_some_and(|constraints| constraints.value.ca)
            );
            assert!(
                parsed
                    .key_usage()
                    .map_err(|_| invalid())?
                    .is_some_and(|usage| usage.value.key_cert_sign())
            );
            // Trust-anchor parsing does not verify a root's self-signature.
            // The provider performs actual RSA/ECDSA verification of the TBS;
            // the fixed DER fingerprints also pin the complete algorithms and key.
            assert!(
                provider
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
        }
        Ok(())
    }
}
