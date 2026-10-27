//! Offline import under a new node identity, never a rollback of a live node.
//!
//! The store owns backup verification, exclusive destination creation and the
//! pending-review transaction. This CLI collects a new administrator password
//! and generates a new key/CSR; it does not issue certificates, grant access or
//! start listeners. A failed command must not be automatically replayed because
//! the destination may already have been claimed or committed.

use std::{
    io::{self, Write},
    net::IpAddr,
    path::PathBuf,
};

use clap::{Args, Subcommand};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, PublicKeyData as _,
};
use rustls_pki_types::ServerName;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{input, store};

/// Explicit new-identity import. Administrator secrets are read only after the
/// non-secret arguments have been checked, and never appear in command options.
#[derive(Args)]
pub struct RestoreArgs {
    /// Acknowledge that old node identity and authorizations will not be restored
    #[arg(long, required = true)]
    as_new_node: bool,
    /// Verified backup package; it is read, never modified
    #[arg(long)]
    input: PathBuf,
    /// New persistent directory under an existing private parent; must not exist
    #[arg(long)]
    data_dir: PathBuf,
    /// One ASCII DNS hostname (no trailing dot) or unbracketed IPv4/IPv6 SAN
    #[arg(long)]
    node_name: String,
    /// New node display name; distinct from its TLS SAN and generated stable ID
    #[arg(long)]
    name: Option<String>,
    /// New initial administrator login, not an imported proxy user
    #[arg(long)]
    administrator: Option<String>,
    /// Read the new password from redirected stdin, never the terminal
    #[arg(long, requires_all = ["name", "administrator"])]
    password_stdin: bool,
}

/// Offline review operations do not issue certificates or restore old trust.
#[derive(Subcommand)]
pub enum Command {
    /// Inspect recovery metadata without changing state or creating missing files
    Status {
        /// Existing persistent directory; never initialized or migrated
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Finish the exact pending review; this does not start or activate a node
    Finalize {
        /// Existing persistent directory; never initialized or migrated
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Recovery ID read from this directory's status; a mismatch fails closed
        #[arg(long)]
        expected_id: String,
    },
}

/// Collect input and import once on the synchronous CLI thread. Cancellation,
/// invalid names and key-generation failure precede destination creation. Store
/// errors or failed success output do not prove the destination is unchanged;
/// inspect it instead of replaying the import. No input secrets are printed.
pub(super) fn restore(args: RestoreArgs) -> io::Result<()> {
    if !args.as_new_node {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "restore requires --as-new-node; old node identity cannot be reused",
        ));
    }
    let parameters = request_parameters(&args.node_name)?;
    let directory = super::directory(Some(args.data_dir))?;
    let (name, administrator, password) = if args.password_stdin {
        let name = args.name.ok_or_else(|| super::missing_input("node name"))?;
        let administrator = args
            .administrator
            .ok_or_else(|| super::missing_input("administrator"))?;
        super::validate_names(&name, &administrator)?;
        (name, administrator, super::password_from_stdin()?)
    } else {
        writeln!(
            io::stderr().lock(),
            "Import as a NEW node for offline review. Old credentials and node authorizations are not restored. No server will start."
        )?;
        input::initialize(&directory, args.name, args.administrator)?
    };
    let password_hash = super::hash_password(&password)?;
    let identity = new_identity(parameters)?;
    let status = store::recovery::restore(
        &args.input,
        &directory,
        &name,
        &administrator,
        &password_hash,
        identity,
    )?;
    writeln!(
        io::stderr().lock(),
        "Imported under a new identity, pending offline review. After recovery finalize, use manage setup recover to prepare checked TLS and launch plans with this node.key/node.csr. Do not reuse the old key/certificate. No server was started."
    )?;
    write_status(&mut io::stdout().lock(), &status)
}

/// Run a single offline read or expected-ID transition. Finalization is not
/// idempotent: a repeated Ready transition is rejected by the store, not retried.
pub(super) fn run(command: Command) -> io::Result<()> {
    let status = match command {
        Command::Status { data_dir } => store::recovery::status(&super::directory(data_dir)?)?,
        Command::Finalize {
            data_dir,
            expected_id,
        } => store::recovery::finalize(&super::directory(data_dir)?, &expected_id)?,
    };
    write_status(&mut io::stdout().lock(), &status)
}

/// Construct only the node's requested TLS usages and one bounded reference
/// name. A SAN is not a URL, wildcard, IP zone or list; internationalized DNS
/// names must be supplied in ASCII A-label form. Name validation happens before
/// asking for a password, and does not contact DNS or prove name ownership.
fn request_parameters(node_name: &str) -> io::Result<CertificateParams> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "node name requires one ASCII DNS hostname (no trailing dot) or unbracketed IPv4/IPv6 address",
        )
    };
    if node_name.parse::<IpAddr>().is_err() {
        if node_name.is_empty() || node_name.len() > 253 {
            return Err(invalid());
        }
        for label in node_name.split('.') {
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
    }
    ServerName::try_from(node_name).map_err(|_| invalid())?;
    let mut parameters =
        CertificateParams::new(vec![node_name.to_owned()]).map_err(|_| invalid())?;
    // Request only SAN and usages here; the CA must issue an end-entity
    // certificate. Startup validates that signed certificate independently
    // instead of treating the CSR or its requested extensions as trust.
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    parameters.distinguished_name = DistinguishedName::new();
    parameters
        .distinguished_name
        .push(DnType::CommonName, "vproxy node");
    Ok(parameters)
}

/// Generate one independent key and a signed PKCS#10 request, not a certificate:
/// https://www.rfc-editor.org/rfc/rfc2986.html#section-4
/// The pin hashes the full DER SubjectPublicKeyInfo, matching rustls's
/// certificate/key comparison, not its inner BIT STRING or PEM encoding.
/// https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.7
/// Owned PEM is zeroized on drop; cryptographic-library allocations retain
/// their upstream ownership/erasure guarantees. No key material is logged.
fn new_identity(parameters: CertificateParams) -> io::Result<store::recovery::Identity> {
    let key = KeyPair::generate()
        .map_err(|_| io::Error::other("cannot generate a new recovery node key"))?;
    let request = parameters
        .serialize_request(&key)
        .map_err(|_| io::Error::other("cannot generate a recovery node certificate request"))?;
    let request_pem = request
        .pem()
        .map_err(|_| io::Error::other("cannot encode a recovery node certificate request"))?;
    Ok(store::recovery::Identity {
        public_key_sha256: Sha256::digest(key.subject_public_key_info()).into(),
        key_pem: Zeroizing::new(key.serialize_pem()),
        request_pem,
    })
}

/// Write only verified identifiers, hashes, counts and fixed phase labels. The
/// source backup is sensitive, but no names, SQL, passwords, PEM or PHC values
/// belong in this status output. A missing record is an ordinary initialized
/// node, not a pending restore and not a declaration of deployment readiness.
fn write_status(output: &mut impl Write, status: &store::recovery::Status) -> io::Result<()> {
    writeln!(output, "node_id={}", status.node_id)?;
    writeln!(output, "schema_version={}", status.schema_version)?;
    let Some(record) = &status.recovery else {
        return writeln!(output, "recovery_phase=none");
    };
    let phase = match record.phase {
        store::recovery::Phase::PendingReview => "pending_review",
        store::recovery::Phase::Ready => "ready",
        store::recovery::Phase::PendingTakeover => "pending_takeover",
    };
    writeln!(output, "recovery_id={}", record.id)?;
    writeln!(output, "recovery_phase={phase}")?;
    writeln!(output, "source_node_id={}", record.source_node_id)?;
    writeln!(
        output,
        "source_schema_version={}",
        record.source_schema_version
    )?;
    writeln!(
        output,
        "source_database_sha256={}",
        record.source_database_sha256
    )?;
    write!(output, "node_key_sha256=")?;
    for byte in record.node_key_sha256 {
        write!(output, "{byte:02x}")?;
    }
    writeln!(output)?;
    writeln!(output, "imported_users={}", record.imported_users)?;
    writeln!(output, "imported_prefixes={}", record.imported_prefixes)?;
    writeln!(output, "imported_addresses={}", record.imported_addresses)?;
    writeln!(output, "imported_pools={}", record.imported_pools)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, DirBuilder, OpenOptions};

    use x509_parser::{
        certification_request::X509CertificationRequest,
        extensions::{GeneralName, ParsedExtension},
        prelude::FromDer as _,
    };

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Owns only a newly claimed random temporary leaf and its test key files.
    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> io::Result<Self> {
            let mut random = [0; 16];
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("test entropy unavailable"))?;
            let suffix = u128::from_be_bytes(random);
            let path = std::env::temp_dir().join(format!("vproxy-recovery-cli-{suffix:032x}"));
            let builder = DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder.create(&path)?;
            Ok(Self(path))
        }

        fn key(&self, identity: &store::recovery::Identity) -> io::Result<PathBuf> {
            let path = self.0.join("node.key");
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            options
                .open(&path)?
                .write_all(identity.key_pem.as_bytes())?;
            Ok(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn node_san_rejects_ambiguous_or_unbounded_input_before_password_read() {
        for invalid in [
            "",
            "https://edge.example",
            "edge.example:443",
            "[2001:db8::1]",
            "fe80::1%eth0",
            "*.example",
            "edge.example.",
            ".example",
            "edge..example",
            "edge_name.example",
            "-edge.example",
            "edge-.example",
            "例子.example",
            " edge.example",
            "edge.example\n",
            "edge.example,other.example",
            "999.1.1.1",
        ] {
            assert_eq!(
                request_parameters(invalid).err().map(|error| error.kind()),
                Some(io::ErrorKind::InvalidInput),
                "{invalid:?}"
            );
        }
        let overlong_label = format!("{}.example", "a".repeat(64));
        let overlong_name = vec!["a".repeat(63); 4].join(".");
        for invalid in [&overlong_label, &overlong_name] {
            assert!(request_parameters(invalid).is_err());
        }
        for valid in ["localhost", "EDGE-01.example", "xn--fiqs8s.example"] {
            assert!(request_parameters(valid).is_ok());
        }
    }

    #[test]
    fn fresh_request_has_one_san_dual_usage_and_matching_full_spki_pin() -> TestResult {
        for name in ["edge.example", "192.0.2.10", "2001:db8::10"] {
            let identity = new_identity(request_parameters(name)?)?;
            let mut request_pem = identity.request_pem.as_bytes();
            let der = rustls_pemfile::csr(&mut request_pem)?
                .ok_or_else(|| io::Error::other("missing test CSR"))?;
            let (remaining, request) = X509CertificationRequest::from_der(&der)?;
            assert!(remaining.is_empty());
            let info = &request.certification_request_info;
            let digest: [u8; 32] = Sha256::digest(info.subject_pki.raw).into();
            assert_eq!(identity.public_key_sha256, digest);
            let raw_digest: [u8; 32] =
                Sha256::digest(&info.subject_pki.subject_public_key.data).into();
            assert_ne!(identity.public_key_sha256, raw_digest);
            let key = KeyPair::from_pem(&identity.key_pem)?;
            assert_eq!(key.subject_public_key_info(), info.subject_pki.raw);
            let provider = rustls::crypto::aws_lc_rs::default_provider();
            assert!(
                provider
                    .signature_verification_algorithms
                    .all
                    .iter()
                    .any(|algorithm| algorithm
                        .verify_signature(
                            &info.subject_pki.subject_public_key.data,
                            info.raw,
                            &request.signature_value.data,
                        )
                        .is_ok())
            );
            let extensions: Vec<_> = request
                .requested_extensions()
                .ok_or_else(|| io::Error::other("missing test CSR extensions"))?
                .collect();
            assert_eq!(extensions.len(), 3);
            let mut checked_san = false;
            let mut checked_key_usage = false;
            let mut checked_extended_usage = false;
            for extension in extensions {
                match extension {
                    ParsedExtension::SubjectAlternativeName(san) => {
                        assert_eq!(san.general_names.len(), 1);
                        match name.parse::<IpAddr>() {
                            Ok(IpAddr::V4(ip)) => {
                                assert_eq!(
                                    san.general_names[0],
                                    GeneralName::IPAddress(&ip.octets())
                                )
                            }
                            Ok(IpAddr::V6(ip)) => {
                                assert_eq!(
                                    san.general_names[0],
                                    GeneralName::IPAddress(&ip.octets())
                                )
                            }
                            Err(_) => assert_eq!(san.general_names[0], GeneralName::DNSName(name)),
                        }
                        checked_san = true;
                    }
                    ParsedExtension::KeyUsage(usage) => {
                        assert!(usage.digital_signature());
                        assert!(!usage.key_cert_sign());
                        assert!(!usage.crl_sign());
                        checked_key_usage = true;
                    }
                    ParsedExtension::ExtendedKeyUsage(usage) => {
                        assert!(usage.client_auth && usage.server_auth);
                        assert!(!usage.any);
                        assert!(usage.other.is_empty());
                        checked_extended_usage = true;
                    }
                    other => return Err(format!("unexpected test CSR extension: {other:?}").into()),
                }
            }
            assert!(checked_san && checked_key_usage && checked_extended_usage);
            let fixture = Fixture::new()?;
            assert_eq!(
                super::super::tls::node_key_sha256(&fixture.key(&identity)?)?,
                identity.public_key_sha256
            );
            let next = new_identity(request_parameters(name)?)?;
            assert_ne!(identity.public_key_sha256, next.public_key_sha256);
        }
        Ok(())
    }

    #[test]
    fn import_requires_explicit_new_identity_without_touching_destination() -> TestResult {
        let fixture = Fixture::new()?;
        let directory = fixture.0.join("not-created");
        let result = restore(RestoreArgs {
            as_new_node: false,
            input: fixture.0.join("missing-backup"),
            data_dir: directory.clone(),
            node_name: "edge.example".into(),
            name: Some("new node".into()),
            administrator: Some("new-admin".into()),
            password_stdin: true,
        });
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
        assert!(!directory.try_exists()?);
        Ok(())
    }

    #[test]
    fn status_prints_only_fixed_non_secret_recovery_metadata() -> TestResult {
        let mut status = store::recovery::Status {
            node_id: "AAECAwQFBgcICQoLDA0ODw".into(),
            schema_version: 14,
            recovery: Some(store::recovery::Record {
                id: "EBESExQVFhcYGRobHB0eHw".into(),
                source_node_id: "ICEiIyQlJicoKSorLC0uLw".into(),
                source_schema_version: 13,
                source_database_sha256: "ab".repeat(32),
                phase: store::recovery::Phase::PendingReview,
                node_key_sha256: [0xcd; 32],
                imported_users: 3,
                imported_prefixes: 2,
                imported_addresses: 4,
                imported_pools: 1,
            }),
        };
        let mut output = Vec::new();
        write_status(&mut output, &status)?;
        assert_eq!(
            String::from_utf8(output)?,
            concat!(
                "node_id=AAECAwQFBgcICQoLDA0ODw\n",
                "schema_version=14\n",
                "recovery_id=EBESExQVFhcYGRobHB0eHw\n",
                "recovery_phase=pending_review\n",
                "source_node_id=ICEiIyQlJicoKSorLC0uLw\n",
                "source_schema_version=13\n",
                "source_database_sha256=abababababababababababababababababababababababababababababababab\n",
                "node_key_sha256=cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\n",
                "imported_users=3\n",
                "imported_prefixes=2\n",
                "imported_addresses=4\n",
                "imported_pools=1\n",
            )
        );
        status.recovery = None;
        let mut output = Vec::new();
        write_status(&mut output, &status)?;
        assert_eq!(
            String::from_utf8(output)?,
            "node_id=AAECAwQFBgcICQoLDA0ODw\nschema_version=14\nrecovery_phase=none\n"
        );
        Ok(())
    }
}
