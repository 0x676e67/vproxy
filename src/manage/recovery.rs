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
