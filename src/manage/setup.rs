//! Offline first installation. Signing authority and node keys never travel
//! together: only the explicit public request/response files are exchanged.
//!
//! Each command claims one new private directory and writes its completion
//! record last. A failed write or lost stdout is not permission to replay into
//! that directory. Ancestors must remain operator-controlled; these helpers do
//! not defend against another process with the same account's file rights.

mod acme;
mod identity;
mod plan;
#[cfg(target_os = "linux")]
mod service;

use std::{
    env, fs,
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Subcommand;
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use self::identity::Role;
use super::files;

const FORMAT: u8 = 1;
const PUBLIC_FILE: &str = "public.json";
const COMPLETE_FILE: &str = "complete.json";
const MAX_PUBLIC: usize = 64 * 1024;
const MAX_PEM: usize = 16 * 1024;

/// All operations are offline. Generated scripts start nothing until an
/// operator runs them; certificate issuance never grants node permissions.
#[derive(Subcommand)]
pub enum Command {
    /// Write a checked private proxy.json; no database, identity or server is created
    Proxy {
        #[arg(long)]
        output: PathBuf,
        #[command(flatten)]
        options: super::proxy::SetupOptions,
    },
    /// Create separate browser and node signing roots in a new private directory
    Authority {
        #[arg(long)]
        output: PathBuf,
    },
    /// On a new node, create its database, local keys and public signing request
    Prepare {
        #[arg(long)]
        output: PathBuf,
        /// Only public.json from the signing machine, obtained through a trusted channel
        #[arg(long)]
        authority_public: PathBuf,
        /// SHA-256 printed by authority; verify through the same trusted channel
        #[arg(long)]
        authority_sha256: String,
        /// Canonical HTTPS origin that browsers will use
        #[arg(long)]
        admin_origin: String,
        /// Separate canonical HTTPS origin for node mTLS
        #[arg(long)]
        node_origin: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        administrator: Option<String>,
        /// Read one password from redirected stdin, never a command argument
        #[arg(long, requires_all = ["name", "administrator"])]
        password_stdin: bool,
    },
    /// Prepare TLS for an already reviewed recovery, preserving its database and node key
    Recover {
        /// Existing Ready recovery directory; never initialized, copied or migrated
        #[arg(long)]
        data_dir: PathBuf,
        /// Exact recovery ID from recovery status
        #[arg(long)]
        expected_id: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        authority_public: PathBuf,
        #[arg(long)]
        authority_sha256: String,
        #[arg(long)]
        admin_origin: String,
        /// Must match the name in the recovery's original node.csr
        #[arg(long)]
        node_origin: String,
    },
    /// On the signing machine, issue fixed-purpose certificates for a public request
    Sign {
        #[arg(long)]
        authority: PathBuf,
        /// Only public.json from a prepared node; no node private keys
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// On the prepared node, validate the response and write checked launch scripts
    Plan {
        #[arg(long)]
        prepared: PathBuf,
        #[arg(long)]
        response: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Local management bind, not inferred from its public origin
        #[arg(long, default_value = "127.0.0.1:8443")]
        admin_bind: SocketAddr,
        /// Local node bind, not inferred from its public origin
        #[arg(long, default_value = "127.0.0.1:8444")]
        node_bind: SocketAddr,
        /// Optional existing managed-proxy startup JSON; its exact bytes are pinned
        #[arg(long)]
        proxy_config: Option<PathBuf>,
        #[command(flatten)]
        acme: super::acme::Options,
    },
    /// On Linux, write a user-service unit from a checked local launch plan; do not install it
    #[cfg(target_os = "linux")]
    Service {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Recheck a completed output; never repairs, signs, starts or grants anything
    Check {
        #[arg(long)]
        input: PathBuf,
    },
}

/// Completion binds the actual public file. It is not an authenticated
/// authorization token: private directories and trusted-channel root pins are
/// still required. Unknown fields/versions fail instead of being guessed.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    format_version: u8,
    stage: Stage,
    public_sha256: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Authority,
    Prepared,
    RecoveredPrepared,
    Signed,
    Plan,
    AcmePlan,
    Service,
}

/// Public trust material only. Distinct complete SPKI values, not merely
/// different certificate DER, enforce the two independent trust domains.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityPublic {
    format_version: u8,
    admin_ca_pem: String,
    node_ca_pem: String,
}

/// Explicit names and trust pins accompany both node-local CSRs. This contains
/// no password, verifier, grant, private key or reusable authentication secret.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    format_version: u8,
    node_id: String,
    name: String,
    admin_origin: String,
    node_origin: String,
    authority: AuthorityPublic,
    admin_csr_pem: String,
    node_csr_pem: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "recovery_binding"
    )]
    recovery: Option<RecoveryBinding>,
}

/// Public pins only; the signing machine never receives the state path or key.
/// The local reference's digest binds the node-side path without interpreting
/// that path on the signing machine. This is not a recovery authorization.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryBinding {
    recovery_id: String,
    node_key_sha256: String,
    local_reference_sha256: String,
}

/// Node-local reference to the existing Ready database. No database or node key
/// is copied into setup output; canonical paths stay on the original machine.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryReference {
    format_version: u8,
    data_dir: PathBuf,
}

fn recovery_binding<'de, D>(deserializer: D) -> Result<Option<RecoveryBinding>, D::Error>
where
    D: Deserializer<'de>,
{
    RecoveryBinding::deserialize(deserializer).map(Some)
}

/// A response is pinned to the entire public request, including node ID, names,
/// roots and CSRs. Re-signing produces a different leaf: never auto-replace a
/// certificate already registered as an exact-DER peer identity.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    format_version: u8,
    request_sha256: String,
    admin_certificate_pem: String,
    node_certificate_pem: String,
}

/// Local references, not a portable service configuration. Scripts run a
/// read-only offline preflight before serving; changing these inputs requires a
/// new plan. It is not a port, DNS, browser trust or node-grant readiness claim.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    format_version: u8,
    prepared: PathBuf,
    response: PathBuf,
    executable: PathBuf,
    request_sha256: String,
    response_sha256: String,
    admin_bind: SocketAddr,
    node_bind: SocketAddr,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "proxy_configuration"
    )]
    proxy_config: Option<ProxyConfig>,
}

/// An independent browser-ACME launch plan; the original manual wire is unchanged.
/// Node identity and public request/response digests remain pinned. Only fixed
/// launch choices are stored here; the renewable cache stays in the state directory.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcmeLaunch {
    format_version: u8,
    prepared: PathBuf,
    response: PathBuf,
    executable: PathBuf,
    request_sha256: String,
    response_sha256: String,
    admin_bind: SocketAddr,
    node_bind: SocketAddr,
    acme: super::acme::PlanOptions,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "proxy_configuration"
    )]
    proxy_config: Option<ProxyConfig>,
}

/// Bind one existing startup JSON at its original absolute location, without
/// copying keys or changing relative TLS references. Only raw JSON bytes are
/// pinned; referenced TLS files retain the existing load-time checks and trust
/// boundary. Changing JSON, even whitespace, requires a new launch plan.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyConfig {
    path: PathBuf,
    sha256: String,
}

impl ProxyConfig {
    /// Validate before claiming an output. The bounded reader validates and
    /// hashes one JSON snapshot; no listener, policy or egress program starts.
    fn capture(path: &Path) -> io::Result<Self> {
        let path = std::path::absolute(path)?;
        path_string(&path)?;
        let sha256 = super::proxy::checked_digest(&path)?;
        Ok(Self { path, sha256 })
    }

    /// Revalidate current bytes before rendering argv. This is a new read and
    /// explicit equality check, not an atomic snapshot through later serve;
    /// trusted ancestors and no hostile same-account mutation remain required.
    fn append_arguments(&self, serve: &mut Vec<String>) -> io::Result<()> {
        if !self.path.is_absolute() || !valid_hash(&self.sha256) {
            return Err(invalid("invalid setup proxy configuration binding"));
        }
        let path = path_string(&self.path)?;
        if super::proxy::checked_digest(&self.path)? != self.sha256 {
            return Err(invalid(
                "proxy configuration changed; create a new launch plan",
            ));
        }
        serve.extend(["--proxy-config".to_owned(), path]);
        Ok(())
    }
}

/// Absent is the original API-only wire. A present field must be a strict
/// binding object, never null silently interpreted as omission.
fn proxy_configuration<'de, D>(deserializer: D) -> Result<Option<ProxyConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    ProxyConfig::deserialize(deserializer).map(Some)
}

/// A Linux user unit references a local launch plan by its completed public
/// digest. It contains no copied keys or credentials and grants no OS rights.
#[cfg(target_os = "linux")]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Service {
    format_version: u8,
    plan: PathBuf,
    plan_sha256: String,
}

/// Checked local argv shared by the two launch stages, not a new on-disk format.
#[cfg(target_os = "linux")]
struct ServiceLaunch {
    executable: PathBuf,
    node_id: String,
    plan_sha256: String,
    serve_arguments: Vec<String>,
}

/// Only non-secret status and public transfer paths are printed. Paths are
/// JSON-escaped, not interpolated into terminal control sequences or shell text.
#[derive(Serialize)]
struct Report {
    state: &'static str,
    directory: PathBuf,
    public_file: PathBuf,
    public_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unit_file: Option<PathBuf>,
    server_started: bool,
    trust_installed: bool,
    node_authorized: bool,
}

/// Execute a single operation. Check paths/names/trust before asking for a
/// password; generate/hash before claiming the output. Partial private outputs
/// are deliberately retained. No existing directory is resumed or overwritten.
pub(super) fn run(command: Command) -> io::Result<()> {
    let report = match command {
        Command::Proxy { output, options } => {
            return print_report(&super::proxy::setup(&output, options)?);
        }
        Command::Authority { output } => authority(&output, now()?)?,
        Command::Prepare {
            output,
            authority_public,
            authority_sha256,
            admin_origin,
            node_origin,
            name,
            administrator,
            password_stdin,
        } => {
            let now = now()?;
            let output = files::output_path(&output)?;
            let public_bytes = files::read(&authority_public, MAX_PUBLIC, false)?;
            if !valid_hash(&authority_sha256) || sha256(&public_bytes) != authority_sha256 {
                return Err(invalid(
                    "authority public file does not match the expected SHA-256",
                ));
            }
            let roots: AuthorityPublic = decode(&public_bytes)?;
            validate_roots(&roots, now)?;
            origin_name(&admin_origin)?;
            origin_name(&node_origin)?;
            if admin_origin == node_origin {
                return Err(invalid("browser and node origins must be separate"));
            }
            let (name, administrator, password) = if password_stdin {
                let name = name.ok_or_else(|| super::missing_input("node name"))?;
                let administrator =
                    administrator.ok_or_else(|| super::missing_input("administrator"))?;
                super::validate_names(&name, &administrator)?;
                (name, administrator, super::password_from_stdin()?)
            } else {
                super::input::initialize(&output.join("state"), name, administrator)?
            };
            let password_hash = super::hash_password(&password)?;
            prepare(
                &output,
                roots,
                &admin_origin,
                &node_origin,
                &name,
                &administrator,
                &password_hash,
                now,
            )?
        }
        Command::Sign {
            authority,
            request,
            output,
        } => sign(&authority, &request, &output, now()?)?,
        Command::Recover {
            data_dir,
            expected_id,
            output,
            authority_public,
            authority_sha256,
            admin_origin,
            node_origin,
        } => {
            let public = files::read(&authority_public, MAX_PUBLIC, false)?;
            if !valid_hash(&authority_sha256) || sha256(&public) != authority_sha256 {
                return Err(invalid(
                    "authority public file does not match the expected SHA-256",
                ));
            }
            recover(
                &data_dir,
                &expected_id,
                &output,
                decode(&public)?,
                &admin_origin,
                &node_origin,
                now()?,
            )?
        }
        Command::Plan {
            prepared,
            response,
            output,
            admin_bind,
            node_bind,
            proxy_config,
            acme,
        } => {
            let now = now()?;
            if acme.enabled() {
                acme::launch(
                    &prepared,
                    &response,
                    &output,
                    (admin_bind, node_bind),
                    &env::current_exe()?,
                    &acme,
                    proxy_config.as_deref(),
                    now,
                )?
            } else {
                launch(
                    &prepared,
                    &response,
                    &output,
                    admin_bind,
                    node_bind,
                    &env::current_exe()?,
                    proxy_config.as_deref(),
                    now,
                )?
            }
        }
        Command::Check { input } => check(&input, now()?)?,
        #[cfg(target_os = "linux")]
        Command::Service { plan, output } => service_plan(&plan, &output, now()?)?,
    };
    print_report(&report)
}

fn print_report(report: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer_pretty(io::stdout().lock(), report).map_err(|_| {
        io::Error::other("cannot write setup status; inspect the output before replaying")
    })?;
    writeln!(io::stdout().lock())
}

fn authority(output: &Path, now: u64) -> io::Result<Report> {
    let output = files::output_path(output)?;
    let admin = identity::authority(Role::Admin, now)?;
    let node = identity::authority(Role::Node, now)?;
    let public = AuthorityPublic {
        format_version: FORMAT,
        admin_ca_pem: admin.certificate_pem,
        node_ca_pem: node.certificate_pem,
    };
    validate_roots(&public, now)?;
    files::create_directory(&output)?;
    files::write(&output, "admin-ca.key", admin.key_pem.as_bytes())?;
    files::write(&output, "node-ca.key", node.key_pem.as_bytes())?;
    files::write(&output, "admin-ca.pem", public.admin_ca_pem.as_bytes())?;
    files::write(&output, "node-ca.pem", public.node_ca_pem.as_bytes())?;
    complete(&output, Stage::Authority, &public, None)
}

/// Password input has already passed the shared policy and Argon2id has run.
/// Only a newly initialized DB is touched; no schema migration is performed.
#[allow(clippy::too_many_arguments)]
fn prepare(
    output: &Path,
    authority: AuthorityPublic,
    admin_origin: &str,
    node_origin: &str,
    name: &str,
    administrator: &str,
    password_hash: &str,
    now: u64,
) -> io::Result<Report> {
    let output = files::output_path(output)?;
    validate_roots(&authority, now)?;
    super::validate_names(name, administrator)?;
    let admin_name = origin_name(admin_origin)?;
    let node_name = origin_name(node_origin)?;
    if admin_origin == node_origin {
        return Err(invalid("browser and node origins must be separate"));
    }
    let admin = identity::request(Role::Admin, &admin_name)?;
    let node = identity::request(Role::Node, &node_name)?;
    files::create_directory(&output)?;
    let state = output.join("state");
    files::create_directory(&state)?;
    let overview = super::store::initialize(&state, name, administrator, password_hash)?;
    files::write(&output, "admin.key", admin.key_pem.as_bytes())?;
    files::write(&output, "node.key", node.key_pem.as_bytes())?;
    files::write(&output, "admin.csr", admin.request_pem.as_bytes())?;
    files::write(&output, "node.csr", node.request_pem.as_bytes())?;
    let request = Request {
        format_version: FORMAT,
        node_id: overview.node_id.clone(),
        name: name.to_owned(),
        admin_origin: admin_origin.to_owned(),
        node_origin: node_origin.to_owned(),
        authority,
        admin_csr_pem: admin.request_pem,
        node_csr_pem: node.request_pem,
        recovery: None,
    };
    validate_request(&request, now)?;
    complete(&output, Stage::Prepared, &request, Some(overview.node_id))
}

/// Bind a reviewed recovery to a new TLS preparation output. The existing
/// author/update gates stay owned through completion, so cooperating writers
/// and serve cannot change the source while this command prepares its request.
/// Failure retains partial new output; it never permits replay or replacement.
#[allow(clippy::too_many_arguments)]
fn recover(
    data_dir: &Path,
    expected_id: &str,
    output: &Path,
    authority: AuthorityPublic,
    admin_origin: &str,
    node_origin: &str,
    now: u64,
) -> io::Result<Report> {
    let output = files::output_path(output)?;
    let data_dir = canonical_directory(data_dir)?;
    if output.starts_with(&data_dir) || !super::store::valid_id(expected_id) {
        return Err(invalid(
            "recovery setup requires an exact recovery ID and a separate new output",
        ));
    }
    validate_roots(&authority, now)?;
    let admin_name = origin_name(admin_origin)?;
    origin_name(node_origin)?;
    if admin_origin == node_origin {
        return Err(invalid("browser and node origins must be separate"));
    }
    let _author = super::store::lock(&data_dir)?;
    let _update = super::store::update_lock(&data_dir)?;
    let status = super::store::recovery::status(&data_dir)?;
    let record = status
        .recovery
        .ok_or_else(|| invalid("setup recover requires a reviewed recovery"))?;
    if status.schema_version != super::store::SCHEMA_VERSION
        || record.phase != super::store::recovery::Phase::Ready
        || record.id != expected_id
    {
        return Err(invalid(
            "recovery identity, phase or schema changed; inspect recovery status",
        ));
    }
    let overview = super::store::inspect(&data_dir)?;
    let node_csr = pem(&data_dir.join("node.csr"), false)?;
    let node_key = pem(&data_dir.join("node.key"), true)?;
    let info =
        identity::verify_recovery_request_key(&origin_name(node_origin)?, &node_csr, &node_key)?;
    let pin = hex_sha256(&record.node_key_sha256);
    if info.spki_sha256 != pin || overview.node_id != status.node_id {
        return Err(invalid(
            "recovery node key does not match its permanent pin",
        ));
    }
    let admin = identity::request(Role::Admin, &admin_name)?;
    let reference = encode(&RecoveryReference {
        format_version: FORMAT,
        data_dir,
    })?;
    let request = Request {
        format_version: FORMAT,
        node_id: status.node_id.clone(),
        name: overview.name,
        admin_origin: admin_origin.to_owned(),
        node_origin: node_origin.to_owned(),
        authority,
        admin_csr_pem: admin.request_pem,
        node_csr_pem: node_csr.to_string(),
        recovery: Some(RecoveryBinding {
            recovery_id: record.id,
            node_key_sha256: pin,
            local_reference_sha256: sha256(&reference),
        }),
    };
    validate_request(&request, now)?;
    files::create_directory(&output)?;
    files::write(&output, "local-reference.json", &reference)?;
    files::write(&output, "admin.key", admin.key_pem.as_bytes())?;
    files::write(&output, "admin.csr", request.admin_csr_pem.as_bytes())?;
    files::write(&output, "node.csr", request.node_csr_pem.as_bytes())?;
    complete(
        &output,
        Stage::RecoveredPrepared,
        &request,
        Some(status.node_id),
    )
}

fn sign(authority_dir: &Path, request_path: &Path, output: &Path, now: u64) -> io::Result<Report> {
    let output = files::output_path(output)?;
    let (roots, _) = load::<AuthorityPublic>(authority_dir, Stage::Authority)?;
    validate_roots(&roots, now)?;
    let admin_key = pem(&authority_dir.join("admin-ca.key"), true)?;
    let node_key = pem(&authority_dir.join("node-ca.key"), true)?;
    identity::verify_authority(&roots.admin_ca_pem, &admin_key, now)?;
    identity::verify_authority(&roots.node_ca_pem, &node_key, now)?;
    let request_bytes = files::read(request_path, MAX_PUBLIC, false)?;
    let request: Request = decode(&request_bytes)?;
    validate_request(&request, now)?;
    if sha256(&encode(&request.authority)?) != sha256(&encode(&roots)?) {
        return Err(invalid("request belongs to a different signing authority"));
    }
    let response = Response {
        format_version: FORMAT,
        request_sha256: sha256(&request_bytes),
        admin_certificate_pem: identity::sign(
            Role::Admin,
            &origin_name(&request.admin_origin)?,
            &request.admin_csr_pem,
            &roots.admin_ca_pem,
            &admin_key,
            now,
        )?,
        node_certificate_pem: if request.recovery.is_some() {
            identity::sign_recovery(
                &origin_name(&request.node_origin)?,
                &request.node_csr_pem,
                &roots.node_ca_pem,
                &node_key,
                now,
            )?
        } else {
            identity::sign(
                Role::Node,
                &origin_name(&request.node_origin)?,
                &request.node_csr_pem,
                &roots.node_ca_pem,
                &node_key,
                now,
            )?
        },
    };
    files::create_directory(&output)?;
    complete(&output, Stage::Signed, &response, Some(request.node_id))
}

/// Validate all identity and database bindings before creating the new plan.
/// Public certificates are copied, never keys. Scripts refer to the prepared
/// node's local keys and run `check` again before the ordinary serve command.
#[allow(clippy::too_many_arguments)]
fn launch(
    prepared: &Path,
    response: &Path,
    output: &Path,
    admin_bind: SocketAddr,
    node_bind: SocketAddr,
    executable: &Path,
    proxy_config: Option<&Path>,
    now: u64,
) -> io::Result<Report> {
    let output = files::output_path(output)?;
    let prepared = canonical_directory(prepared)?;
    let response = canonical_directory(response)?;
    let executable = fs::canonicalize(executable)?;
    let (request, request_hash) = prepared_request(&prepared, now)?;
    let (signed, response_hash) = load::<Response>(&response, Stage::Signed)?;
    verify_response(&prepared, &request, &request_hash, &signed, now)?;
    let launch = Launch {
        format_version: FORMAT,
        prepared,
        response,
        executable,
        request_sha256: request_hash,
        response_sha256: response_hash,
        admin_bind,
        node_bind,
        proxy_config: proxy_config.map(ProxyConfig::capture).transpose()?,
    };
    let scripts = scripts(&output, &launch, &request)?;
    files::create_directory(&output)?;
    files::write(
        &output,
        "admin.pem",
        signed.admin_certificate_pem.as_bytes(),
    )?;
    files::write(&output, "node.pem", signed.node_certificate_pem.as_bytes())?;
    files::write(
        &output,
        "admin-ca.pem",
        request.authority.admin_ca_pem.as_bytes(),
    )?;
    files::write(
        &output,
        "node-ca.pem",
        request.authority.node_ca_pem.as_bytes(),
    )?;
    files::write(&output, "start.sh", scripts.0.as_bytes())?;
    files::write(&output, "start.ps1", scripts.1.as_bytes())?;
    complete(&output, Stage::Plan, &launch, Some(request.node_id))
}

fn check(directory: &Path, now: u64) -> io::Result<Report> {
    let directory = canonical_directory(directory)?;
    let completion: Completion =
        decode(&files::read(&directory.join(COMPLETE_FILE), 4096, false)?)?;
    let node_id = match completion.stage {
        Stage::Authority => {
            let (roots, _) = load::<AuthorityPublic>(&directory, Stage::Authority)?;
            validate_roots(&roots, now)?;
            for (certificate, name) in [
                (&roots.admin_ca_pem, "admin-ca"),
                (&roots.node_ca_pem, "node-ca"),
            ] {
                if pem(&directory.join(format!("{name}.pem")), false)?.as_str() != certificate {
                    return Err(invalid("authority certificate file changed"));
                }
                identity::verify_authority(
                    certificate,
                    &pem(&directory.join(format!("{name}.key")), true)?,
                    now,
                )?;
            }
            None
        }
        Stage::Prepared | Stage::RecoveredPrepared => {
            Some(prepared_request(&directory, now)?.0.node_id)
        }
        Stage::Signed => {
            // No node key is on the signing machine. This limited check confirms
            // the complete response container, not acceptance by its recipient.
            let (response, _) = load::<Response>(&directory, Stage::Signed)?;
            if response.format_version != FORMAT || !valid_hash(&response.request_sha256) {
                return Err(invalid("invalid signed response metadata"));
            }
            certificate_der(&response.admin_certificate_pem)?;
            certificate_der(&response.node_certificate_pem)?;
            None
        }
        Stage::Plan => Some(checked_launch(&directory, now)?.1.node_id),
        Stage::AcmePlan => Some(acme::checked_launch(&directory, now)?.1.node_id),
        Stage::Service => {
            #[cfg(target_os = "linux")]
            {
                Some(checked_service(&directory, now)?)
            }
            #[cfg(not(target_os = "linux"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "setup user-service plans must be checked on their Linux node",
            ));
        }
    };
    // Re-read the public binding after all checks; this is not a same-account
    // race defense or an atomic snapshot of the entire filesystem.
    let (_, public_sha256) = load::<serde_json::Value>(&directory, completion.stage)?;
    Ok(report(&directory, completion.stage, public_sha256, node_id))
}

/// Validate the original launch inputs, certificates and both shell scripts.
/// The digest binds its completed public file, not executable contents or
/// same-account concurrent changes. No command or script is executed here.
fn checked_launch(directory: &Path, now: u64) -> io::Result<(Launch, Request, String)> {
    let (launch, hash) = load::<Launch>(directory, Stage::Plan)?;
    if launch.format_version != FORMAT {
        return Err(invalid("unsupported launch plan format"));
    }
    let (request, request_hash) = prepared_request(&launch.prepared, now)?;
    let (response, response_hash) = load::<Response>(&launch.response, Stage::Signed)?;
    if request_hash != launch.request_sha256 || response_hash != launch.response_sha256 {
        return Err(invalid("launch plan inputs changed; create a new plan"));
    }
    verify_response(&launch.prepared, &request, &request_hash, &response, now)?;
    for (name, expected) in [
        ("admin.pem", response.admin_certificate_pem.as_str()),
        ("node.pem", response.node_certificate_pem.as_str()),
        ("admin-ca.pem", request.authority.admin_ca_pem.as_str()),
        ("node-ca.pem", request.authority.node_ca_pem.as_str()),
    ] {
        equal_file(&directory.join(name), expected)?;
    }
    let (posix, powershell) = scripts(directory, &launch, &request)?;
    equal_file(&directory.join("start.sh"), &posix)?;
    equal_powershell(&directory.join("start.ps1"), &powershell)?;
    Ok((launch, request, hash))
}

/// Reuse the exact manual/ACME preflight, including recovered-state references.
/// This exports a selected plan, never observed runtime state or executable
/// contents. No scripts, listeners, key generation or ACME transport run here.
pub(super) fn snapshot_configuration(
    directory: &Path,
    surface: super::snapshot::config::Surface,
) -> io::Result<(PathBuf, super::snapshot::config::Configuration)> {
    use super::snapshot::config::{Configuration, Management, Node, Tls};
    let directory = canonical_directory(directory)?;
    let completion: Completion =
        decode(&files::read(&directory.join(COMPLETE_FILE), 4096, false)?)?;
    let now = now()?;
    let (prepared, request, admin_bind, node_bind, proxy_config, tls) = match completion.stage {
        Stage::Plan => {
            let (launch, request, _) = checked_launch(&directory, now)?;
            let tls = Tls::Manual {
                certificate: directory.join("admin.pem"),
                private_key: launch.prepared.join("admin.key"),
            };
            (
                launch.prepared,
                request,
                launch.admin_bind,
                launch.node_bind,
                launch.proxy_config,
                tls,
            )
        }
        Stage::AcmePlan => {
            let (launch, request, _) = acme::checked_launch(&directory, now)?;
            let tls = Tls::Acme {
                options: launch.acme,
            };
            (
                launch.prepared,
                request,
                launch.admin_bind,
                launch.node_bind,
                launch.proxy_config,
                tls,
            )
        }
        _ => {
            return Err(invalid(
                "snapshot configuration requires a manual or ACME launch plan",
            ));
        }
    };
    let data_dir = state_directory(&prepared, &request)?;
    let private_key = node_key_path(&prepared, &request)?;
    let configuration = Configuration {
        format_version: 1,
        expected_node_id: request.node_id,
        management: Management {
            bind: admin_bind,
            origin: request.admin_origin,
            surface,
            tls,
        },
        node: Node {
            bind: node_bind,
            origin: request.node_origin,
            ca: directory.join("node-ca.pem"),
            certificate: directory.join("node.pem"),
            private_key,
        },
        proxy_config: proxy_config.map(|configuration| configuration.path),
        health_config: None,
        observe_target_alerts: false,
        egress: None,
        source: None,
    };
    configuration.validate()?;
    Ok((data_dir, configuration))
}

/// Produce a new, uninstalled unit for the same Linux account that owns the
/// prepared state and keys. Do not copy to systemd paths, call D-Bus, enable
/// lingering, change permissions on inputs or start anything.
#[cfg(target_os = "linux")]
fn service_plan(plan: &Path, output: &Path, now: u64) -> io::Result<Report> {
    let output = files::output_path(output)?;
    let plan = canonical_directory(plan)?;
    let launch = checked_service_launch(&plan, now)?;
    // A C6 launch may still name a side-by-side older binary that cannot parse
    // Stage::Service. Never generate its self-preflight against that binary.
    // This pins the path at creation, not executable contents or future upgrades.
    if launch.executable != fs::canonicalize(env::current_exe()?)? {
        return Err(invalid(
            "launch executable differs; regenerate the launch plan with this binary",
        ));
    }
    let unit = service_unit(&output, &launch)?;
    files::create_directory(&output)?;
    files::write(&output, &unit_name(&launch.node_id), unit.as_bytes())?;
    complete(
        &output,
        Stage::Service,
        &Service {
            format_version: FORMAT,
            plan,
            plan_sha256: launch.plan_sha256,
        },
        Some(launch.node_id),
    )
}

/// Only the two launch stages are accepted; a service cannot recursively
/// reference another service. Re-rendering detects edits to the actual unit.
#[cfg(target_os = "linux")]
fn checked_service(directory: &Path, now: u64) -> io::Result<String> {
    let (service, _) = load::<Service>(directory, Stage::Service)?;
    if service.format_version != FORMAT || !valid_hash(&service.plan_sha256) {
        return Err(invalid("invalid user-service plan metadata"));
    }
    let launch = checked_service_launch(&service.plan, now)?;
    if launch.plan_sha256 != service.plan_sha256 {
        return Err(invalid(
            "launch plan changed; create a new user-service plan",
        ));
    }
    let unit = service_unit(directory, &launch)?;
    equal_file(&directory.join(unit_name(&launch.node_id)), &unit)?;
    Ok(launch.node_id)
}

/// Inspect the stage before dispatch, rather than following arbitrary plan links.
/// Each accepted branch validates its own completion, certificates and scripts.
#[cfg(target_os = "linux")]
fn checked_service_launch(directory: &Path, now: u64) -> io::Result<ServiceLaunch> {
    canonical_directory(directory)?;
    let completion: Completion =
        decode(&files::read(&directory.join(COMPLETE_FILE), 4096, false)?)?;
    match completion.stage {
        Stage::Plan => {
            let (launch, request, hash) = checked_launch(directory, now)?;
            let (_, serve_arguments) = arguments(directory, &launch, &request)?;
            Ok(ServiceLaunch {
                executable: launch.executable,
                node_id: request.node_id,
                plan_sha256: hash,
                serve_arguments,
            })
        }
        Stage::AcmePlan => {
            let (launch, request, hash) = acme::checked_launch(directory, now)?;
            let (_, serve_arguments) = acme::arguments(directory, &launch, &request)?;
            Ok(ServiceLaunch {
                executable: launch.executable,
                node_id: request.node_id,
                plan_sha256: hash,
                serve_arguments,
            })
        }
        _ => Err(invalid(
            "a user-service requires a manual or ACME launch plan",
        )),
    }
}

fn unit_name(node_id: &str) -> String {
    format!("vproxy-management-{node_id}.service")
}

#[cfg(target_os = "linux")]
fn service_unit(directory: &Path, launch: &ServiceLaunch) -> io::Result<String> {
    let check = check_arguments(directory)?;
    service::render(&launch.executable, &check, &launch.serve_arguments)
}

fn validate_roots(
    roots: &AuthorityPublic,
    now: u64,
) -> io::Result<(identity::RootInfo, identity::RootInfo)> {
    if roots.format_version != FORMAT {
        return Err(invalid("unsupported authority format"));
    }
    let admin = identity::root_info(&roots.admin_ca_pem, now)?;
    let node = identity::root_info(&roots.node_ca_pem, now)?;
    if admin.role != Role::Admin
        || node.role != Role::Node
        || admin.der_sha256 == node.der_sha256
        || admin.spki_sha256 == node.spki_sha256
    {
        return Err(invalid(
            "browser and node authorities must use independent keys",
        ));
    }
    Ok((admin, node))
}

fn validate_request(request: &Request, now: u64) -> io::Result<()> {
    if request.format_version != FORMAT || !super::store::valid_id(&request.node_id) {
        return Err(invalid("invalid setup request identity or version"));
    }
    super::validate_names(&request.name, "admin")?;
    let (admin_root, node_root) = validate_roots(&request.authority, now)?;
    if request.admin_origin == request.node_origin {
        return Err(invalid("browser and node origins must be separate"));
    }
    let admin = identity::inspect_request(
        Role::Admin,
        &origin_name(&request.admin_origin)?,
        &request.admin_csr_pem,
    )?;
    let node = if let Some(recovery) = &request.recovery {
        if !super::store::valid_id(&recovery.recovery_id)
            || !valid_hash(&recovery.node_key_sha256)
            || !valid_hash(&recovery.local_reference_sha256)
        {
            return Err(invalid("invalid recovery setup binding"));
        }
        let node = identity::inspect_recovery_request(
            &origin_name(&request.node_origin)?,
            &request.node_csr_pem,
        )?;
        if node.spki_sha256 != recovery.node_key_sha256 {
            return Err(invalid(
                "recovery request does not match its permanent key pin",
            ));
        }
        node
    } else {
        identity::inspect_request(
            Role::Node,
            &origin_name(&request.node_origin)?,
            &request.node_csr_pem,
        )?
    };
    if admin.spki_sha256 == node.spki_sha256
        || admin.der_sha256 == node.der_sha256
        || [&admin.spki_sha256, &node.spki_sha256]
            .into_iter()
            .any(|key| key == &admin_root.spki_sha256 || key == &node_root.spki_sha256)
    {
        return Err(invalid(
            "browser and node identities must use independent keys",
        ));
    }
    Ok(())
}

/// Use the existing read-only SQL snapshot, including committed WAL. Rejecting
/// sidecars here would prevent the launch script from reaching normal serve's
/// crash recovery. SQLite can maintain SHM/read marks; this is not immutable
/// filesystem inspection. No checkpoint, migration or application write runs.
fn prepared_request(directory: &Path, now: u64) -> io::Result<(Request, String)> {
    let completion: Completion =
        decode(&files::read(&directory.join(COMPLETE_FILE), 4096, false)?)?;
    if !matches!(completion.stage, Stage::Prepared | Stage::RecoveredPrepared) {
        return Err(invalid("a launch requires a completed node preparation"));
    }
    let (request, hash) = load::<Request>(directory, completion.stage)?;
    if request.recovery.is_some() != (completion.stage == Stage::RecoveredPrepared) {
        return Err(invalid(
            "prepared stage disagrees with its recovery binding",
        ));
    }
    validate_request(&request, now)?;
    let state = state_directory(directory, &request)?;
    let overview = super::store::inspect(&state)?;
    if overview.schema_version != super::store::SCHEMA_VERSION {
        return Err(invalid(
            "setup database requires the current schema; migrate explicitly",
        ));
    }
    if overview.node_id != request.node_id || overview.name != request.name {
        return Err(invalid(
            "prepared database does not match its public request",
        ));
    }
    equal_file(&directory.join("admin.csr"), &request.admin_csr_pem)?;
    identity::verify_request_key(
        Role::Admin,
        &origin_name(&request.admin_origin)?,
        &request.admin_csr_pem,
        &pem(&directory.join("admin.key"), true)?,
    )?;
    equal_file(&directory.join("node.csr"), &request.node_csr_pem)?;
    let key = pem(&node_key_path(directory, &request)?, true)?;
    if let Some(binding) = &request.recovery {
        let status = super::store::recovery::status(&state)?;
        let record = status
            .recovery
            .ok_or_else(|| invalid("recovery setup source is no longer a recovery"))?;
        if status.node_id != request.node_id
            || status.schema_version != overview.schema_version
            || record.phase != super::store::recovery::Phase::Ready
            || record.id != binding.recovery_id
            || hex_sha256(&record.node_key_sha256) != binding.node_key_sha256
        {
            return Err(invalid("recovery setup source identity or phase changed"));
        }
        equal_file(&state.join("node.csr"), &request.node_csr_pem)?;
        let info = identity::verify_recovery_request_key(
            &origin_name(&request.node_origin)?,
            &request.node_csr_pem,
            &key,
        )?;
        if info.spki_sha256 != binding.node_key_sha256 {
            return Err(invalid(
                "recovery node key does not match its permanent pin",
            ));
        }
    } else {
        identity::verify_request_key(
            Role::Node,
            &origin_name(&request.node_origin)?,
            &request.node_csr_pem,
            &key,
        )?;
    }
    Ok((request, hash))
}

/// Resolve only a node-local manifest whose exact bytes were bound into the
/// public request. Sign never calls this helper. Existing ordinary preparation
/// keeps its original state/ layout; a recovery keeps its original directory.
fn state_directory(prepared: &Path, request: &Request) -> io::Result<PathBuf> {
    let Some(binding) = &request.recovery else {
        return Ok(prepared.join("state"));
    };
    let bytes = files::read(&prepared.join("local-reference.json"), MAX_PUBLIC, false)?;
    if sha256(&bytes) != binding.local_reference_sha256 {
        return Err(invalid(
            "recovery local reference changed; inspect the preparation",
        ));
    }
    let reference: RecoveryReference = decode(&bytes)?;
    if reference.format_version != FORMAT
        || !reference.data_dir.is_absolute()
        || canonical_directory(&reference.data_dir)? != reference.data_dir
        || prepared.starts_with(&reference.data_dir)
    {
        return Err(invalid("invalid recovery local reference"));
    }
    Ok(reference.data_dir)
}

fn node_key_path(prepared: &Path, request: &Request) -> io::Result<PathBuf> {
    Ok(if request.recovery.is_some() {
        state_directory(prepared, request)?
    } else {
        prepared.to_owned()
    }
    .join("node.key"))
}

fn verify_node_response(
    prepared: &Path,
    request: &Request,
    response: &Response,
    now: u64,
) -> io::Result<()> {
    let key = pem(&node_key_path(prepared, request)?, true)?;
    let name = origin_name(&request.node_origin)?;
    if request.recovery.is_some() {
        identity::verify_recovery(
            &name,
            &request.authority.node_ca_pem,
            &response.node_certificate_pem,
            &key,
            &request.node_csr_pem,
            now,
        )
    } else {
        identity::verify(
            Role::Node,
            &name,
            &request.authority.node_ca_pem,
            &response.node_certificate_pem,
            &key,
            &request.node_csr_pem,
            now,
        )
    }
}

fn verify_response(
    directory: &Path,
    request: &Request,
    request_hash: &str,
    response: &Response,
    now: u64,
) -> io::Result<()> {
    if response.format_version != FORMAT || response.request_sha256 != request_hash {
        return Err(invalid(
            "signed response does not match this prepared request",
        ));
    }
    identity::verify(
        Role::Admin,
        &origin_name(&request.admin_origin)?,
        &request.authority.admin_ca_pem,
        &response.admin_certificate_pem,
        &pem(&directory.join("admin.key"), true)?,
        &request.admin_csr_pem,
        now,
    )?;
    verify_node_response(directory, request, response, now)
}

fn scripts(directory: &Path, launch: &Launch, request: &Request) -> io::Result<(String, String)> {
    let (check, serve) = arguments(directory, launch, request)?;
    plan::render(&launch.executable, &check, &serve)
}

/// Share the exact checked argv between manual scripts and Linux user units;
/// neither path adds a shell or infers bind addresses. Managed listeners remain
/// opt-in through the same checked startup JSON used by ordinary serve.
fn arguments(
    directory: &Path,
    launch: &Launch,
    request: &Request,
) -> io::Result<(Vec<String>, Vec<String>)> {
    if launch.admin_bind.port() == 0
        || launch.node_bind.port() == 0
        || launch.admin_bind == launch.node_bind
    {
        return Err(invalid(
            "launch binds require distinct non-zero local ports",
        ));
    }
    let check = check_arguments(directory)?;
    let mut serve: Vec<String> = ["manage", "serve", "--data-dir"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    serve.push(path_string(&state_directory(&launch.prepared, request)?)?);
    for (flag, value) in [
        ("--bind", launch.admin_bind.to_string()),
        ("--public-origin", request.admin_origin.clone()),
        ("--tls-cert", path_string(&directory.join("admin.pem"))?),
        (
            "--tls-key",
            path_string(&launch.prepared.join("admin.key"))?,
        ),
        ("--node-bind", launch.node_bind.to_string()),
        ("--node-origin", request.node_origin.clone()),
        ("--node-ca", path_string(&directory.join("node-ca.pem"))?),
        ("--node-cert", path_string(&directory.join("node.pem"))?),
        (
            "--node-key",
            path_string(&node_key_path(&launch.prepared, request)?)?,
        ),
    ] {
        serve.extend([flag.to_owned(), value]);
    }
    if let Some(proxy_config) = &launch.proxy_config {
        proxy_config.append_arguments(&mut serve)?;
    }
    Ok((check, serve))
}

fn check_arguments(directory: &Path) -> io::Result<Vec<String>> {
    Ok(vec![
        "manage".into(),
        "setup".into(),
        "check".into(),
        "--input".into(),
        path_string(directory)?,
    ])
}

/// Match the actual management origin parser first, then constrain its host to
/// one canonical DNS/IP SAN. There is no DNS lookup or inferred public address.
fn origin_name(value: &str) -> io::Result<String> {
    super::api::PublicOrigin::parse(value)?;
    let url = url::Url::parse(value).map_err(|_| invalid("invalid setup origin"))?;
    match url.host() {
        Some(url::Host::Domain(name)) => identity::name(name),
        Some(url::Host::Ipv4(ip)) => identity::name(&ip.to_string()),
        Some(url::Host::Ipv6(ip)) => identity::name(&ip.to_string()),
        None => Err(invalid("setup origin requires a host")),
    }
}

fn complete<T: Serialize>(
    directory: &Path,
    stage: Stage,
    value: &T,
    node_id: Option<String>,
) -> io::Result<Report> {
    let bytes = encode(value)?;
    if bytes.len() > MAX_PUBLIC {
        return Err(invalid("setup public output exceeds its size limit"));
    }
    let public_sha256 = sha256(&bytes);
    files::write(directory, PUBLIC_FILE, &bytes)?;
    files::write(
        directory,
        COMPLETE_FILE,
        &encode(&Completion {
            format_version: FORMAT,
            stage,
            public_sha256: public_sha256.clone(),
        })?,
    )?;
    files::sync_directory(directory)?;
    Ok(report(directory, stage, public_sha256, node_id))
}

fn report(
    directory: &Path,
    stage: Stage,
    public_sha256: String,
    node_id: Option<String>,
) -> Report {
    Report {
        state: match stage {
            Stage::Authority => "authority_ready",
            Stage::Prepared => "prepared",
            Stage::RecoveredPrepared => "recovered_prepared",
            Stage::Signed => "signed_container",
            Stage::Plan => "offline_plan_ready",
            Stage::AcmePlan => "offline_acme_plan_ready",
            Stage::Service => "offline_service_plan_ready",
        },
        directory: directory.to_owned(),
        public_file: directory.join(PUBLIC_FILE),
        public_sha256,
        unit_file: if stage == Stage::Service {
            node_id.as_ref().map(|id| directory.join(unit_name(id)))
        } else {
            None
        },
        node_id,
        server_started: false,
        trust_installed: false,
        node_authorized: false,
    }
}

fn load<T: DeserializeOwned>(directory: &Path, stage: Stage) -> io::Result<(T, String)> {
    canonical_directory(directory)?;
    let completion: Completion =
        decode(&files::read(&directory.join(COMPLETE_FILE), 4096, false)?)?;
    if completion.format_version != FORMAT
        || completion.stage != stage
        || !valid_hash(&completion.public_sha256)
    {
        return Err(invalid(
            "incomplete or incompatible setup directory; do not replay into it",
        ));
    }
    let bytes = files::read(&directory.join(PUBLIC_FILE), MAX_PUBLIC, false)?;
    let hash = sha256(&bytes);
    if hash != completion.public_sha256 {
        return Err(invalid("setup public file changed after completion"));
    }
    Ok((decode(&bytes)?, hash))
}

fn pem(path: &Path, private: bool) -> io::Result<Zeroizing<String>> {
    let bytes = files::read(path, MAX_PEM, private)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("setup PEM must be UTF-8"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn equal_file(path: &Path, expected: &str) -> io::Result<()> {
    if files::read(path, MAX_PUBLIC, false)?.as_slice() != expected.as_bytes() {
        return Err(invalid("setup file no longer matches its checked inputs"));
    }
    Ok(())
}

/// Accept only an exact current or legacy generated script during upgrade.
/// Certificate/input checks remain identical; compatibility does not rewrite it
/// or prove that a legacy PowerShell host actually launched the native program.
fn equal_powershell(path: &Path, expected: &str) -> io::Result<()> {
    if !plan::powershell_matches(&files::read(path, MAX_PUBLIC, false)?, expected) {
        return Err(invalid("setup file no longer matches its checked inputs"));
    }
    Ok(())
}

fn canonical_directory(path: &Path) -> io::Result<PathBuf> {
    files::check_directory(path, false)?;
    let path = fs::canonicalize(path)?;
    path_string(&path)?;
    Ok(path)
}

pub(super) fn path_string(path: &Path) -> io::Result<String> {
    path.to_str()
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or_else(|| invalid("setup paths require UTF-8 without control characters"))
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|_| invalid("invalid setup JSON; input values are not printed"))
}

fn encode<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| io::Error::other("cannot encode setup metadata"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    hex_sha256(&Sha256::digest(bytes))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hash = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        hash.push(char::from(HEX[usize::from(byte >> 4)]));
        hash.push(char::from(HEX[usize::from(byte & 15)]));
    }
    hash
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| invalid("system clock precedes Unix epoch"))
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn certificate_der(pem: &str) -> io::Result<Vec<u8>> {
    let mut reader = pem.as_bytes();
    let mut items = rustls_pemfile::read_all(&mut reader);
    let Some(Ok(rustls_pemfile::Item::X509Certificate(certificate))) = items.next() else {
        return Err(invalid("signed response certificate is missing or invalid"));
    };
    if items.next().is_some() {
        return Err(invalid("signed response must contain one leaf"));
    }
    let (remainder, _) = x509_parser::parse_x509_certificate(&certificate)
        .map_err(|_| invalid("invalid signed response certificate DER"))?;
    if !remainder.is_empty() {
        return Err(invalid("signed response certificate has trailing DER"));
    }
    Ok(certificate.to_vec())
}
