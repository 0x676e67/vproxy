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

#[cfg(test)]
mod tests {
    use super::*;

    mod recovery {
        use rcgen::{
            CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
            KeyUsagePurpose, PublicKeyData as _,
        };

        use super::*;

        /// Independently construct the pre-C6 recovery CSR, then use the real backup,
        /// restore and finalize code. No existing identity or service is touched.
        fn recovered(fixture: &Fixture, name: &str, ready: bool) -> io::Result<(PathBuf, String)> {
            let source = fixture.0.join("source");
            files::create_directory(&source)?;
            super::super::super::store::initialize(&source, "old node", "admin", PHC)?;
            let backup = fixture.0.join("backup");
            super::super::super::store::create_backup(&source, &backup)?;
            let key = KeyPair::generate().map_err(io::Error::other)?;
            let mut params =
                CertificateParams::new(vec![name.to_owned()]).map_err(io::Error::other)?;
            params.distinguished_name = DistinguishedName::new();
            params
                .distinguished_name
                .push(DnType::CommonName, "vproxy node");
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            let identity = super::super::super::store::recovery::Identity {
                key_pem: Zeroizing::new(key.serialize_pem()),
                request_pem: params
                    .serialize_request(&key)
                    .and_then(|csr| csr.pem())
                    .map_err(io::Error::other)?,
                public_key_sha256: Sha256::digest(key.subject_public_key_info()).into(),
            };
            let directory = fixture.0.join("recovered");
            let status = super::super::super::store::recovery::restore(
                &backup,
                &directory,
                "recovered node",
                "new-admin",
                PHC,
                identity,
            )?;
            let id = status
                .recovery
                .ok_or_else(|| io::Error::other("missing recovery record"))?
                .id;
            if ready {
                super::super::super::store::recovery::finalize(&directory, &id)?;
            }
            Ok((directory, id))
        }

        #[test]
        fn recovered_setup_preserves_identity_and_reuses_checked_manual_acme_and_service_paths()
        -> TestResult {
            let fixture = Fixture::new()?;
            let now = now()?;
            let (authority, roots) = fixture.authority(now)?;
            let (state, id) = recovered(&fixture, "EDGE.example", true)?;
            let state = canonical_directory(&state)?;
            let before = inventory(&state)?;
            let prepared = fixture.0.join("recovered-prepared");
            recover(
                &state,
                &id,
                &prepared,
                roots,
                "https://admin.example:24443",
                "https://edge.example:24444",
                now,
            )?;
            let (request, _) = prepared_request(&prepared, now)?;
            let public = files::read(&prepared.join(PUBLIC_FILE), MAX_PUBLIC, false)?;
            let public_text = std::str::from_utf8(&public)?;
            let local_path_json = serde_json::to_string(&path_string(&state)?)?;
            assert!(
                !public_text.contains(&local_path_json)
                    && !public_text.contains("PRIVATE KEY")
                    && !public_text.contains(PHC)
            );
            assert!(!prepared.join("state").exists() && !prepared.join("node.key").exists());
            assert_eq!(state_directory(&prepared, &request)?, state);
            assert_eq!(node_key_path(&prepared, &request)?, state.join("node.key"));
            assert!(
                identity::inspect_request(Role::Node, "edge.example", &request.node_csr_pem)
                    .is_err()
            );
            assert_eq!(check(&prepared, now)?.state, "recovered_prepared");
            // A normal setup completion cannot reinterpret a recovery reference.
            rebind_public(&prepared, Stage::Prepared, &request)?;
            assert!(prepared_request(&prepared, now).is_err());
            rebind_public(&prepared, Stage::RecoveredPrepared, &request)?;
            let signed = fixture.0.join("recovered-signed");
            sign(&authority, &prepared.join(PUBLIC_FILE), &signed, now)?;
            let manual = fixture.0.join("recovered-plan");
            let manual = launch(
                &prepared,
                &signed,
                &manual,
                "127.0.0.1:24443".parse()?,
                "127.0.0.1:24444".parse()?,
                &env::current_exe()?,
                None,
                now,
            )?
            .directory;
            let (launch, request, _) = checked_launch(&manual, now)?;
            let (_, argv) = arguments(&manual, &launch, &request)?;
            for (flag, expected) in [
                ("--data-dir", state.clone()),
                ("--node-key", state.join("node.key")),
            ] {
                let expected = path_string(&expected)?;
                assert!(
                    argv.windows(2)
                        .any(|pair| pair[0] == flag && pair[1] == expected)
                );
            }
            let acme_plan = fixture.0.join("recovered-acme-plan");
            let acme_plan = acme::launch(
                &prepared,
                &signed,
                &acme_plan,
                ("127.0.0.1:24443".parse()?, "127.0.0.1:24444".parse()?),
                &env::current_exe()?,
                &acme_options()?,
                None,
                now,
            )?
            .directory;
            let (launch, request, _) = acme::checked_launch(&acme_plan, now)?;
            let (_, argv) = acme::arguments(&acme_plan, &launch, &request)?;
            let state_text = path_string(&state)?;
            assert!(
                argv.windows(2)
                    .any(|pair| pair[0] == "--data-dir" && pair[1] == state_text)
            );
            #[cfg(target_os = "linux")]
            for plan in [&manual, &acme_plan] {
                let output = fixture.0.join(if plan == &manual {
                    "manual-service"
                } else {
                    "acme-service"
                });
                service_plan(plan, &output, now)?;
                check(&output, now)?;
            }
            // Ordinary checks remain read-only while a cooperating instance owns author.
            {
                let _author = super::super::super::store::lock(&state)?;
                check(&manual, now)?;
                check(&acme_plan, now)?;
            }
            // The inventory reads management.lock too. Windows' exclusive byte lock
            // rejects that read while held; unlike check, this is a raw file inventory.
            assert_eq!(before, inventory(&state)?);
            // The setup exporter must keep the recovered state's original key path,
            // and sealing a snapshot must not discard its previous Ready provenance.
            for (label, plan) in [("manual", &manual), ("acme", &acme_plan)] {
                use crate::manage::snapshot::{self, config::Surface};
                let description = fixture.0.join(format!("snapshot-{label}-configuration"));
                let report = serde_json::to_value(snapshot::configure(
                    plan,
                    Surface::ApiOnly,
                    &description,
                )?)?;
                assert_eq!(report["data_dir"], serde_json::to_value(&state)?);
                let configuration = description.join("configuration.json");
                let parsed: serde_json::Value = serde_json::from_slice(&fs::read(&configuration)?)?;
                assert_eq!(
                    parsed["node"]["private_key"],
                    serde_json::to_value(state.join("node.key"))?
                );
                let output = fixture.0.join(format!("snapshot-{label}"));
                snapshot::create(&state, &configuration, &output)?;
                let marker = files::read(&output.join("database/snapshot.json"), 1024, true)?;
                let marker: serde_json::Value = serde_json::from_slice(&marker)?;
                assert_eq!(marker["previous_recovery"]["id"], id);
                assert_eq!(marker["previous_recovery"]["phase"], "ready");
                snapshot::verify(&output)?;
                assert_eq!(before, inventory(&state)?);
            }
            Ok(())
        }

        #[test]
        fn recovery_setup_rejects_pending_native_wrong_id_and_busy_before_claiming_output()
        -> TestResult {
            let fixture = Fixture::new()?;
            let now = now()?;
            let (_, roots) = fixture.authority(now)?;
            let (state, id) = recovered(&fixture, "edge.example", false)?;
            let attempt = |suffix: &str, expected: &str| {
                let output = fixture.0.join(suffix);
                let result = recover(
                    &state,
                    expected,
                    &output,
                    roots.clone(),
                    "https://admin.example",
                    "https://edge.example",
                    now,
                );
                assert!(!output.exists());
                result
            };
            assert!(attempt("pending-output", &id).is_err());
            super::super::super::store::recovery::finalize(&state, &id)?;
            assert!(attempt("wrong-id", "AAECAwQFBgcICQoLDA0ODw").is_err());
            let author = super::super::super::store::lock(&state)?;
            assert_eq!(
                attempt("busy-output", &id).err().map(|error| error.kind()),
                Some(io::ErrorKind::WouldBlock)
            );
            drop(author);
            let output = fixture.0.join("native-output");
            assert!(
                recover(
                    &fixture.0.join("source"),
                    &id,
                    &output,
                    roots,
                    "https://admin.example",
                    "https://edge.example",
                    now
                )
                .is_err()
            );
            assert!(!output.exists());
            Ok(())
        }

        #[test]
        fn recovery_reference_csr_key_and_stage_tampering_fail_without_new_plan_or_source_mutation()
        -> TestResult {
            let fixture = Fixture::new()?;
            let now = now()?;
            let (_, roots) = fixture.authority(now)?;
            let (state, id) = recovered(&fixture, "edge.example", true)?;
            let prepared = fixture.0.join("prepared-recovery");
            recover(
                &state,
                &id,
                &prepared,
                roots,
                "https://admin.example",
                "https://edge.example",
                now,
            )?;
            let (mut request, _) = prepared_request(&prepared, now)?;
            let before = inventory(&state)?;
            let reference = files::read(&prepared.join("local-reference.json"), MAX_PUBLIC, false)?;
            fs::write(prepared.join("local-reference.json"), b"{}")?;
            assert!(check(&prepared, now).is_err());
            fs::write(prepared.join("local-reference.json"), reference)?;
            let original_csr = request.node_csr_pem.clone();
            let wrong = identity::request(Role::Node, "edge.example")?;
            fs::write(prepared.join("node.csr"), wrong.request_pem.as_bytes())?;
            assert!(check(&prepared, now).is_err());
            fs::write(prepared.join("node.csr"), original_csr.as_bytes())?;
            // Keeping a valid different CSR/key is insufficient: the permanent pin wins.
            let old_key = files::read(&state.join("node.key"), MAX_PEM, true)?;
            fs::write(state.join("node.key"), wrong.key_pem.as_bytes())?;
            assert!(check(&prepared, now).is_err());
            fs::write(state.join("node.key"), old_key)?;
            let recovery = request.recovery.take().ok_or("missing binding")?;
            rebind_public(&prepared, Stage::RecoveredPrepared, &request)?;
            assert!(check(&prepared, now).is_err());
            request.recovery = Some(recovery);
            rebind_public(&prepared, Stage::RecoveredPrepared, &request)?;
            check(&prepared, now)?;
            let mut wire = serde_json::to_value(&request)?;
            wire["recovery"] = serde_json::Value::Null;
            assert!(serde_json::from_value::<Request>(wire).is_err());
            assert_eq!(before, inventory(&state)?);
            Ok(())
        }
    }
    mod snapshot {
        //! Real file-only identities and fresh SQLite state. No cache from an existing
        //! node, system trust, listener, CA network request or infrastructure is used.

        use super::*;
        use crate::manage::{snapshot, store};
        use std::sync::Arc;

        struct Inputs {
            fixture: Fixture,
            state: PathBuf,
            configuration: PathBuf,
            output: PathBuf,
            node_id: String,
            plan: PathBuf,
        }

        fn inputs(automatic: bool) -> TestResultInputs {
            let fixture = Fixture::new()?;
            let time = now()?;
            let (authority, prepared, signed) = acme_inputs(&fixture, time)?;
            let proxy_path = proxy_config_fixture(&fixture, PROXY_JSON)?;
            let plan = fixture.0.join("plan");
            proxy_launch(&prepared, &signed, &plan, &proxy_path, automatic, time)?;
            let state = prepared.join("state");
            let node_id = store::inspect(&state)?.node_id;
            let tls = if automatic {
                serde_json::json!({"mode":"acme", "options":acme_options()?.plan("https://admin.example.com:23443")?.ok_or_else(|| invalid("missing test ACME plan"))?})
            } else {
                serde_json::json!({"mode":"manual", "certificate":plan.join("admin.pem"), "private_key":prepared.join("admin.key")})
            };
            let configuration = fixture.0.join("snapshot-input.json");
            files::write(
                &fixture.0,
                "snapshot-input.json",
                &serde_json::to_vec_pretty(&serde_json::json!({
                    "format_version":1, "expected_node_id":node_id,
                    "management":{"bind":"127.0.0.1:23443", "origin":"https://admin.example.com:23443", "surface":"web", "tls":tls},
                    "node":{"bind":"127.0.0.1:23444", "origin":"https://127.0.0.1:23444", "ca":plan.join("node-ca.pem"), "certificate":plan.join("node.pem"), "private_key":prepared.join("node.key")},
                    "proxy_config":proxy_path, "health_config":null, "observe_target_alerts":true, "egress":null
                }))?,
            )?;
            let _ = authority;
            let output = fixture.0.join("identity-snapshot");
            Ok(Inputs {
                fixture,
                state,
                configuration,
                output,
                node_id,
                plan,
            })
        }

        type TestResultInputs = Result<Inputs, Box<dyn std::error::Error>>;

        #[cfg(feature = "witness-journal")]
        #[test]
        fn fixed_and_archive_capture_bind_the_same_static_inputs_without_preserving_dynamic_cache()
        -> TestResult {
            let input = inputs(true)?;
            let author = Arc::new(store::lock(&input.state)?);
            let _gate = store::update_lock(&input.state)?;
            let base = input
                .configuration
                .parent()
                .ok_or_else(|| invalid("missing configuration parent"))?;
            let read = || -> io::Result<snapshot::config::Configuration> {
                serde_json::from_slice(&files::read(&input.configuration, 32 * 1024, true)?)
                    .map_err(io::Error::other)
            };
            let fixed = snapshot::inputs::capture(
                &input.state,
                author.clone(),
                base,
                read()?,
                snapshot::inputs::Mode::Fixed,
            )?;
            let archive = snapshot::inputs::capture(
                &input.state,
                author,
                base,
                read()?,
                snapshot::inputs::Mode::Archive,
            )?;
            assert!(fixed.acme_cache.is_none());
            assert!(fixed.management.is_none());
            assert!(archive.acme_cache.is_some());
            assert_eq!(fixed.sha256()?, archive.sha256()?);
            assert!(fixed.proxy.is_some());
            assert_eq!(fixed.node_key_sha256, archive.node_key_sha256);
            Ok(())
        }

        #[test]
        fn snapshot_source_selection_is_versioned_and_never_a_feature_off_fallback() -> TestResult {
            let input = inputs(false)?;
            let native: serde_json::Value =
                serde_json::from_slice(&fs::read(&input.configuration)?)?;
            let configuration: snapshot::config::Configuration =
                serde_json::from_value(native.clone())?;
            assert!(serde_json::to_value(configuration)?.get("source").is_none());
            let mut value = native;
            value["source"] = serde_json::json!({
                "endpoint":"https://witness.example:8444",
                "enrollment":{
                    "witness_node_id":"AgICAgICAgICAgICAgICAg", "peer_node_id":input.node_id,
                    "binding_id":"AAAAAAAAAAAAAAAAAAAAAA", "writer_id":"AQEBAQEBAQEBAQEBAQEBAQ", "baseline":"0".repeat(64)
                }
            });
            let wrong_version: snapshot::config::Configuration =
                serde_json::from_value(value.clone())?;
            assert!(wrong_version.validate().is_err());
            value["format_version"] = serde_json::json!(2);
            let selected: snapshot::config::Configuration = serde_json::from_value(value.clone())?;
            #[cfg(feature = "witness-journal")]
            selected.validate()?;
            #[cfg(not(feature = "witness-journal"))]
            {
                assert_eq!(
                    selected.validate().err().map(|e| e.kind()),
                    Some(io::ErrorKind::Unsupported)
                );
                fs::write(&input.configuration, serde_json::to_vec(&value)?)?;
                assert_eq!(
                    snapshot::create(&input.state, &input.configuration, &input.output)
                        .err()
                        .map(|e| e.kind()),
                    Some(io::ErrorKind::Unsupported)
                );
                assert_eq!(
                    snapshot::seal(&input.state, &input.output)
                        .err()
                        .map(|e| e.kind()),
                    Some(io::ErrorKind::Unsupported)
                );
                assert!(!input.output.exists());
            }
            value["source"] = serde_json::Value::Null;
            let missing: snapshot::config::Configuration = serde_json::from_value(value)?;
            assert!(missing.validate().is_err());
            Ok(())
        }

        #[test]
        fn checked_manual_and_acme_plans_export_usable_explicit_descriptions() -> TestResult {
            use snapshot::config::Surface;
            for automatic in [false, true] {
                let input = inputs(automatic)?;
                let description = input.fixture.0.join("description");
                let before = inventory(&input.state)?;
                let plan_before = inventory(&input.plan)?;
                let report = serde_json::to_value(snapshot::configure(
                    &input.plan,
                    Surface::ApiOnly,
                    &description,
                )?)?;
                assert_eq!(
                    report["data_dir"],
                    serde_json::to_value(fs::canonicalize(&input.state)?)?
                );
                assert_eq!(
                    report["scope"],
                    "selected_launch_plan_only_review_later_serve_overrides"
                );
                let configuration = description.join("configuration.json");
                let bytes = files::read(&configuration, 32 * 1024, true)?;
                let value: serde_json::Value = serde_json::from_slice(&bytes)?;
                assert_eq!(value["management"]["surface"], "api_only");
                assert_eq!(
                    value["management"]["tls"]["mode"],
                    if automatic { "acme" } else { "manual" }
                );
                assert!(value["health_config"].is_null() && value["egress"].is_null());
                assert_eq!(value["observe_target_alerts"], false);
                assert!(snapshot::configure(&input.plan, Surface::Web, &description).is_err());
                assert!(
                    bytes.as_slice() == files::read(&configuration, 32 * 1024, true)?.as_slice()
                );
                snapshot::create(&input.state, &configuration, &input.output)?;
                snapshot::verify(&input.output)?;
                assert_eq!(before, inventory(&input.state)?);
                assert_eq!(plan_before, inventory(&input.plan)?);
                // A changed launch script is not silently exported as a checked plan.
                fs::write(
                    input.plan.join("start.sh"),
                    b"not the checked launch script",
                )?;
                let rejected = input.fixture.0.join("rejected-description");
                assert!(snapshot::configure(&input.plan, Surface::Web, &rejected).is_err());
                assert!(!rejected.exists());
            }
            Ok(())
        }

        #[test]
        fn proxy_tls_and_health_are_portable_and_escaping_or_changed_assets_are_rejected()
        -> TestResult {
            let input = inputs(false)?;
            let proxy = input.fixture.0.join("proxy.json");
            let mut configuration: serde_json::Value =
                serde_json::from_slice(&fs::read(&input.configuration)?)?;
            fs::write(
                &proxy,
                serde_json::to_vec(&serde_json::json!({
                    "listeners":[{"protocol":"https", "bind":"127.0.0.1:21081", "tls_cert":input.plan.join("admin.pem"), "tls_key":configuration["management"]["tls"]["private_key"]}], "workers":1
                }))?,
            )?;
            let health = br#"{"interval_secs":60,"timeout_secs":2,"concurrency":1,"probes_per_second":1,"targets":["127.0.0.1:9"]}"#;
            files::write(&input.fixture.0, "health.json", health)?;
            configuration["proxy_config"] = serde_json::to_value(&proxy)?;
            configuration["health_config"] =
                serde_json::to_value(input.fixture.0.join("health.json"))?;
            fs::write(&input.configuration, serde_json::to_vec(&configuration)?)?;
            snapshot::create(&input.state, &input.configuration, &input.output)?;
            let proxy_copy = input.output.join("files/proxy.json");
            let captured = fs::read(&proxy_copy)?;
            let mut parsed: serde_json::Value = serde_json::from_slice(&captured)?;
            assert_eq!(parsed["listeners"][0]["tls_cert"], "proxy-00-cert.pem");
            assert_eq!(parsed["listeners"][0]["tls_key"], "proxy-00-key.pem");
            assert_eq!(fs::read(input.output.join("files/health.json"))?, health);
            snapshot::verify(&input.output)?;
            parsed["listeners"][0]["tls_cert"] =
                serde_json::to_value(input.plan.join("admin.pem"))?;
            fs::write(&proxy_copy, serde_json::to_vec(&parsed)?)?;
            // Even a matching inventory hash cannot authorize following a path outside
            // the package. These hashes do not authenticate the operator or freshness.
            let manifest_path = input.output.join("manifest.json");
            let original_manifest = fs::read(&manifest_path)?;
            let mut manifest: serde_json::Value = serde_json::from_slice(&original_manifest)?;
            for asset in manifest["assets"]
                .as_array_mut()
                .ok_or_else(|| invalid("fixture inventory missing"))?
            {
                if asset["name"] == "proxy.json" {
                    let changed = fs::read(&proxy_copy)?;
                    asset["sha256"] = serde_json::to_value(sha256(&changed))?;
                    asset["bytes"] = serde_json::to_value(changed.len())?;
                }
            }
            fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
            assert!(snapshot::verify(&input.output).is_err());
            fs::write(&proxy_copy, captured)?;
            fs::write(&manifest_path, original_manifest)?;
            snapshot::verify(&input.output)?;
            fs::write(input.output.join("files/health.json"), b"{}")?;
            assert!(snapshot::verify(&input.output).is_err());
            Ok(())
        }

        #[test]
        fn manual_identity_snapshot_retains_state_but_cannot_start_write_or_finalize() -> TestResult
        {
            let input = inputs(false)?;
            let source_before = inventory(&input.state)?;
            let report = snapshot::create(&input.state, &input.configuration, &input.output)?;
            let report = serde_json::to_value(report)?;
            assert_eq!(report["node_id"], input.node_id);
            assert_eq!(report["quarantined"], true);
            assert!(
                report["database_content_sha256"]
                    .as_str()
                    .is_some_and(crate::manage::witness::digest)
            );
            assert_eq!(source_before, inventory(&input.state)?);
            let copied = input.output.join("database");
            let status = store::recovery::status(&copied)?;
            assert_eq!(status.node_id, input.node_id);
            let record = status
                .recovery
                .ok_or_else(|| invalid("test snapshot fence missing"))?;
            assert_eq!(record.phase, store::recovery::Phase::PendingTakeover);
            assert_eq!(
                store::recovery::startup(&copied).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                store::recovery::finalize(&copied, &record.id)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(
                store::migrate(
                    &copied,
                    &input.fixture.0.join("forbidden-migration.sqlite3")
                )
                .is_err()
            );
            let original = snapshot::verify(&input.output)?;
            let before = inventory(&input.output)?;
            assert_eq!(
                serde_json::to_value(snapshot::verify(&input.output)?)?,
                serde_json::to_value(original)?
            );
            assert_eq!(before, inventory(&input.output)?);
            // Removing only the filesystem marker cannot remove the intrinsic SQL gate.
            fs::remove_file(copied.join("snapshot.json"))?;
            assert_eq!(
                store::recovery::startup(&copied).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                store::recovery::finalize(&copied, &record.id)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(snapshot::verify(&input.output).is_err());
            Ok(())
        }

        #[test]
        fn snapshot_capture_is_exclusive_and_an_existing_output_is_never_reused() -> TestResult {
            let input = inputs(false)?;
            let author = store::lock(&input.state)?;
            assert_eq!(
                snapshot::create(&input.state, &input.configuration, &input.output)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            assert!(!input.output.exists());
            drop(author);
            snapshot::create(&input.state, &input.configuration, &input.output)?;
            let before = inventory(&input.output)?;
            assert!(snapshot::create(&input.state, &input.configuration, &input.output).is_err());
            assert_eq!(before, inventory(&input.output)?);
            Ok(())
        }

        #[test]
        fn malformed_identity_is_refused_before_claiming_snapshot_output() -> TestResult {
            let input = inputs(false)?;
            let mut configuration: serde_json::Value =
                serde_json::from_slice(&fs::read(&input.configuration)?)?;
            configuration["node"]["certificate"] =
                serde_json::to_value(input.plan.join("admin.pem"))?;
            fs::write(&input.configuration, serde_json::to_vec(&configuration)?)?;
            assert!(snapshot::create(&input.state, &input.configuration, &input.output).is_err());
            // Static identity preparation now precedes output/SQL capture. No copied
            // credentials exist to quarantine when the identity itself is invalid.
            assert!(!input.output.exists());
            assert!(store::recovery::status(&input.state)?.recovery.is_none());
            Ok(())
        }

        #[test]
        fn acme_absence_and_unresolved_temporary_bytes_are_preserved_without_replay() -> TestResult
        {
            let input = inputs(true)?;
            snapshot::create(&input.state, &input.configuration, &input.output)?;
            let original: serde_json::Value =
                serde_json::from_slice(&fs::read(input.output.join("manifest.json"))?)?;
            assert_eq!(original["acme_cache"]["present"], false);
            assert!(!input.state.join("acme").exists());
            let author = Arc::new(store::lock(&input.state)?);
            let options = acme_options()?;
            let expected = crate::manage::acme::backup::seed_test_cache(
                &input.state,
                author.clone(),
                "https://admin.example.com:23443",
                &options
                    .plan("https://admin.example.com:23443")?
                    .ok_or_else(|| invalid("missing ACME test plan"))?,
            )?;
            drop(author);
            let second = input.fixture.0.join("with-acme-cache");
            let before = inventory(&input.state)?;
            snapshot::create(&input.state, &input.configuration, &second)?;
            assert_eq!(before, inventory(&input.state)?);
            let manifest: serde_json::Value =
                serde_json::from_slice(&fs::read(second.join("manifest.json"))?)?;
            assert_eq!(manifest["acme_cache"]["present"], true);
            assert_eq!(
                manifest["acme_cache"]["names"]
                    .as_array()
                    .ok_or_else(|| invalid("missing cache inventory"))?
                    .len(),
                3
            );
            for (name, bytes) in expected {
                assert_eq!(
                    fs::read(second.join("files").join(format!("acme-{name}")))?,
                    bytes
                );
            }
            let result = serde_json::to_value(snapshot::verify(&second)?)?;
            assert_eq!(
                result["acme_cache_semantics"],
                "preserved_for_separate_recovery_review"
            );
            Ok(())
        }

        #[test]
        fn schema23_migration_preserves_native_state_and_a_genuine_legacy_backup() -> TestResult {
            let input = inputs(false)?;
            let connection = rusqlite::Connection::open(input.state.join("management.sqlite3"))?;
            store::recovery::restore_schema_twenty_three_for_test(&connection)?;
            drop(connection);
            assert_eq!(store::inspect(&input.state)?.schema_version, 23);
            let backup = input.fixture.0.join("before24.sqlite3");
            let migrated = store::migrate(&input.state, &backup)?;
            assert_eq!(migrated.node_id, input.node_id);
            assert_eq!(migrated.schema_version, store::SCHEMA_VERSION);
            let old = rusqlite::Connection::open(&backup)?;
            assert_eq!(
                old.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?,
                23
            );
            let old_sql: String = old.query_row(
                "SELECT sql FROM sqlite_schema WHERE name='recovery_state'",
                [],
                |row| row.get(0),
            )?;
            assert!(!old_sql.contains("pending_takeover"));
            drop(old);
            assert!(store::recovery::status(&input.state)?.recovery.is_none());
            snapshot::create(&input.state, &input.configuration, &input.output)?;
            snapshot::verify(&input.output)?;
            Ok(())
        }

        #[test]
        fn pre_copy_marker_blocks_every_ordinary_writer_without_creating_lock_files() -> TestResult
        {
            let fixture = Fixture::new()?;
            let incomplete = fixture.0.join("incomplete-copy");
            files::create_directory(&incomplete)?;
            files::write(&incomplete, "snapshot.json", b"incomplete marker")?;
            let before = inventory(&incomplete)?;
            assert_eq!(
                store::recovery::startup(&incomplete).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                store::initialize(&incomplete, "must not initialize", "admin", PHC)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::PermissionDenied)
            );
            assert!(
                store::migrate(&incomplete, &fixture.0.join("must-not-back-up.sqlite3")).is_err()
            );
            assert!(store::lock(&incomplete).is_err());
            assert!(store::update_lock(&incomplete).is_err());
            assert!(store::recovery::finalize(&incomplete, "AAAAAAAAAAAAAAAAAAAAAA").is_err());
            assert_eq!(before, inventory(&incomplete)?);
            Ok(())
        }

        /// Compare complete credential rows without allowing assertion diagnostics to
        /// print a verifier. This is synthetic state, but the failure must stay redacted.
        fn credential_rows(
            directory: &Path,
        ) -> Result<Vec<Vec<rusqlite::types::Value>>, Box<dyn std::error::Error>> {
            let connection = rusqlite::Connection::open(directory.join("management.sqlite3"))?;
            let mut statement =
                connection.prepare("SELECT * FROM proxy_credentials ORDER BY id")?;
            let columns = statement.column_count();
            Ok(statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get(column))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        }

        #[test]
        fn retained_credentials_and_revocation_survive_but_as_new_import_discards_them()
        -> TestResult {
            use crate::access::Protocol;
            use rcgen::PublicKeyData as _;
            let input = inputs(false)?;
            let source = rusqlite::Connection::open(input.state.join("management.sqlite3"))?;
            let actor: String =
                source.query_row("SELECT id FROM administrators", [], |row| row.get(0))?;
            drop(source);
            let update = store::update_lock(&input.state)?;
            let created = store::apply_policy(
                &input.state,
                &actor,
                1,
                store::PolicyChange::CreateUser {
                    name: "retained test user".into(),
                    protocols: vec![Protocol::Http, Protocol::Socks5],
                    concurrent_limit: 2,
                },
                &update,
            )?;
            let user = created.user.ok_or_else(|| invalid("test user missing"))?.id;
            let first = store::apply_policy(
                &input.state,
                &actor,
                2,
                store::PolicyChange::CreateCredential {
                    user_id: user.clone(),
                },
                &update,
            )?;
            assert!(first.secret.is_some());
            drop(first);
            let second = store::apply_policy(
                &input.state,
                &actor,
                3,
                store::PolicyChange::CreateCredential { user_id: user },
                &update,
            )?;
            let revoked = second
                .credential
                .as_ref()
                .ok_or_else(|| invalid("test credential missing"))?
                .id
                .clone();
            drop(second);
            store::apply_policy(
                &input.state,
                &actor,
                4,
                store::PolicyChange::RevokeCredential { id: revoked },
                &update,
            )?;
            drop(update);
            let before = credential_rows(&input.state)?;
            assert_eq!(before.len(), 2);
            snapshot::create(&input.state, &input.configuration, &input.output)?;
            let copied = input.output.join("database");
            assert!(before == credential_rows(&copied)?);
            assert!(before == credential_rows(&input.state)?);
            let key = rcgen::KeyPair::generate()?;
            let identity = store::recovery::Identity {
                key_pem: Zeroizing::new(key.serialize_pem()),
                request_pem: rcgen::CertificateParams::new(vec!["recovered.invalid".into()])?
                    .serialize_request(&key)?
                    .pem()?,
                public_key_sha256: Sha256::digest(key.subject_public_key_info()).into(),
            };
            let destination = input.fixture.0.join("as-new-import");
            let recovered = store::recovery::restore(
                &copied,
                &destination,
                "new test node",
                "new-admin",
                PHC,
                identity,
            )?;
            assert_ne!(recovered.node_id, input.node_id);
            let recovery = recovered
                .recovery
                .ok_or_else(|| invalid("as-new recovery record missing"))?;
            assert_eq!(recovery.phase, store::recovery::Phase::PendingReview);
            let policy = store::load_policy(&destination)?;
            assert!(policy.credentials.is_empty());
            assert_eq!(policy.users.len(), 1);
            assert!(!policy.users[0].active && policy.users[0].protocols.is_empty());
            store::recovery::finalize(&destination, &recovery.id)?;
            assert!(store::recovery::startup(&destination)?.is_some());
            // A second-generation capture must project the reviewed as-new provenance,
            // not the native NULL singleton. This exercises the other normalization
            // branch using the real imported draft and its permanent generated key pin.
            let next_snapshot = input.fixture.0.join("reviewed-identity-snapshot");
            let next_manifest = store::create_identity_snapshot(
                &destination,
                &next_snapshot,
                &store::lock(&destination)?,
                &store::update_lock(&destination)?,
                Sha256::digest(key.subject_public_key_info()).into(),
            )?;
            assert!(next_manifest.database_content_sha256.is_some());
            assert_eq!(store::verify_backup(&next_snapshot)?, next_manifest);
            assert!(store::recovery::startup(&next_snapshot).is_err());
            snapshot::verify(&input.output)?;
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    mod service {
        use super::*;

        fn launch_fixture(fixture: &Fixture, now: u64) -> io::Result<PathBuf> {
            let (authority, roots) = fixture.authority(now)?;
            let prepared = fixture.prepare("prepared", roots, 22443, now)?;
            let signed = fixture.0.join("signed");
            sign(&authority, &prepared.join(PUBLIC_FILE), &signed, now)?;
            let plan = fixture.0.join("launch");
            launch(
                &prepared,
                &signed,
                &plan,
                "127.0.0.1:22443".parse().map_err(io::Error::other)?,
                "127.0.0.1:22444".parse().map_err(io::Error::other)?,
                &env::current_exe()?,
                None,
                now,
            )?;
            Ok(plan)
        }

        #[test]
        fn service_plan_preserves_launch_inputs_and_rechecks_its_own_unit() -> TestResult {
            let fixture = Fixture::new()?;
            let now = now()?;
            let plan = launch_fixture(&fixture, now)?;
            let before = inventory(&plan)?;
            let prepared_before = inventory(&fixture.0.join("prepared"))?;
            let output = fixture.0.join("user-service");
            let report = service_plan(&plan, &output, now)?;
            assert_eq!(report.state, "offline_service_plan_ready");
            assert!(!report.server_started && !report.trust_installed && !report.node_authorized);
            let unit_path = report.unit_file.ok_or("missing unit path")?;
            let unit = fs::read_to_string(&unit_path)?;
            assert!(unit.contains(&path_string(&output)?));
            assert!(unit.contains(&path_string(&plan.join("node.pem"))?));
            assert!(unit.contains(&path_string(&fixture.0.join("prepared/state"))?));
            assert!(!unit.contains("PRIVATE KEY") && !unit.contains(PHC));
            assert!(!unit.contains("--proxy-config") && !unit.contains("/bin/sh"));
            assert_eq!(fs::read_dir(&output)?.count(), 3);
            check(&output, now)?;
            assert_eq!(before, inventory(&plan)?);
            assert_eq!(prepared_before, inventory(&fixture.0.join("prepared"))?);
            let output_before = inventory(&output)?;
            assert!(service_plan(&plan, &output, now).is_err());
            assert_eq!(output_before, inventory(&output)?);
            fs::write(&unit_path, format!("{unit}\nEnvironment=UNREVIEWED=yes\n"))?;
            assert!(check(&output, now).is_err());
            fs::write(&unit_path, &unit)?;
            check(&output, now)?;
            fs::write(plan.join("start.sh"), "#!/bin/sh\nexit 0\n")?;
            assert!(check(&output, now).is_err());
            let rejected = fixture.0.join("rejected-service");
            assert!(service_plan(&plan, &rejected, now).is_err());
            assert!(!rejected.exists());
            Ok(())
        }

        #[test]
        fn service_metadata_cannot_reference_itself_or_another_stage() -> TestResult {
            let fixture = Fixture::new()?;
            let now = now()?;
            let plan = launch_fixture(&fixture, now)?;
            let output = fixture.0.join("user-service");
            service_plan(&plan, &output, now)?;
            let original = load::<Service>(&output, Stage::Service)?.0;
            for referenced in [&output, &fixture.0.join("prepared")] {
                let bytes = encode(&Service {
                    format_version: FORMAT,
                    plan: referenced.to_owned(),
                    plan_sha256: original.plan_sha256.clone(),
                })?;
                fs::write(output.join(PUBLIC_FILE), &bytes)?;
                fs::write(
                    output.join(COMPLETE_FILE),
                    encode(&Completion {
                        format_version: FORMAT,
                        stage: Stage::Service,
                        public_sha256: sha256(&bytes),
                    })?,
                )?;
                let before = inventory(&output)?;
                assert!(check(&output, now).is_err());
                assert_eq!(before, inventory(&output)?);
            }
            Ok(())
        }

        #[test]
        fn service_pin_rejects_a_rebound_but_otherwise_valid_launch() -> TestResult {
            let fixture = Fixture::new()?;
            let now = now()?;
            let plan = launch_fixture(&fixture, now)?;
            let output = fixture.0.join("user-service");
            service_plan(&plan, &output, now)?;
            let (mut launch, _) = load::<Launch>(&plan, Stage::Plan)?;
            launch.admin_bind.set_port(22543);
            let request = prepared_request(&launch.prepared, now)?.0;
            let (posix, powershell) = scripts(&plan, &launch, &request)?;
            fs::write(plan.join("start.sh"), posix)?;
            fs::write(plan.join("start.ps1"), powershell)?;
            let bytes = encode(&launch)?;
            fs::write(plan.join(PUBLIC_FILE), &bytes)?;
            fs::write(
                plan.join(COMPLETE_FILE),
                encode(&Completion {
                    format_version: FORMAT,
                    stage: Stage::Plan,
                    public_sha256: sha256(&bytes),
                })?,
            )?;
            check(&plan, now)?;
            assert!(check(&output, now).is_err());
            Ok(())
        }

        #[test]
        fn old_side_by_side_executable_requires_a_new_launch_before_service_creation() -> TestResult
        {
            let fixture = Fixture::new()?;
            let now = now()?;
            let plan = launch_fixture(&fixture, now)?;
            let (mut launch, _) = load::<Launch>(&plan, Stage::Plan)?;
            // This gate compares paths without executing the old program. A small
            // ordinary file avoids copying and inventorying the entire test binary.
            let old_executable = fixture.0.join("old-vproxy");
            files::write(&fixture.0, "old-vproxy", b"non-executed path fixture")?;
            launch.executable = old_executable;
            let request = prepared_request(&launch.prepared, now)?.0;
            let (posix, powershell) = scripts(&plan, &launch, &request)?;
            fs::write(plan.join("start.sh"), posix)?;
            fs::write(plan.join("start.ps1"), powershell)?;
            let bytes = encode(&launch)?;
            fs::write(plan.join(PUBLIC_FILE), &bytes)?;
            fs::write(
                plan.join(COMPLETE_FILE),
                encode(&Completion {
                    format_version: FORMAT,
                    stage: Stage::Plan,
                    public_sha256: sha256(&bytes),
                })?,
            )?;
            check(&plan, now)?;
            let output = fixture.0.join("rejected-old-service");
            let before = inventory(&fixture.0)?;
            assert_eq!(
                service_plan(&plan, &output, now)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::InvalidData)
            );
            assert!(!output.exists());
            assert_eq!(before, inventory(&fixture.0)?);
            Ok(())
        }

        #[test]
        fn acme_service_uses_the_checked_argv_and_rejects_recursive_rebound_or_old_executable_plans()
        -> TestResult {
            let fixture = Fixture::new()?;
            let now = now()?;
            let (_, prepared, signed) = acme_inputs(&fixture, now)?;
            let plan = fixture.0.join("acme-launch");
            let launch_report = acme::launch(
                &prepared,
                &signed,
                &plan,
                ("127.0.0.1:23443".parse()?, "127.0.0.1:23444".parse()?),
                &env::current_exe()?,
                &acme_options()?,
                None,
                now,
            )?;
            let plan = launch_report.directory;
            let (mut launch, request, plan_hash) = acme::checked_launch(&plan, now)?;
            let before_plan = inventory(&plan)?;
            let before_prepared = inventory(&prepared)?;
            let output = fixture.0.join("acme-user-service");
            let report = service_plan(&plan, &output, now)?;
            assert_eq!(report.state, "offline_service_plan_ready");
            assert!(!report.server_started && !report.trust_installed && !report.node_authorized);
            let output = report.directory.clone();
            let unit_path = report.unit_file.ok_or("missing ACME unit path")?;
            let unit = fs::read_to_string(&unit_path)?;
            let (_, serve) = acme::arguments(&plan, &launch, &request)?;
            assert_eq!(
                unit,
                super::super::service::render(
                    &launch.executable,
                    &check_arguments(&output)?,
                    &serve
                )?
            );
            assert!(unit.contains("Type=exec\n") && !unit.contains("Type=notify"));
            assert!(unit.contains("\"--acme\"") && unit.contains("\"--acme-production\""));
            assert!(unit.contains("\"--acme-challenge\" \"http-01\""));
            assert!(
                !unit.contains("--tls-cert")
                    && !unit.contains("--tls-key")
                    && !unit.contains("mailto:")
            );
            assert!(
                !unit.contains("PRIVATE KEY") && !unit.contains(PHC) && !unit.contains("/bin/sh")
            );
            let wire = serde_json::to_value(load::<Service>(&output, Stage::Service)?.0)?;
            assert_eq!(
                wire,
                serde_json::json!({"format_version": 1, "plan": fs::canonicalize(&plan)?, "plan_sha256": plan_hash})
            );
            let before_check = inventory(&fixture.0)?;
            check(&output, now)?;
            assert_eq!(before_check, inventory(&fixture.0)?);
            assert_eq!(before_plan, inventory(&plan)?);
            assert_eq!(before_prepared, inventory(&prepared)?);
            assert!(!prepared.join("state/acme").exists());
            let service_metadata = load::<Service>(&output, Stage::Service)?.0;
            for referenced in [&output, &prepared, &signed] {
                rebind_public(
                    &output,
                    Stage::Service,
                    &Service {
                        format_version: FORMAT,
                        plan: referenced.to_owned(),
                        plan_sha256: service_metadata.plan_sha256.clone(),
                    },
                )?;
                let before = inventory(&fixture.0)?;
                assert!(check(&output, now).is_err());
                assert_eq!(before, inventory(&fixture.0)?);
            }
            rebind_public(&output, Stage::Service, &service_metadata)?;
            check(&output, now)?;
            launch.admin_bind.set_port(23543);
            let (preflight, serve) = acme::arguments(&plan, &launch, &request)?;
            let (posix, powershell) = plan::render(&launch.executable, &preflight, &serve)?;
            fs::write(plan.join("start.sh"), posix)?;
            fs::write(plan.join("start.ps1"), powershell)?;
            rebind_public(&plan, Stage::AcmePlan, &launch)?;
            check(&plan, now)?;
            assert!(check(&output, now).is_err());
            let old_executable = fixture.0.join("old-acme-vproxy");
            // This gate compares canonical paths, not executable contents. Do not copy
            // the large test binary for a file that is never executed by this fixture.
            files::write(&fixture.0, "old-acme-vproxy", b"non-executed path fixture")?;
            launch.executable = old_executable;
            let (preflight, serve) = acme::arguments(&plan, &launch, &request)?;
            let (posix, powershell) = plan::render(&launch.executable, &preflight, &serve)?;
            fs::write(plan.join("start.sh"), posix)?;
            fs::write(plan.join("start.ps1"), powershell)?;
            rebind_public(&plan, Stage::AcmePlan, &launch)?;
            check(&plan, now)?;
            let rejected = fixture.0.join("rejected-old-acme-service");
            let before = inventory(&plan)?;
            assert_eq!(
                service_plan(&plan, &rejected, now)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::InvalidData)
            );
            assert!(!rejected.exists());
            assert_eq!(before, inventory(&plan)?);
            Ok(())
        }

        #[test]
        fn proxy_service_reuses_manual_and_acme_argv_and_rechecks_the_external_config() -> TestResult
        {
            let fixture = Fixture::new()?;
            let now = now()?;
            let (_, prepared, signed) = acme_inputs(&fixture, now)?;
            let config = proxy_config_fixture(&fixture, PROXY_JSON)?;
            let expected_path = path_string(&std::path::absolute(&config)?)?;
            let mut services = Vec::new();
            for automatic in [false, true] {
                let plan = fixture.0.join(if automatic {
                    "proxy-acme-launch"
                } else {
                    "proxy-manual-launch"
                });
                let plan =
                    proxy_launch(&prepared, &signed, &plan, &config, automatic, now)?.directory;
                let (executable, serve) = if automatic {
                    let (launch, request, _) = acme::checked_launch(&plan, now)?;
                    let (_, serve) = acme::arguments(&plan, &launch, &request)?;
                    (launch.executable, serve)
                } else {
                    let (launch, request, _) = checked_launch(&plan, now)?;
                    let (_, serve) = arguments(&plan, &launch, &request)?;
                    (launch.executable, serve)
                };
                let output = fixture.0.join(if automatic {
                    "proxy-acme-service"
                } else {
                    "proxy-manual-service"
                });
                let before = (inventory(&plan)?, inventory(&prepared)?, fs::read(&config)?);
                let report = service_plan(&plan, &output, now)?;
                assert!(
                    !report.server_started && !report.trust_installed && !report.node_authorized
                );
                let output = report.directory;
                let unit =
                    fs::read_to_string(report.unit_file.ok_or("proxy service unit missing")?)?;
                assert_eq!(
                    unit,
                    super::super::service::render(&executable, &check_arguments(&output)?, &serve)?
                );
                assert_eq!(
                    serve
                        .iter()
                        .filter(|value| value.as_str() == "--proxy-config")
                        .count(),
                    1
                );
                assert!(
                    serve
                        .windows(2)
                        .any(|pair| pair[0] == "--proxy-config" && pair[1] == expected_path)
                );
                // A literal percent in the config path must not become a unit specifier;
                // '$' remains literal through the existing ':' command prefix.
                assert!(
                    unit.contains("%%n") && unit.contains("$value") && unit.contains("ExecStart=:")
                );
                assert_eq!(unit.matches("\"--proxy-config\"").count(), 1);
                assert!(unit.contains("Type=exec\n") && !unit.contains("Type=notify"));
                assert!(
                    !unit.contains("/bin/sh")
                        && !unit.contains("PRIVATE KEY")
                        && !unit.contains(PHC)
                );
                assert!(
                    !output
                        .join(config.file_name().ok_or("config filename missing")?)
                        .exists()
                );
                check(&output, now)?;
                assert_eq!(
                    before,
                    (inventory(&plan)?, inventory(&prepared)?, fs::read(&config)?)
                );
                services.push((plan, output));
            }
            let mut equivalent = PROXY_JSON.to_vec();
            equivalent.push(b'\n');
            fs::write(&config, equivalent)?;
            for (index, (plan, service)) in services.iter().enumerate() {
                let rejected = fixture.0.join(format!("changed-proxy-service-{index}"));
                let before = inventory(&fixture.0)?;
                assert!(check(plan, now).is_err());
                assert!(check(service, now).is_err());
                assert!(service_plan(plan, &rejected, now).is_err());
                assert!(!rejected.exists());
                assert_eq!(before, inventory(&fixture.0)?);
            }
            fs::write(&config, PROXY_JSON)?;
            for (plan, service) in &services {
                check(plan, now)?;
                check(service, now)?;
            }
            assert!(!prepared.join("state/acme").exists());
            Ok(())
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn linux_service_stage_is_rejected_without_modifying_its_inputs() -> TestResult {
        let fixture = Fixture::new()?;
        let output = fixture.0.join("linux-service");
        files::create_directory(&output)?;
        complete(&output, Stage::Service, &serde_json::json!({}), None)?;
        let before = inventory(&output)?;
        assert_eq!(
            check(&output, now()?).err().map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported)
        );
        assert_eq!(before, inventory(&output)?);
        Ok(())
    }

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$Zml4dHVyZQ";
    const PROXY_JSON: &[u8] =
        br#"{"listeners":[{"protocol":"socks5","bind":"127.0.0.1:21080"}],"workers":1}"#;

    /// Owns only its newly created, unpredictable private temporary leaf. No test
    /// runs against existing management state, trusted roots or service processes.
    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> io::Result<Self> {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("test random source failed"))?;
            let root = env::temp_dir().join(format!(
                "vproxy-setup-{}-{}",
                std::process::id(),
                sha256(&random)
            ));
            files::create_directory(&root)?;
            Ok(Self(root))
        }

        fn authority(&self, now: u64) -> io::Result<(PathBuf, AuthorityPublic)> {
            let directory = self.0.join("authority");
            authority(&directory, now)?;
            let roots = load::<AuthorityPublic>(&directory, Stage::Authority)?.0;
            Ok((directory, roots))
        }

        fn prepare(
            &self,
            name: &str,
            roots: AuthorityPublic,
            port: u16,
            now: u64,
        ) -> io::Result<PathBuf> {
            let directory = self.0.join(name);
            prepare(
                &directory,
                roots,
                &format!("https://localhost:{port}"),
                &format!("https://127.0.0.1:{}", port + 1),
                name,
                "admin",
                PHC,
                now,
            )?;
            Ok(directory)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Deterministic recursive content inventory, excluding paths outside the
    /// fixture. This proves check's tested inputs remain unchanged, not atomic
    /// inspection of a concurrently running database.
    fn inventory(path: &Path) -> io::Result<std::collections::BTreeMap<PathBuf, (usize, String)>> {
        fn visit(
            root: &Path,
            path: &Path,
            result: &mut std::collections::BTreeMap<PathBuf, (usize, String)>,
        ) -> io::Result<()> {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let path = entry.path();
                // Normal read-only snapshots may maintain SQLite read marks.
                if matches!(
                    entry.file_name().to_str(),
                    Some("management.sqlite3-wal" | "management.sqlite3-shm")
                ) {
                    continue;
                }
                if entry.file_type()?.is_dir() {
                    visit(root, &path, result)?;
                } else {
                    let relative = path
                        .strip_prefix(root)
                        .map_err(|_| io::Error::other("test inventory escaped root"))?;
                    let bytes = Zeroizing::new(fs::read(&path)?);
                    result.insert(relative.to_owned(), (bytes.len(), sha256(&bytes)));
                }
            }
            Ok(())
        }
        let mut result = std::collections::BTreeMap::new();
        visit(path, path, &mut result)?;
        Ok(result)
    }

    fn acme_inputs(fixture: &Fixture, now: u64) -> io::Result<(PathBuf, PathBuf, PathBuf)> {
        let (authority, roots) = fixture.authority(now)?;
        let prepared = fixture.0.join("acme-prepared");
        prepare(
            &prepared,
            roots,
            "https://admin.example.com:23443",
            "https://127.0.0.1:23444",
            "acme-node",
            "admin",
            PHC,
            now,
        )?;
        let signed = fixture.0.join("acme-signed");
        sign(&authority, &prepared.join(PUBLIC_FILE), &signed, now)?;
        Ok((authority, prepared, signed))
    }

    fn acme_options() -> io::Result<crate::manage::acme::Options> {
        let options: crate::manage::acme::PlanOptions = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "accept_terms": true,
            "production": true,
            "contacts": ["operator@example.com", "oncall@example.net"],
            "challenge": "http-01",
            "http_bind": "127.0.0.1:2080"
        }))
        .map_err(io::Error::other)?;
        Ok(options.options())
    }

    fn proxy_config_fixture(fixture: &Fixture, bytes: &[u8]) -> io::Result<PathBuf> {
        // All characters are legal on Windows too. The path must remain one literal
        // argument rather than interpreting quotes, expansions or shell separators.
        let directory = fixture
            .0
            .join("proxy O'Brien ‘quote’ $value %n `literal`; #");
        files::create_directory(&directory)?;
        files::write(&directory, "proxy.json", bytes)?;
        Ok(directory.join("proxy.json"))
    }

    fn proxy_launch(
        prepared: &Path,
        response: &Path,
        output: &Path,
        proxy_config: &Path,
        automatic: bool,
        now: u64,
    ) -> io::Result<Report> {
        let binds = (
            "127.0.0.1:23443".parse().map_err(io::Error::other)?,
            "127.0.0.1:23444".parse().map_err(io::Error::other)?,
        );
        let executable = env::current_exe()?;
        if automatic {
            acme::launch(
                prepared,
                response,
                output,
                binds,
                &executable,
                &acme_options()?,
                Some(proxy_config),
                now,
            )
        } else {
            launch(
                prepared,
                response,
                output,
                binds.0,
                binds.1,
                &executable,
                Some(proxy_config),
                now,
            )
        }
    }

    /// Rebind deliberately changed public fixture data, so rejection must come
    /// from its semantic checks rather than only the outer completion digest.
    fn rebind_public<T: Serialize>(directory: &Path, stage: Stage, value: &T) -> io::Result<()> {
        let bytes = encode(value)?;
        fs::write(directory.join(PUBLIC_FILE), &bytes)?;
        fs::write(
            directory.join(COMPLETE_FILE),
            encode(&Completion {
                format_version: FORMAT,
                stage,
                public_sha256: sha256(&bytes),
            })?,
        )
    }

    #[test]
    fn two_nodes_share_roots_but_keep_private_keys_and_authority_separate() -> TestResult {
        let fixture = Fixture::new()?;
        let now = now()?;
        let (authority, roots) = fixture.authority(now)?;
        let a = fixture.prepare("node-a", roots.clone(), 18443, now)?;
        let b = fixture.prepare("node-b", roots, 18543, now)?;
        let request_a = prepared_request(&a, now)?.0;
        let request_b = prepared_request(&b, now)?.0;
        assert_ne!(request_a.node_id, request_b.node_id);
        assert!(
            fs::read(a.join("node.key"))? != fs::read(b.join("node.key"))?,
            "nodes unexpectedly share a key"
        );
        assert!(
            fs::read(a.join("admin.key"))? != fs::read(a.join("node.key"))?,
            "roles unexpectedly share a key"
        );
        assert_eq!(
            super::super::store::inspect(&a.join("state"))?.schema_version,
            super::super::store::SCHEMA_VERSION
        );
        for (prepared, name, port) in [(&a, "a", 18443), (&b, "b", 18543)] {
            let signed = fixture.0.join(format!("signed-{name}"));
            sign(&authority, &prepared.join(PUBLIC_FILE), &signed, now)?;
            let output = fixture.0.join(format!("plan-{name}"));
            let report = launch(
                prepared,
                &signed,
                &output,
                format!("127.0.0.1:{port}").parse()?,
                format!("127.0.0.1:{}", port + 1).parse()?,
                &env::current_exe()?,
                None,
                now,
            )?;
            assert_eq!(report.state, "offline_plan_ready");
            assert!(!report.server_started && !report.trust_installed && !report.node_authorized);
            let (manual, _) = load::<Launch>(&output, Stage::Plan)?;
            let wire = serde_json::to_value(&manual)?;
            assert_eq!(
                wire.as_object()
                    .ok_or("manual plan is not an object")?
                    .len(),
                8
            );
            assert!(wire.get("acme").is_none());
            assert!(wire.get("proxy_config").is_none());
            assert_eq!(wire["format_version"], 1);
            let request = prepared_request(prepared, now)?.0;
            let (_, serve) = arguments(&output, &manual, &request)?;
            assert!(serve.iter().any(|argument| argument == "--tls-cert"));
            assert!(serve.iter().any(|argument| argument == "--tls-key"));
            assert!(!serve.iter().any(|argument| argument.starts_with("--acme")));
            assert!(!serve.iter().any(|argument| argument == "--proxy-config"));
            let identity = super::super::tls::node_identity(
                &output.join("node-ca.pem"),
                &output.join("node.pem"),
                &prepared.join("node.key"),
            )?;
            identity.verify_name("127.0.0.1")?;
            for directory in [&authority, prepared, &signed, &output] {
                let before = inventory(directory)?;
                check(directory, now)?;
                assert_eq!(before, inventory(directory)?);
                let public = fs::read_to_string(directory.join(PUBLIC_FILE))?;
                assert!(!public.contains("PRIVATE KEY") && !public.contains(PHC));
            }
            assert!(!output.join("node.key").exists());
            assert!(!prepared.join("node-ca.key").exists());
            assert!(!signed.join("node.key").exists());
            let database = rusqlite::Connection::open_with_flags(
                prepared.join("state/management.sqlite3"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            let peers: i64 =
                database.query_row("SELECT count(*) FROM peers", [], |row| row.get(0))?;
            assert_eq!(peers, 0);
        }
        Ok(())
    }

    #[test]
    fn existing_outputs_and_wrong_node_response_fail_without_overwrite() -> TestResult {
        let fixture = Fixture::new()?;
        let now = now()?;
        let (authority_path, roots) = fixture.authority(now)?;
        let a = fixture.prepare("a", roots.clone(), 19443, now)?;
        let b = fixture.prepare("b", roots, 19543, now)?;
        let signed = fixture.0.join("signed");
        sign(&authority_path, &a.join(PUBLIC_FILE), &signed, now)?;
        let before = inventory(&fixture.0)?;
        assert!(authority(&authority_path, now).is_err());
        assert!(sign(&authority_path, &a.join(PUBLIC_FILE), &signed, now).is_err());
        let output = fixture.0.join("wrong-node-plan");
        assert!(
            launch(
                &b,
                &signed,
                &output,
                "127.0.0.1:19443".parse()?,
                "127.0.0.1:19444".parse()?,
                &env::current_exe()?,
                None,
                now
            )
            .is_err()
        );
        assert!(!output.exists());
        assert_eq!(before, inventory(&fixture.0)?);
        Ok(())
    }

    #[test]
    fn incomplete_and_changed_public_outputs_are_not_resumed() -> TestResult {
        let fixture = Fixture::new()?;
        let output = fixture.0.join("partial");
        files::create_directory(&output)?;
        files::write(&output, "node.key", b"private partial sentinel")?;
        let before = inventory(&output)?;
        assert!(check(&output, now()?).is_err());
        assert_eq!(before, inventory(&output)?);
        let (authority, _) = fixture.authority(now()?)?;
        fs::write(authority.join(PUBLIC_FILE), b"{}")?;
        let before = inventory(&authority)?;
        assert!(check(&authority, now()?).is_err());
        assert_eq!(before, inventory(&authority)?);
        Ok(())
    }

    #[test]
    fn existing_manual_and_acme_powershell_templates_remain_read_only_but_not_arbitrary()
    -> TestResult {
        for automatic in [false, true] {
            let fixture = Fixture::new()?;
            let now = now()?;
            let (_, prepared, signed) = acme_inputs(&fixture, now)?;
            let output = fixture.0.join("launch");
            let binds = ("127.0.0.1:23443".parse()?, "127.0.0.1:23444".parse()?);
            if automatic {
                acme::launch(
                    &prepared,
                    &signed,
                    &output,
                    binds,
                    &env::current_exe()?,
                    &acme_options()?,
                    None,
                    now,
                )?;
            } else {
                launch(
                    &prepared,
                    &signed,
                    &output,
                    binds.0,
                    binds.1,
                    &env::current_exe()?,
                    None,
                    now,
                )?;
            }
            let path = output.join("start.ps1");
            let current = fs::read_to_string(&path)?;
            assert_eq!(current.matches("$LASTEXITCODE = 1\n").count(), 2);
            let legacy = current.replace("$LASTEXITCODE = 1\n", "");
            fs::write(&path, &legacy)?;
            let before = inventory(&fixture.0)?;
            check(&output, now)?;
            assert_eq!(before, inventory(&fixture.0)?);
            for changed in [
                current.replacen("$LASTEXITCODE = 1\n", "", 1),
                format!("{legacy}Write-Output 'unexpected'\n"),
                legacy.replacen("'--bind'", "'--different-bind'", 1),
            ] {
                assert_ne!(changed, legacy);
                fs::write(&path, changed)?;
                assert!(check(&output, now).is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn origins_and_root_domains_are_explicit_not_inferred_or_shared() -> TestResult {
        assert_eq!(origin_name("https://[::1]:8443")?, "::1");
        for invalid_origin in [
            "http://localhost:8443",
            "https://localhost:8443/",
            "https://LOCALHOST:8443",
            "https://127.1",
            "https://user@localhost",
            "https://localhost/?x=1",
            "https://localhost:0",
            "https://*.example.com",
        ] {
            assert!(origin_name(invalid_origin).is_err(), "{invalid_origin}");
        }
        let ca = identity::authority(Role::Admin, now()?)?;
        assert!(
            validate_roots(
                &AuthorityPublic {
                    format_version: FORMAT,
                    admin_ca_pem: ca.certificate_pem.clone(),
                    node_ca_pem: ca.certificate_pem
                },
                now()?
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn prepared_snapshot_observes_committed_wal_and_rejects_swapped_keys() -> TestResult {
        let fixture = Fixture::new()?;
        let now = now()?;
        let (_, roots) = fixture.authority(now)?;
        let prepared = fixture.prepare("prepared", roots, 20443, now)?;
        let connection = rusqlite::Connection::open(prepared.join("state/management.sqlite3"))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "wal_autocheckpoint", 0)?;
        connection.execute(
            "UPDATE node_identity SET name='committed WAL mismatch' WHERE singleton=1",
            [],
        )?;
        assert!(fs::metadata(prepared.join("state/management.sqlite3-wal"))?.len() > 32);
        // A main-only/immutable reader could incorrectly see the original name.
        assert!(prepared_request(&prepared, now).is_err());
        connection.execute(
            "UPDATE node_identity SET name='prepared' WHERE singleton=1",
            [],
        )?;
        let before: (String, String) = connection.query_row(
            "SELECT node_id,name FROM node_identity WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        prepared_request(&prepared, now)?;
        let after: (String, String) = connection.query_row(
            "SELECT node_id,name FROM node_identity WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(before, after);
        drop(connection);
        let admin_key = fs::read(prepared.join("admin.key"))?;
        fs::write(prepared.join("node.key"), admin_key)?;
        assert!(prepared_request(&prepared, now).is_err());
        Ok(())
    }

    #[test]
    fn acme_plan_is_offline_and_keeps_mutable_cache_outside_its_wire_and_argv() -> TestResult {
        let fixture = Fixture::new()?;
        let now = now()?;
        let (authority, prepared, signed) = acme_inputs(&fixture, now)?;
        let before_inputs = [
            inventory(&authority)?,
            inventory(&prepared)?,
            inventory(&signed)?,
        ];
        let output = fixture.0.join("acme-launch");
        let options = acme_options()?;
        let report = acme::launch(
            &prepared,
            &signed,
            &output,
            ("127.0.0.1:23443".parse()?, "127.0.0.1:23444".parse()?),
            &env::current_exe()?,
            &options,
            None,
            now,
        )?;
        assert_eq!(report.state, "offline_acme_plan_ready");
        assert!(!report.server_started && !report.trust_installed && !report.node_authorized);
        let output = report.directory.clone();
        for (directory, before) in [&authority, &prepared, &signed]
            .into_iter()
            .zip(before_inputs)
        {
            assert_eq!(before, inventory(directory)?);
        }
        let (launch, request, digest) = acme::checked_launch(&output, now)?;
        let wire = serde_json::to_value(&launch)?;
        assert_eq!(
            wire.as_object().ok_or("ACME plan is not an object")?.len(),
            9
        );
        assert!(wire.get("proxy_config").is_none());
        assert_eq!(digest, report.public_sha256);
        assert_eq!(
            serde_json::to_value(&launch.acme)?,
            serde_json::json!({
                "enabled": true, "accept_terms": true, "production": true,
                "contacts": ["operator@example.com", "oncall@example.net"],
                "challenge": "http-01", "http_bind": "127.0.0.1:2080"
            })
        );
        let (preflight, serve) = acme::arguments(&output, &launch, &request)?;
        assert_eq!(preflight, check_arguments(&output)?);
        for flag in ["--acme", "--acme-accept-terms", "--acme-production"] {
            assert_eq!(
                serve
                    .iter()
                    .filter(|argument| argument.as_str() == flag)
                    .count(),
                1
            );
        }
        for (flag, expected) in [
            ("--acme-challenge", "http-01"),
            ("--acme-http-bind", "127.0.0.1:2080"),
        ] {
            assert!(
                serve
                    .windows(2)
                    .any(|pair| pair[0] == flag && pair[1] == expected)
            );
        }
        assert_eq!(
            serve
                .windows(2)
                .filter(|pair| pair[0] == "--acme-contact")
                .map(|pair| pair[1].as_str())
                .collect::<Vec<_>>(),
            ["operator@example.com", "oncall@example.net"]
        );
        assert!(!serve.iter().any(|argument| argument.contains("mailto:")
            || argument == "--tls-cert"
            || argument == "--tls-key"
            || argument == "--proxy-config"));
        let expected_node_key = path_string(&launch.prepared.join("node.key"))?;
        assert!(
            serve
                .windows(2)
                .any(|pair| pair[0] == "--node-key" && pair[1] == expected_node_key)
        );
        assert_eq!(
            inventory(&output)?
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            [
                PUBLIC_FILE,
                COMPLETE_FILE,
                "node.pem",
                "node-ca.pem",
                "start.sh",
                "start.ps1"
            ]
            .map(PathBuf::from)
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
        );
        let cache = prepared.join("state/acme");
        assert!(!cache.exists());
        let before = inventory(&fixture.0)?;
        check(&output, now)?;
        assert_eq!(before, inventory(&fixture.0)?);
        assert!(!cache.exists());
        let immutable_plan = inventory(&output)?;
        files::create_directory(&cache)?;
        files::write(&cache, "identity.pem", b"unusable mutable cache fixture")?;
        for bytes in [
            b"first cache candidate".as_slice(),
            b"second renewed cache candidate".as_slice(),
        ] {
            fs::write(cache.join("identity.pem"), bytes)?;
            let before = inventory(&fixture.0)?;
            check(&output, now)?;
            assert_eq!(before, inventory(&fixture.0)?);
            assert_eq!(immutable_plan, inventory(&output)?);
            assert_eq!(acme::checked_launch(&output, now)?.2, digest);
        }
        let before = inventory(&fixture.0)?;
        assert!(
            acme::launch(
                &prepared,
                &signed,
                &output,
                (launch.admin_bind, launch.node_bind),
                &launch.executable,
                &options,
                None,
                now
            )
            .is_err()
        );
        assert_eq!(before, inventory(&fixture.0)?);
        let original = serde_json::to_value(&launch)?;
        for changed in [
            {
                let mut value = original.clone();
                value["acme"]["accept_terms"] = false.into();
                value
            },
            {
                let mut value = original.clone();
                value["acme"]["unexpected"] = true.into();
                value
            },
        ] {
            rebind_public(&output, Stage::AcmePlan, &changed)?;
            let before = inventory(&fixture.0)?;
            assert!(check(&output, now).is_err());
            assert_eq!(before, inventory(&fixture.0)?);
        }
        rebind_public(&output, Stage::AcmePlan, &launch)?;
        check(&output, now)?;
        assert_eq!(acme::checked_launch(&output, now)?.2, digest);
        Ok(())
    }

    #[test]
    fn acme_ignores_expired_manual_admin_leaf_but_keeps_node_identity_and_expiry_gates()
    -> TestResult {
        let fixture = Fixture::new()?;
        let now = now()?;
        let old = now
            .checked_sub(91 * 86_400)
            .ok_or("test clock is too early")?;
        let (authority, prepared, signed) = acme_inputs(&fixture, old)?;
        let request = prepared_request(&prepared, now)?.0;
        let mut response = load::<Response>(&signed, Stage::Signed)?.0;
        assert!(
            identity::verify(
                Role::Admin,
                &origin_name(&request.admin_origin)?,
                &request.authority.admin_ca_pem,
                &response.admin_certificate_pem,
                &pem(&prepared.join("admin.key"), true)?,
                &request.admin_csr_pem,
                now
            )
            .is_err()
        );
        let options = acme_options()?;
        let binds = ("127.0.0.1:23443".parse()?, "127.0.0.1:23444".parse()?);
        let executable = env::current_exe()?;
        let rejected = fixture.0.join("expired-node");
        assert!(
            acme::launch(
                &prepared,
                &signed,
                &rejected,
                binds,
                &executable,
                &options,
                None,
                now
            )
            .is_err()
        );
        assert!(!rejected.exists());
        response.node_certificate_pem = identity::sign(
            Role::Node,
            &origin_name(&request.node_origin)?,
            &request.node_csr_pem,
            &request.authority.node_ca_pem,
            &pem(&authority.join("node-ca.key"), true)?,
            now,
        )?;
        rebind_public(&signed, Stage::Signed, &response)?;
        let manual = fixture.0.join("manual-still-expired");
        assert!(
            launch(
                &prepared,
                &signed,
                &manual,
                binds.0,
                binds.1,
                &executable,
                None,
                now
            )
            .is_err()
        );
        assert!(!manual.exists());
        let output = fixture.0.join("fresh-node-acme");
        acme::launch(
            &prepared,
            &signed,
            &output,
            binds,
            &executable,
            &options,
            None,
            now,
        )?;
        let before = inventory(&fixture.0)?;
        check(&output, now)?;
        check(&output, now.checked_add(1).ok_or("test clock overflow")?)?;
        assert_eq!(before, inventory(&fixture.0)?);
        for (target, replacement, private) in [
            ("node.key", "admin.key", true),
            ("node.csr", "admin.csr", false),
        ] {
            let original = files::read(&prepared.join(target), MAX_PEM, private)?;
            let changed = files::read(&prepared.join(replacement), MAX_PEM, private)?;
            fs::write(prepared.join(target), changed.as_slice())?;
            let before = inventory(&fixture.0)?;
            assert!(check(&output, now).is_err());
            assert_eq!(before, inventory(&fixture.0)?);
            fs::write(prepared.join(target), original.as_slice())?;
        }
        check(&output, now)?;
        let node_expired = now.checked_add(91 * 86_400).ok_or("test clock overflow")?;
        assert!(check(&output, node_expired).is_err());
        Ok(())
    }

    #[test]
    fn proxy_bound_manual_and_acme_plans_preserve_legacy_argv_and_quote_one_local_path()
    -> TestResult {
        let fixture = Fixture::new()?;
        let now = now()?;
        let (_, prepared, signed) = acme_inputs(&fixture, now)?;
        let config = proxy_config_fixture(&fixture, PROXY_JSON)?;
        let expected_path = path_string(&std::path::absolute(&config)?)?;
        let expected_binding =
            serde_json::json!({"path": expected_path, "sha256": sha256(PROXY_JSON)});
        for automatic in [false, true] {
            let output = fixture.0.join(if automatic {
                "proxy-acme"
            } else {
                "proxy-manual"
            });
            let inputs = (inventory(&prepared)?, inventory(&signed)?);
            let report = proxy_launch(&prepared, &signed, &output, &config, automatic, now)?;
            assert!(!report.server_started && !report.trust_installed && !report.node_authorized);
            let output = report.directory;
            let (wire, preflight, serve, legacy_serve) = if automatic {
                let (launch, request, _) = acme::checked_launch(&output, now)?;
                let wire = serde_json::to_value(&launch)?;
                let (preflight, serve) = acme::arguments(&output, &launch, &request)?;
                let mut old = wire.clone();
                old.as_object_mut()
                    .ok_or("ACME plan is not an object")?
                    .remove("proxy_config");
                let legacy: AcmeLaunch = serde_json::from_value(old.clone())?;
                assert_eq!(serde_json::to_value(&legacy)?, old);
                let (_, legacy_serve) = acme::arguments(&output, &legacy, &request)?;
                (wire, preflight, serve, legacy_serve)
            } else {
                let (launch, request, _) = checked_launch(&output, now)?;
                let wire = serde_json::to_value(&launch)?;
                let (preflight, serve) = arguments(&output, &launch, &request)?;
                let mut old = wire.clone();
                old.as_object_mut()
                    .ok_or("manual plan is not an object")?
                    .remove("proxy_config");
                let legacy: Launch = serde_json::from_value(old.clone())?;
                assert_eq!(serde_json::to_value(&legacy)?, old);
                let (_, legacy_serve) = arguments(&output, &legacy, &request)?;
                (wire, preflight, serve, legacy_serve)
            };
            assert_eq!(wire["proxy_config"], expected_binding);
            assert_eq!(
                wire.as_object().ok_or("plan is not an object")?.len(),
                if automatic { 10 } else { 9 }
            );
            assert_eq!(preflight, check_arguments(&output)?);
            assert_eq!(&serve[..legacy_serve.len()], legacy_serve.as_slice());
            let expected_tail = ["--proxy-config".to_owned(), expected_path.clone()];
            assert_eq!(&serve[legacy_serve.len()..], expected_tail.as_slice());
            assert_eq!(
                serve
                    .iter()
                    .filter(|value| value.as_str() == "--proxy-config")
                    .count(),
                1
            );
            let posix = fs::read_to_string(output.join("start.sh"))?;
            let powershell = fs::read_to_string(output.join("start.ps1"))?;
            assert!(posix.contains(&format!(
                "'--proxy-config' '{}'",
                expected_path.replace('\'', "'\\''")
            )));
            let powershell_path = expected_path
                .replace('\'', "''")
                .replace('‘', "‘‘")
                .replace('’', "’’");
            assert!(powershell.contains(&format!("'--proxy-config' '{powershell_path}'")));
            assert_eq!(inputs, (inventory(&prepared)?, inventory(&signed)?));
            assert!(
                !output
                    .join(config.file_name().ok_or("config has no filename")?)
                    .exists()
            );
            assert!(!output.join("admin.key").exists() && !output.join("node.key").exists());
            let before = inventory(&fixture.0)?;
            check(&output, now)?;
            assert_eq!(before, inventory(&fixture.0)?);
        }
        assert!(fs::read(&config)?.as_slice() == PROXY_JSON);
        assert!(!prepared.join("state/acme").exists());
        Ok(())
    }

    #[test]
    fn proxy_plan_pin_rejects_even_equal_json_whitespace_and_strict_metadata_changes() -> TestResult
    {
        let fixture = Fixture::new()?;
        let now = now()?;
        let (_, prepared, signed) = acme_inputs(&fixture, now)?;
        let config = proxy_config_fixture(&fixture, PROXY_JSON)?;
        let mut plans = Vec::new();
        for automatic in [false, true] {
            let output = fixture.0.join(if automatic {
                "strict-acme"
            } else {
                "strict-manual"
            });
            let output =
                proxy_launch(&prepared, &signed, &output, &config, automatic, now)?.directory;
            plans.push((output, automatic));
        }
        let mut equal_json = PROXY_JSON.to_vec();
        equal_json.push(b'\n');
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(PROXY_JSON)?,
            serde_json::from_slice::<serde_json::Value>(&equal_json)?
        );
        fs::write(&config, &equal_json)?;
        let before = inventory(&fixture.0)?;
        for (output, _) in &plans {
            assert!(check(output, now).is_err());
        }
        assert_eq!(before, inventory(&fixture.0)?);
        fs::write(&config, PROXY_JSON)?;
        for (output, automatic) in &plans {
            check(output, now)?;
            let stage = if *automatic {
                Stage::AcmePlan
            } else {
                Stage::Plan
            };
            let original = load::<serde_json::Value>(output, stage)?.0;
            let binding = &original["proxy_config"];
            for malformed in [
                serde_json::Value::Null,
                serde_json::json!({}),
                serde_json::json!({"path": binding["path"], "sha256": binding["sha256"], "unexpected": true}),
                serde_json::json!({"path": "relative.json", "sha256": binding["sha256"]}),
                serde_json::json!({"path": binding["path"], "sha256": "A".repeat(64)}),
                serde_json::json!({"path": binding["path"], "sha256": "0".repeat(64)}),
            ] {
                let mut changed = original.clone();
                changed["proxy_config"] = malformed;
                rebind_public(output, stage, &changed)?;
                let before = inventory(&fixture.0)?;
                assert!(check(output, now).is_err());
                assert_eq!(before, inventory(&fixture.0)?);
            }
            rebind_public(output, stage, &original)?;
            check(output, now)?;
        }
        fs::remove_file(&config)?;
        for (output, _) in &plans {
            assert!(check(output, now).is_err());
        }
        assert!(!prepared.join("state/acme").exists());
        Ok(())
    }

    #[test]
    fn setup_proxy_validation_precedes_output_and_keeps_relative_tls_at_the_original_config()
    -> TestResult {
        let fixture = Fixture::new()?;
        let now = now()?;
        let (_, prepared, signed) = acme_inputs(&fixture, now)?;
        let config = proxy_config_fixture(&fixture, b"{")?;
        for (index, invalid) in [
        b"{".to_vec(),
        br#"{"listeners":[],"workers":1}"#.to_vec(),
        br#"{"listeners":[{"protocol":"socks5","bind":"127.0.0.1:21080"}],"workers":0}"#.to_vec(),
        br#"{"listeners":[{"protocol":"https","bind":"127.0.0.1:21080","tls_cert":"missing.pem","tls_key":"acme-prepared/admin.key"}],"workers":1}"#.to_vec(),
        vec![b' '; 16 * 1024 + 1],
    ].into_iter().enumerate() {
        fs::write(&config, invalid)?;
        for automatic in [false, true] {
            let output = fixture.0.join(format!("bad-proxy-{index}-{automatic}"));
            let before = inventory(&fixture.0)?;
            assert!(proxy_launch(&prepared, &signed, &output, &config, automatic, now).is_err());
            assert!(!output.exists());
            assert_eq!(before, inventory(&fixture.0)?);
        }
    }
        let signed_response = load::<Response>(&signed, Stage::Signed)?.0;
        let config_directory = config.parent().ok_or("config directory missing")?;
        files::write(
            config_directory,
            "proxy-server.pem",
            signed_response.admin_certificate_pem.as_bytes(),
        )?;
        let encrypted = br#"{"listeners":[{"protocol":"https","bind":"127.0.0.1:21080","tls_cert":"proxy-server.pem","tls_key":"../acme-prepared/admin.key"}],"workers":1}"#;
        fs::write(&config, encrypted)?;
        let mut plans = Vec::new();
        for automatic in [false, true] {
            let output = fixture.0.join(if automatic {
                "relative-tls-acme"
            } else {
                "relative-tls-manual"
            });
            let report = proxy_launch(&prepared, &signed, &output, &config, automatic, now)?;
            check(&report.directory, now)?;
            assert!(!report.directory.join("proxy-server.pem").exists());
            assert!(!report.directory.join("acme-prepared").exists());
            plans.push(report.directory);
        }
        // The JSON hash is unchanged, but the ordinary referenced-TLS validation
        // must still fail when the original relative certificate disappears.
        fs::remove_file(config_directory.join("proxy-server.pem"))?;
        let before = inventory(&fixture.0)?;
        for output in &plans {
            assert!(check(output, now).is_err());
        }
        assert_eq!(before, inventory(&fixture.0)?);
        Ok(())
    }
}
