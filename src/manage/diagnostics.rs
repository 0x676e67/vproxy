//! Redacted offline configuration and explicit local proxy diagnostics.
//!
//! Offline collection never starts a runtime or probes a listener. The separate
//! connection command accepts an exported profile and an existing proxy password;
//! it owns its client pipeline without using management identities or state.

use std::{
    future::Future,
    io::{self, IsTerminal as _, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures_util::FutureExt as _;
use http::{HeaderValue, Request, StatusCode, header};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, RootCertStore, client::Resumption, crypto::aws_lc_rs};
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use super::{
    store::diagnostics::{
        self as storage, Check, Code, Component, EXPECTED_SCHEMA_VERSION, Inspection, Status,
    },
    tls,
};

/// Explicit paths are inputs only; they are never included in report/error data.
#[derive(clap::Args)]
pub struct Args {
    /// Existing persistent management directory; never initialized or migrated
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Optional PEM CA bundle for the separate node-certificate profile check
    #[arg(long, requires_all = ["node_certificate", "node_name"])]
    node_ca: Option<PathBuf>,
    /// Leaf-first public PEM node chain; no private key is read
    #[arg(long, requires_all = ["node_ca", "node_name"])]
    node_certificate: Option<PathBuf>,
    /// Expected node SAN; not a URL or proof of control authorization
    #[arg(long, requires_all = ["node_ca", "node_certificate"])]
    node_name: Option<String>,
}

/// Stable report envelope; dynamic identities, paths and error text have no field.
#[derive(Serialize)]
struct Report {
    format_version: u8,
    scope: &'static str,
    vproxy_version: &'static str,
    operating_system: &'static str,
    architecture: &'static str,
    features: Features,
    sqlite_version: &'static str,
    expected_schema: u32,
    observed_schema: Option<u32>,
    checks_passed: bool,
    checks: Vec<Check>,
    limitations: [&'static str; 8],
}

/// Compile-time capabilities are not observations of running services or eBPF.
#[derive(Serialize)]
struct Features {
    management: bool,
    embedded_web: bool,
    ebpf_compiled: bool,
}

/// Write one complete offline report, then fail if a check needs attention.
/// Collection never starts a runtime, probes a listener, takes a service lock or
/// scans logs/configuration. Only explicitly selected public node certificates
/// are checked; no TLS private key or automation header is loaded.
///
/// SQLite uses its ordinary read-only WAL behavior, not immutable/forensic mode;
/// sidecars may be accessed or created. Its busy timeout bounds lock waits, not
/// all I/O/SQL execution. No local or remote repair is attempted on any result.
pub(super) fn run(args: Args) -> io::Result<()> {
    let report = collect(&args);
    write_report(&mut io::stdout().lock(), &report)?;
    if report.checks_passed {
        Ok(())
    } else {
        Err(io::Error::other(
            "offline diagnostic checks need attention; inspect the JSON report",
        ))
    }
}

/// Keep certificate checking independent of storage failures, while exposing
/// only fixed result enums from either path; neither input path is retained.
fn collect(args: &Args) -> Report {
    let (resolution, mut inspection) = match super::directory(args.data_dir.clone()) {
        Ok(directory) => (
            Check {
                component: Component::DirectoryResolution,
                status: Status::Passed,
                code: Code::Checked,
            },
            storage::inspect(&directory),
        ),
        Err(error) => (
            Check {
                component: Component::DirectoryResolution,
                status: Status::Failed,
                code: match error.kind() {
                    io::ErrorKind::InvalidInput => Code::InvalidPath,
                    io::ErrorKind::NotFound => Code::Missing,
                    io::ErrorKind::PermissionDenied => Code::PermissionDenied,
                    _ => Code::IoFailure,
                },
            },
            Inspection {
                observed_schema: None,
                expected_schema: EXPECTED_SCHEMA_VERSION,
                checks: Vec::new(),
            },
        ),
    };
    inspection.checks.insert(0, resolution);
    inspection.checks.push(node_certificate(args));
    let checks_passed = inspection
        .checks
        .iter()
        .all(|check| matches!(check.status, Status::Passed | Status::NotChecked));
    Report {
        format_version: 1,
        scope: "offline_configuration",
        vproxy_version: env!("CARGO_PKG_VERSION"),
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        features: Features {
            management: true,
            embedded_web: cfg!(feature = "web-ui"),
            ebpf_compiled: cfg!(all(target_os = "linux", feature = "ebpf")),
        },
        sqlite_version: rusqlite::version(),
        expected_schema: inspection.expected_schema,
        observed_schema: inspection.observed_schema,
        checks_passed,
        checks: inspection.checks,
        limitations: [
            "service_runtime_and_network_not_checked",
            "private_keys_and_key_possession_not_checked",
            "node_authorization_not_checked",
            "not_a_database_integrity_scan",
            "sqlite_wal_sidecar_access_possible",
            "no_total_execution_deadline",
            "trusted_ancestor_directories_required",
            if cfg!(unix) {
                "unix_mode_bits_only_not_an_acl_audit"
            } else {
                "filesystem_acl_not_checked"
            },
        ],
    }
}

/// Check only the explicitly requested public node profile: chain, time, both
/// TLS usages and expected SAN. It cannot prove private-key possession, browser
/// trust, remote reachability, peer enrollment or policy-owner authorization.
fn node_certificate(args: &Args) -> Check {
    let (status, code) = match (&args.node_ca, &args.node_certificate, &args.node_name) {
        (None, None, None) => (Status::NotChecked, Code::NotRequested),
        (Some(ca), Some(certificate), Some(name)) => {
            match tls::load_peer_certificate(ca, certificate, name) {
                Ok(_) => (Status::Passed, Code::Checked),
                Err(error) => (
                    Status::Failed,
                    match error.kind() {
                        io::ErrorKind::NotFound => Code::Missing,
                        io::ErrorKind::PermissionDenied => Code::PermissionDenied,
                        io::ErrorKind::InvalidInput => Code::InvalidArguments,
                        io::ErrorKind::InvalidData => Code::InvalidCertificate,
                        _ => Code::IoFailure,
                    },
                ),
            }
        }
        _ => (Status::Failed, Code::InvalidArguments),
    };
    Check {
        component: Component::NodeCertificate,
        status,
        code,
    }
}

/// Serialize before the first write; a broken stdout still returns a fixed
/// diagnostic and cannot expose a caller's writer error or its embedded paths.
fn write_report(output: &mut impl Write, report: &Report) -> io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(report)
        .map_err(|_| io::Error::other("cannot encode offline diagnostic report"))?;
    bytes.push(b'\n');
    output
        .write_all(&bytes)
        .map_err(|error| io::Error::new(error.kind(), "cannot write offline diagnostic report"))
}

const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TARGET_HOST: &str = "example.com";
const TARGET_AUTHORITY: &str = "example.com:443";

/// One local client invocation. Profiles contain routing metadata, not passwords.
#[derive(clap::Args)]
pub struct ConnectionArgs {
    /// Non-secret connection profile exported from the connection preview
    #[arg(long)]
    profile: PathBuf,
    /// Explicit PEM roots for the HTTPS proxy only, never the target website
    #[arg(long)]
    proxy_ca: Option<PathBuf>,
    /// Read one existing proxy password from redirected stdin instead of a terminal
    #[arg(long)]
    password_stdin: bool,
    /// Consent to sending the proxy password without TLS (HTTP or SOCKS5)
    #[arg(long)]
    allow_plaintext: bool,
}

/// Fixed public stages. A passed tunnel does not imply successful target TLS.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    ProxyTcp,
    ProxyTls,
    ProxyTunnel,
    TargetTls,
    TargetHttp,
}

/// Outcomes deliberately contain no library error strings or remote text.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConnectionCode {
    TcpFailed,
    Timeout,
    Cancelled,
    CancellationUnavailable,
    TlsFailed,
    HttpFailed,
    IoFailed,
    AuthenticationRejected,
    TunnelRejected,
    MethodRejected,
    InvalidResponse,
    RedirectNotFollowed,
    TargetRejected,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    NotRun,
    NotApplicable,
    Passed,
    Failed,
}

/// A status code is the peer's numeric response, not its reason phrase or body.
#[derive(Serialize)]
struct Step {
    stage: Stage,
    outcome: Outcome,
    code: Option<ConnectionCode>,
    status: Option<u16>,
}

/// Stable redacted JSON. Success proves one CONNECT and target response headers,
/// not body integrity, egress location, UDP, billing or continuity under restart.
#[derive(Serialize)]
struct ConnectionReport {
    format_version: u8,
    protocol: Protocol,
    target: &'static str,
    success: bool,
    steps: [Step; 5],
    unchecked: [&'static str; 6],
}

impl ConnectionReport {
    fn new(protocol: Protocol) -> Self {
        Self {
            format_version: 1,
            protocol,
            target: "https://example.com/",
            success: false,
            steps: [
                Stage::ProxyTcp,
                Stage::ProxyTls,
                Stage::ProxyTunnel,
                Stage::TargetTls,
                Stage::TargetHttp,
            ]
            .map(|stage| Step {
                stage,
                outcome: if matches!(stage, Stage::ProxyTls) && protocol != Protocol::Https {
                    Outcome::NotApplicable
                } else {
                    Outcome::NotRun
                },
                code: None,
                status: None,
            }),
            unchecked: [
                "socks5_bind",
                "socks5_udp",
                "masque",
                "egress_ip",
                "response_body",
                "billing_continuity",
            ],
        }
    }

    fn step(&mut self, stage: Stage) -> &mut Step {
        &mut self.steps[stage as usize]
    }

    fn pass(&mut self, stage: Stage, status: Option<u16>) {
        let step = self.step(stage);
        step.outcome = Outcome::Passed;
        step.status = status;
    }

    fn fail(&mut self, stage: Stage, code: ConnectionCode, status: Option<u16>) {
        let step = self.step(stage);
        step.outcome = Outcome::Failed;
        step.code = Some(code);
        step.status = status;
    }
}

/// Validate all public input/trust before reading a secret or opening a socket.
/// Profiles cannot choose a destination, header, trust file or command. Only the
/// operator supplies a proxy CA and password; no retry, redirect or environment
/// proxy is used.
/// The network deadline excludes synchronous file/terminal input; DNS may leave
/// an OS resolver job running after cancellation. No diagnostic starts a server.
pub(super) fn test_connection(args: ConnectionArgs) -> io::Result<()> {
    let profile = Profile::read(&args.profile)?;
    if profile.protocol != Protocol::Https && !args.allow_plaintext {
        return Err(invalid_connection_input(
            "HTTP/SOCKS5 sends the proxy password without TLS; explicitly use --allow-plaintext to continue",
        ));
    }
    if profile.protocol != Protocol::Https && args.proxy_ca.is_some() {
        return Err(invalid_connection_input(
            "--proxy-ca applies only to an HTTPS proxy",
        ));
    }
    let trust = Trust::load(args.proxy_ca.as_deref())?;
    let server_name = profile.server_name()?;
    writeln!(
        io::stderr().lock(),
        "Proxy: {:?} {}. Test destination: https://example.com/. Sends real traffic and may be metered. No retry or redirect.",
        profile.protocol,
        profile.authority(),
    )?;
    if profile.protocol != Protocol::Https {
        writeln!(
            io::stderr().lock(),
            "Warning: target HTTPS does not protect the password sent to this plaintext proxy."
        )?;
    }
    let password = if args.password_stdin {
        if io::stdin().is_terminal() {
            return Err(invalid_connection_input(
                "--password-stdin requires redirected input",
            ));
        }
        super::input::existing_password_from_reader(io::stdin().lock())?
    } else {
        super::input::existing_password()?
    };
    super::input::validate_existing_password(&password)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| io::Error::other("cannot start connection test runtime"))?;
    let mut report = ConnectionReport::new(profile.protocol);
    let mut stage = Stage::ProxyTcp;
    let result = runtime.block_on(async {
        let result = tokio::time::timeout(
            TOTAL_TIMEOUT,
            execute_connection(
                &profile,
                server_name,
                &password,
                trust,
                &mut report,
                &mut stage,
            ),
        );
        tokio::pin!(result);
        tokio::select! {
            biased;
            cancelled = tokio::signal::ctrl_c() => Err((
                if cancelled.is_ok() { ConnectionCode::Cancelled } else { ConnectionCode::CancellationUnavailable },
                None,
            )),
            result = &mut result => result.unwrap_or(Err((ConnectionCode::Timeout, None))),
        }
    });
    // Dropping the network future also drops both Hyper drivers and all sockets;
    // no detached connection task can keep sending credentials after this point.
    runtime.shutdown_timeout(Duration::from_millis(100));
    match result {
        Ok(()) => report.success = true,
        Err((code, status)) => report.fail(stage, code, status),
    }
    serde_json::to_writer_pretty(io::stdout().lock(), &report)
        .map_err(|_| io::Error::other("cannot write connection test report"))?;
    writeln!(io::stdout().lock())?;
    if report.success {
        Ok(())
    } else {
        Err(io::Error::other(
            "connection test failed; inspect the redacted report",
        ))
    }
}

fn invalid_connection_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

const MAX_PROFILE_BYTES: usize = 16 * 1024;

/// Client protocols supported by the fixed CONNECT diagnostic, not every
/// protocol or operation implemented by a vproxy listener.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase", try_from = "String")]
enum Protocol {
    Http,
    Https,
    Socks5,
}

impl TryFrom<String> for Protocol {
    type Error = io::Error;

    fn try_from(value: String) -> io::Result<Self> {
        match value.as_str() {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            "socks5" => Ok(Self::Socks5),
            _ => Err(invalid()),
        }
    }
}

/// A single fixed operation keeps imported profiles from selecting a target,
/// HTTP method, local file or other client behavior.
#[derive(Deserialize)]
#[serde(try_from = "String")]
enum Operation {
    Connect,
}

impl TryFrom<String> for Operation {
    type Error = io::Error;

    fn try_from(value: String) -> io::Result<Self> {
        match value.as_str() {
            "connect" => Ok(Self::Connect),
            _ => Err(invalid()),
        }
    }
}

/// Public endpoint and full extension username, without a password. Do not add
/// `Debug`: callers should print only the selected protocol and authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    format_version: u8,
    protocol: Protocol,
    host: String,
    port: u16,
    username: String,
    operation: Operation,
}

impl Profile {
    /// Read one bounded regular file without changing its permissions. Neither
    /// filesystem paths nor JSON/library error text are retained in failures.
    fn read(path: &Path) -> io::Result<Self> {
        let bytes = super::files::read(path, MAX_PROFILE_BYTES, false).map_err(|error| {
            io::Error::new(error.kind(), "connection profile could not be read")
        })?;
        let profile: Self = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        profile.validate()?;
        Ok(profile)
    }

    /// Validate the whole profile before loading credentials or opening a
    /// socket. Usernames are ASCII and unambiguous in both Basic and SOCKS5.
    fn validate(&self) -> io::Result<()> {
        if self.format_version != 1
            || self.port == 0
            || self.username.is_empty()
            || self.username.len() > 1024
            || self.protocol == Protocol::Socks5 && self.username.len() > 255
            || !self.username.is_ascii()
            || self
                .username
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b':')
        {
            return Err(invalid());
        }
        let Operation::Connect = self.operation;
        self.server_name()?;
        Ok(())
    }

    /// Return the exact IP/DNS identity for normal TLS verification. Input is
    /// canonical ASCII without brackets or URL components; no DNS lookup runs.
    fn server_name(&self) -> io::Result<ServerName<'static>> {
        if let Ok(address) = self.host.parse::<IpAddr>() {
            if self.host != address.to_string() {
                return Err(invalid());
            }
            return Ok(ServerName::IpAddress(address.into()));
        }
        if self.host.len() > 253
            || !self.host.is_ascii()
            || !self.host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && (label.as_bytes()[0].is_ascii_lowercase()
                        || label.as_bytes()[0].is_ascii_digit())
                    && (label.as_bytes()[label.len() - 1].is_ascii_lowercase()
                        || label.as_bytes()[label.len() - 1].is_ascii_digit())
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
            || !matches!(url::Host::parse(&self.host), Ok(url::Host::Domain(host)) if host == self.host)
        {
            return Err(invalid());
        }
        match ServerName::try_from(self.host.clone()).map_err(|_| invalid())? {
            name @ ServerName::DnsName(_) => Ok(name),
            _ => Err(invalid()),
        }
    }

    /// Format an already validated endpoint, adding IPv6 brackets only here.
    fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid connection profile")
}

type ConnectionResult<T> = std::result::Result<T, (ConnectionCode, Option<u16>)>;

/// One cold-path allocation per stream layer; never used by proxy workers.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type Stream = Box<dyn Io>;

/// Independent root stores. A private proxy CA must not authorize the website.
struct Trust {
    proxy: Arc<ClientConfig>,
    target: Arc<ClientConfig>,
}

impl Trust {
    fn load(proxy_ca: Option<&Path>) -> io::Result<Self> {
        let public = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let proxy = if let Some(path) = proxy_ca {
            let pem = super::files::read(path, 256 * 1024, false)
                .map_err(|_| invalid_connection_input("cannot read proxy CA file"))?;
            let mut roots = RootCertStore::empty();
            for item in rustls_pemfile::read_all(&mut pem.as_slice()) {
                let rustls_pemfile::Item::X509Certificate(certificate) =
                    item.map_err(|_| invalid_connection_input("invalid proxy CA file"))?
                else {
                    return Err(invalid_connection_input(
                        "proxy CA file must contain only certificates",
                    ));
                };
                roots
                    .add(certificate)
                    .map_err(|_| invalid_connection_input("invalid proxy CA certificate"))?;
            }
            if roots.is_empty() {
                return Err(invalid_connection_input(
                    "proxy CA file has no certificates",
                ));
            }
            roots
        } else {
            public.clone()
        };
        Ok(Self {
            proxy: config(proxy)?,
            target: config(public)?,
        })
    }
}

/// Normal AWS-LC certificate/name validation, TLS 1.2/1.3 and HTTP/1.1 only.
/// Resumption and early data are disabled for both newly-created client layers.
fn config(roots: RootCertStore) -> io::Result<Arc<ClientConfig>> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid_connection_input("cannot configure connection test TLS"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

/// Dropping this future closes the entire pipeline. Only proxy DNS is resolved
/// locally; SOCKS carries example.com as a domain for proxy-side resolution.
async fn execute_connection(
    profile: &Profile,
    server_name: ServerName<'static>,
    password: &[u8],
    trust: Trust,
    report: &mut ConnectionReport,
    stage: &mut Stage,
) -> ConnectionResult<()> {
    *stage = Stage::ProxyTcp;
    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((profile.host.as_str(), profile.port)),
    )
    .await
    .map_err(|_| (ConnectionCode::Timeout, None))?
    .map_err(|_| (ConnectionCode::TcpFailed, None))?;
    report.pass(*stage, None);
    let stream: Stream = if profile.protocol == Protocol::Https {
        *stage = Stage::ProxyTls;
        let stream = TlsConnector::from(trust.proxy)
            .connect(server_name, stream)
            .await
            .map_err(|_| (ConnectionCode::TlsFailed, None))?;
        report.pass(*stage, None);
        Box::new(stream)
    } else {
        Box::new(stream)
    };
    *stage = Stage::ProxyTunnel;
    let stream = match profile.protocol {
        Protocol::Http | Protocol::Https => {
            http_tunnel(stream, &profile.username, password).await?
        }
        Protocol::Socks5 => socks_tunnel(stream, &profile.username, password).await?,
    };
    report.pass(*stage, None);
    *stage = Stage::TargetTls;
    let server_name =
        ServerName::try_from(TARGET_HOST).map_err(|_| (ConnectionCode::TlsFailed, None))?;
    let stream = TlsConnector::from(trust.target)
        .connect(server_name, stream)
        .await
        .map_err(|_| (ConnectionCode::TlsFailed, None))?;
    report.pass(*stage, None);
    *stage = Stage::TargetHttp;
    let status = target_response(Box::new(stream)).await?;
    report.pass(*stage, Some(status));
    Ok(())
}

/// Sensitive marking prevents ordinary HeaderValue Debug output, not erasure of
/// Hyper/TLS-owned copies. Caller-owned plaintext and Base64 buffers zeroize.
fn authorization(username: &str, password: &[u8]) -> ConnectionResult<HeaderValue> {
    let length = username
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(password.len()))
        .ok_or((ConnectionCode::HttpFailed, None))?;
    let mut plain = Zeroizing::new(Vec::with_capacity(length));
    plain.extend_from_slice(username.as_bytes());
    plain.push(b':');
    plain.extend_from_slice(password);
    let length = base64::encoded_len(length, true)
        .and_then(|length| length.checked_add(6))
        .ok_or((ConnectionCode::HttpFailed, None))?;
    let mut encoded = Zeroizing::new(String::with_capacity(length));
    encoded.push_str("Basic ");
    STANDARD.encode_string(&plain, &mut encoded);
    let mut value = HeaderValue::from_bytes(encoded.as_bytes())
        .map_err(|_| (ConnectionCode::HttpFailed, None))?;
    value.set_sensitive(true);
    Ok(value)
}

fn builder() -> hyper::client::conn::http1::Builder {
    let mut builder = hyper::client::conn::http1::Builder::new();
    builder.max_buf_size(16 * 1024).max_headers(64);
    builder
}

/// RFC 9110 §9.3.6: any 2xx upgrades immediately, ignoring CL/TE. Hyper's
/// upgrade retains over-read bytes; it must be driven through with_upgrades().
/// <https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6>
async fn http_tunnel(stream: Stream, username: &str, password: &[u8]) -> ConnectionResult<Stream> {
    let (mut sender, connection) = builder()
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|_| (ConnectionCode::HttpFailed, None))?;
    let request = Request::builder()
        .method(http::Method::CONNECT)
        .uri(TARGET_AUTHORITY)
        .header(header::HOST, TARGET_AUTHORITY)
        .header(
            header::PROXY_AUTHORIZATION,
            authorization(username, password)?,
        )
        .body(Full::new(Bytes::new()))
        .map_err(|_| (ConnectionCode::HttpFailed, None))?;
    let exchange = async {
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| (ConnectionCode::HttpFailed, None))?;
        let status = response.status();
        if !status.is_success() {
            return Err((
                if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                    ConnectionCode::AuthenticationRejected
                } else {
                    ConnectionCode::TunnelRejected
                },
                Some(status.as_u16()),
            ));
        }
        hyper::upgrade::on(response)
            .await
            .map(|stream| Box::new(TokioIo::new(stream)) as Stream)
            .map_err(|_| (ConnectionCode::HttpFailed, None))
    };
    drive(exchange, connection.with_upgrades()).await
}

/// RFC 1928 §3 and RFC 1929 §2: offer only username/password. An unsolicited
/// NO AUTH selection cannot prove these credentials were checked. No retries.
/// <https://www.rfc-editor.org/rfc/rfc1928.html#section-3>
/// <https://www.rfc-editor.org/rfc/rfc1929.html#section-2>
async fn socks_tunnel(
    mut stream: Stream,
    username: &str,
    password: &[u8],
) -> ConnectionResult<Stream> {
    let user_len =
        u8::try_from(username.len()).map_err(|_| (ConnectionCode::InvalidResponse, None))?;
    let password_len =
        u8::try_from(password.len()).map_err(|_| (ConnectionCode::InvalidResponse, None))?;
    stream
        .write_all(&[5, 1, 2])
        .await
        .map_err(|_| (ConnectionCode::IoFailed, None))?;
    let mut reply = [0; 2];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|_| (ConnectionCode::InvalidResponse, None))?;
    match reply {
        [5, 2] => {}
        [5, 255] => return Err((ConnectionCode::MethodRejected, None)),
        _ => return Err((ConnectionCode::InvalidResponse, None)),
    }
    let mut auth = Zeroizing::new(Vec::with_capacity(3 + username.len() + password.len()));
    auth.extend_from_slice(&[1, user_len]);
    auth.extend_from_slice(username.as_bytes());
    auth.push(password_len);
    auth.extend_from_slice(password);
    stream
        .write_all(&auth)
        .await
        .map_err(|_| (ConnectionCode::IoFailed, None))?;
    drop(auth);
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|_| (ConnectionCode::InvalidResponse, None))?;
    if reply[0] != 1 {
        return Err((ConnectionCode::InvalidResponse, None));
    }
    if reply[1] != 0 {
        return Err((
            ConnectionCode::AuthenticationRejected,
            Some(u16::from(reply[1])),
        ));
    }
    let mut request = vec![5, 1, 0, 3, 11];
    request.extend_from_slice(TARGET_HOST.as_bytes());
    request.extend_from_slice(&443_u16.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|_| (ConnectionCode::IoFailed, None))?;
    let mut head = [0; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|_| (ConnectionCode::InvalidResponse, None))?;
    if head[0] != 5 || head[2] != 0 || head[1] > 8 {
        return Err((ConnectionCode::InvalidResponse, None));
    }
    if head[1] != 0 {
        return Err((ConnectionCode::TunnelRejected, Some(u16::from(head[1]))));
    }
    let length = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let length = stream
                .read_u8()
                .await
                .map_err(|_| (ConnectionCode::InvalidResponse, None))?;
            if length == 0 {
                return Err((ConnectionCode::InvalidResponse, None));
            }
            usize::from(length)
        }
        _ => return Err((ConnectionCode::InvalidResponse, None)),
    };
    let mut tail = [0; 257];
    stream
        .read_exact(&mut tail[..length + 2])
        .await
        .map_err(|_| (ConnectionCode::InvalidResponse, None))?;
    Ok(stream)
}

/// Read only the final response headers. No body/Location is logged or followed.
async fn target_response(stream: Stream) -> ConnectionResult<u16> {
    let (mut sender, connection) = builder()
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|_| (ConnectionCode::HttpFailed, None))?;
    let request = Request::builder()
        .uri("/")
        .header(header::HOST, TARGET_HOST)
        .header(header::CONNECTION, "close")
        .header(header::USER_AGENT, "vproxy-connection-test")
        .body(Full::new(Bytes::new()))
        .map_err(|_| (ConnectionCode::HttpFailed, None))?;
    let exchange = async {
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| (ConnectionCode::HttpFailed, None))?;
        let status = response.status();
        if status.is_success() {
            Ok(status.as_u16())
        } else {
            Err((
                if status.is_redirection() {
                    ConnectionCode::RedirectNotFollowed
                } else {
                    ConnectionCode::TargetRejected
                },
                Some(status.as_u16()),
            ))
        }
    };
    drive(exchange, connection).await
}

/// Poll driver and exchange in this future, never a detached task. A clean close
/// can deliver a buffered response before the driver finishes; consume it first.
async fn drive<T>(
    exchange: impl Future<Output = ConnectionResult<T>>,
    driver: impl Future<Output = std::result::Result<(), hyper::Error>>,
) -> ConnectionResult<T> {
    tokio::pin!(exchange, driver);
    tokio::select! {
        biased;
        result = &mut exchange => result,
        result = &mut driver => match result {
            Ok(()) => exchange.await,
            Err(_) => exchange.as_mut().now_or_never().unwrap_or(Err((ConnectionCode::HttpFailed, None))),
        }
    }
}

#[cfg(test)]
mod tests {

    use rcgen::generate_simple_self_signed;
    use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};

    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    #[test]
    fn plaintext_consent_and_ca_scope_fail_before_secret_input_or_network() {
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(self.0.join("profile.json"));
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let fixture = Fixture(std::env::temp_dir().join(format!(
            "vproxy-client-options-{:032x}",
            u128::from_be_bytes(random)
        )));
        std::fs::create_dir(&fixture.0).unwrap();
        let path = fixture.0.join("profile.json");
        // No listener/password/CA exists. These guards must precede every such read.
        for protocol in ["http", "socks5"] {
            std::fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!({
                    "format_version": 1, "protocol": protocol, "host": "127.0.0.1",
                    "port": 1, "username": "user", "operation": "connect",
                }))
                .unwrap(),
            )
            .unwrap();
            let args = |allow_plaintext| ConnectionArgs {
                profile: path.clone(),
                proxy_ca: Some(fixture.0.join("missing-ca.pem")),
                password_stdin: true,
                allow_plaintext,
            };
            assert!(
                test_connection(args(false))
                    .unwrap_err()
                    .to_string()
                    .contains("--allow-plaintext")
            );
            assert_eq!(
                test_connection(args(true)).unwrap_err().to_string(),
                "--proxy-ca applies only to an HTTPS proxy"
            );
        }
    }

    // Synthetic peers never resolve or contact the public diagnostic destination.
    // They check protocol boundaries, not billing or response body integrity.
    const USER: &str = "diagnostic-user-canary";
    const PASSWORD: &[u8] = b"diagnostic password:canary";

    async fn bounded<T>(future: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("synthetic peer did not finish")
    }

    async fn head(stream: &mut (impl AsyncRead + Unpin + ?Sized)) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            if bytes.len() == 16 * 1024 {
                return Err(io::Error::other("synthetic request exceeded limit"));
            }
            bytes.push(stream.read_u8().await?);
        }
        Ok(bytes)
    }

    fn connect_request(bytes: &[u8]) {
        let request = std::str::from_utf8(bytes).unwrap().to_ascii_lowercase();
        assert!(request.starts_with("connect example.com:443 http/1.1\r\n"));
        assert!(request.contains("\r\nhost: example.com:443\r\n"));
        assert_eq!(request.matches("\r\nproxy-authorization:").count(), 1);
        let expected = authorization(USER, PASSWORD).unwrap();
        assert!(request.contains(&expected.to_str().unwrap().to_ascii_lowercase()));
    }

    struct Identity {
        server: Arc<ServerConfig>,
        pem: String,
    }

    fn identity(names: &[&str]) -> Identity {
        let certified = generate_simple_self_signed(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let mut server =
            ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certified.cert.der().clone()],
                    PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
                )
                .unwrap();
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        Identity {
            server: Arc::new(server),
            pem: certified.cert.pem(),
        }
    }

    fn profile(protocol: Protocol, port: u16) -> Profile {
        serde_json::from_value(serde_json::json!({
            "format_version": 1, "protocol": protocol, "host": "127.0.0.1",
            "port": port, "username": USER, "operation": "connect",
        }))
        .unwrap()
    }

    async fn proxy_accept(stream: &mut (impl Io + ?Sized)) {
        connect_request(&head(stream).await.unwrap());
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
    }

    fn redacted(report: &ConnectionReport) -> serde_json::Value {
        let bytes = serde_json::to_string(report).unwrap();
        for canary in [
            USER,
            std::str::from_utf8(PASSWORD).unwrap(),
            "remote-body-canary",
            "forbidden.invalid",
        ] {
            assert!(
                !bytes.contains(canary),
                "report retained private peer/input text"
            );
        }
        serde_json::from_str(&bytes).unwrap()
    }

    #[tokio::test]
    async fn loading_a_proxy_ca_keeps_the_real_target_root_store_independent() {
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(self.0.join("proxy-ca.pem"));
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let fixture = Fixture(std::env::temp_dir().join(format!(
            "vproxy-test-proxy-ca-{:032x}",
            u128::from_be_bytes(random)
        )));
        crate::manage::files::create_directory(&fixture.0).unwrap();
        let shared = identity(&["127.0.0.1", "example.com"]);
        crate::manage::files::write(&fixture.0, "proxy-ca.pem", shared.pem.as_bytes()).unwrap();
        // Use the production factory, not a hand-built Trust. If it accidentally
        // adds this public test certificate to target roots, the inner TLS would
        // succeed and wait for a GET instead of failing at TargetTls.
        let trust = Trust::load(Some(&fixture.0.join("proxy-ca.pem"))).unwrap();
        bounded(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let profile = profile(Protocol::Https, listener.local_addr().unwrap().port());
            let mut report = ConnectionReport::new(Protocol::Https);
            let mut stage = Stage::ProxyTcp;
            let client = async {
                assert_eq!(
                    execute_connection(
                        &profile,
                        profile.server_name().unwrap(),
                        PASSWORD,
                        trust,
                        &mut report,
                        &mut stage
                    )
                    .await,
                    Err((ConnectionCode::TlsFailed, None))
                );
            };
            let server = async {
                let (stream, _) = listener.accept().await.unwrap();
                let mut outer = TlsAcceptor::from(shared.server.clone())
                    .accept(stream)
                    .await
                    .unwrap();
                proxy_accept(&mut outer).await;
                assert!(
                    TlsAcceptor::from(shared.server.clone())
                        .accept(outer)
                        .await
                        .is_err()
                );
            };
            tokio::join!(client, server);
            assert!(matches!(stage, Stage::TargetTls));
            report.fail(stage, ConnectionCode::TlsFailed, None);
            let value = redacted(&report);
            assert_eq!(value["steps"][1]["outcome"], "passed");
            assert_eq!(value["steps"][2]["outcome"], "passed");
            assert_eq!(value["steps"][3]["code"], "tls_failed");
        })
        .await;
    }
}
