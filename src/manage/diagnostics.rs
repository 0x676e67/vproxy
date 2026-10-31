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
    use std::{
        fs::{self, DirBuilder, OpenOptions},
        path::Path,
    };

    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose, generate_simple_self_signed,
    };
    use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
    use serde_json::Value;
    use tokio::{io::DuplexStream, net::TcpListener, sync::oneshot};
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::manage::store;

    const PATH_CANARY: &str = "diagnostic-private-path-canary";
    const NODE_CANARY: &str = "diagnostic-private-node-canary";
    const ADMIN_CANARY: &str = "diagnostic-private-admin-canary";
    const PHC_CANARY: &str = "diagnostic-private-phc-canary";
    const CA_CANARY: &str = "diagnostic-private-ca-canary";
    const SAN_CANARY: &str = "diagnostic-private-san-canary.invalid";

    /// Each fixture owns an exclusively created directory, never a runtime path.
    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> io::Result<Self> {
            let mut random = [0; 16];
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("test entropy unavailable"))?;
            let path = std::env::temp_dir().join(format!(
                "vproxy-{PATH_CANARY}-{:032x}",
                u128::from_be_bytes(random)
            ));
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

        fn write(&self, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
            let path = self.0.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            options.open(&path)?.write_all(bytes)?;
            Ok(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn args(directory: &Path) -> Args {
        Args {
            data_dir: Some(directory.to_owned()),
            node_ca: None,
            node_certificate: None,
            node_name: None,
        }
    }

    fn rendered(report: &Report) -> io::Result<(String, Value)> {
        let mut output = Vec::new();
        write_report(&mut output, report)?;
        assert!(output.ends_with(b"\n"));
        let value = serde_json::from_slice(&output).map_err(io::Error::other)?;
        let text = String::from_utf8(output).map_err(io::Error::other)?;
        Ok((text, value))
    }

    fn assert_keys(value: &Value, expected: &[&str]) {
        let mut actual: Vec<_> = value
            .as_object()
            .expect("diagnostic object")
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected = expected.to_vec();
        actual.sort_unstable();
        expected.sort_unstable();
        assert_eq!(actual, expected);
    }

    fn check(report: &Report, component: Component) -> Check {
        let found: Vec<_> = report
            .checks
            .iter()
            .filter(|item| item.component == component)
            .copied()
            .collect();
        assert_eq!(found.len(), 1);
        found[0]
    }

    fn public_identity(fixture: &Fixture) -> io::Result<(PathBuf, PathBuf)> {
        let mut ca = CertificateParams::new(Vec::<String>::new()).map_err(io::Error::other)?;
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca.distinguished_name.push(DnType::CommonName, CA_CANARY);
        let issuer =
            CertifiedIssuer::self_signed(ca, KeyPair::generate().map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
        let mut leaf =
            CertificateParams::new(vec![SAN_CANARY.to_owned()]).map_err(io::Error::other)?;
        leaf.is_ca = IsCa::ExplicitNoCa;
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = KeyPair::generate().map_err(io::Error::other)?;
        let certificate = leaf.signed_by(&key, &issuer).map_err(io::Error::other)?;
        // Neither key is written: the diagnostic accepts only public certificates.
        Ok((
            fixture.write("ca-path-canary.pem", issuer.pem().as_bytes())?,
            fixture.write("certificate-path-canary.pem", certificate.pem().as_bytes())?,
        ))
    }

    #[test]
    fn collected_metadata_is_projected_into_an_allowlisted_redacted_report() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let original = store::initialize(&fixture.0, NODE_CANARY, ADMIN_CANARY, PHC_CANARY)?;
        let report = collect(&args(&fixture.0));
        assert!(report.checks_passed);
        assert_eq!(report.observed_schema, Some(report.expected_schema));
        let (text, value) = rendered(&report)?;
        assert_keys(
            &value,
            &[
                "format_version",
                "scope",
                "vproxy_version",
                "operating_system",
                "architecture",
                "features",
                "sqlite_version",
                "expected_schema",
                "observed_schema",
                "checks_passed",
                "checks",
                "limitations",
            ],
        );
        assert_keys(
            &value["features"],
            &["management", "embedded_web", "ebpf_compiled"],
        );
        for item in value["checks"].as_array().expect("checks array") {
            assert_keys(item, &["component", "status", "code"]);
        }
        assert_eq!(value["format_version"], 1);
        assert_eq!(value["scope"], "offline_configuration");
        for canary in [
            PATH_CANARY,
            NODE_CANARY,
            ADMIN_CANARY,
            PHC_CANARY,
            &original.node_id,
        ] {
            assert!(!text.contains(canary), "report disclosed a fixture canary");
        }
        assert!(
            report
                .limitations
                .contains(&"service_runtime_and_network_not_checked")
        );
        assert!(report.limitations.contains(&if cfg!(unix) {
            "unix_mode_bits_only_not_an_acl_audit"
        } else {
            "filesystem_acl_not_checked"
        }));
        Ok(())
    }

    #[test]
    fn missing_and_empty_directory_inputs_fail_without_creating_any_state() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let missing = fixture.0.join("missing-path-canary");
        let report = collect(&args(&missing));
        assert!(!report.checks_passed);
        assert_eq!(check(&report, Component::Directory).code, Code::Missing);
        let (text, value) = rendered(&report)?;
        assert_eq!(value["checks_passed"], false);
        assert!(!text.contains(PATH_CANARY));
        assert!(!text.contains("missing-path-canary"));
        assert!(!missing.exists());
        assert_eq!(fs::read_dir(&fixture.0)?.count(), 0);

        let report = collect(&args(Path::new("")));
        assert!(!report.checks_passed);
        assert_eq!(
            check(&report, Component::DirectoryResolution),
            Check {
                component: Component::DirectoryResolution,
                status: Status::Failed,
                code: Code::InvalidPath,
            }
        );
        assert!(report.observed_schema.is_none());
        let (_, value) = rendered(&report)?;
        assert_eq!(value["checks"][0]["code"], "invalid_path");
        assert_eq!(fs::read_dir(&fixture.0)?.count(), 0);
        Ok(())
    }

    #[test]
    fn optional_certificate_arguments_are_not_silently_completed_or_downgraded() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let defaults = args(&fixture.0);
        assert_eq!(
            node_certificate(&defaults),
            Check {
                component: Component::NodeCertificate,
                status: Status::NotChecked,
                code: Code::NotRequested,
            }
        );
        for mask in 1..7 {
            let mut input = args(&fixture.0);
            input.node_ca = (mask & 1 != 0).then(|| fixture.0.join("unread-ca-path-canary"));
            input.node_certificate =
                (mask & 2 != 0).then(|| fixture.0.join("unread-cert-path-canary"));
            input.node_name = (mask & 4 != 0).then(|| SAN_CANARY.to_owned());
            assert_eq!(
                node_certificate(&input),
                Check {
                    component: Component::NodeCertificate,
                    status: Status::Failed,
                    code: Code::InvalidArguments,
                },
                "partial mask={mask}",
            );
        }
        assert_eq!(fs::read_dir(&fixture.0)?.count(), 0);
        Ok(())
    }

    #[test]
    fn valid_public_node_certificate_needs_no_key_file_and_leaks_no_ca_or_san() -> io::Result<()> {
        let fixture = Fixture::new()?;
        store::initialize(&fixture.0, NODE_CANARY, ADMIN_CANARY, PHC_CANARY)?;
        let (ca, certificate) = public_identity(&fixture)?;
        let mut input = args(&fixture.0);
        input.node_ca = Some(ca);
        input.node_certificate = Some(certificate);
        input.node_name = Some(SAN_CANARY.to_owned());
        let report = collect(&input);
        assert!(report.checks_passed);
        assert_eq!(
            check(&report, Component::NodeCertificate),
            Check {
                component: Component::NodeCertificate,
                status: Status::Passed,
                code: Code::Checked,
            }
        );
        let (text, _) = rendered(&report)?;
        for canary in [
            PATH_CANARY,
            NODE_CANARY,
            ADMIN_CANARY,
            PHC_CANARY,
            CA_CANARY,
            SAN_CANARY,
            "ca-path-canary.pem",
            "certificate-path-canary.pem",
            "-----BEGIN CERTIFICATE-----",
        ] {
            assert!(
                !text.contains(canary),
                "report disclosed certificate or stored metadata"
            );
        }
        assert!(
            report
                .limitations
                .contains(&"private_keys_and_key_possession_not_checked")
        );
        assert!(
            report
                .limitations
                .contains(&"node_authorization_not_checked")
        );
        Ok(())
    }

    #[test]
    fn certificate_failures_map_to_fixed_codes_without_echoing_the_selected_inputs()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (ca, certificate) = public_identity(&fixture)?;
        let mut input = args(&fixture.0);
        input.node_ca = Some(ca);
        input.node_certificate = Some(certificate);
        for (name, expected) in [
            ("wrong-san-path-canary.invalid", Code::InvalidCertificate),
            ("invalid reference name canary", Code::InvalidArguments),
        ] {
            input.node_name = Some(name.to_owned());
            let result = node_certificate(&input);
            assert_eq!(result.status, Status::Failed);
            assert_eq!(result.code, expected);
            let encoded = serde_json::to_string(&result).map_err(io::Error::other)?;
            assert!(!encoded.contains(name));
            assert!(!encoded.contains(PATH_CANARY));
        }
        input.node_name = Some(SAN_CANARY.to_owned());
        input.node_ca = Some(fixture.0.join("missing-ca-path-canary.pem"));
        assert_eq!(node_certificate(&input).code, Code::Missing);
        input.node_ca = Some(fixture.0.join("ca-path-canary.pem"));
        input.node_certificate =
            Some(fixture.write("malformed-public-certificate.pem", b"PEM-PAYLOAD-CANARY")?);
        assert_eq!(node_certificate(&input).code, Code::InvalidCertificate);
        let (text, _) = rendered(&collect(&input))?;
        for canary in [
            PATH_CANARY,
            SAN_CANARY,
            "PEM-PAYLOAD-CANARY",
            "malformed-public-certificate.pem",
        ] {
            assert!(!text.contains(canary));
        }
        Ok(())
    }

    #[test]
    fn writer_errors_preserve_the_io_kind_but_not_the_original_error_text() -> io::Result<()> {
        struct FailingWriter {
            prefix: Vec<u8>,
            allowed: usize,
            kind: io::ErrorKind,
        }
        impl Write for FailingWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.prefix.len() == self.allowed {
                    return Err(io::Error::new(self.kind, "WRITER-PRIVATE-PATH-CANARY"));
                }
                let count = bytes.len().min(self.allowed - self.prefix.len());
                self.prefix.extend_from_slice(&bytes[..count]);
                Ok(count)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let report = collect(&args(Path::new("")));
        for (allowed, kind) in [(0, io::ErrorKind::BrokenPipe), (8, io::ErrorKind::Other)] {
            let mut writer = FailingWriter {
                prefix: Vec::new(),
                allowed,
                kind,
            };
            let error = write_report(&mut writer, &report).expect_err("writer must fail");
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), "cannot write offline diagnostic report");
            assert!(!error.to_string().contains("WRITER-PRIVATE-PATH-CANARY"));
            assert_eq!(writer.prefix.len(), allowed);
        }
        Ok(())
    }

    #[test]
    fn report_preserves_partial_progress_without_credentials_or_remote_text() {
        let mut report = ConnectionReport::new(Protocol::Http);
        report.pass(Stage::ProxyTcp, None);
        report.pass(Stage::ProxyTunnel, None);
        report.fail(Stage::TargetTls, ConnectionCode::TlsFailed, None);
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["success"], false);
        assert_eq!(value["steps"][0]["outcome"], "passed");
        assert_eq!(value["steps"][1]["outcome"], "not_applicable");
        assert_eq!(value["steps"][2]["outcome"], "passed");
        assert_eq!(value["steps"][3]["code"], "tls_failed");
        assert_eq!(value["steps"][4]["outcome"], "not_run");
        assert_eq!(value["target"], "https://example.com/");
        assert!(
            value["unchecked"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("response_body"))
        );
        let keys = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert!(!keys.contains(&"username"));
        assert!(!keys.contains(&"password"));
        assert!(!keys.contains(&"endpoint"));
    }

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

    fn imported_profile(protocol: Protocol, host: &str, username: &str) -> Profile {
        Profile {
            format_version: 1,
            protocol,
            host: host.to_owned(),
            port: 1080,
            username: username.to_owned(),
            operation: Operation::Connect,
        }
    }

    fn document() -> serde_json::Value {
        serde_json::json!({
            "format_version": 1,
            "protocol": "https",
            "host": "proxy.example",
            "port": 443,
            "username": "user_region-us_session-1_device-linux",
            "operation": "connect"
        })
    }

    fn decode(value: serde_json::Value) -> io::Result<Profile> {
        let profile: Profile = serde_json::from_value(value).map_err(|_| invalid())?;
        profile.validate()?;
        Ok(profile)
    }

    #[test]
    fn canonical_endpoints_and_extension_usernames_are_preserved() {
        for protocol in [Protocol::Http, Protocol::Https, Protocol::Socks5] {
            for (host, authority) in [
                ("proxy.example", "proxy.example:1080"),
                ("localhost", "localhost:1080"),
                ("127.0.0.1", "127.0.0.1:1080"),
                ("2001:db8::1", "[2001:db8::1]:1080"),
            ] {
                let profile =
                    imported_profile(protocol, host, "user_region-us_session-1_device-linux");
                profile.validate().unwrap();
                assert_eq!(profile.authority(), authority);
                assert!(profile.server_name().is_ok());
                assert_eq!(profile.username, "user_region-us_session-1_device-linux");
            }
        }
        assert!(decode(document()).is_ok());
    }

    #[test]
    fn imported_shape_is_exact_and_cannot_add_secrets_or_operations() {
        for (key, value) in [
            ("password", serde_json::json!("secret-canary")),
            ("target", serde_json::json!("https://other.example/")),
            (
                "headers",
                serde_json::json!({"Authorization": "secret-canary"}),
            ),
            ("format_version", serde_json::json!(2)),
            ("format_version", serde_json::json!("1")),
            ("protocol", serde_json::json!("masque")),
            ("protocol", serde_json::json!("HTTPS")),
            ("protocol", serde_json::json!({"http": null})),
            ("operation", serde_json::json!("bind")),
            ("operation", serde_json::json!({"connect": {}})),
            ("operation", serde_json::json!({"connect": null})),
            ("port", serde_json::json!(0)),
            ("port", serde_json::json!(65536)),
            ("port", serde_json::json!("443")),
        ] {
            let mut value_with_change = document();
            value_with_change[key] = value;
            assert_eq!(
                decode(value_with_change).err().unwrap().to_string(),
                "invalid connection profile"
            );
        }
        for key in [
            "format_version",
            "protocol",
            "host",
            "port",
            "username",
            "operation",
        ] {
            let mut value = document();
            value.as_object_mut().unwrap().remove(key);
            assert!(decode(value).is_err());
        }
        let duplicate = br#"{"format_version":1,"protocol":"http","host":"localhost","port":80,"username":"a","username":"b","operation":"connect"}"#;
        assert!(serde_json::from_slice::<Profile>(duplicate).is_err());
    }

    #[test]
    fn hostname_and_username_bounds_reject_ambiguous_destinations() {
        for host in [
            "",
            "Proxy.example",
            "proxy.example.",
            "-proxy.example",
            "proxy-.example",
            "proxy..example",
            "proxy_name",
            "例子.example",
            "user@proxy.example",
            "proxy.example:443",
            "proxy.example/path",
            "proxy.example\\path",
            "proxy%2eexample",
            " proxy.example",
            "proxy.example\n",
            "[::1]",
            "2001:0db8::1",
            "2001:DB8::1",
            "fe80::1%1",
            "127.1",
            "0177.0.0.1",
            "0x7f000001",
            "2130706433",
        ] {
            assert!(
                imported_profile(Protocol::Http, host, "user")
                    .validate()
                    .is_err(),
                "{host:?}"
            );
        }
        let longest = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(longest.len(), 253);
        assert!(
            imported_profile(Protocol::Http, &longest, "user")
                .validate()
                .is_ok()
        );
        assert!(
            imported_profile(Protocol::Http, &format!("a.{longest}"), "user")
                .validate()
                .is_err()
        );
        for username in [
            "",
            "user:name",
            "user name",
            "user\tname",
            "user\u{7f}",
            "用户",
            "user\u{a0}",
        ] {
            assert!(
                imported_profile(Protocol::Http, "localhost", username)
                    .validate()
                    .is_err()
            );
        }
        assert!(
            imported_profile(Protocol::Http, "localhost", &"x".repeat(1024))
                .validate()
                .is_ok()
        );
        assert!(
            imported_profile(Protocol::Https, "localhost", &"x".repeat(1025))
                .validate()
                .is_err()
        );
        assert!(
            imported_profile(Protocol::Socks5, "localhost", &"x".repeat(255))
                .validate()
                .is_ok()
        );
        assert!(
            imported_profile(Protocol::Socks5, "localhost", &"x".repeat(256))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn file_reads_are_bounded_and_errors_do_not_retain_paths_or_input() {
        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_file(self.0.join("profile.json"));
                let _ = fs::remove_dir(&self.0);
            }
        }
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).unwrap();
        let fixture = Fixture(std::env::temp_dir().join(format!(
            "vproxy-profile-{:032x}",
            u128::from_be_bytes(random)
        )));
        fs::create_dir(&fixture.0).unwrap();
        let path = fixture.0.join("profile.json");
        fs::write(&path, serde_json::to_vec(&document()).unwrap()).unwrap();
        assert!(Profile::read(&path).is_ok());
        let mut oversized = serde_json::to_vec(&document()).unwrap();
        oversized.resize(MAX_PROFILE_BYTES + 1, b' ');
        fs::write(&path, oversized).unwrap();
        assert_eq!(
            Profile::read(&path).err().unwrap().to_string(),
            "connection profile could not be read"
        );
        fs::write(
            &path,
            br#"{"username":"secret-canary","password":"secret-canary"}"#,
        )
        .unwrap();
        assert_eq!(
            Profile::read(&path).err().unwrap().to_string(),
            "invalid connection profile"
        );
        let error = Profile::read(&fixture.0.join("secret-canary.json"))
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "connection profile could not be read");
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

    async fn fragmented(stream: &mut (impl AsyncWrite + Unpin + ?Sized), bytes: &[u8]) {
        for chunk in bytes.chunks(3) {
            stream.write_all(chunk).await.unwrap();
            tokio::task::yield_now().await;
        }
    }

    fn connect_request(bytes: &[u8]) {
        let request = std::str::from_utf8(bytes).unwrap().to_ascii_lowercase();
        assert!(request.starts_with("connect example.com:443 http/1.1\r\n"));
        assert!(request.contains("\r\nhost: example.com:443\r\n"));
        assert_eq!(request.matches("\r\nproxy-authorization:").count(), 1);
        let expected = authorization(USER, PASSWORD).unwrap();
        assert!(request.contains(&expected.to_str().unwrap().to_ascii_lowercase()));
    }

    async fn socks_auth(stream: &mut (impl Io + ?Sized)) {
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 2]);
        fragmented(stream, &[5, 2]).await;
        let mut prefix = [0; 2];
        stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(prefix, [1, u8::try_from(USER.len()).unwrap()]);
        let mut username = vec![0; USER.len()];
        stream.read_exact(&mut username).await.unwrap();
        assert!(username == USER.as_bytes(), "unexpected synthetic username");
        assert_eq!(usize::from(stream.read_u8().await.unwrap()), PASSWORD.len());
        let mut password = vec![0; PASSWORD.len()];
        stream.read_exact(&mut password).await.unwrap();
        assert!(password == PASSWORD, "unexpected synthetic password");
    }

    async fn socks_connect(stream: &mut (impl Io + ?Sized)) {
        fragmented(stream, &[1, 0]).await;
        let mut request = [0; 18];
        stream.read_exact(&mut request).await.unwrap();
        let mut expected = vec![5, 1, 0, 3, 11];
        expected.extend_from_slice(b"example.com");
        expected.extend_from_slice(&443_u16.to_be_bytes());
        assert_eq!(request.as_slice(), expected);
    }

    #[tokio::test]
    async fn connect_any_success_ignores_body_framing_and_preserves_both_directions() {
        bounded(async {
        let (client, mut peer) = tokio::io::duplex(4096);
        let client = async {
            let mut stream = http_tunnel(Box::new(client), USER, PASSWORD).await.unwrap();
            let mut early = [0; 5];
            stream.read_exact(&mut early).await.unwrap();
            assert_eq!(&early, b"early");
            stream.write_all(b"outbound").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut tail = Vec::new();
            stream.read_to_end(&mut tail).await.unwrap();
            assert_eq!(tail, b"after-half-close");
        };
        let server = async {
            connect_request(&head(&mut peer).await.unwrap());
            fragmented(&mut peer, b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 999999\r\nTransfer-Encoding: chunked").await;
            peer.write_all(b"\r\n\r\nearly").await.unwrap();
            let mut outbound = Vec::new();
            peer.read_to_end(&mut outbound).await.unwrap();
            assert_eq!(outbound, b"outbound");
            peer.write_all(b"after-half-close").await.unwrap();
            peer.shutdown().await.unwrap();
        };
        tokio::join!(client, server);
    }).await;
    }

    #[tokio::test]
    async fn rejected_connect_closes_without_retry_or_following_location() {
        for (status, code) in [
            (407, ConnectionCode::AuthenticationRejected),
            (302, ConnectionCode::TunnelRejected),
        ] {
            bounded(async {
            let (client, mut peer) = tokio::io::duplex(4096);
            let client = async {
                assert_eq!(http_tunnel(Box::new(client), USER, PASSWORD).await.err().unwrap(), (code, Some(status)));
            };
            let server = async {
                connect_request(&head(&mut peer).await.unwrap());
                peer.write_all(format!("HTTP/1.1 {status} synthetic\r\nLocation: https://forbidden.invalid/\r\nContent-Length: 1000\r\n\r\nremote-body-canary").as_bytes()).await.unwrap();
                let mut byte = [0];
                assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
            };
            tokio::join!(client, server);
        }).await;
        }
    }

    #[tokio::test]
    async fn socks_requires_offered_method_and_checks_authentication_once() {
        for (selection, expected) in [
            ([5, 0], ConnectionCode::InvalidResponse),
            ([5, 255], ConnectionCode::MethodRejected),
            ([4, 2], ConnectionCode::InvalidResponse),
        ] {
            bounded(async {
                let (client, mut peer) = tokio::io::duplex(4096);
                let client = async {
                    assert_eq!(
                        socks_tunnel(Box::new(client), USER, PASSWORD)
                            .await
                            .err()
                            .unwrap(),
                        (expected, None)
                    );
                };
                let server = async {
                    let mut greeting = [0; 3];
                    peer.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(greeting, [5, 1, 2]);
                    peer.write_all(&selection).await.unwrap();
                    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
                };
                tokio::join!(client, server);
            })
            .await;
        }
        bounded(async {
            let (client, mut peer) = tokio::io::duplex(4096);
            let client = async {
                assert_eq!(
                    socks_tunnel(Box::new(client), USER, PASSWORD)
                        .await
                        .err()
                        .unwrap(),
                    (ConnectionCode::AuthenticationRejected, Some(7))
                );
            };
            let server = async {
                socks_auth(&mut peer).await;
                fragmented(&mut peer, &[1, 7]).await;
                assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
            };
            tokio::join!(client, server);
        })
        .await;
    }

    #[tokio::test]
    async fn socks_consumes_every_bound_address_without_losing_tunnel_bytes() {
        let mut ipv6 = vec![5, 0, 0, 4];
        ipv6.extend_from_slice(&[0; 16]);
        ipv6.extend_from_slice(&[0x12, 0x34]);
        for reply in [
            vec![5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34],
            vec![5, 0, 0, 3, 3, b'b', b'n', b'd', 0x12, 0x34],
            ipv6,
        ] {
            bounded(async {
                let (client, mut peer) = tokio::io::duplex(4096);
                let client = async {
                    let mut stream = socks_tunnel(Box::new(client), USER, PASSWORD)
                        .await
                        .unwrap();
                    let mut early = [0; 5];
                    stream.read_exact(&mut early).await.unwrap();
                    assert_eq!(&early, b"early");
                };
                let server = async {
                    socks_auth(&mut peer).await;
                    socks_connect(&mut peer).await;
                    // The last address fragment and first tunnel bytes share a write.
                    fragmented(&mut peer, &reply[..reply.len() - 2]).await;
                    let mut tail = reply[reply.len() - 2..].to_vec();
                    tail.extend_from_slice(b"early");
                    peer.write_all(&tail).await.unwrap();
                };
                tokio::join!(client, server);
            })
            .await;
        }
    }

    struct Identity {
        server: Arc<ServerConfig>,
        client: Arc<ClientConfig>,
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
        let mut roots = RootCertStore::empty();
        roots.add(certified.cert.der().clone()).unwrap();
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
            client: config(roots).unwrap(),
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

    async fn proxy_accept(stream: &mut (impl Io + ?Sized), protocol: Protocol) {
        if protocol == Protocol::Socks5 {
            socks_auth(stream).await;
            socks_connect(stream).await;
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                .await
                .unwrap();
        } else {
            connect_request(&head(stream).await.unwrap());
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
        }
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
    async fn all_protocols_reach_fixed_tls_target_and_return_headers_without_body_or_eof() {
        let proxy = identity(&["127.0.0.1"]);
        let target = identity(&["example.com"]);
        for protocol in [Protocol::Http, Protocol::Https, Protocol::Socks5] {
            bounded(async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let profile = profile(protocol, listener.local_addr().unwrap().port());
                let mut report = ConnectionReport::new(protocol);
                let mut stage = Stage::ProxyTcp;
                let client = async {
                    execute_connection(
                        &profile,
                        profile.server_name().unwrap(),
                        PASSWORD,
                        Trust {
                            proxy: proxy.client.clone(),
                            target: target.client.clone(),
                        },
                        &mut report,
                        &mut stage,
                    )
                    .await
                    .unwrap();
                };
                let server = async {
                    let (stream, _) = listener.accept().await.unwrap();
                    let mut stream: Stream = if protocol == Protocol::Https {
                        Box::new(
                            TlsAcceptor::from(proxy.server.clone())
                                .accept(stream)
                                .await
                                .unwrap(),
                        )
                    } else {
                        Box::new(stream)
                    };
                    proxy_accept(&mut *stream, protocol).await;
                    let mut origin = TlsAcceptor::from(target.server.clone())
                        .accept(stream)
                        .await
                        .unwrap();
                    let request = String::from_utf8(head(&mut origin).await.unwrap())
                        .unwrap()
                        .to_ascii_lowercase();
                    assert!(request.starts_with("get / http/1.1\r\n"));
                    assert!(request.contains("\r\nhost: example.com\r\n"));
                    assert!(!request.contains("authorization:"));
                    assert!(!request.contains(USER));
                    origin
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\nremote-body-canary",
                        )
                        .await
                        .unwrap();
                    origin.flush().await.unwrap();
                    // Keep the response incomplete: returning must depend on headers,
                    // not a complete body, TLS close_notify or the peer's EOF.
                    assert!(matches!(origin.read(&mut [0]).await, Ok(0) | Err(_)));
                };
                tokio::join!(client, server);
                report.success = true;
                let value = redacted(&report);
                assert_eq!(value["steps"][4]["outcome"], "passed");
                assert_eq!(value["steps"][4]["status"], 200);
                assert!(
                    value["unchecked"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|value| value == "response_body")
                );
            })
            .await;
        }
    }

    #[tokio::test]
    async fn outer_ca_and_name_validation_cannot_authorize_the_target() {
        let shared = identity(&["127.0.0.1", "example.com"]);
        let target = identity(&["example.com"]);
        let wrong_name = identity(&["wrong.invalid"]);
        // First fail before sending credentials; then reject an origin signed by
        // the trusted proxy identity; finally reject a trusted origin's wrong SAN.
        for case in 0..3 {
            bounded(async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let profile = profile(Protocol::Https, listener.local_addr().unwrap().port());
                let outer = if case == 0 { &wrong_name } else { &shared };
                let inner = if case == 1 { &shared } else { &wrong_name };
                let mut report = ConnectionReport::new(Protocol::Https);
                let mut stage = Stage::ProxyTcp;
                let client = async {
                    let result = execute_connection(
                        &profile,
                        profile.server_name().unwrap(),
                        PASSWORD,
                        Trust {
                            proxy: outer.client.clone(),
                            target: if case == 2 {
                                wrong_name.client.clone()
                            } else {
                                target.client.clone()
                            },
                        },
                        &mut report,
                        &mut stage,
                    )
                    .await;
                    assert_eq!(result, Err((ConnectionCode::TlsFailed, None)));
                };
                let server = async {
                    let (stream, _) = listener.accept().await.unwrap();
                    let outer = TlsAcceptor::from(outer.server.clone()).accept(stream).await;
                    if case == 0 {
                        assert!(outer.is_err());
                        return;
                    }
                    let mut outer = outer.unwrap();
                    proxy_accept(&mut outer, Protocol::Https).await;
                    assert!(
                        TlsAcceptor::from(inner.server.clone())
                            .accept(outer)
                            .await
                            .is_err()
                    );
                };
                tokio::join!(client, server);
                assert!(matches!(
                    (case, stage),
                    (0, Stage::ProxyTls) | (1 | 2, Stage::TargetTls)
                ));
                report.fail(stage, ConnectionCode::TlsFailed, None);
                redacted(&report);
            })
            .await;
        }
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
                proxy_accept(&mut outer, Protocol::Https).await;
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

    #[tokio::test]
    async fn target_redirect_is_reported_without_following_or_waiting_for_body() {
        bounded(async {
        let (client, mut peer) = tokio::io::duplex(4096);
        let client = async {
            assert_eq!(target_response(Box::new(client)).await, Err((ConnectionCode::RedirectNotFollowed, Some(302))));
        };
        let server = async {
            let request = head(&mut peer).await.unwrap();
            assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
            peer.write_all(b"HTTP/1.1 302 Found\r\nLocation: https://forbidden.invalid/\r\nContent-Length: 1000\r\n\r\nremote-body-canary").await.unwrap();
            assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        };
        tokio::join!(client, server);
    }).await;
    }

    #[tokio::test]
    async fn timeout_and_explicit_cancellation_drop_the_single_owned_http_driver() {
        for cancel in [false, true] {
            bounded(async {
                let (client, mut peer): (DuplexStream, DuplexStream) = tokio::io::duplex(4096);
                let (accepted, observed) = oneshot::channel();
                let client = async {
                    let exchange = http_tunnel(Box::new(client), USER, PASSWORD);
                    tokio::pin!(exchange);
                    tokio::select! {
                        result = observed => result.unwrap(),
                        _ = &mut exchange => panic!("stalled proxy unexpectedly answered"),
                    }
                    if !cancel {
                        assert!(
                            tokio::time::timeout(Duration::from_millis(50), &mut exchange)
                                .await
                                .is_err()
                        );
                    }
                    // Explicit cancellation drops the still-pending future here;
                    // timeout above must drop the same driver and socket as well.
                };
                let server = async {
                    connect_request(&head(&mut peer).await.unwrap());
                    accepted.send(()).unwrap();
                    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
                };
                tokio::join!(client, server);
            })
            .await;
        }
    }
}
