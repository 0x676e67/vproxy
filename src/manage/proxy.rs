//! Startup configuration and lifecycle for real managed proxy listeners.
//!
//! Only authentication policies are hot. Listener sockets, workers, TLS files,
//! and outbound routing settings are immutable until restart. In particular,
//! this path never changes sysctls or routes: operators must prepare CIDR routing
//! before launch. The legacy `run` command retains its existing behavior.

mod endpoints;
mod lifecycle;
pub(super) mod service;
pub(super) mod settings;
pub(super) use endpoints::{
    EndpointCatalog, ListenerView, SettingsCatalog, endpoint_id, public_address,
};
pub(super) use lifecycle::{DrainActor, DrainIntent, Error, Lifecycle, Phase, View};

use std::{
    fmt,
    fs::OpenOptions,
    io::{self, Read},
    net::SocketAddr,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock, mpsc},
    time::Duration,
};

use cidr::IpCidr;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::{sync::oneshot, task::JoinSet};
use zeroize::Zeroizing;

use crate::{
    access::Reader,
    connect::{Connector, Fallback},
    server::{BoundServer, Completion, Context, Handle, Runtime, ServerKind, Source},
};

const MAX_CONFIG_BYTES: usize = 16 * 1024;
const MAX_LISTENERS: usize = 16;
const MAX_WORKERS: usize = 256;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(6);

#[cfg(not(test))]
type Readiness = ();
// Test listeners bind port zero atomically, then report the actual addresses
// through the existing single readiness response. Production keeps unit data.
#[cfg(test)]
type Readiness = Vec<SocketAddr>;

/// Fully checked startup inputs. It deliberately contains no legacy password or
/// administrator session: every listener uses the supplied managed reader.
pub(super) struct Prepared {
    listeners: Vec<PreparedListener>,
    endpoints: Vec<ListenerView>,
    certificates: Certificates,
    workers: NonZeroUsize,
    concurrent: u32,
    connect_timeout: u64,
    connector: Connector,
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    interface_fallback: bool,
}

/// Keep the non-secret protocol label with its constructor, rather than infer
/// it from a second inventory or format TLS paths when construction fails.
struct PreparedListener {
    protocol: Protocol,
    bind: SocketAddr,
    kind: ServerKind,
}

/// Cold observations of actual loaded proxy identities. Configuration fixes the
/// endpoint identities, while a single publication requires every bind to have
/// succeeded. A clone does not own keys, open paths or follow later PEM edits.
#[derive(Clone)]
pub(super) struct Certificates(Arc<CertificateState>);

struct CertificateState {
    configured: Vec<(Protocol, SocketAddr)>,
    loaded: OnceLock<Vec<super::certificates::State>>,
    managed_tls: Option<settings::Tls>,
}

impl Default for Certificates {
    /// An absent proxy configuration is a known empty inventory, not an
    /// unprepared configured group. It needs no runtime readiness publication.
    fn default() -> Self {
        Self(Arc::new(CertificateState {
            configured: Vec::new(),
            loaded: OnceLock::from(Vec::new()),
            managed_tls: None,
        }))
    }
}

impl Certificates {
    fn configured(listeners: &[ListenerView]) -> Self {
        Self(Arc::new(CertificateState {
            configured: listeners
                .iter()
                .map(|listener| (listener.protocol, listener.bind))
                .collect(),
            loaded: OnceLock::new(),
            managed_tls: None,
        }))
    }

    fn managed(listeners: &[ListenerView], tls: settings::Tls) -> Self {
        Self(Arc::new(CertificateState {
            configured: listeners
                .iter()
                .map(|listener| (listener.protocol, listener.bind))
                .collect(),
            loaded: OnceLock::new(),
            managed_tls: Some(tls),
        }))
    }

    /// Coverage is a startup fact, independent of readiness or date validity.
    pub(super) fn has_tls(&self) -> bool {
        self.0.configured.iter().any(|(protocol, _)| {
            matches!(
                protocol,
                Protocol::Https | Protocol::Masque | Protocol::Auto
            )
        })
    }

    /// Return public metadata only after the whole configured group loaded.
    /// A partial/failed bind remains unavailable, never a successful empty or
    /// half-populated inventory. Plaintext entries explicitly have no identity.
    pub(super) fn snapshot(
        &self,
        node_id: &str,
    ) -> io::Result<Vec<super::certificates::ProxyIdentity>> {
        if !super::store::valid_id(node_id) {
            return Err(invalid("invalid certificate inventory node"));
        }
        let loaded =
            self.0.loaded.get().ok_or_else(|| {
                io::Error::other("managed proxy certificate inventory is not ready")
            })?;
        if loaded.len() != self.0.configured.len() || loaded.len() > MAX_LISTENERS {
            return Err(io::Error::other(
                "managed proxy certificate inventory is unavailable",
            ));
        }
        Ok(self
            .0
            .configured
            .iter()
            .zip(loaded)
            .map(
                |(&(protocol, bind), state)| super::certificates::ProxyIdentity {
                    id: endpoint_id(node_id, protocol, bind),
                    protocol,
                    state: match (&self.0.managed_tls, protocol) {
                        (Some(tls), Protocol::Https | Protocol::Masque | Protocol::Auto) => {
                            tls.certificate()
                        }
                        _ => state.clone(),
                    },
                    source: self
                        .0
                        .managed_tls
                        .as_ref()
                        .filter(|_| {
                            matches!(
                                protocol,
                                Protocol::Https | Protocol::Masque | Protocol::Auto
                            )
                        })
                        .map_or(super::certificates::Source::Manual, settings::Tls::source),
                },
            )
            .collect())
    }
}

/// One cold-path failure shared by readiness and the supervisor result. The
/// original I/O error remains available through `source`; ordinary formatting
/// deliberately excludes its arbitrary message, which may contain TLS paths.
struct StartupError {
    protocol: Protocol,
    bind: SocketAddr,
    source: io::Error,
    // Observe real ephemeral bindings before bind() drops them on failure.
    // Fixtures can then verify release without closing a TCP port probe first.
    #[cfg(test)]
    prepared_addresses: io::Result<Vec<SocketAddr>>,
}

impl StartupError {
    /// Both envelopes keep the original kind and share one cause. Wrapping a
    /// custom error makes the outer `raw_os_error()` absent; the native code
    /// remains on the original I/O cause and in this safe diagnostic summary.
    fn into_io(self: Arc<Self>) -> io::Error {
        io::Error::new(self.source.kind(), self)
    }
}

impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "managed proxy listener preparation failed (protocol={:?}, bind={}, kind={:?}, os_error={:?})",
            self.protocol,
            self.bind,
            self.source.kind(),
            self.source.raw_os_error()
        )
    }
}

impl fmt::Debug for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartupError")
            .field("protocol", &self.protocol)
            .field("bind", &self.bind)
            .field("kind", &self.source.kind())
            .field("os_error", &self.source.raw_os_error())
            .finish()
    }
}

impl std::error::Error for StartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl Prepared {
    /// Retain this handle before consuming startup inputs. It becomes ready
    /// only from the actual all-listener bind, not this loader's prechecks.
    pub(super) fn certificate_handle(&self) -> Certificates {
        self.certificates.clone()
    }

    /// Non-secret configured endpoints, not proof of successful socket binding.
    /// Public addresses are explicit operator claims, never inferred from bind.
    pub(super) fn endpoints(&self) -> &[ListenerView] {
        &self.endpoints
    }

    /// Reuse exactly the startup-owned backend for every managed connector.
    /// This does not alter the immutable listener or routing configuration.
    pub(super) fn with_profile_config(mut self, config: crate::ebpf::Config) -> Self {
        self.connector = self.connector.with_profile_config(config);
        self
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub(super) fn privileged_bind(&self) -> bool {
        self.listeners
            .iter()
            .any(|listener| listener.bind.port() < 1024)
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub(super) fn interface_fallback(&self) -> bool {
        self.interface_fallback
    }

    /// Health observations share the data plane's socket settings, but always
    /// attach an explicit source so startup CIDR/fallback cannot change it.
    pub(super) fn connector(&self) -> Connector {
        self.connector.clone()
    }
}

/// Owns a separate Pingora no-steal runtime and its single supervisor result.
/// Keep this object outside the management runtime's `block_on`; async code only
/// borrows it. Always call [`Self::finish`] after that runtime returns, including
/// startup errors, to join workers without blocking a management executor.
pub(super) struct Running {
    runtime: Option<Runtime>,
    handle: Handle,
    lifecycle: Lifecycle,
    ready: Option<oneshot::Receiver<io::Result<Readiness>>>,
    #[cfg(test)]
    addresses: Vec<SocketAddr>,
    completion: Completion,
    author: Option<Arc<super::store::Guard>>,
}

/// The service result and runtime teardown are separate facts. A listener can
/// fail while every worker still stops successfully; final accounting needs
/// the latter fact without hiding the error returned to the caller.
pub(super) struct ShutdownResult {
    pub(super) result: io::Result<()>,
    /// False when runtime ownership or bounded worker cleanup was not confirmed.
    pub(super) runtime_stopped: bool,
}

impl ShutdownResult {
    fn new(result: io::Result<()>, cleanup: io::Result<()>) -> Self {
        Self {
            runtime_stopped: cleanup.is_ok(),
            result: cleanup.and(result),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    listeners: Vec<Listener>,
    workers: Option<usize>,
    #[serde(default = "default_concurrent")]
    concurrent: u32,
    #[serde(default = "default_connect_timeout")]
    connect_timeout: u64,
    cidr: Option<String>,
    cidr_range: Option<u8>,
    fallback: Option<String>,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[serde(default = "default_tcp_user_timeout")]
    tcp_user_timeout: Option<u64>,
    #[serde(default = "default_reuseaddr")]
    reuseaddr: Option<bool>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Listener {
    protocol: Protocol,
    bind: SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_cert: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_key: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Protocol {
    Http,
    Https,
    Socks5,
    Masque,
    Auto,
}

const fn default_concurrent() -> u32 {
    1024
}
const fn default_connect_timeout() -> u64 {
    10
}
const fn default_reuseaddr() -> Option<bool> {
    Some(true)
}
#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
const fn default_tcp_user_timeout() -> Option<u64> {
    Some(30)
}

/// Read at most 16 KiB of startup JSON from a regular file and validate every
/// listener before creating a forwarding runtime. Unknown fields, empty or more
/// than 16 listeners, unsupported protocol names, zero limits, workers above
/// 256, and incomplete/unexpected TLS settings fail closed.
///
/// Relative certificate paths are relative to this configuration file, not the
/// process working directory. Encrypted listeners require explicit matching
/// certificate/key files; they never generate a self-signed identity. The files
/// and their ancestors must remain trusted and stable through startup because
/// protocol constructors read them again when binding. This validation does not
/// establish a peer trust root, verify certificate SANs, or install system routes.
pub(super) fn load(path: &Path) -> io::Result<Prepared> {
    let (path, bytes) = read_configuration(path)?;
    prepare_bytes(&path, &bytes)
}

/// Validate and hash the exact same bounded startup JSON bytes for an offline
/// launch plan. This creates no runtime/listener and does not pin the contents
/// of referenced TLS files: they receive the ordinary load-time validation.
/// Relative TLS paths retain the supplied configuration location as their base.
pub(super) fn checked_digest(path: &Path) -> io::Result<String> {
    let (path, bytes) = read_configuration(path)?;
    checked_bytes(&path, &bytes)
}

/// One actual bounded read, already checked by the same signer constructor used
/// for the prepared listener. Secret buffers zeroize on failure or consumption.
pub(super) struct SnapshotInput {
    pub(super) name: String,
    pub(super) bytes: Zeroizing<Vec<u8>>,
}

/// Portable JSON, exact static files, and their prepared runtime objects. An
/// archive discards Prepared; a startup admission can retain it without another
/// read. Neither branch binds sockets or starts forwarding during capture.
pub(super) struct CapturedConfiguration {
    pub(super) bytes: Vec<u8>,
    pub(super) inputs: Vec<SnapshotInput>,
    pub(super) prepared: Prepared,
}

/// Capture one typed JSON buffer and rewrite only its TLS references. Validation
/// uses that same buffer, not a second read of the source JSON. No listener is
/// bound, and relative source paths remain relative to the original JSON parent.
pub(super) fn snapshot_configuration(path: &Path) -> io::Result<CapturedConfiguration> {
    let (path, bytes) = read_configuration(path)?;
    let mut configuration: Configuration = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("invalid managed proxy snapshot configuration"))?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("proxy snapshot configuration requires a parent"))?;
    let mut inputs = Vec::new();
    let prepared = prepare_with(&configuration, parent, |index, certificate, key| {
        let certificate = super::files::read(certificate, 256 * 1024, false)?;
        let key = super::files::read(key, 64 * 1024, true)?;
        let identity = super::tls::captured_proxy_identity(&certificate, &key)?;
        inputs.push(SnapshotInput {
            name: format!("proxy-{index:02}-cert.pem"),
            bytes: certificate,
        });
        inputs.push(SnapshotInput {
            name: format!("proxy-{index:02}-key.pem"),
            bytes: key,
        });
        Ok(identity)
    })?;
    for (index, listener) in configuration.listeners.iter_mut().enumerate() {
        for (field, suffix) in [
            (&mut listener.tls_cert, "cert.pem"),
            (&mut listener.tls_key, "key.pem"),
        ] {
            if let Some(source) = field {
                let name = format!("proxy-{index:02}-{suffix}");
                *source = PathBuf::from(name);
            }
        }
    }
    let bytes = serde_json::to_vec_pretty(&configuration)
        .map_err(|_| invalid("cannot encode managed proxy snapshot configuration"))?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(invalid(
            "managed proxy snapshot configuration exceeds 16 KiB",
        ));
    }
    Ok(CapturedConfiguration {
        bytes,
        inputs,
        prepared,
    })
}

/// Reuse the normal pure startup validator, additionally requiring each archive
/// TLS reference to be its generated single component. No external path is
/// allowed to escape a package during subsequent verification or recovery.
pub(super) fn check_snapshot_configuration(path: &Path) -> io::Result<Vec<String>> {
    let (path, bytes) = read_configuration(path)?;
    let configuration: Configuration = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("invalid managed proxy snapshot configuration"))?;
    let mut names = Vec::new();
    for (index, listener) in configuration.listeners.iter().enumerate() {
        for (field, suffix) in [
            (&listener.tls_cert, "cert.pem"),
            (&listener.tls_key, "key.pem"),
        ] {
            if let Some(reference) = field {
                let name = format!("proxy-{index:02}-{suffix}");
                if reference.to_str() != Some(name.as_str()) {
                    return Err(invalid("proxy snapshot TLS reference is not portable"));
                }
                names.push(name);
            }
        }
    }
    prepare_bytes(&path, &bytes)?;
    Ok(names)
}

/// Validate one bounded snapshot at its final location before it is written.
/// The ordinary loader and offline generator share the same configuration rules;
/// this does not bind sockets, pin TLS files or alter forwarding state.
fn checked_bytes(path: &Path, bytes: &[u8]) -> io::Result<String> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(invalid("proxy configuration exceeds 16 KiB"));
    }
    drop(prepare_bytes(path, bytes)?);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        digest.push(char::from(HEX[usize::from(byte >> 4)]));
        digest.push(char::from(HEX[usize::from(byte & 15)]));
    }
    Ok(digest)
}

/// Explicit choices for an offline startup file. Missing listeners select the
/// bounded terminal guide; supplying listeners never falls back to prompting.
#[derive(clap::Args, Default)]
pub struct SetupOptions {
    /// Repeat for each listener: http, https, socks5, masque or auto
    #[arg(long, value_name = "PROTOCOL=IP:PORT")]
    listen: Vec<String>,
    /// Existing certificate for all encrypted listeners; relative to current directory
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// Existing private key; referenced by absolute path, never copied
    #[arg(long)]
    tls_key: Option<PathBuf>,
    #[arg(long)]
    workers: Option<usize>,
    /// Per-listener limit; defaults to the managed-proxy configuration default
    #[arg(long)]
    concurrent: Option<u32>,
    /// Target connection timeout in seconds
    #[arg(long)]
    connect_timeout: Option<u64>,
    #[arg(long)]
    cidr: Option<String>,
    #[arg(long)]
    cidr_range: Option<u8>,
    #[arg(long)]
    fallback: Option<String>,
    #[arg(long, action = clap::ArgAction::Set)]
    reuseaddr: Option<bool>,
    /// TCP user timeout in seconds, using the existing managed-proxy semantics
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[arg(long)]
    tcp_user_timeout: Option<u64>,
}

/// This is a configuration file, not an identity package or a running listener.
#[derive(Serialize)]
pub(super) struct SetupReport {
    state: &'static str,
    directory: PathBuf,
    configuration_file: PathBuf,
    configuration_sha256: String,
    server_started: bool,
}

impl SetupOptions {
    /// Convert only syntax here; `checked_bytes` remains the authority for all
    /// limits, CIDR, socket settings and TLS checks before any output is created.
    fn bytes(&self) -> io::Result<Vec<u8>> {
        let mut listeners = Vec::with_capacity(self.listen.len().min(MAX_LISTENERS));
        if self.listen.len() > MAX_LISTENERS {
            return Err(invalid("managed proxy requires between 1 and 16 listeners"));
        }
        for value in &self.listen {
            let (protocol, bind) = value.split_once('=').ok_or_else(|| {
                invalid("listener must use PROTOCOL=IP:PORT, with brackets around IPv6")
            })?;
            let protocol: Protocol =
                serde_json::from_value(serde_json::Value::String(protocol.to_owned())).map_err(
                    |_| invalid("listener protocol must be http, https, socks5, masque or auto"),
                )?;
            let bind = bind
                .parse()
                .map_err(|_| invalid("listener requires an IP address and port"))?;
            let encrypted = matches!(
                protocol,
                Protocol::Https | Protocol::Masque | Protocol::Auto
            );
            listeners.push(Listener {
                protocol,
                bind,
                public_address: None,
                tls_cert: if encrypted {
                    absolute_reference(self.tls_cert.as_deref())?
                } else {
                    None
                },
                tls_key: if encrypted {
                    absolute_reference(self.tls_key.as_deref())?
                } else {
                    None
                },
            });
        }
        if !listeners.iter().any(|listener| {
            matches!(
                listener.protocol,
                Protocol::Https | Protocol::Masque | Protocol::Auto
            )
        }) && (self.tls_cert.is_some() || self.tls_key.is_some())
        {
            return Err(invalid("TLS options require an encrypted proxy listener"));
        }
        let configuration = Configuration {
            listeners,
            workers: self.workers,
            concurrent: self.concurrent.unwrap_or_else(default_concurrent),
            connect_timeout: self.connect_timeout.unwrap_or_else(default_connect_timeout),
            cidr: self.cidr.clone(),
            cidr_range: self.cidr_range,
            fallback: self.fallback.clone(),
            reuseaddr: self.reuseaddr.or_else(default_reuseaddr),
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            tcp_user_timeout: self.tcp_user_timeout.or_else(default_tcp_user_timeout),
        };
        let mut bytes = serde_json::to_vec_pretty(&configuration)
            .map_err(|_| invalid("cannot encode proxy configuration"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// One reader owns the entire guide, including Windows console buffering.
    /// Confirmation follows validation and defaults to no; no files exist yet.
    fn prompt(
        &mut self,
        reader: &mut dyn Read,
        output: &mut dyn io::Write,
        path: &Path,
    ) -> io::Result<(Vec<u8>, String)> {
        use super::input::visible_line;
        writeln!(
            output,
            "Create offline proxy configuration; no server will start."
        )?;
        writeln!(
            output,
            "Protocols: http, https, socks5, masque, auto. Use [IPv6]:PORT for IPv6."
        )?;
        self.listen.push(visible_line(
            reader,
            output,
            "First listener [http=127.0.0.1:8080]: ",
            128,
            "http=127.0.0.1:8080",
        )?);
        while self.listen.len() < MAX_LISTENERS {
            let listener = visible_line(
                reader,
                output,
                "Additional listener [empty to finish]: ",
                128,
                "",
            )?;
            if listener.is_empty() {
                break;
            }
            self.listen.push(listener);
        }
        let encrypted = self.listen.iter().any(|value| {
            matches!(
                value.split_once('='),
                Some(("https" | "masque" | "auto", _))
            )
        });
        if encrypted {
            if self.tls_cert.is_none() {
                self.tls_cert =
                    Some(visible_line(reader, output, "Certificate path: ", 4096, "")?.into());
            }
            if self.tls_key.is_none() {
                self.tls_key =
                    Some(visible_line(reader, output, "Private key path: ", 4096, "")?.into());
            }
        }
        let bytes = self.bytes()?;
        let digest = checked_bytes(path, &bytes)?;
        writeln!(output, "Configuration file: {path:?}")?;
        output.write_all(&bytes)?;
        let confirmation =
            visible_line(reader, output, "Write this configuration? [y/N]: ", 3, "n")?;
        if !confirmation.eq_ignore_ascii_case("y") && !confirmation.eq_ignore_ascii_case("yes") {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "proxy configuration cancelled; no files were created",
            ));
        }
        Ok((bytes, digest))
    }
}

/// Resolve CLI references against cwd, not the new output directory. The
/// existing JSON loader still resolves hand-written relative paths as before.
fn absolute_reference(path: Option<&Path>) -> io::Result<Option<PathBuf>> {
    path.map(|path| {
        if path.as_os_str().is_empty() {
            return Err(invalid("TLS path must not be empty"));
        }
        let path = std::path::absolute(path)?;
        super::setup::path_string(&path)?;
        Ok(path)
    })
    .transpose()
}

/// Validate the exact bounded bytes before exclusively claiming a new private
/// directory. A failed write leaves its partial output for explicit inspection;
/// neither retries nor rollback can overwrite an existing configuration.
pub(super) fn setup(output: &Path, mut options: SetupOptions) -> io::Result<SetupReport> {
    let output = super::files::output_path(output)?;
    let path = output.join("proxy.json");
    let (bytes, digest) = if options.listen.is_empty() {
        super::input::with_visible_input(|reader, terminal| {
            options.prompt(reader, terminal, &path)
        })?
    } else {
        let bytes = options.bytes()?;
        let digest = checked_bytes(&path, &bytes)?;
        (bytes, digest)
    };
    super::files::create_directory(&output)?;
    super::files::write(&output, "proxy.json", &bytes)?;
    Ok(SetupReport {
        state: "offline_proxy_config_written",
        directory: output,
        configuration_file: path,
        configuration_sha256: digest,
        server_started: false,
    })
}

/// Share the original no-follow, regular-file and size checks. Hashing one
/// read followed by validation of another could approve different JSON bytes.
/// Keep the absolute input location, not a canonicalized symlink destination,
/// because existing relative TLS references belong to its original parent.
fn read_configuration(path: &Path) -> io::Result<(PathBuf, Vec<u8>)> {
    let path = std::path::absolute(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES as u64 {
        return Err(invalid(
            "proxy configuration must be a regular file no larger than 16 KiB",
        ));
    }
    let mut bytes = Vec::with_capacity(MAX_CONFIG_BYTES + 1);
    file.take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(invalid("proxy configuration exceeds 16 KiB"));
    }
    Ok((path, bytes))
}

fn prepare_bytes(path: &Path, bytes: &[u8]) -> io::Result<Prepared> {
    let config: Configuration = serde_json::from_slice(bytes)
        .map_err(|_| invalid("invalid managed proxy configuration JSON"))?;
    let base = path
        .parent()
        .ok_or_else(|| invalid("proxy configuration has no parent directory"))?;
    prepare_with(&config, base, |_, certificate, key| {
        super::tls::proxy_identity(certificate, key)
    })
}

fn prepare_with(
    config: &Configuration,
    base: &Path,
    mut identity: impl FnMut(usize, &Path, &Path) -> io::Result<crate::server::tls::Identity>,
) -> io::Result<Prepared> {
    prepare_resolved(config, |index, listener| {
        let (Some(certificate), Some(key)) = (&listener.tls_cert, &listener.tls_key) else {
            return Err(invalid(
                "encrypted proxy listeners require both tls_cert and tls_key",
            ));
        };
        identity(index, &base.join(certificate), &base.join(key))
    })
}

/// Common cold limits, connector and protocol selection. The owning loader
/// supplies either a once-loaded file identity or the managed normal resolver;
/// no placeholder paths or protocol-specific duplicate constructors are used.
fn prepare_resolved(
    config: &Configuration,
    mut identity: impl FnMut(usize, &Listener) -> io::Result<crate::server::tls::Identity>,
) -> io::Result<Prepared> {
    if config.listeners.is_empty() || config.listeners.len() > MAX_LISTENERS {
        return Err(invalid("managed proxy requires between 1 and 16 listeners"));
    }
    let workers = config
        .workers
        .map_or_else(std::thread::available_parallelism, |count| {
            NonZeroUsize::new(count).ok_or_else(|| invalid("proxy workers must be non-zero"))
        })?;
    if workers.get() > MAX_WORKERS {
        return Err(invalid("managed proxy supports at most 256 workers"));
    }
    crate::server::validate_concurrent(config.concurrent)?;
    if config.connect_timeout == 0
        || std::time::Instant::now()
            .checked_add(Duration::from_secs(config.connect_timeout))
            .is_none()
    {
        return Err(invalid(
            "proxy connect_timeout must be a representable positive duration",
        ));
    }
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if config.tcp_user_timeout.is_some_and(|seconds| {
        seconds
            .checked_mul(1000)
            .and_then(|millis| u32::try_from(millis).ok())
            .is_none()
    }) {
        return Err(invalid(
            "proxy tcp_user_timeout must fit unsigned 32-bit milliseconds",
        ));
    }
    let cidr = config
        .cidr
        .as_deref()
        .map(|value| value.parse::<IpCidr>())
        .transpose()
        .map_err(|_| invalid("invalid proxy CIDR"))?;
    if let Some(range) = config.cidr_range {
        let bits = match cidr {
            Some(IpCidr::V4(_)) => 32,
            Some(IpCidr::V6(_)) => 128,
            None => return Err(invalid("proxy cidr_range requires a CIDR")),
        };
        if range > bits {
            return Err(invalid("proxy cidr_range exceeds the address family width"));
        }
    }
    let fallback = config
        .fallback
        .as_deref()
        .map(|value| {
            if value.is_empty() {
                return Err(invalid("proxy fallback cannot be empty"));
            }
            value.parse::<Fallback>()
        })
        .transpose()?;
    let mut listeners = Vec::with_capacity(config.listeners.len());
    let mut endpoints = Vec::with_capacity(config.listeners.len());
    for (index, listener) in config.listeners.iter().enumerate() {
        if listener.bind.port() == 0 {
            return Err(invalid(
                "managed proxy bind requires an explicit non-zero port",
            ));
        }
        let public_address = listener
            .public_address
            .as_deref()
            .map(endpoints::public_address)
            .transpose()?;
        endpoints.push(ListenerView {
            protocol: listener.protocol,
            bind: listener.bind,
            public_address,
        });
        let encrypted = matches!(
            listener.protocol,
            Protocol::Https | Protocol::Masque | Protocol::Auto
        );
        let kind = if encrypted {
            // Retain this exact once-loaded signer. Bind must not reopen a PEM
            // path after configuration/future Source admission has checked it.
            // Each protocol still supplies its own TLS versions and ALPN.
            let tls = crate::server::tls::Source::Identity(identity(index, listener)?);
            match listener.protocol {
                Protocol::Https => ServerKind::Https { tls },
                Protocol::Masque => ServerKind::Masque { tls },
                Protocol::Auto => ServerKind::Auto { tls },
                Protocol::Http | Protocol::Socks5 => {
                    return Err(invalid("invalid encrypted proxy protocol"));
                }
            }
        } else {
            if listener.tls_cert.is_some() || listener.tls_key.is_some() {
                return Err(invalid("plaintext proxy listeners do not accept TLS files"));
            }
            match listener.protocol {
                Protocol::Http => ServerKind::Http,
                Protocol::Socks5 => ServerKind::Socks5,
                Protocol::Https | Protocol::Masque | Protocol::Auto => {
                    return Err(invalid("missing encrypted proxy protocol"));
                }
            }
        };
        listeners.push(PreparedListener {
            protocol: listener.protocol,
            bind: listener.bind,
            kind,
        });
    }
    Ok(Prepared {
        listeners,
        certificates: Certificates::configured(&endpoints),
        endpoints,
        workers,
        concurrent: config.concurrent,
        connect_timeout: config.connect_timeout,
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        interface_fallback: matches!(fallback.as_ref(), Some(Fallback::Interface(_))),
        connector: Connector::new(
            cidr,
            config.cidr_range,
            fallback,
            config.connect_timeout,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            config.tcp_user_timeout,
            config.reuseaddr,
        ),
    })
}

/// Start actual listeners on their own forwarding runtime, without logging or
/// signal installation. Await readiness before advertising a running proxy.
/// A binding/construction failure drops every previously created listener.
pub(super) fn start(
    prepared: Prepared,
    access: Reader,
    author: Arc<super::store::Guard>,
) -> io::Result<Running> {
    let identity = Lifecycle::prepare()?;
    let runtime = Runtime::new(prepared.workers);
    let handle = runtime.handle()?;
    let lifecycle = identity.attach(handle.clone());
    let (ready, readiness) = oneshot::channel();
    let task_handle = handle.clone();
    let task_author = Arc::clone(&author);
    let completion = runtime.spawn(async move {
        // Cancellation/drop cannot release the sole-author lease while the
        // forwarding supervisor is still able to accept authenticated work.
        let _author = task_author;
        let servers = bind(prepared, access);
        let servers = match servers {
            Ok(servers) => servers,
            Err(error) => {
                let error = Arc::new(error);
                let _ = ready.send(Err(Arc::clone(&error).into_io()));
                return Err(error.into_io().into());
            }
        };
        #[cfg(test)]
        let addresses = servers
            .iter()
            .map(BoundServer::local_addr)
            .collect::<io::Result<Vec<_>>>()?;
        #[cfg(test)]
        let readiness = ready.send(Ok(addresses));
        #[cfg(not(test))]
        let readiness = ready.send(Ok(()));
        if readiness.is_err() {
            task_handle.request_graceful_shutdown();
            return Ok(());
        }
        serve(servers, task_handle).await.map_err(Into::into)
    })?;
    Ok(Running {
        runtime: Some(runtime),
        handle,
        lifecycle,
        ready: Some(readiness),
        #[cfg(test)]
        addresses: Vec::new(),
        completion,
        author: Some(author),
    })
}

fn bind(prepared: Prepared, access: Reader) -> Result<Vec<BoundServer>, StartupError> {
    let mut servers = Vec::with_capacity(prepared.listeners.len());
    let mut certificates = Vec::with_capacity(prepared.listeners.len());
    for PreparedListener {
        protocol,
        bind,
        kind,
    } in prepared.listeners
    {
        let server = BoundServer::bind(
            Context {
                bind,
                concurrent: prepared.concurrent,
                connect_timeout: prepared.connect_timeout,
                auth: Source::Managed(access.clone()),
                connector: prepared.connector.clone(),
            },
            kind,
        )
        .map_err(|source| StartupError {
            protocol,
            bind,
            source,
            #[cfg(test)]
            prepared_addresses: servers.iter().map(BoundServer::local_addr).collect(),
        })?;
        certificates.push(match protocol {
            Protocol::Http | Protocol::Socks5 => super::certificates::State::Disabled,
            Protocol::Https | Protocol::Masque | Protocol::Auto => server
                .certificate_leaf()
                .map(super::certificates::State::from_leaf)
                .unwrap_or(super::certificates::State::Unavailable),
        });
        servers.push(server);
    }
    // Prepared is consumed once. Publish the complete cold capture before the
    // readiness response; no state from an earlier successful bind is visible
    // if a later listener fails. Diagnostic publication cannot alter TLS.
    let _ = prepared.certificates.0.loaded.set(certificates);
    Ok(servers)
}

async fn serve(servers: Vec<BoundServer>, handle: Handle) -> io::Result<()> {
    let mut listeners = JoinSet::new();
    for server in servers {
        listeners.spawn_on(server.start(handle.clone()), handle.runtime_handle());
    }
    let mut result = tokio::select! {
        biased;
        _ = handle.wait_graceful_shutdown() => Ok(()),
        result = listeners.join_next() => listener_completion(
            result, handle.is_graceful_shutdown_requested()),
    };
    if result.is_err() {
        handle.request_graceful_shutdown();
    }
    let drain = async {
        while let Some(joined) = listeners.join_next().await {
            let error = match joined {
                Ok(Err(error)) => Some(error),
                Err(_) => Some(io::Error::other(
                    "managed proxy listener task failed while draining",
                )),
                Ok(Ok(())) => None,
            };
            if let Some(error) = error {
                handle.request_graceful_shutdown();
                if result.is_ok() {
                    result = Err(error);
                }
            }
        }
    };
    if let Err(error) = handle.wait_for_drain(drain, Duration::from_secs(5)).await {
        listeners.abort_all();
        while listeners.join_next().await.is_some() {}
        return result.and(Err(error));
    }
    result
}

fn listener_completion(
    result: Option<Result<io::Result<()>, tokio::task::JoinError>>,
    shutdown_requested: bool,
) -> io::Result<()> {
    match result {
        // Another worker can request shutdown after select! polls its first
        // branch but before it polls this completion. Biased order alone does
        // not make those observations atomic. Errors must still be preserved.
        Some(Ok(Ok(()))) if shutdown_requested => Ok(()),
        Some(Ok(Err(error))) => Err(error),
        Some(Err(_)) => Err(io::Error::other("managed proxy listener task failed")),
        _ => Err(io::Error::other(
            "managed proxy listener stopped unexpectedly",
        )),
    }
}

impl Running {
    /// Wait until all listener sockets and TLS identities have been prepared.
    /// Canceling this wait retains the receiver for cleanup or another wait.
    /// Preparation failures share their original cause with the unconsumed
    /// supervisor result, while their displayed context excludes source text.
    pub(super) async fn ready(&mut self) -> io::Result<()> {
        let ready = self
            .ready
            .as_mut()
            .ok_or_else(|| invalid("proxy readiness already received"))?;
        let result = ready.await;
        self.ready = None;
        let readiness =
            result.map_err(|_| io::Error::other("managed proxy startup task stopped"))?;
        #[cfg(test)]
        {
            self.addresses = readiness?;
            Ok(())
        }
        #[cfg(not(test))]
        {
            readiness
        }
    }

    /// Wait for normal shutdown or a fatal forwarding listener failure. This
    /// wait is cancellation-safe but a delivered result is consumed only once.
    pub(super) async fn finished(&mut self) -> io::Result<()> {
        self.completion.finished().await.map_err(proxy_error)
    }

    /// The same shutdown state observed by every listener and connection task.
    pub(super) fn handle(&self) -> Handle {
        self.handle.clone()
    }

    /// Control only this already-started listener group, without transferring
    /// its runtime or process-author ownership to API request handlers.
    pub(super) fn lifecycle(&self) -> Lifecycle {
        self.lifecycle.clone()
    }

    /// Stop new admissions and initiate each protocol's existing drain behavior.
    pub(super) fn shutdown(&self) {
        self.handle.request_graceful_shutdown();
    }

    /// Outside every async runtime, request shutdown and wait at most ten seconds
    /// for the task. A one-shot cleanup thread then owns both runtime and author
    /// guard, with six seconds allowed for its five-second Pingora shutdown.
    ///
    /// Pingora joins OS worker threads after sending its timeout; a synchronously
    /// stuck worker can therefore outlive that library timeout. On cleanup
    /// timeout the service result is `TimedOut` and `runtime_stopped` is false.
    /// The cleanup thread retains the author guard until all workers really exit;
    /// a failed process can terminate and let the OS reclaim remaining resources.
    /// The async supervisor's previously consumed result is not returned twice.
    pub(super) fn finish(mut self) -> ShutdownResult {
        self.shutdown();
        let result = self
            .completion
            .wait_timeout(DRAIN_TIMEOUT)
            .map_err(proxy_error);
        let cleanup = match (self.runtime.take(), self.author.take()) {
            (Some(runtime), Some(author)) => cleanup(runtime, author, CLEANUP_TIMEOUT),
            _ => Err(io::Error::other(
                "managed proxy cleanup ownership is missing",
            )),
        };
        // Cleanup failures take precedence: an earlier listener error must not
        // hide the fact that OS workers may still be alive and retain the lock.
        ShutdownResult::new(result, cleanup)
    }
}

fn cleanup(
    runtime: Runtime,
    author: Arc<super::store::Guard>,
    deadline: Duration,
) -> io::Result<()> {
    let (stopped, completion) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("vproxy-proxy-cleanup".into())
        .spawn(move || {
            runtime.shutdown();
            drop(author);
            let _ = stopped.send(());
        })?;
    match completion.recv_timeout(deadline) {
        Ok(()) => {
            // The signal is the cleanup thread's final operation. Detaching the
            // now-finished thread avoids reintroducing an unbounded OS join in
            // the caller after its explicit deadline.
            drop(worker);
            Ok(())
        }
        Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "proxy runtime worker cleanup exceeded its deadline",
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("proxy runtime worker cleanup failed"))
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        // Cancellation must not call a blocking join inside an async executor.
        // The outer synchronous owner must still use finish() on every path.
        self.shutdown();
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn proxy_error(error: crate::error::Error) -> io::Error {
    match error {
        crate::error::Error::IO(error) => error,
        error => io::Error::other(error),
    }
}

#[cfg(test)]
pub(in crate::manage) mod tests {
    use std::{
        fs,
        io::Write as _,
        net::{Ipv4Addr, TcpListener, TcpStream},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::access::PolicyData;

    const CERTIFICATE_NODE: &str = "AAAAAAAAAAAAAAAAAAAAAA";

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "vproxy-managed-proxy-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder.create(&path).expect("create unique proxy fixture");
            Self(path)
        }

        fn configuration(&self, value: &str) -> PathBuf {
            let path = self.0.join("proxy.json");
            fs::write(&path, value).expect("write configuration");
            path
        }

        fn guard(&self) -> Arc<super::super::store::Guard> {
            Arc::new(super::super::store::lock(&self.0).expect("claim fixture author lock"))
        }

        fn identity(&self) -> io::Result<(rcgen::CertifiedKey<rcgen::KeyPair>, PathBuf)> {
            let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .map_err(io::Error::other)?;
            fs::write(self.0.join("certificate.pem"), identity.cert.pem())?;
            let key_path = self.0.join("key.pem");
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            options
                .open(&key_path)?
                .write_all(identity.signing_key.serialize_pem().as_bytes())?;
            Ok((identity, key_path))
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn empty_reader() -> Reader {
        Reader::new(PolicyData {
            revision: 1,
            accepting: true,
            users: Vec::new(),
            credentials: Vec::new(),
            routing: crate::access::routing::RoutingData::default(),
            presets: crate::access::presets::PresetData::default(),
        })
        .expect("valid empty managed policy")
    }

    /// Load the real, nonzero-port configuration before requesting atomic ephemeral
    /// allocation in the fixture. Production validation still rejects port zero.
    pub(in crate::manage) fn ephemeral(mut prepared: Prepared) -> Prepared {
        for listener in &mut prepared.listeners {
            listener.bind.set_port(0);
        }
        prepared
    }

    fn control_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("control runtime")
    }

    fn setup_options(listeners: &[&str]) -> SetupOptions {
        SetupOptions {
            listen: listeners.iter().map(|value| (*value).to_owned()).collect(),
            ..SetupOptions::default()
        }
    }

    #[test]
    fn offline_proxy_configuration_preserves_settings_digest_and_private_exclusive_output()
    -> io::Result<()> {
        let directory = Directory::new();
        let output = directory.0.join("configured");
        let mut options = setup_options(&["http=127.0.0.1:18080", "socks5=[::1]:11080"]);
        options.workers = Some(2);
        options.concurrent = Some(4);
        options.connect_timeout = Some(7);
        options.cidr = Some("192.0.2.0/24".to_owned());
        options.cidr_range = Some(24);
        options.fallback = Some("127.0.0.1".to_owned());
        options.reuseaddr = Some(false);
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        {
            options.tcp_user_timeout = Some(9);
        }
        let report = setup(&output, options)?;
        assert_eq!(report.state, "offline_proxy_config_written");
        assert!(!report.server_started);
        assert_eq!(
            report.configuration_file,
            report.directory.join("proxy.json")
        );
        let bytes = super::super::files::read(&report.configuration_file, MAX_CONFIG_BYTES, true)?;
        assert_eq!(
            report.configuration_sha256,
            checked_bytes(&report.configuration_file, &bytes)?
        );
        assert_eq!(
            report.configuration_sha256,
            checked_digest(&report.configuration_file)?
        );
        let config: Configuration = serde_json::from_slice(&bytes)?;
        assert_eq!(config.workers, Some(2));
        assert_eq!(config.concurrent, 4);
        assert_eq!(config.connect_timeout, 7);
        assert_eq!(config.cidr.as_deref(), Some("192.0.2.0/24"));
        assert_eq!(config.cidr_range, Some(24));
        assert_eq!(config.fallback.as_deref(), Some("127.0.0.1"));
        assert_eq!(config.reuseaddr, Some(false));
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        assert_eq!(config.tcp_user_timeout, Some(9));
        assert_eq!(load(&report.configuration_file)?.endpoints().len(), 2);
        assert_eq!(fs::read_dir(&report.directory)?.count(), 1);
        assert_eq!(
            serde_json::to_value(&report)?
                .as_object()
                .expect("report object")
                .len(),
            5
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&report.directory)?.permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&report.configuration_file)?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert_eq!(
            setup(&output, setup_options(&["http=127.0.0.1:18081"]))
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::AlreadyExists)
        );
        assert_eq!(
            &*bytes,
            &*super::super::files::read(&report.configuration_file, MAX_CONFIG_BYTES, true)?
        );
        assert_eq!(fs::read_dir(&report.directory)?.count(), 1);
        Ok(())
    }

    #[test]
    fn offline_proxy_configuration_uses_all_protocols_without_copying_tls_material()
    -> io::Result<()> {
        let directory = Directory::new();
        let identity = directory.0.join("identity");
        super::super::files::create_directory(&identity)?;
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                .map_err(io::Error::other)?;
        super::super::files::write(&identity, "certificate.pem", cert.pem().as_bytes())?;
        super::super::files::write(&identity, "key.pem", signing_key.serialize_pem().as_bytes())?;
        let certificate = identity.join("certificate.pem");
        let key = identity.join("key.pem");
        let original_key = super::super::files::read(&key, 16384, true)?;
        let mut options = setup_options(&[
            "http=127.0.0.1:18080",
            "https=127.0.0.1:18443",
            "socks5=127.0.0.1:11080",
            "masque=127.0.0.1:18443",
            "auto=[::1]:19443",
        ]);
        options.tls_cert = Some(certificate.clone());
        options.tls_key = Some(key.clone());
        let report = setup(&directory.0.join("all-protocols"), options)?;
        let bytes = super::super::files::read(&report.configuration_file, MAX_CONFIG_BYTES, true)?;
        let mut config: Configuration = serde_json::from_slice(&bytes)?;
        let expected = [
            Protocol::Http,
            Protocol::Https,
            Protocol::Socks5,
            Protocol::Masque,
            Protocol::Auto,
        ];
        for (listener, protocol) in config.listeners.iter_mut().zip(expected) {
            assert_eq!(listener.protocol, protocol);
            assert!(listener.public_address.is_none());
            if matches!(
                protocol,
                Protocol::Https | Protocol::Masque | Protocol::Auto
            ) {
                assert_eq!(listener.tls_cert.as_deref(), Some(certificate.as_path()));
                assert_eq!(listener.tls_key.as_deref(), Some(key.as_path()));
                // Existing hand-written JSON still resolves relative to its own
                // directory; the CLI's absolute-reference choice does not change it.
                listener.tls_cert = Some(PathBuf::from("../identity/certificate.pem"));
                listener.tls_key = Some(PathBuf::from("../identity/key.pem"));
            } else {
                assert!(listener.tls_cert.is_none() && listener.tls_key.is_none());
            }
        }
        assert_eq!(load(&report.configuration_file)?.endpoints().len(), 5);
        assert!(checked_bytes(&report.configuration_file, &serde_json::to_vec(&config)?).is_ok());
        assert_eq!(
            absolute_reference(Some(Path::new("relative-certificate.pem")))?,
            Some(std::path::absolute("relative-certificate.pem")?)
        );
        assert_eq!(fs::read_dir(&report.directory)?.count(), 1);
        assert_eq!(
            &*original_key,
            &*super::super::files::read(&key, 16384, true)?
        );
        Ok(())
    }

    #[test]
    fn offline_proxy_configuration_rejects_invalid_inputs_before_creating_output() -> io::Result<()>
    {
        let directory = Directory::new();
        let mut cases = Vec::new();
        for listener in [
            "unknown=127.0.0.1:8080",
            "http=localhost:8080",
            "http=127.0.0.1:0",
            "http",
            "https=127.0.0.1:8443",
        ] {
            cases.push(setup_options(&[listener]));
        }
        for workers in [0, MAX_WORKERS + 1] {
            let mut options = setup_options(&["http=127.0.0.1:8080"]);
            options.workers = Some(workers);
            cases.push(options);
        }
        for concurrent in [0, u32::MAX] {
            let mut options = setup_options(&["http=127.0.0.1:8080"]);
            options.concurrent = Some(concurrent);
            cases.push(options);
        }
        let mut options = setup_options(&["http=127.0.0.1:8080"]);
        options.connect_timeout = Some(0);
        cases.push(options);
        let mut options = setup_options(&["http=127.0.0.1:8080"]);
        options.cidr_range = Some(24);
        cases.push(options);
        let mut options = setup_options(&["http=127.0.0.1:8080"]);
        options.cidr = Some("192.0.2.0/24".to_owned());
        options.cidr_range = Some(33);
        cases.push(options);
        let mut options = setup_options(&["http=127.0.0.1:8080"]);
        options.fallback = Some(String::new());
        cases.push(options);
        let mut options = setup_options(&["http=127.0.0.1:8080"]);
        options.tls_key = Some(PathBuf::from("must-not-be-used.pem"));
        cases.push(options);
        cases.push(setup_options(&["socks5=127.0.0.1:1080"; MAX_LISTENERS + 1]));
        let mut options = setup_options(&["http=127.0.0.1:8080"]);
        options.fallback = Some("x".repeat(MAX_CONFIG_BYTES));
        cases.push(options);
        for (index, options) in cases.into_iter().enumerate() {
            let output = directory.0.join(format!("invalid-{index}"));
            assert!(setup(&output, options).is_err());
            assert!(!output.exists());
        }
        assert!(absolute_reference(Some(Path::new("bad\npath.pem"))).is_err());
        assert!(absolute_reference(Some(Path::new(""))).is_err());
        assert_eq!(
            checked_bytes(
                &directory.0.join("proxy.json"),
                &vec![b' '; MAX_CONFIG_BYTES + 1]
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput
        );
        Ok(())
    }

    #[test]
    fn offline_proxy_guide_validates_before_confirmation_and_keeps_no_or_eof_read_only()
    -> io::Result<()> {
        let directory = Directory::new();
        let path = directory.0.join("guided").join("proxy.json");
        for (input, expected) in [
            ("http=127.0.0.1:8080\n\n\n", io::ErrorKind::Interrupted),
            ("http=127.0.0.1:8080\n\n", io::ErrorKind::UnexpectedEof),
            ("http=127.0.0.1:0\n\n", io::ErrorKind::InvalidInput),
        ] {
            let mut output = Vec::new();
            let failure = SetupOptions::default()
                .prompt(&mut input.as_bytes(), &mut output, &path)
                .unwrap_err();
            assert_eq!(failure.kind(), expected);
            if expected == io::ErrorKind::InvalidInput {
                assert!(!String::from_utf8_lossy(&output).contains("Write this configuration?"));
            }
            assert!(!path.parent().expect("new directory").exists());
        }
        let (bytes, digest) =
            SetupOptions::default().prompt(&mut &b"\n\nyes\n"[..], &mut Vec::new(), &path)?;
        assert_eq!(digest, checked_bytes(&path, &bytes)?);
        assert!(!path.parent().expect("new directory").exists());
        Ok(())
    }

    /// The outer I/O envelope has the original kind but no native code of its own.
    /// Inspect its shared cause instead of accidentally asserting a recreated OS error.
    fn startup_failure(error: &io::Error) -> &Arc<StartupError> {
        error
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<Arc<StartupError>>())
            .expect("shared startup failure")
    }

    #[test]
    fn startup_errors_share_native_or_custom_causes_without_formatting_private_messages() {
        const PRIVATE_MESSAGE: &str = "/private/fixture-key-path password=fixture-only";
        let address = "[::1]:8443".parse().expect("fixture address");
        // These raw values test lossless storage, not the host's classification of
        // Windows errors. The real occupied-listener tests verify native behavior.
        for source in [
            io::Error::from_raw_os_error(10013),
            io::Error::from_raw_os_error(10048),
            io::Error::new(io::ErrorKind::InvalidData, PRIVATE_MESSAGE),
        ] {
            let kind = source.kind();
            let code = source.raw_os_error();
            let failure = Arc::new(StartupError {
                protocol: Protocol::Https,
                bind: address,
                source,
                prepared_addresses: Ok(Vec::new()),
            });
            let readiness = Arc::clone(&failure).into_io();
            let completion = Arc::clone(&failure).into_io();
            assert_eq!(readiness.kind(), kind);
            assert_eq!(completion.kind(), kind);
            assert!(readiness.raw_os_error().is_none());
            assert!(completion.raw_os_error().is_none());
            assert!(Arc::ptr_eq(
                startup_failure(&readiness),
                startup_failure(&completion)
            ));
            assert!(Arc::ptr_eq(startup_failure(&readiness), &failure));
            let original = std::error::Error::source(failure.as_ref())
                .and_then(|cause| cause.downcast_ref::<io::Error>())
                .expect("original I/O cause");
            assert!(std::ptr::eq(original, &failure.source));
            assert_eq!(original.kind(), kind);
            assert_eq!(original.raw_os_error(), code);
            for error in [&readiness, &completion] {
                let mut cause = std::error::Error::source(error);
                let mut original_found = false;
                while let Some(current) = cause {
                    if current
                        .downcast_ref::<io::Error>()
                        .is_some_and(|value| std::ptr::eq(value, original))
                    {
                        original_found = true;
                        break;
                    }
                    cause = current.source();
                }
                assert!(
                    original_found,
                    "I/O envelope must expose the original cause"
                );
            }
            for summary in [
                readiness.to_string(),
                format!("{readiness:?}"),
                completion.to_string(),
                format!("{completion:?}"),
            ] {
                assert!(summary.contains("Https"));
                assert!(summary.contains("[::1]:8443"));
                assert!(summary.contains(&format!("{kind:?}")));
                assert!(summary.contains(&format!("{code:?}")));
                assert!(!summary.contains(PRIVATE_MESSAGE));
                assert!(!summary.contains("fixture-key-path"));
                assert!(!summary.contains("fixture-only"));
            }
            if code.is_none() {
                assert_eq!(original.to_string(), PRIVATE_MESSAGE);
            }
        }
    }

    #[tokio::test]
    async fn normal_listener_completion_observes_shutdown_between_select_polls() {
        let handle = Handle::new();
        let mut waiting = std::pin::pin!(handle.wait_graceful_shutdown());
        // Reproduce the order within one select! poll deterministically: its first
        // branch is pending, then another worker stops before the join is observed.
        let pending = std::future::poll_fn(|context| {
            std::task::Poll::Ready(waiting.as_mut().poll(context).is_pending())
        })
        .await;
        assert!(pending);
        handle.request_graceful_shutdown();
        listener_completion(Some(Ok(Ok(()))), handle.is_graceful_shutdown_requested())
            .expect("requested shutdown allows a normal listener completion");
    }

    #[tokio::test]
    async fn listener_completion_rejects_early_stop_and_preserves_shutdown_errors() {
        assert!(listener_completion(Some(Ok(Ok(()))), false).is_err());
        assert!(listener_completion(None, true).is_err());
        for kind in [io::ErrorKind::ConnectionAborted, io::ErrorKind::TimedOut] {
            let error = listener_completion(Some(Ok(Err(io::Error::from(kind)))), true)
                .expect_err("shutdown must not hide the listener error");
            assert_eq!(error.kind(), kind);
        }
        let task = tokio::spawn(std::future::pending::<io::Result<()>>());
        task.abort();
        let error = listener_completion(Some(task.await), true)
            .expect_err("shutdown must not hide a failed listener task");
        assert_eq!(error.to_string(), "managed proxy listener task failed");
    }

    #[test]
    fn configuration_is_bounded_strict_and_cannot_enable_anonymous_or_implicit_tls() {
        let directory = Directory::new();
        for value in [
            r#"{"listeners":[]}"#,
            r#"{"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"}],"workers":0}"#,
            r#"{"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"}],"workers":257}"#,
            r#"{"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"}],"concurrent":0}"#,
            r#"{"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"}],"concurrent":4294967295}"#,
            r#"{"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"}],"connect_timeout":0}"#,
            r#"{"listeners":[{"protocol":"http","bind":"127.0.0.1:0"}]}"#,
            r#"{"listeners":[{"protocol":"unknown","bind":"127.0.0.1:8080"}]}"#,
            r#"{"listeners":[{"protocol":"http","bind":"127.0.0.1:8080","auth":"anonymous"}]}"#,
            r#"{"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"}],"password":"secret"}"#,
            r#"{"listeners":[{"protocol":"https","bind":"127.0.0.1:8080"}]}"#,
            r#"{"listeners":[{"protocol":"masque","bind":"127.0.0.1:8080","tls_cert":"certificate.pem"}]}"#,
            r#"{"listeners":[{"protocol":"auto","bind":"127.0.0.1:8080","tls_key":"key.pem"}]}"#,
            r#"{"listeners":[{"protocol":"socks5","bind":"127.0.0.1:8080","tls_key":"key.pem"}]}"#,
            r#"{"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"}],"cidr_range":64}"#,
            r#"{"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"}],"cidr":"192.0.2.0/24","cidr_range":33}"#,
            r#"{"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"}],"fallback":""}"#,
        ] {
            assert!(
                load(&directory.configuration(value)).is_err(),
                "accepted {value}"
            );
        }
        let too_many = format!(
            r#"{{"listeners":[{}]}}"#,
            std::iter::repeat_n(r#"{"protocol":"http","bind":"127.0.0.1:8080"}"#, 17)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(load(&directory.configuration(&too_many)).is_err());
        assert!(load(&directory.configuration(&" ".repeat(MAX_CONFIG_BYTES + 1))).is_err());
        assert!(load(&directory.0).is_err());
        let prepared = load(&directory.configuration(
            r#"{"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"}],"workers":1}"#,
        ))
        .expect("valid configuration");
        assert_eq!(prepared.concurrent, 1024);
        assert_eq!(prepared.connect_timeout, 10);
        let catalog = prepared.endpoints();
        assert_eq!(catalog.len(), 1);
        assert_eq!(catalog[0].bind.to_string(), "127.0.0.1:8080");
        assert!(catalog[0].public_address.is_none());
    }

    #[test]
    fn public_endpoint_claims_are_optional_normalized_and_do_not_change_listener_bindings() {
        let directory = Directory::new();
        let prepared = load(&directory.configuration(
        r#"{"listeners":[{"protocol":"http","bind":"0.0.0.0:8080","public_address":"PROXY.example:443"},{"protocol":"socks5","bind":"[::]:1080","public_address":"[2001:0DB8:0:0:0:0:0:7]:1081"}],"workers":1}"#,
    ))
    .unwrap();
        assert_eq!(prepared.listeners[0].bind.to_string(), "0.0.0.0:8080");
        assert_eq!(prepared.listeners[1].bind.to_string(), "[::]:1080");
        let json = serde_json::to_value(prepared.endpoints()).unwrap();
        assert_eq!(json[0]["public_address"], "proxy.example:443");
        assert_eq!(json[1]["public_address"], "[2001:db8::7]:1081");
        assert_eq!(json[0].as_object().unwrap().len(), 3);
        assert!(load(&directory.configuration(
        r#"{"listeners":[{"protocol":"http","bind":"127.0.0.1:8080","public_address":"https://proxy.example:443"}]}"#,
    )).is_err());
    }

    #[test]
    fn all_listener_bindings_must_succeed_before_readiness_and_failure_releases_sockets() {
        let directory = Directory::new();
        let _identity = directory.identity().expect("first listener TLS identity");
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("occupied port");
        let occupied_port = occupied.local_addr().expect("occupied address").port();
        let configuration = format!(
            r#"{{"workers":1,"listeners":[{{"protocol":"https","bind":"127.0.0.1:8080","tls_cert":"certificate.pem","tls_key":"key.pem"}},{{"protocol":"socks5","bind":"127.0.0.1:{occupied_port}"}}]}}"#
        );
        let mut prepared =
            load(&directory.configuration(&configuration)).expect("valid configuration");
        prepared.listeners[0].bind.set_port(0);
        let certificates = prepared.certificate_handle();
        assert!(certificates.has_tls());
        assert!(certificates.snapshot(CERTIFICATE_NODE).is_err());
        let mut running =
            start(prepared, empty_reader(), directory.guard()).expect("start forwarding runtime");
        assert!(
            matches!(super::super::store::lock(&directory.0), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        let (readiness, completion) = control_runtime().block_on(async {
            let readiness = tokio::time::timeout(Duration::from_secs(3), running.ready())
                .await
                .expect("bounded readiness")
                .expect_err("all listeners must be bound before readiness");
            let completion = running.finished().await.expect_err("failed startup result");
            (readiness, completion)
        });
        let failure = startup_failure(&readiness);
        assert_eq!(failure.protocol, Protocol::Socks5);
        assert_eq!(
            failure.bind,
            occupied.local_addr().expect("occupied address")
        );
        assert!(failure.source.raw_os_error().is_some());
        assert_eq!(readiness.kind(), failure.source.kind());
        assert_eq!(completion.kind(), readiness.kind());
        assert!(Arc::ptr_eq(failure, startup_failure(&completion)));
        assert!(
            certificates.snapshot(CERTIFICATE_NODE).is_err(),
            "a partial bind must not publish a successful half-inventory"
        );
        let prepared_addresses = failure
            .prepared_addresses
            .as_ref()
            .expect("bound addresses");
        assert_eq!(prepared_addresses.len(), 1);
        let first_address = prepared_addresses[0];
        assert_ne!(first_address.port(), 0);
        assert!(first_address.ip().is_loopback());
        let shutdown = running.finish();
        assert!(shutdown.runtime_stopped);
        shutdown.result.expect("result was already delivered");
        let _rebound = TcpListener::bind(first_address).expect("earlier socket was released");
    }

    #[test]
    fn failed_readiness_keeps_the_service_error_but_closes_a_stopped_traffic_run() -> io::Result<()>
    {
        use crate::manage::{policy::Coordinator, store, traffic};

        let directory = Directory::new();
        store::initialize(&directory.0, "startup fixture", "admin", "fixture PHC")?;
        let author = directory.guard();
        let policy = Coordinator::new(
            directory.0.clone(),
            store::load_policy(&directory.0)?,
            author.clone(),
        )?;
        let runtime = control_runtime();
        let (traffic, _runner) = runtime.block_on(traffic::new(policy.clone()))?;
        runtime.block_on(traffic.begin())?;
        assert!(!store::traffic::status(&directory.0)?.clean);

        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = occupied.local_addr()?.port();
        let configuration = format!(
            r#"{{"workers":1,"listeners":[{{"protocol":"http","bind":"127.0.0.1:{port}"}}]}}"#
        );
        let prepared = load(&directory.configuration(&configuration))?;
        let mut running = start(prepared, policy.reader(), author)?;
        let readiness = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), running.ready())
                .await
                .expect("bounded failed startup")
        });
        let readiness = readiness.unwrap_err();
        let failure = readiness.kind();
        let cause = startup_failure(&readiness);
        assert_eq!(cause.protocol, Protocol::Http);
        assert_eq!(cause.bind, occupied.local_addr()?);
        assert_eq!(cause.source.kind(), failure);
        assert!(cause.source.raw_os_error().is_some());
        // WinSock can reject a conflicting bind as ACCESS rather than INUSE.
        // https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
        #[cfg(windows)]
        assert!(matches!(
            failure,
            io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
        ));
        #[cfg(not(windows))]
        assert_eq!(failure, io::ErrorKind::AddrInUse);

        // The real API exits readiness without consuming finished(). Its final
        // accounting decision must depend on worker teardown, not this error.
        let shutdown = running.finish();
        assert!(shutdown.runtime_stopped);
        let final_error = shutdown.result.unwrap_err();
        assert_eq!(final_error.kind(), failure);
        assert!(Arc::ptr_eq(cause, startup_failure(&final_error)));
        runtime.block_on(traffic.finish(shutdown.runtime_stopped))?;
        let durable = store::traffic::status(&directory.0)?;
        assert!(durable.clean && !durable.loss_possible);
        assert!(traffic.observation()?.active_run.is_none());
        Ok(())
    }

    #[test]
    fn managed_listeners_require_credentials_and_stop_via_one_shared_handle() {
        let directory = Directory::new();
        let configuration = r#"{"workers":2,"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"},{"protocol":"socks5","bind":"127.0.0.1:1080"}]}"#;
        let prepared =
            ephemeral(load(&directory.configuration(configuration)).expect("valid configuration"));
        let certificates = prepared.certificate_handle();
        assert!(!certificates.has_tls());
        assert!(!Certificates::default().has_tls());
        assert!(
            Certificates::default()
                .snapshot(CERTIFICATE_NODE)
                .expect("known empty configuration")
                .is_empty()
        );
        let mut running =
            start(prepared, empty_reader(), directory.guard()).expect("start forwarding runtime");
        let runtime = control_runtime();
        runtime.block_on(async {
            running.ready().await.expect("all listeners ready");
        });
        assert_eq!(running.addresses.len(), 2);
        let identities = certificates
            .snapshot(CERTIFICATE_NODE)
            .expect("all plaintext listeners bound");
        assert_eq!(identities.len(), 2);
        assert!(identities.iter().all(|identity| {
            matches!(identity.protocol, Protocol::Http | Protocol::Socks5)
                && identity.state == super::super::certificates::State::Disabled
        }));
        let http_address = running.addresses[0];
        let socks_address = running.addresses[1];
        assert_ne!(http_address.port(), 0);
        assert_ne!(socks_address.port(), 0);
        let mut http = TcpStream::connect(http_address).expect("HTTP listener");
        http.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("HTTP read timeout");
        http.write_all(
            b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: 127.0.0.1:9\r\nConnection: close\r\n\r\n",
        )
        .expect("HTTP request");
        let mut response = String::new();
        http.read_to_string(&mut response).expect("HTTP response");
        assert!(
            response.starts_with("HTTP/1.1 407"),
            "expected proxy authentication challenge"
        );
        let mut socks = TcpStream::connect(socks_address).expect("SOCKS listener");
        socks
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("SOCKS read timeout");
        socks.write_all(&[5, 1, 0]).expect("no-auth offer");
        let mut reply = [0; 2];
        socks.read_exact(&mut reply).expect("SOCKS reply");
        assert_eq!(reply, [5, 0xff]);
        drop(socks);
        running.handle().request_graceful_shutdown();
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(8), running.finished())
                .await
                .expect("bounded forwarding shutdown")
                .expect("graceful forwarding result");
        });
        running.finish().result.expect("join forwarding workers");
        let _author_again =
            super::super::store::lock(&directory.0).expect("cleanup released author guard");
        assert!(TcpStream::connect(http_address).is_err());
        assert!(TcpStream::connect(socks_address).is_err());
    }

    /// Exercise real bind/auth/reap across generations, without creating users or
    /// credentials. A stale page must not stop a later live listener group.
    #[test]
    fn service_restarts_real_listeners_and_refuses_stale_generation() -> io::Result<()> {
        use super::service::{Phase, Service};

        let directory = Directory::new();
        let path = directory.configuration(
        r#"{"workers":1,"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"},{"protocol":"socks5","bind":"127.0.0.1:1080"}]}"#,
    );
        let runtime = control_runtime();
        let mut owner = Service::spawn(empty_reader(), directory.guard())?;
        let control = owner.control();
        let outcome = (|| -> io::Result<()> {
            runtime.block_on(owner.ready())?;
            let initial = control.snapshot()?;
            assert_eq!((initial.generation, initial.phase), (0, Phase::Stopped));
            let first = runtime.block_on(control.apply(0, Some(ephemeral(load(&path)?))))?;
            assert_eq!((first.generation, first.phase), (1, Phase::Running));
            assert!(first.cleanup_confirmed);
            assert_eq!(first.endpoints.len(), 2);
            let old_runtime = first
                .runtime
                .as_ref()
                .expect("ready runtime")
                .snapshot()?
                .runtime_id;
            assert_eq!(first.certificates.snapshot(CERTIFICATE_NODE)?.len(), 2);

            let mut http = TcpStream::connect(first.addresses[0])?;
            http.set_read_timeout(Some(Duration::from_secs(3)))?;
            http.write_all(
            b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: 127.0.0.1:9\r\nConnection: close\r\n\r\n",
        )?;
            let mut response = String::new();
            http.read_to_string(&mut response)?;
            assert!(response.starts_with("HTTP/1.1 407"));
            let mut socks = TcpStream::connect(first.addresses[1])?;
            socks.set_read_timeout(Some(Duration::from_secs(3)))?;
            socks.write_all(&[5, 1, 0])?;
            let mut reply = [0; 2];
            socks.read_exact(&mut reply)?;
            assert_eq!(reply, [5, 0xff]);
            drop((http, socks));

            let stale = runtime
                .block_on(control.apply(0, None))
                .err()
                .expect("stale page rejected");
            assert_eq!(stale.kind(), io::ErrorKind::AlreadyExists);
            assert_eq!(control.snapshot()?.phase, Phase::Running);
            let stopped = runtime.block_on(control.apply(1, None))?;
            assert_eq!((stopped.generation, stopped.phase), (2, Phase::Stopped));
            assert!(stopped.runtime.is_none() && stopped.cleanup_confirmed);
            for address in first.addresses {
                assert!(TcpStream::connect(address).is_err());
            }
            let second = runtime.block_on(control.apply(2, Some(ephemeral(load(&path)?))))?;
            assert_eq!((second.generation, second.phase), (3, Phase::Running));
            assert_ne!(
                second
                    .runtime
                    .as_ref()
                    .expect("replacement")
                    .snapshot()?
                    .runtime_id,
                old_runtime
            );
            Ok(())
        })();
        let shutdown = owner.finish();
        assert!(shutdown.runtime_stopped);
        shutdown.result?;
        assert_eq!(
            control
                .snapshot()
                .err()
                .expect("no stale running snapshot")
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        let _released = super::super::store::lock(&directory.0)?;
        outcome
    }

    #[test]
    fn service_bind_failure_retains_control_and_allows_explicit_retry() -> io::Result<()> {
        use super::service::{Phase, Service};

        let directory = Directory::new();
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = occupied.local_addr()?;
        let path = directory.configuration(&format!(
            r#"{{"workers":1,"listeners":[{{"protocol":"http","bind":"{address}"}}]}}"#,
        ));
        let runtime = control_runtime();
        let mut owner = Service::spawn(empty_reader(), directory.guard())?;
        let control = owner.control();
        let outcome = (|| -> io::Result<()> {
            runtime.block_on(owner.ready())?;
            let error = runtime
                .block_on(control.apply(0, Some(load(&path)?)))
                .err()
                .expect("occupied port");
            let failed = control.snapshot()?;
            assert_eq!((failed.generation, failed.phase), (1, Phase::Failed));
            assert_eq!(failed.failure, Some(error.kind()));
            assert!(failed.runtime.is_none() && failed.cleanup_confirmed);
            assert_eq!(occupied.local_addr()?, address);
            drop(occupied);
            let retry = runtime.block_on(control.apply(1, Some(load(&path)?)))?;
            assert_eq!((retry.generation, retry.phase), (2, Phase::Running));
            assert_eq!(retry.addresses, [address]);
            assert!(retry.failure.is_none());
            Ok(())
        })();
        let shutdown = owner.finish();
        assert!(shutdown.runtime_stopped);
        shutdown.result?;
        assert!(TcpStream::connect(address).is_err());
        let _released = super::super::store::lock(&directory.0)?;
        outcome
    }

    #[test]
    fn service_keeps_admitted_work_after_waiter_cancel_and_retains_planned_drain() -> io::Result<()>
    {
        use super::service::{Phase, Service};

        let directory = Directory::new();
        let path = directory.configuration(
            r#"{"workers":1,"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"}]}"#,
        );
        let runtime = control_runtime();
        let mut owner = Service::spawn(empty_reader(), directory.guard())?;
        let control = owner.control();
        let mut observed = control.subscribe();
        let outcome = (|| -> io::Result<()> {
            runtime.block_on(owner.ready())?;
            drop(control.request(0, Some(ephemeral(load(&path)?)))?);
            let first = runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        let view = observed.borrow_and_update().clone();
                        if view.phase == Phase::Running {
                            return Ok::<_, io::Error>(view);
                        }
                        observed
                            .changed()
                            .await
                            .map_err(|_| io::Error::other("owner stopped before readiness"))?;
                    }
                })
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "cancelled wait lost admitted start",
                    )
                })?
            })?;
            assert_eq!(first.generation, 1);
            let lifecycle = first.runtime.as_ref().expect("ready lifecycle");
            let runtime_id = lifecycle.snapshot()?.runtime_id;
            let intent = DrainIntent {
                node_id: CERTIFICATE_NODE.into(),
                request_id: "AQEBAQEBAQEBAQEBAQEBAQ".into(),
                epoch: 1,
                revision: 1,
                actor: DrainActor::Local {
                    administrator_id: "AgICAgICAgICAgICAgICAg".into(),
                },
            };
            lifecycle.request(&runtime_id, intent.clone())?;
            let drained = runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        let view = observed.borrow_and_update().clone();
                        if view.phase == Phase::Stopped {
                            return Ok::<_, io::Error>(view);
                        }
                        observed
                            .changed()
                            .await
                            .map_err(|_| io::Error::other("owner stopped during drain"))?;
                    }
                })
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "planned drain did not finish")
                })?
            })?;
            assert!(drained.cleanup_confirmed && drained.failure.is_none());
            let receipt = drained
                .runtime
                .as_ref()
                .expect("retained drain receipt")
                .snapshot()?;
            assert_eq!(receipt.phase, super::Phase::Drained);
            assert_eq!(receipt.intent, Some(intent));
            assert!(TcpStream::connect(first.addresses[0]).is_err());
            let second = runtime.block_on(control.apply(1, Some(ephemeral(load(&path)?))))?;
            assert_eq!((second.generation, second.phase), (2, Phase::Running));
            assert_ne!(
                second
                    .runtime
                    .as_ref()
                    .expect("replacement")
                    .snapshot()?
                    .runtime_id,
                runtime_id
            );
            Ok(())
        })();
        let shutdown = owner.finish();
        assert!(shutdown.runtime_stopped);
        shutdown.result?;
        let _released = super::super::store::lock(&directory.0)?;
        outcome
    }

    #[test]
    fn service_bounds_queued_operations_and_stop_does_not_start_the_queued_replacement()
    -> io::Result<()> {
        use super::service::{Phase, Service};

        let directory = Directory::new();
        let path = directory.configuration(
            r#"{"workers":1,"listeners":[{"protocol":"socks5","bind":"127.0.0.1:1080"}]}"#,
        );
        let runtime = control_runtime();
        let mut owner = Service::spawn(empty_reader(), directory.guard())?;
        let control = owner.control();
        let mut observed = control.subscribe();
        runtime.block_on(owner.ready())?;
        let started = runtime.block_on(control.apply(0, Some(ephemeral(load(&path)?))))?;
        let address = started.addresses[0];
        let mut socks = TcpStream::connect(address)?;
        socks.set_read_timeout(Some(Duration::from_secs(3)))?;
        socks.write_all(&[5, 1, 2])?;
        let mut method = [0; 2];
        socks.read_exact(&mut method)?;
        assert_eq!(method, [5, 2]);
        // The real admitted authentication, not a sleep or backlog socket, keeps
        // the old group's drain active while its bounded command queue is probed.
        let stopped = control.request(1, None)?;
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let view = observed.borrow_and_update().clone();
                    if view.phase == Phase::Stopping {
                        return Ok::<_, io::Error>(());
                    }
                    observed
                        .changed()
                        .await
                        .map_err(|_| io::Error::other("owner stopped before drain"))?;
                }
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "drain did not start"))?
        })?;
        let queued = control.request(2, Some(ephemeral(load(&path)?)))?;
        let error = control
            .request(2, None)
            .err()
            .expect("one queued command limit");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        // finish cancels before joining: even though an operation is queued, no
        // replacement may bind after whole-process stop. Keep authentication open
        // to exercise the existing protocol deadline and actual runtime reaping.
        let shutdown = owner.finish();
        assert!(shutdown.runtime_stopped);
        shutdown.result?;
        drop(socks);
        let original = runtime.block_on(stopped).expect("original stop receipt");
        assert_eq!(
            original.err().expect("authentication drain timeout").kind(),
            io::ErrorKind::TimedOut
        );
        assert!(runtime.block_on(queued).is_err());
        assert!(TcpStream::connect(address).is_err());
        let _released = super::super::store::lock(&directory.0)?;
        Ok(())
    }

    #[test]
    fn sibling_shutdown_preserves_a_real_connection_drain_timeout_after_completion_is_consumed() {
        let directory = Directory::new();
        let configuration = r#"{"workers":1,"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"},{"protocol":"socks5","bind":"127.0.0.1:1080"}]}"#;
        let prepared =
            ephemeral(load(&directory.configuration(configuration)).expect("valid listeners"));
        let mut running =
            start(prepared, empty_reader(), directory.guard()).expect("start listeners");
        let runtime = control_runtime();
        // Always complete runtime cleanup before asserting the scenario outcome.
        // The HTTP sibling has no connections; SOCKS has entered authentication,
        // so its deadline is exercised by owned work, not a socket in the backlog.
        let result = (|| -> io::Result<io::Result<()>> {
            runtime.block_on(running.ready())?;
            let mut socks = TcpStream::connect(running.addresses[1])?;
            socks.set_read_timeout(Some(Duration::from_secs(3)))?;
            socks.write_all(&[5, 1, 2])?;
            let mut method = [0; 2];
            socks.read_exact(&mut method)?;
            if method != [5, 2] {
                return Err(io::Error::other(
                    "SOCKS fixture did not enter password authentication",
                ));
            }
            // Leave the password exchange unfinished while retaining the socket.
            running.shutdown();
            runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(10), running.finished())
                    .await
                    .map_err(|_| io::Error::other("managed drain observation deadline exceeded"))
            })
        })();
        let shutdown = running.finish();
        let error = result
            .expect("real SOCKS fixture completed")
            .expect_err("timed-out connection drain must not be a successful shutdown");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            shutdown.runtime_stopped,
            "driver failure and worker teardown are separate facts"
        );
        shutdown
            .result
            .expect("the original timeout was already delivered exactly once");
    }

    #[test]
    fn explicit_tls_paths_are_relative_to_configuration_and_validated_before_startup() {
        let directory = Directory::new();
        let (rcgen::CertifiedKey { cert, signing_key }, key_path) =
            directory.identity().expect("TLS fixture");
        for protocol in ["https", "masque", "auto"] {
            let configuration = format!(
                r#"{{"workers":1,"listeners":[{{"protocol":"{protocol}","bind":"127.0.0.1:8443","tls_cert":"certificate.pem","tls_key":"key.pem"}}]}}"#
            );
            let prepared = load(&directory.configuration(&configuration))
                .expect("relative TLS files validated");
            assert_eq!(prepared.listeners.len(), 1);
        }
        let encrypted = ["https", "masque", "auto"].into_iter().map(|protocol| {
        format!(r#"{{"protocol":"{protocol}","bind":"127.0.0.1:8443","tls_cert":"certificate.pem","tls_key":"key.pem"}}"#)
    }).collect::<Vec<_>>().join(",");
        let configuration = format!(r#"{{"workers":1,"listeners":[{encrypted}]}}"#);
        let prepared = ephemeral(
            load(&directory.configuration(&configuration)).expect("encrypted configuration"),
        );
        let certificates = prepared.certificate_handle();
        assert!(certificates.has_tls());
        assert!(certificates.snapshot(CERTIFICATE_NODE).is_err());
        // Preparation now owns the actual signer. Replacing both valid PEM files
        // before the forwarding runtime starts must not change that selection.
        let actual = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("actual installed TLS fixture");
        fs::write(directory.0.join("certificate.pem"), actual.cert.pem())
            .expect("replace preflight leaf");
        fs::write(&key_path, actual.signing_key.serialize_pem()).expect("replace preflight key");
        let reloaded = ephemeral(
            load(&directory.configuration(&configuration))
                .expect("a new preparation must select the replacement PEM identity"),
        );
        let reloaded_certificates = reloaded.certificate_handle();
        let expected = super::super::certificates::State::from_leaf(cert.der().as_ref());
        assert!(matches!(
            expected,
            super::super::certificates::State::Loaded(_)
        ));
        assert_ne!(
            expected,
            super::super::certificates::State::from_leaf(actual.cert.der().as_ref())
        );
        let mut running = start(prepared, empty_reader(), directory.guard())
            .expect("encrypted forwarding runtime");
        control_runtime().block_on(async {
            running
                .ready()
                .await
                .expect("all three encrypted listeners bound");
            assert_eq!(running.addresses.len(), 3);
            assert!(running.addresses.iter().all(|address| address.port() != 0));
            verify_prepared_tls(&running.addresses, cert.der().clone())
                .await
                .expect("same selected signer in all real TLS handshakes");
            // Monitoring never reopens the paths after the all-listener publication.
            fs::remove_file(directory.0.join("certificate.pem"))
                .expect("remove original certificate path");
            fs::remove_file(&key_path).expect("remove original key path");
            let identities = certificates
                .snapshot(CERTIFICATE_NODE)
                .expect("complete installed TLS inventory");
            assert_eq!(identities.len(), 3);
            for (identity, protocol) in
                identities
                    .iter()
                    .zip([Protocol::Https, Protocol::Masque, Protocol::Auto])
            {
                assert_eq!(identity.protocol, protocol);
                assert_eq!(identity.state, expected);
                assert_eq!(
                    identity.id,
                    endpoint_id(
                        CERTIFICATE_NODE,
                        protocol,
                        "127.0.0.1:8443".parse().expect("configured identity bind"),
                    )
                );
            }
            running.shutdown();
            running
                .finished()
                .await
                .expect("encrypted listeners shut down");
        });
        running.finish().result.expect("encrypted runtime cleanup");
        let replacement = super::super::certificates::State::from_leaf(actual.cert.der().as_ref());
        let mut reloaded = start(reloaded, empty_reader(), directory.guard())
            .expect("replacement forwarding runtime");
        control_runtime().block_on(async {
            reloaded.ready().await.expect("replacement listeners ready");
            verify_prepared_tls(&reloaded.addresses, actual.cert.der().clone())
                .await
                .expect("a new preparation uses the new signer without a path cache");
            for identity in reloaded_certificates
                .snapshot(CERTIFICATE_NODE)
                .expect("replacement inventory")
            {
                assert_eq!(identity.state, replacement);
            }
            reloaded.shutdown();
            reloaded
                .finished()
                .await
                .expect("replacement listeners stopped");
        });
        reloaded
            .finish()
            .result
            .expect("replacement runtime cleanup");
        fs::write(directory.0.join("certificate.pem"), cert.pem())
            .expect("restore certificate fixture");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        options
            .open(&key_path)
            .expect("restore private key leaf")
            .write_all(signing_key.serialize_pem().as_bytes())
            .expect("restore key fixture");
        fs::write(&key_path, b"not a private key").expect("corrupt key fixture");
        let configuration = r#"{"listeners":[{"protocol":"https","bind":"127.0.0.1:8443","tls_cert":"certificate.pem","tls_key":"key.pem"}]}"#;
        assert!(load(&directory.configuration(configuration)).is_err());
    }

    #[test]
    fn managed_service_persists_and_applies_real_default_egress_without_reissuing_credentials()
    -> io::Result<()> {
        use crate::manage::{policy::Coordinator, store, traffic};
        use base64::{
            Engine as _,
            engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
        };
        use service::{Managed, Service};

        let directory = Directory::new();
        let node = store::initialize(
            &directory.0,
            "managed service fixture",
            "admin",
            "fixture verifier, not a usable login",
        )?
        .node_id;
        let author = directory.guard();
        let policy = Coordinator::new(
            directory.0.clone(),
            store::load_policy(&directory.0)?,
            author.clone(),
        )?;
        let connection = rusqlite::Connection::open(directory.0.join("management.sqlite3"))
            .map_err(io::Error::other)?;
        let administrator: String = connection
            .query_row("SELECT id FROM administrators", [], |r| r.get(0))
            .map_err(io::Error::other)?;
        drop(connection);
        let runtime = control_runtime();
        let created = runtime.block_on(policy.change(
            administrator.clone(),
            1,
            store::PolicyChange::CreateUser {
                name: "default exit user".into(),
                protocols: vec![crate::access::Protocol::Http],
                concurrent_limit: 2,
            },
        ))?;
        let user = created
            .user
            .ok_or_else(|| io::Error::other("fixture user missing"))?;
        let issued = runtime.block_on(policy.change(
            administrator.clone(),
            created.revision,
            store::PolicyChange::CreateCredential { user_id: user.id },
        ))?;
        let credential = issued
            .credential
            .ok_or_else(|| io::Error::other("fixture credential missing"))?;
        let secret = issued
            .secret
            .ok_or_else(|| io::Error::other("fixture secret missing"))?;
        let (traffic, _runner) = runtime.block_on(traffic::new(policy.clone()))?;
        let (_, key) = directory.identity()?;
        let identity =
            super::super::tls::proxy_identity(&directory.0.join("certificate.pem"), &key)?;
        let mut managed = Managed::new(
            policy.clone(),
            traffic.clone(),
            settings::Tls::Manual(identity),
            crate::ebpf::Config::default(),
            node.clone(),
            vec![8443],
        )?;
        managed.ephemeral = true;
        let mut owner = Service::managed(managed, author)?;
        let control = owner.control();
        policy.configure_service(node.clone(), control.clone())?;
        assert!(policy.service().is_some());
        let settings = settings::Configuration {
            workers: 1,
            concurrent: 1024,
            connect_timeout: 10,
            listeners: vec![ListenerView {
                protocol: Protocol::Http,
                bind: "127.0.0.1:18080".parse().map_err(io::Error::other)?,
                public_address: Some("localhost:18080".into()),
            }],
        };
        let request = |revision, enabled, id: String| store::proxy_service::Request {
            assertion: store::admission::Assertion {
                node_id: node.clone(),
                epoch: 1,
            },
            expected_revision: revision,
            request_id: id,
            enabled,
            configuration: settings.clone(),
        };
        let outcome = (|| -> io::Result<()> {
            runtime.block_on(owner.ready())?;
            runtime.block_on(control.restore())?;
            assert!(runtime.block_on(control.restore()).is_err());
            assert!(traffic.observation()?.active_run.is_none());
            let id = URL_SAFE_NO_PAD.encode([31; 16]);
            let first = runtime
                .block_on(control.configure(administrator.clone(), request(1, true, id.clone())))?;
            assert_eq!(first.phase, service::Phase::Running);
            assert!(policy.is_running());
            let runtime_id = first
                .runtime
                .as_ref()
                .expect("ready runtime")
                .snapshot()?
                .runtime_id;
            let receipt = store::proxy_service::exact(
                &directory.0,
                &administrator,
                &store::admission::Assertion {
                    node_id: node.clone(),
                    epoch: 1,
                },
                2,
                &id,
            )?;
            assert_eq!(receipt.outcome, store::proxy_service::Outcome::Applied);
            let duplicate =
                runtime.block_on(control.configure(administrator.clone(), request(1, true, id)))?;
            assert_eq!(
                duplicate
                    .runtime
                    .as_ref()
                    .expect("same runtime")
                    .snapshot()?
                    .runtime_id,
                runtime_id
            );

            let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            upstream.set_nonblocking(true)?;
            let target = upstream.local_addr()?;
            let destination = std::thread::spawn(move || -> io::Result<()> {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    match upstream.accept() {
                        Ok((mut stream, _)) => {
                            stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                            let mut input = [0; 4096];
                            let _ = stream.read(&mut input)?;
                            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ndefault")?;
                            return Ok(());
                        }
                        Err(error)
                            if error.kind() == io::ErrorKind::WouldBlock
                                && std::time::Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) => return Err(error),
                    }
                }
            });
            let mut client = TcpStream::connect(first.addresses[0])?;
            client.set_read_timeout(Some(Duration::from_secs(5)))?;
            let encoded = STANDARD.encode(format!("{}:{}", credential.login, secret.as_str()));
            client.write_all(format!("GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {encoded}\r\nConnection: close\r\n\r\n").as_bytes())?;
            let mut response = String::new();
            let response_result = client.read_to_string(&mut response);
            destination
                .join()
                .map_err(|_| io::Error::other("fixture destination panicked"))??;
            response_result?;
            assert!(response.starts_with("HTTP/1.1 200"));
            assert!(response.ends_with("default"));
            drop(client);
            let stopped = runtime.block_on(control.configure(
                administrator.clone(),
                request(2, false, URL_SAFE_NO_PAD.encode([32; 16])),
            ))?;
            assert_eq!(stopped.phase, service::Phase::Stopped);
            assert!(!policy.is_running());
            assert!(TcpStream::connect(first.addresses[0]).is_err());
            let restarted = runtime.block_on(control.configure(
                administrator.clone(),
                request(3, true, URL_SAFE_NO_PAD.encode([33; 16])),
            ))?;
            assert_eq!(restarted.phase, service::Phase::Running);
            assert_ne!(
                restarted
                    .runtime
                    .as_ref()
                    .expect("new runtime")
                    .snapshot()?
                    .runtime_id,
                runtime_id
            );
            let (series, _) = runtime.block_on(traffic.sample())?;
            assert!(
                series
                    .iter()
                    .any(|series| series.credential_id.as_ref() == credential.id
                        && series.value.download > 0)
            );
            assert_eq!(
                store::list_credentials(&directory.0, None, None, 50)?
                    .items
                    .len(),
                1
            );
            Ok(())
        })();
        let stopped = owner.finish();
        assert!(stopped.runtime_stopped);
        stopped.result?;
        assert!(!policy.is_running());
        runtime.block_on(traffic.finish(stopped.runtime_stopped))?;
        assert!(store::traffic::status(&directory.0)?.clean);
        outcome
    }

    #[test]
    fn web_service_settings_use_one_managed_identity_with_real_https_auto_and_quic()
    -> io::Result<()> {
        let directory = Directory::new();
        let (identity, key) = directory.identity()?;
        let (management, descriptor, proxy) =
            super::super::tls::admin_proxy_identity(&directory.0.join("certificate.pem"), &key)?;
        assert_eq!(management.alpn_protocols, [b"http/1.1".to_vec()]);
        assert_eq!(
            descriptor,
            super::super::certificates::State::from_leaf(identity.cert.der().as_ref())
        );
        let tls = settings::Tls::Manual(proxy);
        let settings = settings::Configuration {
            workers: 1,
            concurrent: 1024,
            connect_timeout: 10,
            listeners: [Protocol::Https, Protocol::Masque, Protocol::Auto]
                .into_iter()
                .map(|protocol| ListenerView {
                    protocol,
                    bind: "127.0.0.1:18443".parse().expect("fixed fixture bind"),
                    public_address: Some("localhost:18443".into()),
                })
                .collect(),
        };
        // HTTPS and auto are both TCP, so use a distinct configured port while
        // retaining actual ephemeral allocation for the real handshake fixtures.
        let mut settings = settings;
        settings.listeners[2].bind.set_port(19443);
        let prepared = ephemeral(settings.prepare(&tls, crate::ebpf::Config::default())?);
        let certificates = prepared.certificate_handle();
        let mut running = start(prepared, empty_reader(), directory.guard())?;
        // Remove paths after preparation. Neither the shared manual signer nor
        // any of the three protocol-specific TLS configurations may reopen them.
        fs::remove_file(directory.0.join("certificate.pem"))?;
        fs::remove_file(key)?;
        let runtime = control_runtime();
        let result = runtime.block_on(async {
            running.ready().await?;
            verify_prepared_tls(&running.addresses, identity.cert.der().clone()).await?;
            let identities = certificates.snapshot(CERTIFICATE_NODE)?;
            assert_eq!(identities.len(), 3);
            for value in identities {
                assert_eq!(value.state, descriptor);
                assert_eq!(value.source, super::super::certificates::Source::Manual);
            }
            Ok::<_, io::Error>(())
        });
        let stopped = running.finish();
        assert!(stopped.runtime_stopped);
        stopped.result?;
        result
    }

    /// Recreate the actual cold owner, Coordinator and traffic registry from the
    /// same saved state. A pre-activation pending intent is not replayed as success.
    #[test]
    fn managed_service_restores_saved_listeners_but_preserves_interrupted_receipt() -> io::Result<()>
    {
        use crate::manage::{policy::Coordinator, store, traffic};
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let directory = Directory::new();
        let node = store::initialize(&directory.0, "restore fixture", "admin", "fixture verifier")?
            .node_id;
        let connection = rusqlite::Connection::open(directory.0.join("management.sqlite3"))
            .map_err(io::Error::other)?;
        let administrator: String = connection
            .query_row("SELECT id FROM administrators", [], |row| row.get(0))
            .map_err(io::Error::other)?;
        drop(connection);
        let id = URL_SAFE_NO_PAD.encode([34; 16]);
        let assertion = store::admission::Assertion {
            node_id: node.clone(),
            epoch: 1,
        };
        let configuration = settings::Configuration {
            workers: 1,
            concurrent: 1024,
            connect_timeout: 10,
            listeners: vec![ListenerView {
                protocol: Protocol::Socks5,
                bind: "127.0.0.1:1080".parse().map_err(io::Error::other)?,
                public_address: Some("localhost:1080".into()),
            }],
        };
        {
            let gate = store::update_lock(&directory.0)?;
            let (_, accepted) = store::proxy_service::accept(
                &directory.0,
                &gate,
                &administrator,
                &store::proxy_service::Request {
                    assertion: assertion.clone(),
                    expected_revision: 1,
                    request_id: id.clone(),
                    enabled: true,
                    configuration,
                },
            )?;
            assert!(accepted);
        }
        let (_, key) = directory.identity()?;
        let identity =
            super::super::tls::proxy_identity(&directory.0.join("certificate.pem"), &key)?;
        let runtime = control_runtime();
        let mut prior_runtime = None;
        for _ in 0..2 {
            let author = directory.guard();
            let policy = Coordinator::new(
                directory.0.clone(),
                store::load_policy(&directory.0)?,
                author.clone(),
            )?;
            let (traffic, runner) = runtime.block_on(traffic::new(policy.clone()))?;
            let mut managed = service::Managed::new(
                policy.clone(),
                traffic.clone(),
                settings::Tls::Manual(identity.clone()),
                crate::ebpf::Config::default(),
                node.clone(),
                vec![8443],
            )?;
            managed.ephemeral = true;
            let mut owner = service::Service::managed(managed, author.clone())?;
            let control = owner.control();
            policy.configure_service(node.clone(), control.clone())?;
            let exercised = (|| -> io::Result<()> {
                runtime.block_on(owner.ready())?;
                let ready = runtime.block_on(control.restore())?;
                assert_eq!(ready.phase, service::Phase::Running);
                assert_eq!(ready.configuration_revision, Some(2));
                assert!(policy.is_running());
                let receipt =
                    store::proxy_service::exact(&directory.0, &administrator, &assertion, 2, &id)?;
                assert_eq!(receipt.outcome, store::proxy_service::Outcome::Interrupted);
                let runtime_id = ready
                    .runtime
                    .as_ref()
                    .expect("restored runtime")
                    .snapshot()?
                    .runtime_id;
                assert_ne!(prior_runtime.as_ref(), Some(&runtime_id));
                prior_runtime = Some(runtime_id);
                let mut client = TcpStream::connect(ready.addresses[0])?;
                client.set_read_timeout(Some(Duration::from_secs(3)))?;
                client.write_all(&[5, 1, 0])?;
                let mut reply = [0; 2];
                client.read_exact(&mut reply)?;
                assert_eq!(reply, [5, 0xff]);
                Ok(())
            })();
            let stopped = owner.finish();
            assert!(stopped.runtime_stopped);
            stopped.result?;
            runtime.block_on(traffic.finish(true))?;
            exercised?;
            drop((control, traffic, runner, policy, author));
            let _released = store::lock(&directory.0)?;
        }
        Ok(())
    }

    /// Real strict TLS, not just the monitoring leaf: trust only the prepared
    /// self-signed certificate, negotiate H2 on both TCP branches and H3 on QUIC.
    async fn verify_prepared_tls(
        addresses: &[SocketAddr],
        certificate: rustls_pki_types::CertificateDer<'static>,
    ) -> io::Result<()> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).map_err(io::Error::other)?;
        for index in [0, 2] {
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
            config.alpn_protocols = vec![b"h2".to_vec()];
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let address = *addresses
                .get(index)
                .ok_or_else(|| io::Error::other("missing TCP fixture address"))?;
            let stream = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::TcpStream::connect(address),
            )
            .await
            .map_err(io::Error::other)??;
            let name =
                rustls_pki_types::ServerName::try_from("localhost").map_err(io::Error::other)?;
            let stream =
                tokio::time::timeout(Duration::from_secs(5), connector.connect(name, stream))
                    .await
                    .map_err(io::Error::other)??;
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        }
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(io::Error::other)?;
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().map_err(io::Error::other)?)?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let address = *addresses
            .get(1)
            .ok_or_else(|| io::Error::other("missing QUIC fixture address"))?;
        let connecting = endpoint
            .connect(address, "localhost")
            .map_err(io::Error::other)?;
        let connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        let handshake = connection
            .handshake_data()
            .ok_or_else(|| io::Error::other("missing QUIC handshake data"))?
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .map_err(|_| io::Error::other("wrong QUIC fixture handshake"))?;
        assert_eq!(handshake.protocol.as_deref(), Some(b"h3".as_slice()));
        connection.close(0u32.into(), b"fixture complete");
        tokio::time::timeout(Duration::from_secs(5), endpoint.wait_idle())
            .await
            .map_err(io::Error::other)?;
        Ok(())
    }

    #[test]
    fn captured_proxy_bytes_and_runtime_identity_come_from_the_same_read() -> io::Result<()> {
        let directory = Directory::new();
        // Captured archives require private leaves on Windows too, unlike the
        // older ordinary-startup fixture. Create new private inputs, not an ACL
        // repair of a pre-existing key.
        let input = directory.0.join("capture");
        super::super::files::create_directory(&input)?;
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(io::Error::other)?;
        super::super::files::write(&input, "certificate.pem", identity.cert.pem().as_bytes())?;
        super::super::files::write(
            &input,
            "key.pem",
            identity.signing_key.serialize_pem().as_bytes(),
        )?;
        let listeners = ["https","masque","auto"].into_iter().map(|protocol|
        format!(r#"{{"protocol":"{protocol}","bind":"127.0.0.1:8443","tls_cert":"certificate.pem","tls_key":"key.pem"}}"#)
    ).collect::<Vec<_>>().join(",");
        let configuration = input.join("proxy.json");
        super::super::files::write(
            &input,
            "proxy.json",
            format!(r#"{{"workers":1,"listeners":[{listeners}]}}"#).as_bytes(),
        )?;
        let captured = snapshot_configuration(&configuration)?;
        assert_eq!(captured.inputs.len(), 6);
        for file in &captured.inputs {
            let expected = if file.name.ends_with("cert.pem") {
                identity.cert.pem()
            } else {
                identity.signing_key.serialize_pem()
            };
            assert!(
                file.bytes.as_slice() == expected.as_bytes(),
                "captured TLS input differs"
            );
        }
        let portable: serde_json::Value =
            serde_json::from_slice(&captured.bytes).map_err(io::Error::other)?;
        assert_eq!(portable["listeners"][0]["tls_cert"], "proxy-00-cert.pem");
        assert_eq!(portable["listeners"][2]["tls_key"], "proxy-02-key.pem");
        fs::remove_file(input.join("certificate.pem"))?;
        fs::remove_file(input.join("key.pem"))?;
        fs::remove_file(configuration)?;
        let mut running = start(
            ephemeral(captured.prepared),
            empty_reader(),
            directory.guard(),
        )?;
        let result = control_runtime().block_on(async {
            running.ready().await?;
            let result = verify_prepared_tls(&running.addresses, identity.cert.der().clone()).await;
            running.shutdown();
            result.and(running.finished().await)
        });
        result.and(running.finish().result)
    }

    #[test]
    fn managed_tls_retains_prepared_identity_when_original_files_disappear_before_bind()
    -> io::Result<()> {
        let directory = Directory::new();
        let (identity, key_path) = directory.identity()?;
        let listeners = ["https","masque","auto"].into_iter().map(|protocol|
        format!(r#"{{"protocol":"{protocol}","bind":"127.0.0.1:8443","tls_cert":"certificate.pem","tls_key":"key.pem"}}"#)
    ).collect::<Vec<_>>().join(",");
        let prepared = ephemeral(load(
            &directory.configuration(&format!(r#"{{"workers":1,"listeners":[{listeners}]}}"#)),
        )?);
        fs::remove_file(directory.0.join("certificate.pem"))?;
        fs::remove_file(key_path)?;
        let mut running = start(prepared, empty_reader(), directory.guard())?;
        let result = control_runtime().block_on(async {
            running.ready().await?;
            let result = verify_prepared_tls(&running.addresses, identity.cert.der().clone()).await;
            running.shutdown();
            let finished = running.finished().await;
            result.and(finished)
        });
        result.and(running.finish().result)
    }

    #[test]
    fn blocked_worker_cleanup_is_bounded_and_keeps_the_author_guard_until_exit() {
        let directory = Directory::new();
        let runtime = Runtime::new(NonZeroUsize::new(1).expect("one worker"));
        let (entered, entry) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let _completion = runtime
            .spawn(async move {
                entered.send(()).map_err(io::Error::other)?;
                // Deliberately block a Pingora worker to reproduce its OS-join timeout
                // gap, not a production execution pattern. The test always releases it.
                released.recv().map_err(io::Error::other)?;
                Ok(())
            })
            .expect("start blocked fixture worker");
        entry
            .recv_timeout(Duration::from_secs(3))
            .expect("worker entered blocked fixture");
        let result = ShutdownResult::new(
            Ok(()),
            cleanup(runtime, directory.guard(), Duration::from_millis(30)),
        );
        let remained_locked = matches!(super::super::store::lock(&directory.0), Err(error) if error.kind() == io::ErrorKind::WouldBlock);
        // Release before assertions: even a failed assertion must not strand an OS
        // worker and a cleanup thread for the rest of the test process.
        release.send(()).expect("release blocked fixture worker");
        assert!(!result.runtime_stopped);
        assert!(matches!(result.result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
        assert!(remained_locked);
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            match super::super::store::lock(&directory.0) {
                Ok(_guard) => break,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("cleanup did not release the author lock: {error}"),
            }
        }
    }
}
