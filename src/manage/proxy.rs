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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize, utoipa::ToSchema)]
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

/// Portable JSON and the exact validated static files. Capture does not bind
/// sockets or start forwarding.
pub(super) struct CapturedConfiguration {
    pub(super) bytes: Vec<u8>,
    pub(super) inputs: Vec<SnapshotInput>,
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
    prepare_with(&configuration, parent, |index, certificate, key| {
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
    Ok(CapturedConfiguration { bytes, inputs })
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
            // path after configuration validation has checked it.
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

    /// The outer I/O envelope has the original kind but no native code of its own.
    /// Inspect its shared cause instead of accidentally asserting a recreated OS error.
    fn startup_failure(error: &io::Error) -> &Arc<StartupError> {
        error
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<Arc<StartupError>>())
            .expect("shared startup failure")
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
}
