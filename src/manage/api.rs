//! A bounded HTTPS administration API, separate from all proxy listeners.
//!
//! Sessions deliberately live only in this process: restarting revokes every
//! browser session without changing the durable node or administrator identity.

mod acme;
mod alerts;
mod automation;
mod certificates;
mod endpoints;
mod health;
mod maintenance;
mod notifications;
mod password;
mod presets;
#[cfg(feature = "witness-journal")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "Public Source management startup awaits complete activation gates"
    )
)]
mod registered;
mod remote_traffic;
mod routing;
mod runtime;
mod service;
mod targets;
mod traffic;
mod users;

use std::{
    collections::HashMap,
    io::{self, IsTerminal},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use argon2::{Argon2, PasswordHasher};
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header, uri::Authority},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hyper_util::{rt::TokioIo, rt::TokioTimer, service::TowerToHyperService};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use subtle::ConstantTimeEq;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use zeroize::Zeroizing;

const COOKIE_NAME: &str = "__Host-vproxy-session";
const SESSION_LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);
const MAX_SESSIONS: usize = 1024;
const MAX_RATE_ADDRESSES: usize = 1024;
const RATE_WINDOW: Duration = Duration::from_secs(60);
const IP_LOGIN_LIMIT: u16 = 10;
const GLOBAL_LOGIN_LIMIT: u16 = 60;
const MAX_JSON_BYTES: usize = 4096;
const JSON_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// HTTPS listener settings; a browser-visible origin is explicit, never inferred
/// from untrusted forwarding headers. Initialization must have completed offline.
#[derive(clap::Args)]
#[group(id = "ManagementServe")]
pub struct Args {
    /// Persistent directory previously created with `manage init`
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Management HTTPS listener, independent of the proxy port
    #[arg(long, default_value = "127.0.0.1:8443")]
    bind: SocketAddr,
    /// PEM certificate chain for the management HTTPS identity
    #[arg(
        long,
        required_unless_present = "acme",
        requires = "tls_key",
        conflicts_with = "acme"
    )]
    tls_cert: Option<PathBuf>,
    /// PEM private key, not the node-enrollment signing key
    #[arg(
        long,
        required_unless_present = "acme",
        requires = "tls_cert",
        conflicts_with = "acme"
    )]
    tls_key: Option<PathBuf>,
    #[command(flatten)]
    acme: super::acme::Options,
    /// Canonical browser origin, e.g. https://localhost:8443 (no trailing slash)
    #[arg(long)]
    public_origin: String,
    #[command(flatten)]
    node: super::node::ListenArgs,
    /// Optional startup JSON for local proxy listeners using managed credentials
    #[arg(long)]
    proxy_config: Option<PathBuf>,
    /// Optional bounded numeric TCP probe configuration (default: bind-only)
    #[arg(long)]
    health_config: Option<PathBuf>,
    /// Collect saved targets' own alerts in the background (requires schema22 and node mTLS)
    #[arg(long)]
    observe_target_alerts: bool,
    /// Optional node-local egress backend; built-in preset values are not CLI settings.
    #[command(flatten)]
    egress: crate::ebpf::Args,
}

/// Start the management API and optional managed listeners, keeping their
/// bounded administration runtime separate from proxy workers.
///
/// Filesystem/TLS/DB validation errors abort startup. Synchronous database and
/// password work is isolated from async execution and never enters proxy workers.
pub(super) fn run(args: Args) -> io::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(tracing::Level::INFO.into())
        .from_env()
        .map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid management log filter")
        })?;
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_env_filter(filter)
            .with_writer(io::stderr)
            .with_ansi(io::stderr().is_terminal())
            .finish(),
    )
    .map_err(|_| io::Error::other("cannot initialize management logging"))?;
    let origin = PublicOrigin::parse(&args.public_origin)?;
    let directory = super::directory(args.data_dir)?;
    // Recovery state is an offline startup gate, not a post-initialization
    // check. Retain author through all later runtime/proxy cleanup, before an
    // egress loader can attach programs or any listener can bind.
    let (author, recovery_key) = startup(&directory)?;
    let (tls, acme, certificate_source, service_tls) = match (
        args.acme
            .prepare(origin.value(), &directory, author.clone())?,
        args.tls_cert.as_deref(),
        args.tls_key.as_deref(),
    ) {
        (Some(prepared), None, None) => {
            let source = super::certificates::ManagementSource::Acme(prepared.tls());
            let service_tls = Some(super::proxy::settings::Tls::Acme(prepared.tls()));
            (
                Acceptor::Acme(prepared.tls()),
                Some(prepared),
                source,
                service_tls,
            )
        }
        (None, Some(certificate), Some(key)) => {
            let (config, identity, proxy) = super::tls::admin_proxy_identity(certificate, key)?;
            (
                Acceptor::Manual(TlsAcceptor::from(config)),
                None,
                super::certificates::ManagementSource::Manual(identity),
                Some(super::proxy::settings::Tls::Manual(proxy)),
            )
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "choose --tls-cert with --tls-key, or --acme",
            ));
        }
    };
    let node = super::node::configure(args.node, recovery_key)?;
    let profile_config = args.egress.load()?;
    let prepared_proxy = args
        .proxy_config
        .as_deref()
        .map(super::proxy::load)
        .transpose()?
        .map(|prepared| prepared.with_profile_config(profile_config.clone()));
    let health_config = health::load(args.health_config.as_deref())?;
    // Loading/attaching needs startup privileges. Drop those privileges before
    // Tokio can create blocking workers or the proxy runtime starts any thread.
    // Managed mode deliberately does not prepare routes or change sysctls.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    profile_config.restrict_runtime_privileges(
        args.bind.port() != 0 && args.bind.port() < 1024
            || acme
                .as_ref()
                .and_then(super::acme::Prepared::http)
                .is_some_and(|(bind, _)| bind.port() < 1024)
            || node
                .as_ref()
                .is_some_and(|config| config.bind.port() != 0 && config.bind.port() < 1024)
            || prepared_proxy
                .as_ref()
                .is_some_and(super::proxy::Prepared::privileged_bind),
        prepared_proxy
            .as_ref()
            .is_some_and(super::proxy::Prepared::interface_fallback),
    )?;
    run_prepared(
        async move {
            let state = initialize(directory, origin, author).await?;
            Ok(Prepared {
                state,
                bind: args.bind,
                tls,
                acme,
                certificate_source,
                service_tls,
                node,
                prepared_proxy,
                profile_config,
                health_config,
                health_explicit: args.health_config.is_some(),
                observe_target_alerts: args.observe_target_alerts,
                #[cfg(feature = "witness-journal")]
                source: None,
            })
        },
        shutdown_signal(),
    )
}

/// Already-owned startup choices for the common administration/data-plane
/// supervisor. Construction alone neither binds a listener nor activates policy.
/// Kernel attachment and privilege reduction must precede the runtime below.
struct Prepared {
    state: Arc<AppState>,
    bind: SocketAddr,
    tls: Acceptor,
    acme: Option<super::acme::Prepared>,
    certificate_source: super::certificates::ManagementSource,
    service_tls: Option<super::proxy::settings::Tls>,
    node: Option<super::node::Config>,
    prepared_proxy: Option<super::proxy::Prepared>,
    profile_config: crate::ebpf::Config,
    health_config: super::health::Config,
    health_explicit: bool,
    observe_target_alerts: bool,
    /// Original registered reference and actual node signer, not a takeover
    /// grant. Rechecked after startup writes and binds, before any accept/issuer.
    #[cfg(feature = "witness-journal")]
    source: Option<(super::store::journal::configuration::Reference, [u8; 32])>,
}

/// Keep proxy reaping, final metering and Source writer completion outside the
/// cancellable startup/supervision future. The original stop future is polled
/// once for both startup and steady state; it is never recreated on a retry.
fn run_prepared(
    prepare: impl std::future::Future<Output = io::Result<Prepared>>,
    stop: impl std::future::Future<Output = io::Result<()>> + Send + 'static,
) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()?;
    // These owners outlive the async supervisor. Runtime destruction may block;
    // the proxy reaper is joined outside the management executor, with its
    // process-author guard retained until data-plane cleanup actually finishes.
    let mut running_proxy = None;
    let mut managed_proxy = None;
    let mut state_owner = None;
    let mut writer_owner = None;
    // A planned drain may consume Completion while management stays online.
    // Keep its failure outside that future: finish() cannot return it twice.
    let mut driver_error = None;
    let mut result = runtime.block_on(async {
        let mut signals = JoinSet::new();
        signals.spawn(stop);
        let Prepared {
            mut state, bind, tls, acme, certificate_source, service_tls, node, prepared_proxy,
            profile_config, health_config, health_explicit, observe_target_alerts,
            #[cfg(feature = "witness-journal")]
            source,
        } = tokio::select! {
            prepared = prepare => prepared?,
            signal = signals.join_next() => return signal_result(signal),
        };
        // Retain the coordinator before any later fallible startup work. A
        // partial preparation must still drain its Source writer before Tokio
        // disappears. This owner must not prevent the unique AppState setup.
        writer_owner = state.policy.clone();
        let directory = state.directory.clone();
        let web_service=prepared_proxy.is_none() && service_tls.is_some() && state.schema_version>=27;
        #[cfg(feature = "witness-journal")]
        if source.is_some() && node.is_none() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "registered node transport required"));
        }
        let node_listener = if let Some(config) = node {
            if let Some(policy) = &state.policy {
                policy.read(super::store::list_peers).await?;
            } else {
                let database = directory.clone();
                tokio::task::spawn_blocking(move || super::store::list_peers(&database))
                    .await
                    .map_err(|_| io::Error::other("node database validation task failed"))??;
            }
            let listener = TcpListener::bind(config.bind).await?;
            Some((listener, config))
        } else {
            None
        };
        let node_directory = directory.clone();
        Arc::get_mut(&mut state)
            .ok_or_else(|| io::Error::other("management state was shared before initialization"))?
            .acme = acme.as_ref().map(super::acme::Prepared::status);
        let certificates = super::certificates::Handle::new(
            state.node.node_id.clone(),
            certificate_source,
            node_listener.as_ref().map_or(super::certificates::State::Disabled,
                |(_, config)| config.certificate.clone()),
            prepared_proxy.as_ref().map(super::proxy::Prepared::certificate_handle)
                .unwrap_or_default(),
        )?;
        Arc::get_mut(&mut state)
            .ok_or_else(|| io::Error::other("management state was shared before initialization"))?
            .certificates = Some(certificates);
        if let Some(policy) = state.policy.as_ref() {
            policy.configure_presets(profile_config.clone())?;
            if let Some(prepared) = prepared_proxy.as_ref() {
                policy.configure_endpoints(prepared.endpoints().to_vec())?;
            }
            if !web_service { policy.configure_endpoint_settings(&state.node.node_id).await?; }
        }
        let controller = match (state.policy.as_ref(), node_listener.as_ref()) {
            (Some(policy), Some((_, config))) if state.schema_version >= 10 => {
                let (controller, runner) = super::controller::Service::new(
                    policy.clone(), config.client_tls.clone(), state.node.node_id.clone());
                Arc::get_mut(&mut state)
                    .ok_or_else(|| io::Error::other("management state was shared before initialization"))?
                    .controller = Some(controller);
                Some(runner)
            }
            _ => None,
        };
        let observations = if observe_target_alerts {
            if state.schema_version < 22 || state.controller.is_none() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput,
                    "background target alerts require schema22 and a configured node mTLS listener; migrate explicitly before enabling"));
            }
            Some(super::observations::Handle::default())
        } else { None };
        let health_connector = prepared_proxy.as_ref().map(super::proxy::Prepared::connector)
            .unwrap_or_else(|| crate::connect::Connector::new(
                None, None, None, health_config.timeout_secs,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                None,
                Some(true),
            ));
        let health = if let Some(policy) = state.policy.as_ref() {
            let (handle, runner) = super::health::new(policy.clone(), health_connector, health_config)?;
            Arc::get_mut(&mut state)
                .ok_or_else(|| io::Error::other("management state was shared before initialization"))?
                .health = Some(handle);
            Some(runner)
        } else {
            if health_explicit {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                    "health observation requires an explicit management schema migration"));
            }
            None
        };
        let traffic = if let Some(policy) = state.policy.as_ref() {
            let (handle, runner) = super::traffic::new(policy.clone()).await?;
            Arc::get_mut(&mut state)
                .ok_or_else(|| io::Error::other("management state was shared before initialization"))?
                .traffic = Some(handle);
            Some(runner)
        } else {
            None
        };
        let listener = TcpListener::bind(bind).await?;
        if web_service {
            let policy=state.policy.clone().ok_or_else(||io::Error::other("managed service policy is missing"))?;
            let traffic=state.traffic.clone().ok_or_else(||io::Error::other("managed service traffic is missing"))?;
            let tls=service_tls.ok_or_else(||io::Error::other("managed service TLS is missing"))?;
            let mut ports=vec![listener.local_addr()?.port()];
            if let Some((listener,_))=node_listener.as_ref() { ports.push(listener.local_addr()?.port()); }
            if let Some((bind,_))=acme.as_ref().and_then(super::acme::Prepared::http) { ports.push(bind.port()); }
            let managed=super::proxy::service::Managed::new(policy.clone(),traffic,tls,profile_config,state.node.node_id.clone(),ports)?;
            let owner=super::proxy::service::Service::managed(managed,state._author.clone().ok_or_else(||io::Error::other("management author guard is missing"))?)?;
            let control=owner.control();
            managed_proxy=Some(owner);
            policy.configure_service(state.node.node_id.clone(),control.clone())?;
            state.certificates.as_ref().ok_or_else(||io::Error::other("certificate inventory is missing"))?.configure_service(control)?;
        }
        let remote_traffic = state.policy.as_ref().zip(state.controller.as_ref()).map(|(policy, controller)| {
            let runner = super::remote_traffic::Runner::new(policy.clone(), controller.clone());
            match observations.as_ref() {
                Some(observations) => runner.with_observations(observations.clone()),
                None => runner,
            }
        });
        // Alert facts include versioned endpoint/outbox and traffic metadata.
        // Old databases remain readable through their existing APIs; alerts do
        // not implicitly migrate them or mislabel missing tables as incidents.
        let alerts = if let Some(policy) = state.policy.as_ref().filter(|_| state.schema_version >= 17) {
            let (handle, mut runner) = super::alerts::new(
                policy.clone(),
                state.node.node_id.clone(),
                state.health.clone(),
                state.traffic.clone(),
                prepared_proxy.is_some() || policy.service().is_some(),
                remote_traffic.is_some(),
                state.acme.clone(),
                state.certificates.clone(),
            )?;
            if state.schema_version >= 21 {
                runner.enable_history();
            }
            if let Some(observations) = observations {
                runner.enable_remote_observation(observations);
            }
            Arc::get_mut(&mut state)
                .ok_or_else(|| io::Error::other("management state was shared before initialization"))?
                .alerts = Some(handle);
            Some(runner)
        } else {
            None
        };
        state_owner = Some(state.clone());
        // All validation listeners must be ready before the runner can ask the
        // CA to validate. Bind failure cannot leave a detached issuance task.
        let acme_http = if let Some((bind, http)) = acme.as_ref().and_then(super::acme::Prepared::http) {
            Some((TcpListener::bind(bind).await?, http))
        } else {
            None
        };
        #[cfg(feature = "witness-journal")]
        if let Some((reference, key)) = source {
            state.policy.as_ref().ok_or_else(|| io::Error::new(
                io::ErrorKind::PermissionDenied, "registered coordinator required"))?
                .source_startup(state.directory.clone(), reference, key).await?;
        }
        if let Some(prepared) = prepared_proxy {
            let policy = state.policy.as_ref().ok_or_else(|| io::Error::new(
                io::ErrorKind::InvalidData, "managed proxy requires an explicit management schema migration"))?;
            let author = state._author.clone().ok_or_else(|| io::Error::other("management author guard is missing"))?;
            state.traffic.as_ref().ok_or_else(|| io::Error::other("traffic collector is missing"))?
                .begin().await?;
            running_proxy = Some(super::proxy::start(prepared, policy.reader(), author)?);
            if let Some(proxy) = running_proxy.as_mut() {
                tokio::select! {
                    ready = timeout(Duration::from_secs(15), proxy.ready()) => ready
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "managed proxy startup timed out"))??,
                    signal = signals.join_next() => return signal_result(signal),
                }
                policy.configure_runtime(proxy.lifecycle())?;
            }
            policy.activate().await?;
        }
        if let Some(owner)=managed_proxy.as_mut() {
            tokio::select! {
                ready=owner.ready()=>ready?,
                signal=signals.join_next()=>return signal_result(signal),
            }
            let control=owner.control();
            tokio::select! {
                ready=control.restore()=>{ ready?; },
                signal=signals.join_next()=>return signal_result(signal),
            }
        }
        tracing::info!(address = %listener.local_addr()?, "management HTTPS API listening");
        let shutdown = CancellationToken::new();
        let mut listeners = JoinSet::new();
        if let Some(control)=state.policy.as_ref().and_then(|p|p.service()).cloned() {
            let token=shutdown.clone();
            listeners.spawn(async move{control.monitor(token).await});
        }
        if let Some(controller) = controller {
            listeners.spawn(controller.run(shutdown.clone()));
        }
        if let Some(remote_traffic) = remote_traffic {
            listeners.spawn(remote_traffic.run(shutdown.clone()));
        }
        if let Some(health) = health {
            listeners.spawn(health.run(shutdown.clone()));
        }
        if let Some(traffic) = traffic {
            listeners.spawn(traffic.run(shutdown.clone()));
        }
        if let Some(alerts) = alerts {
            listeners.spawn(alerts.run(shutdown.clone()));
        }
        if state.schema_version >= 23 && let Some(policy) = state.policy.as_ref() {
            listeners.spawn(super::notifications::run(policy.clone(), shutdown.clone()));
        }
        if let Some((listener, http)) = acme_http {
            tracing::info!(address = %listener.local_addr()?, "ACME challenge-only HTTP listener ready");
            listeners.spawn(http.serve(listener, shutdown.clone()));
        }
        if let Some(acme) = acme {
            listeners.spawn(acme.run(shutdown.clone()));
        }
        listeners.spawn(serve(
            listener,
            tls,
            router(state.clone()),
            shutdown.clone(),
        ));
        if let Some((listener, config)) = node_listener {
            tracing::info!(address = %listener.local_addr()?, "node mTLS API listening");
            listeners.spawn(super::node::serve(
                listener,
                config,
                node_directory,
                shutdown.clone(),
                state.policy.clone(),
                state.health.clone(),
                state.alerts.clone(),
            ));
        }
        let proxy_handle = running_proxy.as_ref().map(super::proxy::Running::handle);
        let signal = async { signal_result(signals.join_next().await) };
        let stop = async {
            if let Some(proxy) = running_proxy.as_mut() {
                let lifecycle = proxy.lifecycle();
                supervise_proxy(
                    proxy.finished(), signal, lifecycle, state.policy.as_ref(), &mut driver_error,
                ).await
            } else {
                signal.await
            }
        };
        supervise(listeners, shutdown, stop, proxy_handle, state.policy.clone()).await
    });
    if let Some(error) = driver_error {
        if let Err(later) = &result {
            tracing::error!(kind = ?later.kind(),
                "management stopped after an earlier proxy drain error");
        }
        result = Err(error);
    }
    let mut proxy_runtime_stopped = true;
    if let Some(proxy) = running_proxy {
        let cleanup = proxy.finish();
        proxy_runtime_stopped = cleanup.runtime_stopped;
        match (result.is_ok(), cleanup.result) {
            (true, cleanup) => result = cleanup,
            // Completion may repeat a startup/listener error even when the
            // runtime stopped cleanly. Preserve that separate teardown fact.
            (false, Err(error)) => tracing::error!(kind = ?error.kind(),
                runtime_stopped = proxy_runtime_stopped,
                "managed proxy completion reported an error after an earlier service error"),
            (false, Ok(())) => {}
        }
    }
    if let Some(proxy) = managed_proxy {
        let cleanup = proxy.finish();
        proxy_runtime_stopped &= cleanup.runtime_stopped;
        if result.is_ok() {
            result = cleanup.result;
        } else if let Err(error) = cleanup.result {
            tracing::error!(kind=?error.kind(),runtime_stopped=proxy_runtime_stopped,"managed service cleanup failed after earlier service error");
        }
    }
    if let Some(state) = state_owner.as_ref()
        && let Some(traffic) = state.traffic.as_ref()
    {
        // The proxy reaper has now confirmed runtime teardown, or reported its
        // failure. Stopping the async listener/collector alone was not enough:
        // draining flows may have accepted more payload after that cancellation.
        let flush = runtime.block_on(async {
            timeout(
                Duration::from_secs(15),
                traffic.finish(proxy_runtime_stopped),
            )
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "final traffic checkpoint timed out",
                )
            })?
        });
        match (result.is_ok(), flush) {
            (true, flush) => result = flush,
            (false, Err(error)) => tracing::error!(kind = ?error.kind(),
                "final traffic checkpoint failed after an earlier service error"),
            (false, Ok(())) => {}
        }
    }
    if let Some(policy) = state_owner
        .as_ref()
        .and_then(|state| state.policy.as_ref())
        .or(writer_owner.as_ref())
    {
        // A witnessed source thread still needs this runtime for Offline TLS
        // authorization. Drain its accepted work before destroying Tokio;
        // dropping a wait is not proof that a write or confirmation stopped.
        let stopped = runtime.block_on(policy.shutdown_writer());
        match (result.is_ok(), stopped) {
            (true, stopped) => result = stopped,
            (false, Err(error)) => tracing::error!(kind = ?error.kind(),
                "source writer shutdown failed after an earlier service error"),
            (false, Ok(())) => {}
        }
    }
    runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
    drop(state_owner);
    result
}

/// Pure startup-file validation for a private snapshot; no observer, socket or
/// DNS request is created. Keep the ordinary serve parser as the source of truth.
pub(super) fn check_health_configuration(path: &Path) -> io::Result<()> {
    health::load(Some(path)).map(|_| ())
}

/// Keep fixed-input capture and ordinary serve on the same bounded parser.
pub(super) fn captured_health_configuration(bytes: &[u8]) -> io::Result<super::health::Config> {
    health::from_bytes(bytes)
}

/// Canonical origin and matching HTTP Host authority, validated once at startup.
/// Restricting spelling prevents a browser's URL normalization from producing a
/// different Origin than the configured value (especially explicit port 443).
pub(super) struct PublicOrigin {
    value: String,
    authority: String,
}

impl PublicOrigin {
    pub(super) fn parse(value: &str) -> io::Result<Self> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "public origin must be canonical https://authority without userinfo, path, query or fragment",
            )
        };
        // Match the browser's WHATWG URL parser, rather than treating spellings
        // such as 127.1, hexadecimal IPv4 or Unicode DNS as canonical origins.
        let url = url::Url::parse(value).map_err(|_| invalid())?;
        if value.len() > 300
            || url.scheme() != "https"
            || url.host().is_none()
            || url.port() == Some(0)
            || value != url.origin().ascii_serialization()
        {
            return Err(invalid());
        }
        let authority = value.strip_prefix("https://").ok_or_else(invalid)?;
        Ok(Self {
            value: value.to_owned(),
            authority: authority.to_owned(),
        })
    }

    pub(super) fn value(&self) -> &str {
        &self.value
    }

    pub(super) fn authority(&self) -> &str {
        &self.authority
    }
}

/// Shared API state contains no proxy connector and cannot forward user traffic.
struct AppState {
    directory: PathBuf,
    // Older schemas keep local policy/node services but cannot query the new
    // target metadata column before an explicit, backed-up migration.
    schema_version: u32,
    origin: PublicOrigin,
    node: NodeView,
    dummy_phc: String,
    password_work: Arc<Semaphore>,
    security: Mutex<SecurityState>,
    policy: Option<Arc<super::policy::Coordinator>>,
    controller: Option<Arc<super::controller::Service>>,
    health: Option<super::health::Handle>,
    traffic: Option<super::traffic::Handle>,
    alerts: Option<super::alerts::Handle>,
    acme: Option<super::acme::Handle>,
    certificates: Option<super::certificates::Handle>,
    // Normal initialization always holds an author guard. In-memory router
    // fixtures intentionally omit filesystem ownership and the policy service.
    _author: Option<Arc<super::store::Guard>>,
}

impl AppState {
    /// A locally committed Source row is not yet authority. This check never
    /// acquires SQL or a writer permit and is a no-op for ordinary Native state.
    fn confirmed(&self) -> Result<(), ApiError> {
        if let Some(policy) = &self.policy {
            policy.ensure_source_confirmed().map_err(|_| {
                ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "authentication_busy")
            })?;
        }
        Ok(())
    }

    /// A poisoned security lock is a failed request, never an unauthenticated
    /// fallback or an excuse to discard existing rate/session state.
    fn security(&self) -> Result<MutexGuard<'_, SecurityState>, ApiError> {
        self.security.lock().map_err(|_| ApiError::internal())
    }
}

/// Direct TCP peer, supplied outside the router; Forwarded/X-Forwarded-For have
/// no authority for the per-source login budget.
#[derive(Clone, Copy)]
struct PeerIp(IpAddr);

/// Only facts available to this management process are advertised. CPU, proxy
/// state, throughput and IP health remain absent until real collectors exist.
#[derive(Serialize)]
struct NodeView {
    node_id: String,
    name: String,
    version: &'static str,
    os: &'static str,
    arch: &'static str,
    capabilities: [&'static str; 1],
}

#[derive(Clone, Serialize)]
struct AdministratorView {
    id: String,
    username: String,
}

/// Session lifetime is enforced by monotonic time, not a user-adjustable clock.
/// The Unix expiry is display metadata only. Neither random secret is logged.
struct Session {
    administrator: AdministratorView,
    csrf_token: String,
    created_at: Instant,
    expires_at: u64,
}

#[derive(Serialize)]
struct SessionView {
    administrator: AdministratorView,
    csrf_token: String,
    expires_at: u64,
}

impl Session {
    fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created_at) >= SESSION_LIFETIME
    }

    fn view(&self) -> SessionView {
        SessionView {
            administrator: self.administrator.clone(),
            csrf_token: self.csrf_token.clone(),
            expires_at: self.expires_at,
        }
    }
}

/// A bounded fixed window; failed/malformed login attempts consume budget too.
struct RateWindow {
    started_at: Instant,
    attempts: u16,
}

impl RateWindow {
    fn new(now: Instant) -> Self {
        Self {
            started_at: now,
            attempts: 0,
        }
    }

    fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.started_at) >= RATE_WINDOW
    }
}

/// In-process state is bounded independently of administrator/database size.
struct SecurityState {
    sessions: HashMap<String, Session>,
    address_rates: HashMap<IpAddr, RateWindow>,
    global_rate: RateWindow,
    // A global fence rejects old in-flight login verifications, even when they
    // read the former PHC just before another request commits a password change.
    login_generation: u64,
    // At most one change may cross the session/SQL boundary at a time. Unknown
    // commit outcomes keep this fail-closed until restart; no guessed rollback.
    password_change_pending: bool,
}

impl SecurityState {
    fn new(now: Instant) -> Self {
        Self {
            sessions: HashMap::new(),
            address_rates: HashMap::new(),
            global_rate: RateWindow::new(now),
            login_generation: 0,
            password_change_pending: false,
        }
    }

    /// Expired entries are removed before admission; active addresses are not
    /// evicted to let an attacker rotate source addresses around their limits.
    fn allow_login(&mut self, address: IpAddr, now: Instant) -> bool {
        if self.global_rate.expired(now) {
            self.global_rate = RateWindow::new(now);
        }
        self.address_rates.retain(|_, rate| !rate.expired(now));
        if self.global_rate.attempts >= GLOBAL_LOGIN_LIMIT {
            return false;
        }
        if !self.address_rates.contains_key(&address)
            && self.address_rates.len() >= MAX_RATE_ADDRESSES
        {
            return false;
        }
        let rate = self
            .address_rates
            .entry(address)
            .or_insert_with(|| RateWindow::new(now));
        if rate.attempts >= IP_LOGIN_LIMIT {
            return false;
        }
        rate.attempts += 1;
        self.global_rate.attempts += 1;
        true
    }

    fn session(&mut self, token: &str, now: Instant) -> Result<&Session, ApiError> {
        self.sessions.retain(|_, session| !session.expired(now));
        self.sessions
            .get(token)
            .ok_or_else(ApiError::authentication_required)
    }

    /// Rotation happens only after successful password verification. No live
    /// session is evicted to make room for a new browser at the capacity limit.
    fn insert_session(
        &mut self,
        old_token: Option<&str>,
        token: String,
        session: Session,
    ) -> Result<SessionView, ApiError> {
        self.sessions
            .retain(|_, entry| !entry.expired(session.created_at));
        let replacing = old_token.is_some_and(|old| self.sessions.contains_key(old));
        if !replacing && self.sessions.len() >= MAX_SESSIONS {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "session_capacity",
            ));
        }
        if self.sessions.contains_key(&token) {
            return Err(ApiError::internal());
        }
        if let Some(old) = old_token {
            self.sessions.remove(old);
        }
        let view = session.view();
        self.sessions.insert(token, session);
        Ok(view)
    }

    /// Verification happens outside this mutex; generation and insertion must
    /// be checked under the same lock so a late old-PHC login cannot reappear.
    fn insert_verified_session(
        &mut self,
        generation: u64,
        old_token: Option<&str>,
        token: String,
        session: Session,
    ) -> Result<SessionView, ApiError> {
        if self.password_change_pending || self.login_generation != generation {
            return Err(ApiError::authentication_required());
        }
        self.insert_session(old_token, token, session)
    }
}

/// Public failures contain stable codes only; filesystem, SQL and password
/// verifier details are never sent to clients or included in request logging.
#[derive(Debug)]
pub(super) struct ApiError {
    status: StatusCode,
    code: &'static str,
    challenge: Option<&'static str>,
}

impl ApiError {
    pub(super) const fn new(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code,
            challenge: None,
        }
    }

    pub(super) const fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
    }

    /// Cookie/form authentication is outside HTTP challenge authentication
    /// (RFC 9110 section 11.1). A 401 would require an applicable challenge under
    /// section 15.5.2; advertising Basic/Bearer here would falsely promise one.
    /// https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.2
    const fn authentication_required() -> Self {
        Self::new(StatusCode::FORBIDDEN, "authentication_required")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct ErrorDetail {
            code: &'static str,
        }
        #[derive(Serialize)]
        struct ErrorBody {
            error: ErrorDetail,
        }
        let mut response = (
            self.status,
            Json(ErrorBody {
                error: ErrorDetail { code: self.code },
            }),
        )
            .into_response();
        if self.status == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        }
        if let Some(challenge) = self.challenge {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(challenge),
            );
        }
        response
    }
}

/// Read existing metadata and create a fresh, same-cost unknown-user verifier
/// before binding a socket. Neither startup nor login creates missing DB state.
/// The caller supplies its already-held author; cancellation leaves any blocking
/// initializer owning that guard until its actual work finishes.
async fn initialize(
    directory: PathBuf,
    origin: PublicOrigin,
    author: Arc<super::store::Guard>,
) -> io::Result<Arc<AppState>> {
    let database_directory = directory.clone();
    let (overview, dummy_phc, author, policy) = tokio::task::spawn_blocking(move || {
        author.ensure(&database_directory)?;
        // Reusable initialization must not bypass the ordinary Source/recovery
        // gate merely because the outer CLI already checked before binding.
        super::store::recovery::startup(&database_directory)?;
        let overview = super::store::inspect(&database_directory)?;
        let policy = if overview.schema_version >= 9 {
            Some(super::policy::Coordinator::new(
                database_directory.clone(),
                super::store::load_policy(&database_directory)?,
                author.clone(),
            )?)
        } else {
            None
        };
        let dummy_phc = dummy_verifier()?;
        Ok::<_, io::Error>((overview, dummy_phc, author, policy))
    })
    .await
    .map_err(|_| io::Error::other("management initialization task failed"))??;
    Ok(initialized_state(
        directory, origin, overview, dummy_phc, author, policy,
    ))
}

/// Native and registered startup use the same fresh unknown-user verifier cost.
/// Run only in owned startup blocking work; no plaintext survives this function.
fn dummy_verifier() -> io::Result<String> {
    let mut secret = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *secret).map_err(|_| io::Error::other("random source failed"))?;
    Argon2::default()
        .hash_password(&*secret)
        .map(|hash| hash.to_string())
        .map_err(|_| io::Error::other("failed to prepare password verifier"))
}

/// Construct only process-local state from already-checked metadata and owners.
/// Neither this helper nor a verifier grants Source startup/activation authority.
fn initialized_state(
    directory: PathBuf,
    origin: PublicOrigin,
    overview: super::store::Overview,
    dummy_phc: String,
    author: Arc<super::store::Guard>,
    policy: Option<Arc<super::policy::Coordinator>>,
) -> Arc<AppState> {
    Arc::new(AppState {
        directory,
        schema_version: overview.schema_version,
        origin,
        node: NodeView {
            node_id: overview.node_id,
            name: overview.name,
            version: env!("CARGO_PKG_VERSION"),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            capabilities: ["local_administration"],
        },
        dummy_phc,
        password_work: Arc::new(Semaphore::new(2)),
        security: Mutex::new(SecurityState::new(Instant::now())),
        policy,
        controller: None,
        health: None,
        traffic: None,
        alerts: None,
        acme: None,
        certificates: None,
        _author: Some(author),
    })
}

/// Acquire the process lifetime gate before inspecting recovery readiness.
/// No egress program, TLS identity, runtime or listener is created on rejection.
fn startup(directory: &Path) -> io::Result<(Arc<super::store::Guard>, Option<[u8; 32]>)> {
    let author = Arc::new(super::store::lock(directory)?);
    let key = super::store::recovery::startup(directory)?;
    Ok((author, key))
}

fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/session", get(current_session))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/password", post(password::change))
        .route("/api/v1/node", get(node))
        .merge(alerts::routes(state.clone()))
        .merge(notifications::routes(state.clone()))
        .merge(acme::routes(state.clone()))
        .merge(certificates::routes(state.clone()))
        .merge(maintenance::routes(state.clone()))
        .merge(runtime::routes(state.clone()))
        .merge(service::routes(state.clone()))
        .merge(users::routes(state.clone()))
        .merge(endpoints::routes(state.clone()))
        .merge(routing::routes(state.clone()))
        .merge(presets::routes(state.clone()))
        .merge(health::routes(state.clone()))
        .merge(traffic::routes(state.clone()))
        .merge(remote_traffic::routes(state.clone()))
        .merge(targets::routes(state.clone()))
        .fallback(not_found)
        .method_not_allowed_fallback(|| async {
            ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed")
        })
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

async fn not_found(request: Request) -> Response {
    #[cfg(feature = "web-ui")]
    if !request.uri().path().starts_with("/api/")
        && let Some(response) =
            super::assets::response(request.method(), request.uri(), request.headers())
    {
        return response;
    }
    #[cfg(not(feature = "web-ui"))]
    let _ = request;
    ApiError::new(StatusCode::NOT_FOUND, "not_found").into_response()
}

/// Admit only this configured HTTPS origin, never arbitrary proxy destinations.
/// Host must exist exactly once and be valid even when absolute-form supplies
/// the target authority. In that form its value cannot override the URI:
/// https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2
/// Browser mutations additionally require the configured Origin and JSON.
fn validate_request(
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    origin: &PublicOrigin,
) -> Result<(), ApiError> {
    validate_target(headers, uri, origin)?;
    automation::validate_request(headers, method, uri)?;
    let bearer = headers.contains_key(header::AUTHORIZATION) && automation::enabled(method, uri);
    let mutation = !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    let supplied_origin = if bearer || mutation {
        single_header(headers, header::ORIGIN)?
    } else {
        None
    };
    if bearer && supplied_origin.is_some_and(|value| value != origin.value()) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "invalid_origin"));
    }
    if mutation {
        if !bearer && supplied_origin != Some(origin.value()) {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "invalid_origin"));
        }
        let content_type =
            single_header(headers, header::CONTENT_TYPE)?.and_then(|value| value.split(';').next());
        if !content_type.is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "json_required",
            ));
        }
    }
    Ok(())
}

/// Check only HTTP destination authority, without applying browser identity,
/// Cookie or CSRF rules to the separately authenticated node listener.
/// https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2
pub(super) fn validate_target(
    headers: &HeaderMap,
    uri: &Uri,
    origin: &PublicOrigin,
) -> Result<(), ApiError> {
    // RFC 9112 section 3.2 requires 400 for missing/duplicate/invalid Host.
    // Empty Host is syntactically permitted for an unspecified authority; it
    // simply cannot select this service when no absolute URI supplies one.
    // https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2
    let invalid_host = || ApiError::new(StatusCode::BAD_REQUEST, "invalid_host");
    let host = single_header(headers, header::HOST)?.ok_or_else(invalid_host)?;
    if !host.is_empty() {
        let authority: Authority = host.parse().map_err(|_| invalid_host())?;
        if host.contains(['@', ','])
            || authority.host().is_empty()
            || authority
                .as_str()
                .strip_prefix(authority.host())
                .filter(|suffix| !suffix.is_empty())
                .is_some_and(|suffix| {
                    !suffix
                        .strip_prefix(':')
                        .is_some_and(|port| port.bytes().all(|byte| byte.is_ascii_digit()))
                })
        {
            return Err(invalid_host());
        }
    }
    if uri.scheme().is_some() || uri.authority().is_some() {
        if uri.scheme_str() != Some("https")
            || uri.authority().map(Authority::as_str) != Some(origin.authority())
        {
            return Err(ApiError::new(
                StatusCode::MISDIRECTED_REQUEST,
                "misdirected_request",
            ));
        }
    } else if host != origin.authority() {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "invalid_host"));
    }
    Ok(())
}

fn single_header(headers: &HeaderMap, name: header::HeaderName) -> Result<Option<&str>, ApiError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .map(|value| value.to_str())
        .transpose()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_headers"))?;
    if values.next().is_some() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_headers"));
    }
    Ok(value)
}

async fn guard(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    let read = matches!(*request.method(), Method::GET | Method::HEAD);
    let mut response = match validate_request(
        request.headers(),
        request.method(),
        request.uri(),
        &state.origin,
    ) {
        Err(error) => error.into_response(),
        Ok(()) => match state.confirmed() {
            Err(error) => error.into_response(),
            Ok(()) => match timeout(REQUEST_TIMEOUT, next.run(request)).await {
                // Reads must not export locally committed, unconfirmed facts.
                // Do not replace a mutation handler's original outcome-unknown
                // response with a generic authentication error after dispatch.
                Ok(response) if read => match state.confirmed() {
                    Ok(()) => response,
                    Err(error) => error.into_response(),
                },
                Ok(response) => response,
                Err(_) => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "request_timeout")
                    .into_response(),
            },
        },
    };
    for (name, value) in [
        (header::CACHE_CONTROL, "no-store"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; frame-ancestors 'none'",
        ),
    ] {
        response
            .headers_mut()
            .entry(name)
            .or_insert(HeaderValue::from_static(value));
    }
    response
}

/// Consume a bounded JSON object within a body deadline. Body I/O failures are
/// distinct from size and syntax errors; no rejection exposes parser internals.
pub(super) async fn json<T: DeserializeOwned>(request: Request) -> Result<T, ApiError> {
    json_with_limit(request, MAX_JSON_BYTES).await
}

/// A route may allow a larger bounded wire representation without changing the
/// decoded field limits or widening every management mutation's body allowance.
async fn json_with_limit<T: DeserializeOwned>(
    request: Request,
    limit: usize,
) -> Result<T, ApiError> {
    use std::error::Error as _;
    let bytes = timeout(JSON_TIMEOUT, to_bytes(request.into_body(), limit))
        .await
        .map_err(|_| ApiError::new(StatusCode::REQUEST_TIMEOUT, "body_timeout"))?
        .map_err(|error| {
            if error
                .source()
                .is_some_and(|source| source.is::<http_body_util::LengthLimitError>())
            {
                ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large")
            } else {
                ApiError::new(StatusCode::BAD_REQUEST, "invalid_body")
            }
        })?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_json"))
}

/// Input has no Debug/Serialize implementation: passwords must not enter traces
/// through generic request logging or an accidental response echo.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginInput {
    username: String,
    password: String,
}

async fn login(
    State(state): State<Arc<AppState>>,
    Extension(PeerIp(address)): Extension<PeerIp>,
    request: Request,
) -> Result<Response, ApiError> {
    let generation = {
        let mut security = state.security()?;
        if !security.allow_login(address, Instant::now()) {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "login_rate_limited",
            ));
        }
        if security.password_change_pending {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_busy",
            ));
        }
        security.login_generation
    };
    let old_token = session_cookie(request.headers())?.map(str::to_owned);
    let LoginInput { username, password } = json(request).await?;
    let password = Zeroizing::new(password);
    if username.is_empty()
        || username.len() > 64
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        || password.len() > super::MAX_PASSWORD_BYTES
        || password.chars().any(char::is_control)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_credentials_input",
        ));
    }
    let permit = state
        .password_work
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "authentication_busy"))?;
    let verification = state.clone();
    // The permit belongs to the blocking operation, not this cancellable HTTP
    // future. A disconnected browser cannot release capacity while Argon2 runs.
    let administrator = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        super::store::authenticate(
            &verification.directory,
            &username,
            password.as_bytes(),
            &verification.dummy_phc,
        )
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(|_| ApiError::internal())?;
    // Hashing/body I/O can outlive the earlier guard. Check both successful and
    // failed verification before issuing a cookie or blaming the credentials.
    state.confirmed()?;
    let administrator =
        administrator.ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "invalid_credentials"))?;
    let token = random_token()?;
    let session = Session {
        administrator: AdministratorView {
            id: administrator.id,
            username: administrator.username,
        },
        csrf_token: random_token()?,
        created_at: Instant::now(),
        expires_at: SystemTime::now()
            .checked_add(SESSION_LIFETIME)
            .and_then(|expiry| expiry.duration_since(UNIX_EPOCH).ok())
            .map(|expiry| expiry.as_secs())
            .ok_or_else(ApiError::internal)?,
    };
    let cookie = HeaderValue::from_str(&format!(
        "{COOKIE_NAME}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
        SESSION_LIFETIME.as_secs()
    ))
    .map_err(|_| ApiError::internal())?;
    let view = state.security()?.insert_verified_session(
        generation,
        old_token.as_deref(),
        token,
        session,
    )?;
    let mut response = Json(view).into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(response)
}

/// Ambiguous duplicate session cookies fail closed; no cookie prefix matching or
/// URL decoding can turn another application's cookie into this session token.
fn session_cookie(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE) {
        let value = value
            .to_str()
            .map_err(|_| ApiError::authentication_required())?;
        for cookie in value.split(';') {
            let Some((name, value)) = cookie.trim().split_once('=') else {
                continue;
            };
            if name != COOKIE_NAME {
                continue;
            }
            if found.is_some()
                || value.len() != 43
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
            {
                return Err(ApiError::authentication_required());
            }
            found = Some(value);
        }
    }
    Ok(found)
}

fn random_token() -> Result<String, ApiError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *bytes).map_err(|_| ApiError::internal())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes.as_slice()))
}

fn authenticated_session(headers: &HeaderMap, state: &AppState) -> Result<SessionView, ApiError> {
    state.confirmed()?;
    let token = session_cookie(headers)?.ok_or_else(ApiError::authentication_required)?;
    state
        .security()?
        .session(token, Instant::now())
        .map(Session::view)
}

async fn current_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<SessionView>, ApiError> {
    authenticated_session(&headers, &state).map(Json)
}

async fn node(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    authenticated_session(&headers, &state)?;
    Ok(Json(&state.node).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyInput {}

async fn logout(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Response, ApiError> {
    let token = session_cookie(request.headers())?
        .ok_or_else(ApiError::authentication_required)?
        .to_owned();
    let csrf = single_header(
        request.headers(),
        header::HeaderName::from_static("x-csrf-token"),
    )?
    .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "invalid_csrf"))?
    .to_owned();
    {
        let mut security = state.security()?;
        let session = security.session(&token, Instant::now())?;
        if !bool::from(session.csrf_token.as_bytes().ct_eq(csrf.as_bytes())) {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "invalid_csrf"));
        }
    }
    let _: EmptyInput = json(request).await?;
    state.security()?.sessions.remove(&token);
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-vproxy-session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    Ok(response)
}

/// Admit at most 128 TCP connections including TLS handshakes. Every connection
/// has a total lifetime cap; SIGINT/SIGTERM stops admission and drains for 5 s.
async fn serve(
    listener: TcpListener,
    tls: impl Into<Acceptor>,
    app: Router,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let tls = tls.into();
    let connections_shutdown = shutdown.child_token();
    let mut connections = JoinSet::new();
    let capacity = Arc::new(Semaphore::new(128));
    let mut last_accept_warning: Option<Instant> = None;
    let result = loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break Ok(()),
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result { tracing::debug!(cancelled = error.is_cancelled(), "management connection task ended"); }
            }
            incoming = listener.accept() => {
                let (stream, address) = match incoming {
                    Ok(connection) => connection,
                    Err(error) if retryable_accept_error(&error) => {
                        let now = Instant::now();
                        if last_accept_warning.is_none_or(|last| now.saturating_duration_since(last) >= Duration::from_secs(60)) {
                            tracing::warn!(kind = ?error.kind(), code = error.raw_os_error(), "management accept temporarily unavailable; retrying");
                            last_accept_warning = Some(now);
                        }
                        tokio::select! {
                            _ = shutdown.cancelled() => break Ok(()),
                            _ = tokio::time::sleep(Duration::from_millis(200)) => continue,
                        }
                    }
                    Err(error) => break Err(error),
                };
                let Ok(permit) = capacity.clone().try_acquire_owned() else { continue; };
                let tls = tls.clone();
                let app = app.clone();
                let shutdown = connections_shutdown.clone();
                let ip = match address.ip() { IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(ip)), ip => ip };
                connections.spawn(async move {
                    let _permit = permit;
                    let _ = timeout(CONNECTION_TIMEOUT, serve_connection(stream, tls, app, PeerIp(ip), shutdown)).await;
                });
            }
        }
    };
    drop(listener);
    connections_shutdown.cancel();
    if timeout(SHUTDOWN_TIMEOUT, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    result
}

/// One signal owner supervises both identity domains. A fatal listener result
/// stops its sibling, and all connection tasks receive the same drain request.
/// The supplied signal future is held for the entire wait, never re-created by
/// an accept retry. Dropping this supervisor also requests cancellation.
async fn supervise(
    mut listeners: JoinSet<io::Result<()>>,
    shutdown: CancellationToken,
    signal: impl std::future::Future<Output = io::Result<()>>,
    proxy: Option<crate::server::Handle>,
    policy: Option<Arc<super::policy::Coordinator>>,
) -> io::Result<()> {
    let stop = Shutdown {
        management: shutdown,
        proxy,
        policy,
    };
    let mut result = tokio::select! {
        biased;
        result = signal => result,
        result = listeners.join_next() => match result {
            Some(Ok(Err(error))) => Err(error),
            Some(Err(_)) => Err(io::Error::other("management listener task failed")),
            _ => Err(io::Error::other("management listener stopped unexpectedly")),
        },
    };
    stop.cancel();
    let drain = async {
        while let Some(joined) = listeners.join_next().await {
            let error = match joined {
                Ok(Err(error)) => Some(error),
                Err(_) => Some(io::Error::other("management listener task failed")),
                Ok(Ok(())) => None,
            };
            if result.is_ok()
                && let Some(error) = error
            {
                result = Err(error);
            }
        }
    };
    if timeout(SHUTDOWN_TIMEOUT, drain).await.is_err() {
        listeners.abort_all();
        while listeners.join_next().await.is_some() {}
    }
    result
}

/// Consume the driver's result at most once. A recognised maintenance request
/// leaves the original signal future and administration listeners alive; it
/// does not destroy the retained worker runtime or finalise traffic collection.
/// A driver error is saved even if a later administration failure cancels this
/// wait. Unplanned completion retains the previous fatal-service behaviour.
async fn supervise_proxy(
    completion: impl std::future::Future<Output = io::Result<()>>,
    signal: impl std::future::Future<Output = io::Result<()>>,
    lifecycle: super::proxy::Lifecycle,
    policy: Option<&Arc<super::policy::Coordinator>>,
    driver_error: &mut Option<io::Error>,
) -> io::Result<()> {
    tokio::pin!(signal);
    let result = tokio::select! {
        biased;
        result = signal.as_mut() => return result,
        result = completion => result,
    };
    if let Some(policy) = policy {
        policy.deactivate();
    }
    let planned = match lifecycle.complete(&result) {
        Ok(planned) => planned,
        Err(error) => {
            if let Err(driver) = result {
                driver_error.get_or_insert(driver);
            }
            return Err(error);
        }
    };
    if !planned {
        return result.and(Err(io::Error::other("managed proxy stopped unexpectedly")));
    }
    if let Err(error) = result {
        driver_error.get_or_insert(error);
    }
    signal.await
}

#[cfg(test)]
mod runtime_supervision_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::{
        manage::proxy::{DrainActor, DrainIntent, Lifecycle, Phase},
        server::Handle,
    };

    fn planned(lifecycle: &Lifecycle) {
        let id = lifecycle.snapshot().unwrap().runtime_id;
        lifecycle
            .request(
                &id,
                DrainIntent {
                    node_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
                    request_id: "AQEBAQEBAQEBAQEBAQEBAQ".into(),
                    epoch: 1,
                    revision: 2,
                    actor: DrainActor::Local {
                        administrator_id: "AgICAgICAgICAgICAgICAg".into(),
                    },
                },
            )
            .unwrap();
    }

    #[tokio::test]
    async fn planned_completion_keeps_original_signal_and_retains_driver_error() {
        for kind in [
            None,
            Some(io::ErrorKind::TimedOut),
            Some(io::ErrorKind::PermissionDenied),
        ] {
            let lifecycle = Lifecycle::new(Handle::new()).unwrap();
            planned(&lifecycle);
            let (stop, signal) = tokio::sync::oneshot::channel();
            let starts = Arc::new(AtomicUsize::new(0));
            let counted = starts.clone();
            let signal = async move {
                counted.fetch_add(1, Ordering::Relaxed);
                signal
                    .await
                    .map_err(|_| io::Error::other("fixture signal dropped"))
            };
            let completion = async move {
                kind.map_or(Ok(()), |kind| {
                    Err(io::Error::new(kind, "original driver fixture"))
                })
            };
            let mut driver_error = None;
            {
                let wait = supervise_proxy(
                    completion,
                    signal,
                    lifecycle.clone(),
                    None,
                    &mut driver_error,
                );
                tokio::pin!(wait);
                assert!(futures_util::poll!(wait.as_mut()).is_pending());
                assert_eq!(starts.load(Ordering::Relaxed), 1);
                assert_eq!(
                    lifecycle.snapshot().unwrap().phase,
                    match kind {
                        None => Phase::Drained,
                        Some(io::ErrorKind::TimedOut) => Phase::Interrupted,
                        _ => Phase::Failed,
                    }
                );
                stop.send(()).unwrap();
                wait.await.unwrap();
            }
            assert_eq!(starts.load(Ordering::Relaxed), 1);
            // No completion is requested again when the signal finally arrives.
            assert_eq!(driver_error.as_ref().map(io::Error::kind), kind);
            if let Some(error) = driver_error {
                assert_eq!(error.to_string(), "original driver fixture");
            }
        }
    }

    #[tokio::test]
    async fn unplanned_completion_and_early_signal_keep_existing_fatal_boundary() {
        let lifecycle = Lifecycle::new(Handle::new()).unwrap();
        let mut driver_error = None;
        let error = supervise_proxy(
            async { Ok(()) },
            std::future::pending(),
            lifecycle,
            None,
            &mut driver_error,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(driver_error.is_none());

        let lifecycle = Lifecycle::new(Handle::new()).unwrap();
        planned(&lifecycle);
        supervise_proxy(
            std::future::pending(),
            async { Ok(()) },
            lifecycle.clone(),
            None,
            &mut driver_error,
        )
        .await
        .unwrap();
        assert_eq!(lifecycle.snapshot().unwrap().phase, Phase::Draining);
        assert!(driver_error.is_none());
    }
}

/// A single cancellation owner covers both administration and data-plane
/// admission, including supervisor cancellation before its normal drain path.
struct Shutdown {
    management: CancellationToken,
    proxy: Option<crate::server::Handle>,
    policy: Option<Arc<super::policy::Coordinator>>,
}

impl Shutdown {
    fn cancel(&self) {
        if let Some(policy) = &self.policy {
            policy.deactivate();
            if let Some(service) = policy.service() {
                service.shutdown();
            }
        }
        if let Some(proxy) = &self.proxy {
            proxy.request_graceful_shutdown();
        }
        self.management.cancel();
    }
}

impl Drop for Shutdown {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn signal_result(result: Option<Result<io::Result<()>, tokio::task::JoinError>>) -> io::Result<()> {
    match result {
        Some(Ok(result)) => result,
        _ => Err(io::Error::other("management signal task failed")),
    }
}

/// An individual pending connection or transient descriptor/memory exhaustion
/// must not stop all management sessions. Linux also returns pending network
/// errors directly from accept; its documented retry set is broader than EINTR.
/// https://man7.org/linux/man-pages/man2/accept.2.html
pub(super) fn retryable_accept_error(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::TimedOut
            | io::ErrorKind::OutOfMemory
    ) {
        return true;
    }
    let Some(code) = error.raw_os_error() else {
        return false;
    };
    #[cfg(unix)]
    if [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM].contains(&code) {
        return true;
    }
    #[cfg(target_os = "linux")]
    if [
        libc::ENETDOWN,
        libc::EPROTO,
        libc::ENOPROTOOPT,
        libc::EHOSTDOWN,
        libc::ENONET,
        libc::EHOSTUNREACH,
        libc::EOPNOTSUPP,
        libc::ENETUNREACH,
    ]
    .contains(&code)
    {
        return true;
    }
    #[cfg(windows)]
    if [10024, 10050, 10051, 10052, 10055, 10064, 10065].contains(&code) {
        return true;
    }
    #[cfg(not(any(unix, windows)))]
    let _ = code;
    false
}

/// Both modes produce the same authenticated HTTP transport. A challenge-only
/// handshake returns None and can never receive the administration router.
#[derive(Clone)]
enum Acceptor {
    Manual(TlsAcceptor),
    Acme(super::acme::Tls),
}

impl From<TlsAcceptor> for Acceptor {
    fn from(value: TlsAcceptor) -> Self {
        Self::Manual(value)
    }
}

impl Acceptor {
    async fn accept(
        &self,
        stream: TcpStream,
    ) -> io::Result<Option<tokio_rustls::server::TlsStream<TcpStream>>> {
        match self {
            Self::Manual(tls) => tls.accept(stream).await.map(Some),
            Self::Acme(tls) => tls.accept(stream).await,
        }
    }
}

async fn serve_connection(
    stream: TcpStream,
    tls: impl Into<Acceptor>,
    app: Router,
    peer: PeerIp,
    shutdown: CancellationToken,
) {
    let tls = tls.into();
    let stream = tokio::select! {
        _ = shutdown.cancelled() => return,
        stream = timeout(Duration::from_secs(5), tls.accept(stream)) => match stream { Ok(Ok(Some(stream))) => stream, _ => return },
    };
    let service = TowerToHyperService::new(app.layer(Extension(peer)));
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_buf_size(16 * 1024)
        .max_headers(64);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    tokio::select! {
        _ = connection.as_mut() => {},
        _ = shutdown.cancelled() => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
        }
    }
}

async fn shutdown_signal() -> io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            received = interrupt.recv() => received.ok_or_else(|| io::Error::other("SIGINT stream closed")),
            received = terminate.recv() => received.ok_or_else(|| io::Error::other("SIGTERM stream closed")),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

#[cfg(test)]
mod recovery_tests {
    //! Cold startup gates only; no listener, egress backend or remote is started.

    use super::*;
    use crate::manage::{node::tests::Fixture, store};

    fn restored(fixture: &Fixture, phase: &str, key: [u8; 32]) -> io::Result<()> {
        let connection =
            rusqlite::Connection::open(fixture.client_state.join("management.sqlite3"))
                .map_err(io::Error::other)?;
        connection.execute(
        "UPDATE recovery_state SET kind='restored',phase=?1,recovery_id=?2,source_node_id=?3,
         source_schema_version=13,source_database_sha256=?4,node_key_sha256=?5,
         imported_users=0,imported_prefixes=0,imported_addresses=0,imported_pools=0 WHERE singleton=1",
        rusqlite::params![phase, "AAAAAAAAAAAAAAAAAAAAAA", fixture.server_id, "1".repeat(64), &key[..]],
    ).map_err(io::Error::other)?;
        Ok(())
    }

    #[tokio::test]
    async fn startup_author_is_reused_and_retained_by_initialized_state() -> io::Result<()> {
        let fixture = tokio::task::spawn_blocking(|| Fixture::new(true, true))
            .await
            .map_err(io::Error::other)??;
        let (author, key) = startup(&fixture.client_state)?;
        assert!(key.is_none());
        let state = initialize(
            fixture.client_state.clone(),
            PublicOrigin::parse("https://localhost:8443")?,
            author.clone(),
        )
        .await?;
        drop(author);
        assert!(
            matches!(store::lock(&fixture.client_state), Err(error) if error.kind()==io::ErrorKind::WouldBlock)
        );
        drop(state);
        drop(store::lock(&fixture.client_state)?);
        Ok(())
    }

    #[test]
    fn pending_and_corrupt_startup_fail_closed_and_release_the_author() -> io::Result<()> {
        let fixture = Fixture::new(true, true)?;
        let key = crate::manage::tls::node_key_sha256(&fixture.client_key)?;
        restored(&fixture, "pending_review", key)?;
        let before = store::recovery::status(&fixture.client_state)?;
        assert_eq!(
            startup(&fixture.client_state).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(store::recovery::status(&fixture.client_state)?, before);
        drop(store::lock(&fixture.client_state)?);
        let connection =
            rusqlite::Connection::open(fixture.client_state.join("management.sqlite3"))
                .map_err(io::Error::other)?;
        connection
        .execute_batch(
            "PRAGMA ignore_check_constraints=ON; UPDATE recovery_state SET node_key_sha256=x'00'",
        )
        .map_err(io::Error::other)?;
        assert!(startup(&fixture.client_state).is_err());
        connection
            .execute("DELETE FROM recovery_state", [])
            .map_err(io::Error::other)?;
        assert!(startup(&fixture.client_state).is_err());
        drop(store::lock(&fixture.client_state)?);
        Ok(())
    }

    #[test]
    fn startup_returns_ready_pin_and_keeps_genuine_legacy_native_state_usable() -> io::Result<()> {
        let fixture = Fixture::new(true, true)?;
        let key = crate::manage::tls::node_key_sha256(&fixture.client_key)?;
        restored(&fixture, "ready", key)?;
        let (author, actual) = startup(&fixture.client_state)?;
        assert_eq!(actual, Some(key));
        drop(author);
        // Relabelling a current database is not a genuine historical fixture.
        let connection =
            rusqlite::Connection::open(fixture.server_state.join("management.sqlite3"))
                .map_err(io::Error::other)?;
        let schema_version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(io::Error::other)?;
        connection
            .pragma_update(None, "user_version", 13)
            .map_err(io::Error::other)?;
        assert!(
            matches!(startup(&fixture.server_state), Err(error) if error.kind() == io::ErrorKind::InvalidData)
        );
        drop(store::lock(&fixture.server_state)?);
        connection
            .pragma_update(None, "user_version", schema_version)
            .map_err(io::Error::other)?;
        // Remove the endpoint namespace and receipt/outbox vocabulary as well as
        // recovery_state; genuine v13 predates all of them.
        store::recovery::remove_schema_for_test(&connection)?;
        let (author, legacy) = startup(&fixture.server_state)?;
        assert!(legacy.is_none());
        drop(author);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt as _;
    use hyper::service::Service as _;

    pub(super) fn state() -> Arc<AppState> {
        Arc::new(AppState {
            schema_version: 10,
            controller: None,
            health: None,
            traffic: None,
            alerts: None,
            acme: None,
            certificates: None,
            directory: PathBuf::new(),
            origin: PublicOrigin::parse("https://localhost:8443").unwrap(),
            node: NodeView {
                node_id: "node-fixture".into(),
                name: "Local".into(),
                version: "test",
                os: "test",
                arch: "test",
                capabilities: ["local_administration"],
            },
            dummy_phc: String::new(),
            password_work: Arc::new(Semaphore::new(2)),
            security: Mutex::new(SecurityState::new(Instant::now())),
            policy: None,
            _author: None,
        })
    }

    pub(super) fn fixture_session(now: Instant) -> Session {
        Session {
            administrator: AdministratorView {
                id: "admin-fixture".into(),
                username: "admin".into(),
            },
            csrf_token: "c".repeat(43),
            created_at: now,
            expires_at: 100,
        }
    }

    pub(super) fn request(method: Method, path: &str, body: &str) -> Request {
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "localhost:8443")
            .header(header::ORIGIN, "https://localhost:8443")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    pub(super) async fn call(state: Arc<AppState>, request: Request) -> Response {
        let app = router(state).layer(Extension(PeerIp(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))));
        TowerToHyperService::new(app).call(request).await.unwrap()
    }

    #[tokio::test]
    async fn supervisor_signals_and_drains_both_identity_domains() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let shutdown = CancellationToken::new();
        let completed = Arc::new(AtomicUsize::new(0));
        let mut listeners = JoinSet::new();
        for _ in 0..2 {
            let stop = shutdown.clone();
            let completed = completed.clone();
            listeners.spawn(async move {
                stop.cancelled().await;
                completed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
        }
        supervise(listeners, shutdown.clone(), async { Ok(()) }, None, None)
            .await
            .unwrap();
        assert!(shutdown.is_cancelled());
        assert_eq!(completed.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failed_listener_stops_its_sibling_and_is_not_reported_as_normal_shutdown() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let shutdown = CancellationToken::new();
        let completed = Arc::new(AtomicBool::new(false));
        let mut listeners = JoinSet::new();
        let stop = shutdown.clone();
        let drained = completed.clone();
        listeners.spawn(async move {
            stop.cancelled().await;
            drained.store(true, Ordering::SeqCst);
            Ok(())
        });
        listeners.spawn(async { Err(io::Error::from(io::ErrorKind::ConnectionAborted)) });
        let error = supervise(listeners, shutdown, std::future::pending(), None, None)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert!(completed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn signal_setup_failure_still_requests_listener_shutdown() {
        let shutdown = CancellationToken::new();
        let mut listeners = JoinSet::new();
        let stop = shutdown.clone();
        listeners.spawn(async move {
            stop.cancelled().await;
            Ok(())
        });
        let error = supervise(
            listeners,
            shutdown.clone(),
            async { Err(io::Error::from(io::ErrorKind::PermissionDenied)) },
            None,
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(shutdown.is_cancelled());
    }

    #[cfg(feature = "web-ui")]
    #[tokio::test]
    async fn public_assets_keep_their_policy_without_relaxing_api_guards() {
        let state = state();
        let page = call(state.clone(), request(Method::GET, "/", "")).await;
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(page.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(page.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(page.headers()[header::X_FRAME_OPTIONS], "DENY");
        assert!(
            page.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("script-src 'self'")
        );

        let private = call(state.clone(), request(Method::GET, "/api/v1/node", "")).await;
        assert_eq!(private.status(), StatusCode::FORBIDDEN);
        assert_eq!(private.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            private.headers()[header::CONTENT_SECURITY_POLICY],
            "default-src 'none'; frame-ancestors 'none'"
        );
        let missing = call(state.clone(), request(Method::GET, "/api/v1/missing", "")).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(missing.headers()[header::CONTENT_TYPE], "application/json");

        let mut wrong_host = request(Method::GET, "/", "");
        wrong_host
            .headers_mut()
            .insert(header::HOST, "attacker.test".parse().unwrap());
        let rejected = call(state, wrong_host).await;
        assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
        assert_eq!(rejected.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[test]
    fn origin_validation_rejects_browser_normalization_and_ambiguous_origins() {
        for value in [
            "http://localhost",
            "https://localhost/",
            "https://localhost?x=1",
            "https://user@localhost",
            "https://localhost:443",
            "https://LOCALHOST",
            "https://localhost:0",
            "https://localhost:bad",
            "https://[0:0:0:0:0:0:0:1]",
            "https://localhost#fragment",
            "https://127.1",
            "https://2130706433",
            "https://0x7f000001",
            "https://0177.0.0.1",
            "https://localhost:08443",
        ] {
            assert!(PublicOrigin::parse(value).is_err(), "accepted {value}");
        }
        assert!(PublicOrigin::parse("https://localhost").is_ok());
        assert!(PublicOrigin::parse("https://[::1]:8443").is_ok());
    }

    #[tokio::test]
    async fn host_origin_and_media_type_checks_precede_password_work() {
        let state = state();
        for (header_name, value, status) in [
            (header::HOST, "attacker.test", StatusCode::FORBIDDEN),
            (
                header::ORIGIN,
                "https://attacker.test",
                StatusCode::FORBIDDEN,
            ),
            (
                header::CONTENT_TYPE,
                "text/plain",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
        ] {
            let mut req = request(Method::POST, "/api/v1/auth/login", "{}");
            req.headers_mut()
                .insert(header_name, value.parse().unwrap());
            let response = call(state.clone(), req).await;
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
        }
        let mut req = request(Method::POST, "/api/v1/auth/login", "{}");
        req.headers_mut().remove(header::ORIGIN);
        assert_eq!(call(state, req).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn absolute_form_uses_target_authority_without_forwarding_or_trusting_host() {
        let state = state();
        for host in ["other.example:443", "OTHER.example", ""] {
            let mut req = request(Method::GET, "https://localhost:8443/api/v1/node", "");
            req.headers_mut()
                .insert(header::HOST, host.parse().unwrap());
            let response = call(state.clone(), req).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"]["code"],
                "authentication_required"
            );
        }
        for target in [
            "https://other.example/api/v1/auth/login",
            "http://localhost:8443/api/v1/auth/login",
        ] {
            let response = call(state.clone(), request(Method::POST, target, "{}")).await;
            assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"]["code"],
                "misdirected_request"
            );
        }
        assert!(state.security().unwrap().address_rates.is_empty());
        let mut req = request(Method::GET, "/api/v1/node", "");
        req.headers_mut().insert(header::HOST, "".parse().unwrap());
        let response = call(state, req).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"]["code"],
            "invalid_host"
        );
    }

    #[tokio::test]
    async fn absolute_form_still_rejects_missing_duplicate_and_malformed_host() {
        let state = state();
        let target = "https://localhost:8443/api/v1/node";
        for host in [
            "user@other.example",
            "a.example,b.example",
            "other.example:bad",
            "other.example/path",
        ] {
            let mut req = request(Method::GET, target, "");
            req.headers_mut()
                .insert(header::HOST, host.parse().unwrap());
            assert_eq!(
                call(state.clone(), req).await.status(),
                StatusCode::BAD_REQUEST
            );
        }
        let mut req = request(Method::GET, target, "");
        req.headers_mut().remove(header::HOST);
        assert_eq!(
            call(state.clone(), req).await.status(),
            StatusCode::BAD_REQUEST
        );
        let mut req = request(Method::GET, target, "");
        req.headers_mut()
            .append(header::HOST, "other.example".parse().unwrap());
        assert_eq!(call(state, req).await.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn method_not_allowed_retains_the_route_specific_allow_header() {
        let state = state();
        for (method, path, expected) in [
            (Method::GET, "/api/v1/auth/login", vec!["POST"]),
            (Method::PUT, "/api/v1/node", vec!["GET", "HEAD"]),
        ] {
            let response = call(state.clone(), request(method, path, "{}")).await;
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            let mut allowed: Vec<_> = response.headers()[header::ALLOW]
                .to_str()
                .unwrap()
                .split(',')
                .map(str::trim)
                .collect();
            allowed.sort_unstable();
            assert_eq!(allowed, expected);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"]["code"],
                "method_not_allowed"
            );
        }
    }

    #[test]
    fn cookie_parser_rejects_duplicate_and_malformed_session_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("other=ok; {COOKIE_NAME}={}", "x".repeat(43))
                .parse()
                .unwrap(),
        );
        assert_eq!(session_cookie(&headers).unwrap().unwrap(), "x".repeat(43));
        headers.append(
            header::COOKIE,
            format!("{COOKIE_NAME}={}", "y".repeat(43)).parse().unwrap(),
        );
        assert!(session_cookie(&headers).is_err());
        headers.insert(
            header::COOKIE,
            format!("{COOKIE_NAME}=short").parse().unwrap(),
        );
        assert!(session_cookie(&headers).is_err());
    }

    #[test]
    fn sessions_expire_absolutely_and_rotation_invalidates_old_token() {
        let now = Instant::now();
        let mut security = SecurityState::new(now);
        security
            .insert_session(None, "old".into(), fixture_session(now))
            .unwrap();
        assert!(
            security
                .session("old", now + SESSION_LIFETIME - Duration::from_secs(1))
                .is_ok()
        );
        security
            .insert_session(Some("old"), "new".into(), fixture_session(now))
            .unwrap();
        assert!(security.session("old", now).is_err());
        assert!(security.session("new", now + SESSION_LIFETIME).is_err());
    }

    #[test]
    fn login_rate_limits_apply_per_peer_globally_and_recover_after_expiry() {
        let now = Instant::now();
        let mut security = SecurityState::new(now);
        for address in 1..=6 {
            let address = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, address));
            for _ in 0..IP_LOGIN_LIMIT {
                assert!(security.allow_login(address, now));
            }
            assert!(!security.allow_login(address, now));
        }
        let new_peer = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        assert!(!security.allow_login(new_peer, now));
        assert!(security.allow_login(new_peer, now + RATE_WINDOW));
        assert_eq!(security.address_rates.len(), 1);
    }

    #[test]
    fn capacity_rejects_new_sessions_without_evicting_a_live_browser() {
        let now = Instant::now();
        let mut security = SecurityState::new(now);
        for index in 0..MAX_SESSIONS {
            security
                .insert_session(None, format!("token-{index}"), fixture_session(now))
                .unwrap();
        }
        assert!(
            security
                .insert_session(None, "overflow".into(), fixture_session(now))
                .is_err()
        );
        assert!(security.session("token-0", now).is_ok());
        security
            .insert_session(Some("token-0"), "replacement".into(), fixture_session(now))
            .unwrap();
        assert_eq!(security.sessions.len(), MAX_SESSIONS);
        assert!(security.session("token-0", now).is_err());
        assert!(security.session("replacement", now).is_ok());
    }

    #[test]
    fn accept_retries_transient_network_and_resource_errors_but_not_invalid_listeners() {
        for kind in [
            io::ErrorKind::Interrupted,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::OutOfMemory,
        ] {
            assert!(retryable_accept_error(&io::Error::from(kind)));
        }
        assert!(!retryable_accept_error(&io::Error::from(
            io::ErrorKind::InvalidInput
        )));
        #[cfg(unix)]
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOMEM] {
            assert!(retryable_accept_error(&io::Error::from_raw_os_error(code)));
        }
        #[cfg(target_os = "linux")]
        {
            assert!(retryable_accept_error(&io::Error::from_raw_os_error(
                libc::ENONET
            )));
            assert!(!retryable_accept_error(&io::Error::from_raw_os_error(
                libc::ENOTSOCK
            )));
        }
        #[cfg(windows)]
        {
            assert!(retryable_accept_error(&io::Error::from_raw_os_error(10024)));
            assert!(!retryable_accept_error(&io::Error::from_raw_os_error(
                10038
            )));
        }
    }

    #[tokio::test]
    async fn protected_routes_logout_and_csrf_use_server_session_state() {
        let state = state();
        assert_eq!(
            call(state.clone(), request(Method::GET, "/api/v1/node", ""))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let token = "t".repeat(43);
        state
            .security()
            .unwrap()
            .insert_session(None, token.clone(), fixture_session(Instant::now()))
            .unwrap();
        let cookie = format!("{COOKIE_NAME}={token}");
        let mut req = request(Method::GET, "/api/v1/node", "");
        req.headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        let response = call(state.clone(), req).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["node_id"], "node-fixture");
        assert!(body.get("cpu").is_none());
        assert!(body.get("traffic").is_none());
        for csrf in [None, Some("wrong")] {
            let mut req = request(Method::POST, "/api/v1/auth/logout", "{}");
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            if let Some(csrf) = csrf {
                req.headers_mut()
                    .insert("x-csrf-token", csrf.parse().unwrap());
            }
            assert_eq!(
                call(state.clone(), req).await.status(),
                StatusCode::FORBIDDEN
            );
        }
        let mut req = request(Method::POST, "/api/v1/auth/logout", "{}");
        req.headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        req.headers_mut()
            .insert("x-csrf-token", "c".repeat(43).parse().unwrap());
        let response = call(state.clone(), req).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        let mut req = request(Method::GET, "/api/v1/auth/session", "");
        req.headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(call(state, req).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn malformed_oversized_json_and_unknown_routes_have_stable_errors() {
        let state = state();
        for (body, status) in [
            ("{", StatusCode::BAD_REQUEST),
            ("{\"unexpected\":1}", StatusCode::BAD_REQUEST),
            (
                &"x".repeat(MAX_JSON_BYTES + 1),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            assert_eq!(
                call(
                    state.clone(),
                    request(Method::POST, "/api/v1/auth/login", body)
                )
                .await
                .status(),
                status
            );
        }
        let response = call(state, request(Method::GET, "/api/v1/missing", "")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"]["code"],
            "not_found"
        );
    }

    /// Own exactly the randomly named fixture directory created by initialize.
    pub(super) struct TestDirectory(PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn initialized_state() -> (TestDirectory, Arc<AppState>) {
        let path =
            std::env::temp_dir().join(format!("vproxy-api-test-{}", random_token().unwrap()));
        let directory = TestDirectory(path);
        let phc = Argon2::default()
            .hash_password(b"fixture-password")
            .unwrap()
            .to_string();
        super::super::store::initialize(&directory.0, "Fixture", "admin", &phc).unwrap();
        let mut state = state();
        let mutable = Arc::get_mut(&mut state).unwrap();
        mutable.directory = directory.0.clone();
        mutable.dummy_phc = phc;
        mutable.schema_version = super::super::store::inspect(&directory.0)
            .unwrap()
            .schema_version;
        (directory, state)
    }

    /// A real policy author with a session bound to its stored administrator.
    pub(super) fn managed_state() -> (TestDirectory, Arc<AppState>, String) {
        let (directory, mut state) = initialized_state();
        let administrator: String =
            rusqlite::Connection::open(directory.0.join("management.sqlite3"))
                .unwrap()
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .unwrap();
        let author = Arc::new(super::super::store::lock(&directory.0).unwrap());
        let mutable = Arc::get_mut(&mut state).unwrap();
        mutable.policy = Some(
            super::super::policy::Coordinator::new(
                directory.0.clone(),
                super::super::store::load_policy(&directory.0).unwrap(),
                author.clone(),
            )
            .unwrap(),
        );
        mutable._author = Some(author);
        let token = "t".repeat(43);
        let mut session = fixture_session(Instant::now());
        session.administrator.id = administrator;
        state
            .security()
            .unwrap()
            .insert_session(None, token.clone(), session)
            .unwrap();
        (directory, state, format!("{COOKIE_NAME}={token}"))
    }

    #[tokio::test]
    async fn real_password_login_rotates_cookie_and_unknown_users_have_same_public_error() {
        let (_directory, state) = initialized_state();
        for username in ["admin", "missing"] {
            let body = format!(r#"{{"username":"{username}","password":"incorrect"}}"#);
            let response = call(
                state.clone(),
                request(Method::POST, "/api/v1/auth/login", &body),
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"]["code"],
                "invalid_credentials"
            );
        }
        let body = r#"{"username":"admin","password":"fixture-password"}"#;
        let response = call(
            state.clone(),
            request(Method::POST, "/api/v1/auth/login", body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_owned();
        for flag in [
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Strict",
            "Max-Age=28800",
        ] {
            assert!(cookie.contains(flag));
        }
        let old_cookie = cookie.split(';').next().unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let session: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(session["administrator"]["username"], "admin");
        assert_eq!(session["csrf_token"].as_str().unwrap().len(), 43);
        assert!(session.get("password").is_none());
        let mut req = request(Method::POST, "/api/v1/auth/login", body);
        req.headers_mut()
            .insert(header::COOKIE, old_cookie.parse().unwrap());
        let response = call(state.clone(), req).await;
        assert_eq!(response.status(), StatusCode::OK);
        let new_cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert_ne!(new_cookie, old_cookie);
        for (cookie, expected) in [
            (old_cookie, StatusCode::FORBIDDEN),
            (new_cookie.as_str(), StatusCode::OK),
        ] {
            let mut req = request(Method::GET, "/api/v1/auth/session", "");
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            assert_eq!(call(state.clone(), req).await.status(), expected);
        }
    }

    #[tokio::test]
    async fn password_capacity_rejects_without_queueing_and_internal_errors_are_redacted() {
        let state = state();
        let permits = state
            .password_work
            .clone()
            .try_acquire_many_owned(2)
            .unwrap();
        let body = r#"{"username":"admin","password":"fixture-password"}"#;
        assert_eq!(
            call(
                state.clone(),
                request(Method::POST, "/api/v1/auth/login", body)
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(permits);
        let response = call(state, request(Method::POST, "/api/v1/auth/login", body)).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"]["code"],
            "internal_error"
        );
    }
}

#[cfg(test)]
mod transport_tests {
    //! Loopback integration of the actual TLS identity, HTTP/1 driver and API router.
    //! Clients trust only the generated root and still verify the requested SAN.

    use std::{fs::OpenOptions, io::Write, path::Path, sync::Arc};

    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt as _, Full};
    use rcgen::generate_simple_self_signed;
    use rustls::{ClientConfig, RootCertStore, crypto::aws_lc_rs};
    use rustls_pki_types::ServerName;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_rustls::TlsConnector;

    /// Owns only a randomly named test directory and its test transport identities.
    struct Fixture {
        directory: PathBuf,
        acceptor: TlsAcceptor,
        connector: TlsConnector,
    }

    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory = std::env::temp_dir().join(format!(
                "vproxy-api-transport-{}",
                random_token().map_err(|_| io::Error::other("fixture randomness failed"))?
            ));
            let phc = Argon2::default()
                .hash_password(b"transport-password")
                .map_err(|_| io::Error::other("fixture hash failed"))?
                .to_string();
            super::super::store::initialize(&directory, "Transport fixture", "admin", &phc)?;
            // Remove partial certificate fixtures on identity/client setup failure,
            // before a successful Fixture can take responsibility for the directory.
            let result = Self::identities(&directory);
            match result {
                Ok((acceptor, connector)) => Ok(Self {
                    directory,
                    acceptor,
                    connector,
                }),
                Err(error) => {
                    let _ = std::fs::remove_dir_all(&directory);
                    Err(error)
                }
            }
        }

        fn identities(directory: &Path) -> io::Result<(TlsAcceptor, TlsConnector)> {
            let identity =
                generate_simple_self_signed(vec!["localhost".into()]).map_err(io::Error::other)?;
            let certificate = directory.join("https-cert.pem");
            let key = directory.join("https-key.pem");
            write_private(&certificate, identity.cert.pem().as_bytes())?;
            write_private(&key, identity.signing_key.serialize_pem().as_bytes())?;
            let server = super::super::tls::admin_server_config(&certificate, &key)?;
            let mut roots = RootCertStore::empty();
            roots
                .add(identity.cert.der().clone())
                .map_err(io::Error::other)?;
            let mut client =
                ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .map_err(io::Error::other)?
                    .with_root_certificates(roots)
                    .with_no_client_auth();
            client.alpn_protocols = vec![b"http/1.1".to_vec()];
            Ok((
                TlsAcceptor::from(server),
                TlsConnector::from(Arc::new(client)),
            ))
        }

        async fn state(&self, port: u16) -> io::Result<Arc<AppState>> {
            initialize(
                self.directory.clone(),
                PublicOrigin::parse(&format!("https://localhost:{port}"))?,
                Arc::new(super::super::store::lock(&self.directory)?),
            )
            .await
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        options.open(path)?.write_all(bytes)
    }

    /// The same connection handler is used by the production accept loop. JoinSet
    /// owns every driver; timeout/unwind cannot leave detached listeners or clients.
    fn spawn_server(
        tasks: &mut JoinSet<io::Result<()>>,
        listener: TcpListener,
        fixture: &Fixture,
        state: Arc<AppState>,
        shutdown: CancellationToken,
        connection_count: usize,
    ) {
        let acceptor = fixture.acceptor.clone();
        let app = router(state);
        tasks.spawn(async move {
            for _ in 0..connection_count {
                let (stream, peer) = listener.accept().await?;
                serve_connection(
                    stream,
                    acceptor.clone(),
                    app.clone(),
                    PeerIp(peer.ip()),
                    shutdown.clone(),
                )
                .await;
            }
            Ok(())
        });
    }

    fn request(method: Method, path: &str, port: u16, body: &str) -> http::Request<Full<Bytes>> {
        http::Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, format!("localhost:{port}"))
            .header(header::ORIGIN, format!("https://localhost:{port}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
            .unwrap()
    }

    #[tokio::test]
    async fn native_full_supervisor_serves_real_https_and_releases_author_after_stop()
    -> io::Result<()> {
        let fixture = tokio::task::spawn_blocking(Fixture::new)
            .await
            .map_err(io::Error::other)??;
        let reservation = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = reservation.local_addr()?;
        let directory = fixture.directory.clone();
        let author = Arc::new(super::super::store::lock(&directory)?);
        let (_, metadata, proxy_identity) = super::super::tls::admin_proxy_identity(
            &directory.join("https-cert.pem"),
            &directory.join("https-key.pem"),
        )?;
        let tls = fixture.acceptor.clone();
        let profile_config = crate::ebpf::Args::default().load()?;
        let (stop, stopping) = tokio::sync::oneshot::channel();
        drop(reservation);
        let driver = tokio::task::spawn_blocking(move || {
            run_prepared(
                async move {
                    let state = initialize(
                        directory,
                        PublicOrigin::parse(&format!("https://localhost:{}", address.port()))?,
                        author,
                    )
                    .await?;
                    Ok(Prepared {
                        state,
                        bind: address,
                        tls: Acceptor::Manual(tls),
                        acme: None,
                        certificate_source: super::super::certificates::ManagementSource::Manual(
                            metadata,
                        ),
                        service_tls: Some(super::super::proxy::settings::Tls::Manual(
                            proxy_identity,
                        )),
                        node: None,
                        prepared_proxy: None,
                        profile_config,
                        health_config: super::super::health::Config::default(),
                        health_explicit: false,
                        observe_target_alerts: false,
                        #[cfg(feature = "witness-journal")]
                        source: None,
                    })
                },
                async move { stopping.await.map_err(io::Error::other) },
            )
        });
        let mut tasks = JoinSet::new();
        let exercised = timeout(Duration::from_secs(20), async {
            let stream = loop {
                match TcpStream::connect(address).await {
                    Ok(stream) => break stream,
                    Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                        tokio::time::sleep(Duration::from_millis(10)).await
                    }
                    Err(e) => return Err(e),
                }
            };
            let stream = fixture
                .connector
                .connect(
                    ServerName::try_from("localhost").map_err(io::Error::other)?,
                    stream,
                )
                .await?;
            let (mut client, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .map_err(io::Error::other)?;
            tasks.spawn(async move { connection.await.map_err(io::Error::other) });
            let response = client
                .send_request(request(
                    Method::POST,
                    "/api/v1/auth/login",
                    address.port(),
                    r#"{"username":"admin","password":"transport-password"}"#,
                ))
                .await
                .map_err(io::Error::other)?;
            if response.status() != StatusCode::OK {
                return Err(io::Error::other("native supervisor login failed"));
            }
            let cookie = Zeroizing::new(
                response
                    .headers()
                    .get(header::SET_COOKIE)
                    .ok_or_else(|| io::Error::other("cookie"))?
                    .to_str()
                    .map_err(io::Error::other)?
                    .split(';')
                    .next()
                    .ok_or_else(|| io::Error::other("cookie pair"))?
                    .to_owned(),
            );
            response
                .into_body()
                .collect()
                .await
                .map_err(io::Error::other)?;
            let mut query = request(Method::GET, "/api/v1/tls/status", address.port(), "");
            query.headers_mut().insert(
                header::COOKIE,
                HeaderValue::from_str(cookie.as_str()).map_err(io::Error::other)?,
            );
            let response = client.send_request(query).await.map_err(io::Error::other)?;
            if response.status() != StatusCode::OK {
                return Err(io::Error::other(
                    "native supervisor certificate inventory failed",
                ));
            }
            response
                .into_body()
                .collect()
                .await
                .map_err(io::Error::other)?;
            Ok::<_, io::Error>(())
        })
        .await
        .map_err(io::Error::other)
        .and_then(|r| r);
        let _ = stop.send(());
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        let stopped = timeout(Duration::from_secs(20), driver)
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        exercised?;
        stopped?;
        super::super::store::lock(&fixture.directory)?;
        super::super::store::update_lock(&fixture.directory)?;
        Ok(())
    }

    #[tokio::test]
    async fn trusted_https_http1_login_node_and_csrf_logout_round_trip() {
        let mut tasks = JoinSet::new();
        let shutdown = CancellationToken::new();
        // Test data construction is not the application/network scenario. A timed
        // out blocking worker is not interrupted and keeps its owned resources.
        let preparation_started = Instant::now();
        let worker_started = Arc::new(std::sync::OnceLock::new());
        let entered = worker_started.clone();
        let prepared = timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(move || {
                let _ = entered.set(Instant::now());
                Fixture::new()
            }),
        )
        .await;
        let preparation_elapsed = preparation_started.elapsed();
        let queue_elapsed = worker_started
            .get()
            .map(|started| started.duration_since(preparation_started));
        assert!(
            prepared.is_ok(),
            "HTTPS fixture preparation deadline, total {:?}, queue {:?}, worker-entry elapsed {:?}; blocking work is not interrupted",
            preparation_elapsed,
            queue_elapsed,
            worker_started.get().map(Instant::elapsed)
        );
        let fixture = prepared.unwrap().unwrap().unwrap();
        let mut phase = ("listener and application initialization", Instant::now());
        let result = timeout(Duration::from_secs(10), async {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let state = fixture.state(address.port()).await.unwrap();
            spawn_server(&mut tasks, listener, &fixture, state, shutdown.clone(), 1);
            phase = ("TLS handshake", Instant::now());
            let stream = TcpStream::connect(address).await.unwrap();
            let stream = fixture
                .connector
                .connect(ServerName::try_from("localhost").unwrap(), stream)
                .await
                .unwrap();
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
            let (mut client, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .unwrap();
            tasks.spawn(async move { connection.await.map_err(io::Error::other) });
            #[cfg(feature = "web-ui")]
            {
                phase = ("embedded Web requests", Instant::now());
                let mut req = request(Method::GET, "/", address.port(), "");
                req.headers_mut()
                    .insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
                let response = client.send_request(req).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.headers()[header::CONTENT_ENCODING], "gzip");
                assert_eq!(response.headers()[header::VARY], "Accept-Encoding");
                assert!(!response.headers().contains_key(header::SET_COOKIE));
                let length: usize = response.headers()[header::CONTENT_LENGTH]
                    .to_str()
                    .unwrap()
                    .parse()
                    .unwrap();
                let bytes = response.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(bytes.len(), length);
                assert!(bytes.starts_with(&[0x1f, 0x8b]));
                let response = client
                    .send_request(request(Method::HEAD, "/", address.port(), ""))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert!(response.headers().contains_key(header::CONTENT_LENGTH));
                assert!(
                    response
                        .into_body()
                        .collect()
                        .await
                        .unwrap()
                        .to_bytes()
                        .is_empty()
                );
            }
            phase = ("password login", Instant::now());
            let response = client
                .send_request(request(
                    Method::POST,
                    "/api/v1/auth/login",
                    address.port(),
                    r#"{"username":"admin","password":"transport-password"}"#,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let cookie = response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let session: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let csrf = session["csrf_token"].as_str().unwrap();
            phase = ("authenticated identity read", Instant::now());
            let mut req = request(Method::GET, "/api/v1/node", address.port(), "");
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            let response = client.send_request(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let node: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(node["name"], "Transport fixture");
            assert!(node["node_id"].as_str().is_some_and(|id| !id.is_empty()));
            assert!(node.get("traffic").is_none());
            phase = ("logout and revoked-session rejection", Instant::now());
            let mut req = request(Method::POST, "/api/v1/auth/logout", address.port(), "{}");
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-csrf-token", csrf.parse().unwrap());
            let response = client.send_request(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert!(
                response.headers()[header::SET_COOKIE]
                    .to_str()
                    .unwrap()
                    .contains("Max-Age=0")
            );
            response.into_body().collect().await.unwrap();
            let mut req = request(Method::GET, "/api/v1/node", address.port(), "");
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            let response = client.send_request(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            response.into_body().collect().await.unwrap();
            drop(client);
            phase = ("driver drain", Instant::now());
            shutdown.cancel();
            while let Some(result) = tasks.join_next().await {
                result.unwrap().unwrap();
            }
        })
        .await;
        shutdown.cancel();
        tasks.shutdown().await;
        assert!(
            result.is_ok(),
            "HTTPS deadline at {}, phase elapsed {:?}; fixture preparation {:?}, queue {:?}",
            phase.0,
            phase.1.elapsed(),
            preparation_elapsed,
            queue_elapsed
        );
    }

    #[tokio::test]
    async fn wrong_certificate_san_and_plaintext_never_reach_login_router() {
        let mut tasks = JoinSet::new();
        let shutdown = CancellationToken::new();
        let preparation_started = Instant::now();
        let worker_started = Arc::new(std::sync::OnceLock::new());
        let entered = worker_started.clone();
        let prepared = timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(move || {
                let _ = entered.set(Instant::now());
                Fixture::new()
            }),
        )
        .await;
        let preparation_elapsed = preparation_started.elapsed();
        let queue_elapsed = worker_started
            .get()
            .map(|started| started.duration_since(preparation_started));
        assert!(
            prepared.is_ok(),
            "TLS rejection fixture preparation deadline, total {:?}, queue {:?}, worker-entry elapsed {:?}; blocking work is not interrupted",
            preparation_elapsed,
            queue_elapsed,
            worker_started.get().map(Instant::elapsed)
        );
        let fixture = prepared.unwrap().unwrap().unwrap();
        let mut phase = ("listener and application initialization", Instant::now());
        let result = timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let state = fixture.state(address.port()).await.unwrap();
        spawn_server(
            &mut tasks,
            listener,
            &fixture,
            state.clone(),
            shutdown.clone(),
            2,
        );
        phase = ("wrong-SAN TLS rejection", Instant::now());
        let stream = TcpStream::connect(address).await.unwrap();
        assert!(fixture.connector
            .connect(ServerName::try_from("wrong.example").unwrap(), stream)
            .await
            .is_err());
        phase = ("plaintext rejection", Instant::now());
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(format!(
            "POST /api/v1/auth/login HTTP/1.1\r\nHost: localhost:{}\r\nOrigin: https://localhost:{}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}",
            address.port(), address.port()
        ).as_bytes()).await.unwrap();
        let mut received = Vec::new();
        if let Err(error) = stream.read_to_end(&mut received).await {
            assert!(matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted));
        }
        assert!(!received.starts_with(b"HTTP/"));
        drop(stream);
        phase = ("driver drain", Instant::now());
        shutdown.cancel();
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        let security = state.security().unwrap();
        assert!(security.address_rates.is_empty());
        assert!(security.sessions.is_empty());
    })
    .await;
        shutdown.cancel();
        tasks.shutdown().await;
        assert!(
            result.is_ok(),
            "TLS rejection deadline at {}, phase elapsed {:?}; fixture preparation {:?}, queue {:?}",
            phase.0,
            phase.1.elapsed(),
            preparation_elapsed,
            queue_elapsed
        );
    }
}
