//! A separate, mandatory-mTLS node identity and proxy-policy channel.
//!
//! A TLS certificate proves key possession, not node permissions. The exact
//! leaf DER must also be registered locally; every request rechecks persistent
//! authorization. Browser cookies and proxy credentials have no role here.

pub(super) mod control;
mod probe;
mod witness;

pub(super) use probe::{ProbeArgs, probe};

use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Extension, Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use rustls::{ClientConfig, ServerConfig};
use serde::Serialize;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use super::{
    api::{self, ApiError, PublicOrigin},
    policy::Coordinator,
    store,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 128;
const MAX_AUTHORIZATION_WORK: usize = 2;
const IDENTITY_PATH: &str = "/node/v1/identity";
const PROTOCOL_VERSION: u8 = 1;
const CAPABILITIES: [&str; 1] = ["identity_read"];

/// Optional listener settings. Supplying only some fields is an error, not an
/// instruction to fall back to browser TLS or silently disable authentication.
#[derive(clap::Args, Default)]
pub struct ListenArgs {
    /// Separate node mTLS address; all five --node-* settings are required
    #[arg(long)]
    node_bind: Option<SocketAddr>,
    /// Canonical HTTPS origin of the node listener, without a trailing slash
    #[arg(long)]
    node_origin: Option<String>,
    /// Explicit PEM CA roots for node identities (not the system root store)
    #[arg(long)]
    node_ca: Option<PathBuf>,
    /// PEM node leaf/chain with both serverAuth and clientAuth purposes
    #[arg(long)]
    node_cert: Option<PathBuf>,
    /// Private PEM key matching the node leaf certificate
    #[arg(long)]
    node_key: Option<PathBuf>,
}

/// Validated startup configuration; TLS filesystem work precedes async serving.
pub(super) struct Config {
    /// The supervisor binds all listeners before admitting any requests.
    pub(super) bind: SocketAddr,
    origin: PublicOrigin,
    tls: Arc<ServerConfig>,
    /// SPKI of the exact once-loaded chain/key used by both production resolvers.
    /// Reusable node serving rechecks its persistent recovery pin before accept.
    key_sha256: [u8; 32],
    /// The same local node identity, restricted to the fixed node CA domain.
    /// Outbound control never borrows the browser listener's TLS identity.
    pub(super) client_tls: Arc<ClientConfig>,
    /// Public metadata from the same actual identity as both TLS resolvers.
    pub(super) certificate: super::certificates::State,
    /// Present only for an actual registered capture. A Native configuration
    /// cannot borrow a Source coordinator to bypass ordinary startup refusal.
    #[cfg(feature = "witness-journal")]
    source: Option<store::journal::configuration::Reference>,
}

/// Keep the node listener disabled by default; reject partial/invalid settings.
///
/// Performs bounded synchronous TLS file loading. Invalid origins, incomplete
/// arguments, inaccessible keys and invalid certificate identities abort startup.
/// A recovery pin must match the actual loaded server/client identity; no pin
/// preserves native startup. Disabling the optional listener starts no node TLS.
pub(super) fn configure(
    args: ListenArgs,
    expected_key: Option<[u8; 32]>,
) -> io::Result<Option<Config>> {
    match (
        args.node_bind,
        args.node_origin,
        args.node_ca,
        args.node_cert,
        args.node_key,
    ) {
        (None, None, None, None, None) => Ok(None),
        (Some(bind), Some(origin), Some(ca), Some(cert), Some(key)) => {
            let origin = PublicOrigin::parse(&origin)?;
            let identity = super::tls::node_identity(&ca, &cert, &key)?;
            Config::prepare(bind, origin, &identity, expected_key).map(Some)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "node listener requires --node-bind, --node-origin, --node-ca, --node-cert and --node-key together",
        )),
    }
}

impl Config {
    /// Share the once-loaded identity with both transport resolvers. The name
    /// and recovery pin apply to that signer, not a later file read.
    fn prepare(
        bind: SocketAddr,
        origin: PublicOrigin,
        identity: &super::tls::NodeIdentity,
        expected_key: Option<[u8; 32]>,
    ) -> io::Result<Self> {
        let url = url::Url::parse(origin.value()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid node listener origin")
        })?;
        let reference = match url.host() {
            Some(url::Host::Domain(host)) => host.to_owned(),
            Some(url::Host::Ipv4(address)) => address.to_string(),
            Some(url::Host::Ipv6(address)) => address.to_string(),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "node listener origin has no host",
                ));
            }
        };
        identity.verify_name(&reference)?;
        let key_sha256 = identity.key_sha256()?;
        if let Some(expected) = expected_key
            && key_sha256 != expected
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "node TLS identity does not match the recovered node key",
            ));
        }
        Ok(Self {
            bind,
            origin,
            tls: identity.server_config()?,
            client_tls: identity.client_config()?,
            key_sha256,
            certificate: identity.certificate(),
            #[cfg(feature = "witness-journal")]
            source: None,
        })
    }
}

/// Prepare the node transport from its owned registered projection. No path is
/// reopened and no listener is bound. Serving still requires the same directory,
/// exact reference and signer on a freshly confirmed original Source worker.
#[cfg(feature = "witness-journal")]
pub(super) fn configure_registered(
    inputs: &super::snapshot::inputs::Prepared,
    reference: store::journal::configuration::Reference,
) -> io::Result<Config> {
    if inputs.configuration.source.is_none()
        || inputs.sha256()? != reference.sha256
        || inputs.node.key_sha256()? != inputs.node_key_sha256
    {
        return Err(source_required());
    }
    let mut config = Config::prepare(
        inputs.configuration.node.bind,
        PublicOrigin::parse(&inputs.configuration.node.origin)?,
        &inputs.node,
        Some(inputs.node_key_sha256),
    )?;
    config.source = Some(reference);
    Ok(config)
}

#[cfg(feature = "witness-journal")]
fn source_required() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "matching registered node configuration required",
    )
}

/// Local listener identity plus the one existing policy application service.
/// This transport never creates a second Reader, proxy runner or writer queue.
struct AppState {
    directory: PathBuf,
    origin: PublicOrigin,
    node_id: String,
    name: String,
    authorization_work: Arc<Semaphore>,
    policy: Option<Arc<Coordinator>>,
    health: Option<super::health::Handle>,
    alerts: Option<super::alerts::Handle>,
}

/// Server-created identity only: no HTTP header can construct this extension.
/// The original revision is pinned for this connection, never silently upgraded.
struct BoundIdentity {
    leaf: Arc<[u8]>,
    node_id: String,
    authorization_revision: u64,
}

/// Initial failures remain failures for this connection; reconnect after repair
/// or new registration. No cached permission is used when the database fails.
#[derive(Clone)]
enum ConnectionIdentity {
    Authorized(Arc<BoundIdentity>),
    Forbidden,
    Unavailable,
}

/// Fresh request-scoped permission, inserted only after the DB check succeeds.
#[derive(Clone)]
struct VerifiedPeer {
    node_id: String,
    authorization_revision: u64,
    /// Exact handshake leaf, not a certificate supplied by the HTTP caller.
    leaf: Arc<[u8]>,
}

impl VerifiedPeer {
    fn authorization(&self) -> store::RemoteAuthorization {
        store::RemoteAuthorization {
            node_id: self.node_id.clone(),
            authorization_revision: self.authorization_revision,
            leaf: self.leaf.clone(),
        }
    }
}

/// Versioned wire contract shared by every node; neither field grants control.
#[derive(Serialize)]
struct IdentityResponse<'a> {
    protocol_version: u8,
    node_id: &'a str,
    name: &'a str,
    version: &'static str,
    os: &'static str,
    arch: &'static str,
    capabilities: [&'static str; 1],
    verified_peer: VerifiedPeerResponse<'a>,
}

#[derive(Serialize)]
struct VerifiedPeerResponse<'a> {
    node_id: &'a str,
    authorization_revision: u64,
}

/// API startup already gates before binding; this reusable node entry repeats
/// the readiness/pin check against its once-loaded actual TLS identity so a new
/// internal caller cannot omit it. This runs once, never on the request path.
async fn initialize(
    directory: PathBuf,
    config: Config,
    policy: Option<Arc<Coordinator>>,
    health: Option<super::health::Handle>,
    alerts: Option<super::alerts::Handle>,
) -> io::Result<(Arc<AppState>, TlsAcceptor)> {
    let overview = startup_overview(&directory, &config, policy.as_ref()).await?;
    // Identity v1 remains available on explicitly supported old schemas.
    // The current shared coordinator also restores schema-nine preset policy
    // provenance. Do not expose new control/traffic reads through an older
    // partially initialized service, or infer that identity permission grants it.
    let policy = policy.filter(|_| overview.schema_version >= 9);
    let health = health.filter(|_| overview.schema_version >= 9);
    let alerts = alerts.filter(|_| overview.schema_version >= 17);
    Ok((
        Arc::new(AppState {
            directory,
            origin: config.origin,
            node_id: overview.node_id,
            name: overview.name,
            authorization_work: Arc::new(Semaphore::new(MAX_AUTHORIZATION_WORK)),
            policy,
            health,
            alerts,
        }),
        TlsAcceptor::from(config.tls),
    ))
}

/// Source and Native checks are explicit, never selected from a missing marker
/// or failed attempt. Source uses the original worker's fresh read-only turn;
/// Native keeps its ordinary recovery/source refusal before any request accept.
async fn startup_overview(
    directory: &std::path::Path,
    config: &Config,
    policy: Option<&Arc<Coordinator>>,
) -> io::Result<store::Overview> {
    #[cfg(feature = "witness-journal")]
    if let Some(reference) = config.source {
        return policy
            .ok_or_else(source_required)?
            .source_startup(directory.to_owned(), reference, config.key_sha256)
            .await;
    }
    #[cfg(not(feature = "witness-journal"))]
    let _ = policy;
    let key_sha256 = config.key_sha256;
    let storage = directory.to_owned();
    let overview = tokio::task::spawn_blocking(move || {
        if let Some(expected) = store::recovery::startup(&storage)?
            && expected != key_sha256
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "node TLS identity does not match the recovered node key",
            ));
        }
        let overview = store::inspect(&storage)?;
        if overview.schema_version < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "node channel requires an explicit management schema migration",
            ));
        }
        Ok(overview)
    })
    .await
    .map_err(|_| io::Error::other("node identity initialization task failed"))??;
    Ok(overview)
}

/// Check the current exact certificate binding without holding async locks.
/// The permit belongs to blocking work so cancellation cannot exceed capacity.
async fn authorize(
    state: &AppState,
    leaf: Arc<[u8]>,
) -> Result<Option<store::PeerAuthorization>, ApiError> {
    let confirmed = || {
        if let Some(policy) = &state.policy {
            policy.ensure_source_confirmed().map_err(|_| {
                ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "authorization_unavailable")
            })?;
        }
        Ok::<_, ApiError>(())
    };
    confirmed()?;
    let permit = state
        .authorization_work
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "authorization_busy"))?;
    let directory = state.directory.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let peer = store::authorize_peer(&directory, &leaf)?;
        if let Some(peer) = &peer {
            // Chain/clientAuth validation already ran in the mandatory TLS
            // handshake. This is the separate, operator-chosen SAN constraint.
            if super::tls::verify_peer_name(&leaf, &peer.expected_san).is_err() {
                return Ok(None);
            }
        }
        Ok::<_, io::Error>(peer)
    })
    .await
    .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "authorization_unavailable"))?
    .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "authorization_unavailable"))?;
    // A locally committed peer grant is not authority while its Source is
    // unconfirmed. Repeat after the bounded DB read, including keepalive use.
    confirmed()?;
    Ok(result)
}

fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(IDENTITY_PATH, get(identity))
        .merge(control::routes())
        .merge(witness::routes())
        .fallback(|| async { ApiError::new(StatusCode::NOT_FOUND, "not_found") })
        .method_not_allowed_fallback(|| async {
            ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed")
        })
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

async fn identity(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
) -> Response {
    Json(IdentityResponse {
        protocol_version: PROTOCOL_VERSION,
        node_id: &state.node_id,
        name: &state.name,
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        capabilities: CAPABILITIES,
        verified_peer: VerifiedPeerResponse {
            node_id: &peer.node_id,
            authorization_revision: peer.authorization_revision,
        },
    })
    .into_response()
}

async fn guard(State(state): State<Arc<AppState>>, mut request: Request, next: Next) -> Response {
    let outcome = timeout(REQUEST_TIMEOUT, async {
        api::validate_target(request.headers(), request.uri(), &state.origin)?;
        let Some(connection) = request.extensions().get::<ConnectionIdentity>().cloned() else {
            return Err(ApiError::internal());
        };
        let original = match connection {
            ConnectionIdentity::Authorized(identity) => identity,
            ConnectionIdentity::Forbidden => {
                return Err(ApiError::new(StatusCode::FORBIDDEN, "peer_not_authorized"));
            }
            ConnectionIdentity::Unavailable => {
                return Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authorization_unavailable",
                ));
            }
        };
        let peer = authorize(&state, original.leaf.clone())
            .await?
            .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "peer_not_authorized"))?;
        if peer.node_id != original.node_id
            || peer.authorization_revision != original.authorization_revision
        {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "peer_authorization_changed",
            ));
        }
        request.extensions_mut().insert(VerifiedPeer {
            node_id: peer.node_id,
            authorization_revision: peer.authorization_revision,
            leaf: original.leaf.clone(),
        });
        if matches!(*request.method(), Method::GET | Method::HEAD) {
            // This read-only protocol has no request payload semantics. Reject
            // content without allocating it or waiting beyond the request cap.
            // https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.1
            let (parts, body) = request.into_parts();
            to_bytes(body, 0).await.map_err(|error| {
                use std::error::Error as _;
                if error
                    .source()
                    .is_some_and(|source| source.is::<http_body_util::LengthLimitError>())
                {
                    ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "body_not_allowed")
                } else {
                    ApiError::new(StatusCode::BAD_REQUEST, "invalid_body")
                }
            })?;
            request = Request::from_parts(parts, Body::empty());
        }
        Ok::<_, ApiError>(next.run(request).await)
    })
    .await;
    let mut response = match outcome {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => error.into_response(),
        Err(_) => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "request_timeout").into_response(),
    };
    for (name, value) in [
        (header::CACHE_CONTROL, "no-store"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; frame-ancestors 'none'",
        ),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
}

/// Serve one already-bound listener under the management supervisor's shutdown.
///
/// Startup requires schema 2 and readable existing identity; nothing migrates or
/// repairs storage. Proxy control, health and traffic additionally require
/// schema 9 and the shared coordinator, including durable preset policy;
/// the unchanged identity-v1 endpoint grants no control or statistics permission.
/// Admission is capped at 128 connections including handshake,
/// each connection lasts at most 30 seconds, and authorization has two blocking
/// permits. Shutdown stops admission and drains at most five seconds. This
/// function installs neither OS signals nor global logging.
/// It rechecks recovery readiness and the configured actual-key pin before
/// accepting requests. The caller must still gate recovery before binding this
/// supplied listener or attaching egress programs, and retain process authority.
pub(super) async fn serve(
    listener: TcpListener,
    config: Config,
    directory: PathBuf,
    shutdown: CancellationToken,
    policy: Option<Arc<Coordinator>>,
    health: Option<super::health::Handle>,
    alerts: Option<super::alerts::Handle>,
) -> io::Result<()> {
    #[cfg(feature = "witness-journal")]
    if config.source.is_some() && listener.local_addr()? != config.bind {
        return Err(source_required());
    }
    let (state, tls) = initialize(directory, config, policy, health, alerts).await?;
    let app = router(state.clone());
    let connections_shutdown = shutdown.child_token();
    let mut connections = JoinSet::new();
    let capacity = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut last_accept_warning: Option<Instant> = None;
    let result = loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break Ok(()),
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result { tracing::debug!(cancelled = error.is_cancelled(), "node connection task ended"); }
            }
            incoming = listener.accept() => {
                let (stream, _) = match incoming {
                    Ok(connection) => connection,
                    Err(error) if api::retryable_accept_error(&error) => {
                        let now = Instant::now();
                        if last_accept_warning.is_none_or(|last| now.saturating_duration_since(last) >= Duration::from_secs(60)) {
                            tracing::warn!(kind = ?error.kind(), code = error.raw_os_error(), "node accept temporarily unavailable; retrying");
                            last_accept_warning = Some(now);
                        }
                        tokio::select! { _ = shutdown.cancelled() => break Ok(()), _ = tokio::time::sleep(Duration::from_millis(200)) => continue }
                    }
                    Err(error) => break Err(error),
                };
                let Ok(permit) = capacity.clone().try_acquire_owned() else { continue; };
                let tls = tls.clone();
                let state = state.clone();
                let app = app.clone();
                let shutdown = connections_shutdown.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let _ = timeout(CONNECTION_TIMEOUT, serve_connection(stream, tls, state, app, shutdown)).await;
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

async fn serve_connection(
    stream: TcpStream,
    tls: TlsAcceptor,
    state: Arc<AppState>,
    app: Router,
    shutdown: CancellationToken,
) {
    // TLS tickets and small control replies can otherwise wait for delayed
    // ACKs. Configure only this node channel, before any TLS or HTTP exchange.
    if stream.set_nodelay(true).is_err() {
        return;
    }
    let stream = tokio::select! {
        _ = shutdown.cancelled() => return,
        stream = timeout(HANDSHAKE_TIMEOUT, tls.accept(stream)) => match stream { Ok(Ok(stream)) => stream, _ => return },
    };
    if stream.get_ref().1.alpn_protocol() != Some(&b"http/1.1"[..]) {
        return;
    }
    let Ok(leaf) = super::tls::checked_leaf(stream.get_ref().1.peer_certificates()) else {
        return;
    };
    let leaf: Arc<[u8]> = leaf.into();
    let binding = tokio::select! {
        _ = shutdown.cancelled() => return,
        binding = authorize(&state, leaf.clone()) => binding,
    };
    let identity = match binding {
        Ok(Some(peer)) => ConnectionIdentity::Authorized(Arc::new(BoundIdentity {
            leaf,
            node_id: peer.node_id,
            authorization_revision: peer.authorization_revision,
        })),
        Ok(None) => ConnectionIdentity::Forbidden,
        Err(_) => ConnectionIdentity::Unavailable,
    };
    let service = TowerToHyperService::new(app.layer(Extension(identity)));
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

#[cfg(test)]
pub(super) mod tests {
    //! Real loopback mTLS and persistent authorization, not mocked peer headers.

    mod address_lookup {
        //! Exact inventory reads use the real node channel and current authorization.

        use super::*;
        use crate::{
            access::routing::{ResourceState, RoutingEntity},
            manage::{controller::Service, policy::Coordinator},
        };
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use futures_util::FutureExt as _;
        use std::panic::{AssertUnwindSafe, resume_unwind};

        fn coordinator(directory: &std::path::Path) -> io::Result<Arc<Coordinator>> {
            Coordinator::new(
                directory.to_owned(),
                store::load_policy(directory)?,
                Arc::new(store::lock(directory)?),
            )
        }

        fn administrator(directory: &std::path::Path) -> io::Result<String> {
            rusqlite::Connection::open(directory.join("management.sqlite3"))
                .map_err(io::Error::other)?
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)
        }

        #[tokio::test]
        async fn exact_address_mtls_reads_require_owner_and_keep_retired_identity_and_strict_paths()
        -> io::Result<()> {
            let fixture = Fixture::new(true, true)?;
            let server = coordinator(&fixture.server_state)?;
            let caller = coordinator(&fixture.client_state)?;
            let administrator = administrator(&fixture.server_state)?;
            let Some(RoutingEntity::Address(active)) = server
                .change(
                    administrator.clone(),
                    1,
                    store::PolicyChange::CreateAddress {
                        name: "Active source".into(),
                        ip: "127.0.0.2".parse().map_err(io::Error::other)?,
                        prefix_id: None,
                    },
                )
                .await?
                .routing
            else {
                return Err(io::Error::other("expected active fixture address"));
            };
            let Some(RoutingEntity::Address(retired)) = server
                .change(
                    administrator.clone(),
                    2,
                    store::PolicyChange::CreateAddress {
                        name: "Retired source".into(),
                        ip: "127.0.0.3".parse().map_err(io::Error::other)?,
                        prefix_id: None,
                    },
                )
                .await?
                .routing
            else {
                return Err(io::Error::other("expected retired fixture address"));
            };
            server
                .change(
                    administrator.clone(),
                    3,
                    store::PolicyChange::SetAddressState {
                        id: retired.id.clone(),
                        state: ResourceState::Retired,
                    },
                )
                .await?;
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let origin = format!("https://localhost:{}", address.port());
            let shutdown = CancellationToken::new();
            let mut tasks = Tasks::new();
            tasks.spawn(serve(
                listener,
                fixture.config(address)?,
                fixture.server_state.clone(),
                shutdown.clone(),
                Some(server.clone()),
                None,
                None,
            ));
            let outcome = AssertUnwindSafe(timeout(Duration::from_secs(20), async {
                let read = |address_id| {
                    control::request(
                        &caller,
                        fixture.client_tls.clone(),
                        &origin,
                        &fixture.server_id,
                        control::Request::Address { address_id },
                    )
                };
                let denied = read(active.id.clone())
                    .await
                    .err()
                    .ok_or_else(|| io::Error::other("registration must not grant address reads"))?;
                assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
                server
                    .set_owner(administrator, 1, Some(fixture.client_id.clone()))
                    .await?;
                for (id, state, revision) in [
                    (&active.id, ResourceState::Active, "2"),
                    (&retired.id, ResourceState::Retired, "4"),
                ] {
                    let control::Reply::Address(snapshot) = read(id.clone()).await? else {
                        return Err(io::Error::other("expected exact address snapshot"));
                    };
                    assert_eq!(snapshot.revision, "4");
                    assert_eq!(&snapshot.address.id, id);
                    assert_eq!(snapshot.address.state, state);
                    assert_eq!(snapshot.address.revision, revision);
                }
                let mut wire = client(&fixture, address, &mut tasks).await?;
                let path = format!("/node/v2/proxy/addresses/{}", active.id);
                for query in ["", "limit=1", "target=local"] {
                    let (status, _) =
                        request(&mut wire, address, &format!("{path}?{query}"), Method::GET)
                            .await?;
                    assert_eq!(status, StatusCode::BAD_REQUEST, "query: {query}");
                }
                for id in ["not-an-id", "AAAAAAAAAAAAAAAAAAAAAB", "%FF", "%2F"] {
                    let (status, _) = request(
                        &mut wire,
                        address,
                        &format!("/node/v2/proxy/addresses/{id}"),
                        Method::GET,
                    )
                    .await?;
                    assert_eq!(status, StatusCode::BAD_REQUEST, "id: {id}");
                }
                let missing = read(URL_SAFE_NO_PAD.encode([91; 16]))
                    .await
                    .err()
                    .ok_or_else(|| io::Error::other("expected missing address"))?;
                let rejected = missing
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<control::RemoteError>())
                    .ok_or_else(|| io::Error::other("expected typed missing address"))?;
                assert_eq!(
                    (rejected.status, rejected.code),
                    (404, "resource_not_found")
                );
                let directory = fixture.server_state.clone();
                let peer = fixture.client_id.clone();
                server
                    .read(move |_| store::set_peer_active(&directory, &peer, 1, false))
                    .await?;
                // The connection predates the authorization change; its TLS session
                // must not retain the previous request's authority.
                let (status, _) = request(&mut wire, address, &path, Method::GET).await?;
                assert_eq!(status, StatusCode::FORBIDDEN);
                Ok(())
            }))
            .catch_unwind()
            .await;
            shutdown.cancel();
            tasks.shutdown().await;
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(payload) => resume_unwind(payload),
            };
            outcome.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "exact address node fixture deadline",
                )
            })?
        }

        #[tokio::test]
        async fn old_node_address_lookup_404_does_not_change_v1_user_listing() -> io::Result<()> {
            let fixture = Fixture::new(true, true)?;
            let caller = coordinator(&fixture.client_state)?;
            for (operation, expected) in [
                (
                    control::Request::Address {
                        address_id: URL_SAFE_NO_PAD.encode([92; 16]),
                    },
                    "node_protocol_unsupported",
                ),
                (
                    control::Request::OperationsAlerts(
                        crate::manage::alerts::Query::parse(None).unwrap(),
                    ),
                    "node_protocol_unsupported",
                ),
                (
                    control::Request::UsersPage {
                        after: None,
                        limit: 25,
                        include_deleted: false,
                    },
                    "node_request_rejected",
                ),
            ] {
                let endpoint = RawEndpoint::start(fixture.server_tls.clone(), RawReply::NotFound)?;
                let response = control::request(
                    &caller,
                    fixture.client_tls.clone(),
                    &format!("https://localhost:{}", endpoint.address.port()),
                    &fixture.server_id,
                    operation,
                )
                .await;
                let served = endpoint.wait()?;
                let error = response
                    .err()
                    .ok_or_else(|| io::Error::other("expected old-node lookup rejection"))?;
                let rejected = error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<control::RemoteError>())
                    .ok_or_else(|| io::Error::other("expected typed old-node lookup rejection"))?;
                assert_eq!((rejected.status, rejected.code), (404, expected));
                assert!(served > 0);
            }
            Ok(())
        }

        #[tokio::test]
        async fn changed_target_invalidates_new_scoped_reads_but_keeps_old_error_precedence()
        -> io::Result<()> {
            for replacement_origin in [None, Some("https://localhost:1")] {
                for (operation, scoped_read) in [
                    (
                        control::Request::Address {
                            address_id: URL_SAFE_NO_PAD.encode([93; 16]),
                        },
                        true,
                    ),
                    (
                        control::Request::EgressAlerts(
                            crate::manage::alerts::Query::parse(None).unwrap(),
                        ),
                        true,
                    ),
                    (
                        control::Request::OperationsAlerts(
                            crate::manage::alerts::Query::parse(None).unwrap(),
                        ),
                        true,
                    ),
                    (
                        control::Request::UsersPage {
                            after: None,
                            limit: 25,
                            include_deleted: false,
                        },
                        false,
                    ),
                ] {
                    let fixture = Fixture::new(true, true)?;
                    let caller = coordinator(&fixture.client_state)?;
                    let administrator = administrator(&fixture.client_state)?;
                    let endpoint = RawEndpoint::start(
                        fixture.server_tls.clone(),
                        RawReply::ChangeTargetThenNotFound {
                            directory: fixture.client_state.clone(),
                            administrator: administrator.clone(),
                            peer: fixture.server_id.clone(),
                            replacement_origin: replacement_origin.map(str::to_owned),
                        },
                    )?;
                    let origin = format!("https://localhost:{}", endpoint.address.port());
                    let peer = fixture.server_id.clone();
                    caller
                        .read(move |directory| {
                            store::targets::configure(
                                directory,
                                &administrator,
                                &peer,
                                None,
                                &origin,
                                true,
                                None,
                            )
                        })
                        .await?;
                    let (service, _commands) = Service::new(
                        caller.clone(),
                        fixture.client_tls.clone(),
                        fixture.client_id.clone(),
                    );
                    let response = service.remote(fixture.server_id.clone(), operation).await;
                    let served = endpoint.wait()?;
                    let error = response.err().ok_or_else(|| {
                        io::Error::other("expected in-flight missing result rejection")
                    })?;
                    let remote = error
                        .get_ref()
                        .and_then(|error| error.downcast_ref::<control::RemoteError>());
                    if scoped_read {
                        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
                        assert!(remote.is_none());
                    } else {
                        let remote = remote
                            .ok_or_else(|| io::Error::other("old read lost its remote error"))?;
                        assert_eq!(error.kind(), io::ErrorKind::Other);
                        assert_eq!((remote.status, remote.code), (404, "resource_not_found"));
                    }
                    assert!(served > 0);
                    let peer = fixture.server_id;
                    let target = caller
                        .read(move |directory| store::targets::get(directory, &peer))
                        .await?;
                    assert_eq!(target.active, replacement_origin.is_some());
                    assert!(!target.retired);
                    assert_eq!(target.revision, 2);
                    if let Some(origin) = replacement_origin {
                        assert_eq!(target.origin, origin);
                    }
                }
            }
            Ok(())
        }
    }
    mod endpoints {
        //! Endpoint metadata uses real mTLS and the same current owner authorization as
        //! policy reads; advertised addresses never become control request destinations.

        use super::*;
        use crate::manage::{policy::Coordinator, proxy};

        fn coordinator(directory: &std::path::Path) -> io::Result<Arc<Coordinator>> {
            Coordinator::new(
                directory.to_owned(),
                store::load_policy(directory)?,
                Arc::new(store::lock(directory)?),
            )
        }

        #[tokio::test]
        async fn endpoint_catalog_requires_current_mtls_owner_and_keeps_unadvertised_binds_separate()
        -> io::Result<()> {
            let fixture = Fixture::new(true, true)?;
            let server = coordinator(&fixture.server_state)?;
            let caller = coordinator(&fixture.client_state)?;
            let administrator: String =
                rusqlite::Connection::open(fixture.server_state.join("management.sqlite3"))
                    .map_err(io::Error::other)?
                    .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                    .map_err(io::Error::other)?;
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let origin = format!("https://localhost:{}", address.port());
            let shutdown = CancellationToken::new();
            let mut tasks = Tasks::new();
            tasks.spawn(serve(
                listener,
                fixture.config(address)?,
                fixture.server_state.clone(),
                shutdown.clone(),
                Some(server.clone()),
                None,
                None,
            ));
            let result = timeout(Duration::from_secs(15), async {
        let call = || control::request(&caller, fixture.client_tls.clone(), &origin, &fixture.server_id, control::Request::Endpoints);
        assert_eq!(call().await.err().unwrap().kind(), io::ErrorKind::PermissionDenied);
        server.set_owner(administrator.clone(), 1, Some(fixture.client_id.clone())).await?;
        let control::Reply::Endpoints(empty) = call().await? else {
            return Err(io::Error::other("expected endpoint catalog"));
        };
        assert_eq!(empty.node_id, fixture.server_id);
        assert!(!empty.proxy_running);
        assert!(empty.listeners.is_empty());
        let configuration = fixture.server_state.join("endpoint-fixture.json");
        let mut file = OpenOptions::new().create_new(true).write(true).open(&configuration)?;
        file.write_all(br#"{"workers":1,"listeners":[{"protocol":"http","bind":"0.0.0.0:8080"},{"protocol":"socks5","bind":"[::]:1080","public_address":"proxy.example:1081"}]}"#)?;
        drop(file);
        let prepared = proxy::load(&configuration)?;
        server.configure_endpoints(prepared.endpoints().to_vec())?;
        assert!(server.configure_endpoints(Vec::new()).is_err());
        let control::Reply::Endpoints(catalog) = call().await? else {
            return Err(io::Error::other("expected configured endpoint catalog"));
        };
        assert!(!catalog.proxy_running);
        assert_eq!(catalog.listeners.len(), 2);
        assert_eq!(catalog.listeners[0].bind.to_string(), "0.0.0.0:8080");
        assert!(catalog.listeners[0].public_address.is_none());
        assert_eq!(catalog.listeners[1].public_address.as_deref(), Some("proxy.example:1081"));
        server.set_owner(administrator, 2, None).await?;
        assert_eq!(call().await.err().unwrap().kind(), io::ErrorKind::PermissionDenied);
        Ok(())
    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "endpoint fixture deadline"))?;
            shutdown.cancel();
            tasks.shutdown().await;
            result
        }

        #[tokio::test]
        async fn old_node_endpoint_404_negotiates_support_without_changing_policy_v1_errors()
        -> io::Result<()> {
            let fixture = Fixture::new(true, true)?;
            let caller = coordinator(&fixture.client_state)?;
            for (operation, expected) in [
                (control::Request::Endpoints, "node_protocol_unsupported"),
                (
                    control::Request::EndpointSettings,
                    "node_protocol_unsupported",
                ),
                (control::Request::Policy, "node_request_rejected"),
            ] {
                let endpoint = RawEndpoint::start(fixture.server_tls.clone(), RawReply::NotFound)?;
                let error = control::request(
                    &caller,
                    fixture.client_tls.clone(),
                    &format!("https://localhost:{}", endpoint.address.port()),
                    &fixture.server_id,
                    operation,
                )
                .await
                .err()
                .ok_or_else(|| io::Error::other("expected old node route rejection"))?;
                let rejection = error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<control::RemoteError>())
                    .ok_or_else(|| io::Error::other("expected typed node rejection"))?;
                assert_eq!(rejection.status, 404);
                assert_eq!(rejection.code, expected);
                assert!(endpoint.wait()? > 0);
            }
            Ok(())
        }

        #[tokio::test]
        async fn v4_metadata_command_rejects_missing_duplicate_and_non_json_content_type_without_writes()
        -> io::Result<()> {
            let fixture = Fixture::new(true, true)?;
            let server = coordinator(&fixture.server_state)?;
            server
                .configure_endpoint_settings(&fixture.server_id)
                .await?;
            let administrator: String =
                rusqlite::Connection::open(fixture.server_state.join("management.sqlite3"))
                    .map_err(io::Error::other)?
                    .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                    .map_err(io::Error::other)?;
            server
                .set_owner(administrator, 1, Some(fixture.client_id.clone()))
                .await?;
            let before = store::endpoints::read(&fixture.server_state)?;
            let before_policy = server.reader().revision()?;
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let shutdown = CancellationToken::new();
            let mut tasks = Tasks::new();
            tasks.spawn(serve(
                listener,
                fixture.config(address)?,
                fixture.server_state.clone(),
                shutdown.clone(),
                Some(server.clone()),
                None,
                None,
            ));
            let result = timeout(Duration::from_secs(10), async {
                let mut client = client(&fixture, address, &mut tasks).await?;
                for types in [
                    vec![],
                    vec!["text/plain"],
                    vec!["application/json", "application/json"],
                ] {
                    let mut input = http::Request::builder()
                        .method(Method::POST)
                        .uri("/node/v4/proxy/commands")
                        .header(header::HOST, format!("localhost:{}", address.port()))
                        .body(Empty::<Bytes>::new())
                        .map_err(io::Error::other)?;
                    for value in types {
                        input
                            .headers_mut()
                            .append(header::CONTENT_TYPE, value.parse().unwrap());
                    }
                    let response = client.send_request(input).await.map_err(io::Error::other)?;
                    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
                    let bytes = response
                        .into_body()
                        .collect()
                        .await
                        .map_err(io::Error::other)?
                        .to_bytes();
                    let body: serde_json::Value =
                        serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                    assert_eq!(body["error"]["code"], "json_required");
                }
                let after = store::endpoints::read(&fixture.server_state)?;
                assert_eq!(after.revision, before.revision);
                assert_eq!(server.reader().revision()?, before_policy);
                assert_eq!(
                    store::ownership(&fixture.server_state)?.last_terminal_command,
                    0
                );
                Ok::<_, io::Error>(())
            })
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "metadata header fixture deadline")
            })?;
            shutdown.cancel();
            tasks.shutdown().await;
            result
        }
    }
    mod operations {
        //! The atomic route reads the existing monitor under current owner/leaf
        //! authorization. No collector, source history or recursive downstream RPC runs.

        use futures_util::FutureExt as _;

        use super::*;
        use crate::manage::{alerts, policy::Coordinator};

        fn coordinator(directory: &std::path::Path) -> io::Result<Arc<Coordinator>> {
            Coordinator::new(
                directory.to_owned(),
                store::load_policy(directory)?,
                Arc::new(store::lock(directory)?),
            )
        }

        #[tokio::test]
        async fn operations_snapshot_rechecks_owner_and_carries_actual_tls_leaf() -> io::Result<()>
        {
            let fixture = Fixture::new(true, true)?;
            let server = coordinator(&fixture.server_state)?;
            let caller = coordinator(&fixture.client_state)?;
            let administrator: String =
                rusqlite::Connection::open(fixture.server_state.join("management.sqlite3"))
                    .map_err(io::Error::other)?
                    .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                    .map_err(io::Error::other)?;
            let (monitor, _not_started) = alerts::new(
                server.clone(),
                fixture.server_id.clone(),
                None,
                None,
                false,
                false,
                None,
                None,
            )?;
            let boot = monitor
                .node_snapshot()
                .map_err(|_| io::Error::other("test snapshot unavailable"))?
                .boot_id;
            let leaf = crate::manage::tls::read_certificate_leaf(&fixture.server_cert)?;
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let origin = format!("https://localhost:{}", address.port());
            let shutdown = CancellationToken::new();
            let _cancel_on_drop = shutdown.clone().drop_guard();
            let mut tasks = Tasks::new();
            tasks.spawn(serve(
                listener,
                fixture.config(address)?,
                fixture.server_state.clone(),
                shutdown.clone(),
                Some(server.clone()),
                None,
                Some(monitor),
            ));
            let result = std::panic::AssertUnwindSafe(timeout(Duration::from_secs(15), async {
                let call = || {
                    control::request(
                        &caller,
                        fixture.client_tls.clone(),
                        &origin,
                        &fixture.server_id,
                        control::Request::OperationsSnapshot,
                    )
                };
                assert_eq!(
                    call().await.err().unwrap().kind(),
                    io::ErrorKind::PermissionDenied
                );
                server
                    .set_owner(administrator.clone(), 1, Some(fixture.client_id.clone()))
                    .await?;
                let control::Reply::OperationsSnapshot(snapshot) = call().await? else {
                    return Err(io::Error::other("expected atomic operations snapshot"));
                };
                assert_eq!(snapshot.authorization.node_id, fixture.server_id);
                assert_eq!(snapshot.authorization.authorization_revision, 1);
                assert_eq!(&*snapshot.authorization.leaf, leaf);
                assert_eq!(snapshot.value.node_id, fixture.server_id);
                assert_eq!(snapshot.value.boot_id, boot);
                assert!(snapshot.value.active.is_empty() && snapshot.value.recent.is_empty());
                assert_eq!(
                    (snapshot.value.active_count, snapshot.value.recent_count),
                    (0, 0)
                );
                assert!(
                    snapshot.value.age_millis.is_none()
                        && snapshot.value.observed_at_unix_ms.is_none()
                );
                let mut raw = client(&fixture, address, &mut tasks).await?;
                let (status, rejected) = request(
                    &mut raw,
                    address,
                    "/node/v1/proxy/operations-snapshot?",
                    Method::GET,
                )
                .await?;
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert_eq!(rejected["error"]["code"], "invalid_query");
                drop(raw);
                server.set_owner(administrator, 2, None).await?;
                assert_eq!(
                    call().await.err().unwrap().kind(),
                    io::ErrorKind::PermissionDenied
                );
                io::Result::Ok(())
            }))
            .catch_unwind()
            .await;
            shutdown.cancel();
            tasks.shutdown().await;
            match result {
                Err(panic) => std::panic::resume_unwind(panic),
                Ok(result) => result.map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "atomic snapshot fixture timed out")
                })?,
            }
        }

        /// A complete otherwise-valid snapshot cannot escape after the client's exact
        /// DER authorization is revoked between the first and final response bytes.
        #[test]
        fn operations_snapshot_does_not_return_proof_after_mid_body_revocation() -> io::Result<()> {
            let fixture = Fixture::new(true, true)?;
            let caller = coordinator(&fixture.client_state)?;
            let server = coordinator(&fixture.server_state)?;
            let (monitor, _not_started) = alerts::new(
                server,
                fixture.server_id.clone(),
                None,
                None,
                false,
                false,
                None,
                None,
            )?;
            let snapshot = monitor
                .node_snapshot()
                .map_err(|_| io::Error::other("test snapshot unavailable"))?;
            let value = serde_json::json!({"version":1,"node_id":fixture.server_id,
        "resource":"proxy_policy","data":snapshot});
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let call = |address: SocketAddr| {
                runtime.block_on(control::request(
                    &caller,
                    fixture.client_tls.clone(),
                    &format!("https://localhost:{}", address.port()),
                    &fixture.server_id,
                    control::Request::OperationsSnapshot,
                ))
            };
            let valid =
                RawEndpoint::start(fixture.server_tls.clone(), RawReply::Json(value.clone()))?;
            assert!(matches!(
                call(valid.address)?,
                control::Reply::OperationsSnapshot(_)
            ));
            assert!(valid.wait()? > 0);
            let revoked = RawEndpoint::start(
                fixture.server_tls.clone(),
                RawReply::RevokeThenJson {
                    value,
                    directory: fixture.client_state.clone(),
                    leaf: crate::manage::tls::read_certificate_leaf(&fixture.server_cert)?,
                },
            )?;
            assert_eq!(
                call(revoked.address).err().unwrap().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(revoked.wait()? > 0);
            Ok(())
        }
    }
    mod presets {
        //! Real mandatory-mTLS v3 preset control shares the same policy publisher and
        //! owner/epoch/command namespace as the unchanged v1 and v2 resources.

        use super::*;
        use crate::{
            access::{self, presets as model},
            manage::policy::Coordinator,
        };

        fn coordinator(directory: &std::path::Path) -> io::Result<Arc<Coordinator>> {
            Coordinator::new(
                directory.to_owned(),
                store::load_policy(directory)?,
                Arc::new(store::lock(directory)?),
            )
        }
        fn administrator(directory: &std::path::Path) -> io::Result<String> {
            rusqlite::Connection::open(directory.join("management.sqlite3"))
                .map_err(io::Error::other)?
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)
        }

        #[tokio::test]
        async fn v3_mtls_presets_publish_once_without_fabricating_backend_readiness_or_old_receipts()
        -> io::Result<()> {
            let fixture = Fixture::new(true, true)?;
            let server = coordinator(&fixture.server_state)?;
            let caller = coordinator(&fixture.client_state)?;
            server.configure_presets(crate::ebpf::Args::default().load()?)?;
            let source = administrator(&fixture.client_state)?;
            let administrator = administrator(&fixture.server_state)?;
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let origin = format!("https://localhost:{}", address.port());
            let shutdown = CancellationToken::new();
            let mut tasks = Tasks::new();
            tasks.spawn(serve(
                listener,
                fixture.config(address)?,
                fixture.server_state.clone(),
                shutdown.clone(),
                Some(server.clone()),
                None,
                None,
            ));
            let result = timeout(Duration::from_secs(30), async {
        let call = |operation| {
            control::request(
                &caller,
                fixture.client_tls.clone(),
                &origin,
                &fixture.server_id,
                operation,
            )
        };
        assert_eq!(
            call(control::Request::PresetCatalog)
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        server
            .set_owner(administrator, 1, Some(fixture.client_id.clone()))
            .await?;
        let control::Reply::PresetCatalog(catalog) = call(control::Request::PresetCatalog).await?
        else {
            return Err(io::Error::other("expected typed catalog"));
        };
        assert!(
            catalog.available_presets.is_empty()
                && catalog.operations.is_empty()
                && catalog.abi_version.is_none()
        );
        let catalog_json = serde_json::to_value(catalog).map_err(io::Error::other)?;
        assert_ne!(catalog_json["backend_state"], "ready");
        let v1 = |id: u64, revision: u64, mutation| control::Command {
            version: 1,
            target_node_id: fixture.server_id.clone(),
            resource: "proxy_policy".into(),
            controller_epoch: "2".into(),
            command_id: id.to_string(),
            expected_policy_revision: revision.to_string(),
            source_administrator_id: source.clone(),
            mutation,
        };
        let v3 = |id: u64, revision: u64, mutation| control::PresetCommand {
            version: 3,
            target_node_id: fixture.server_id.clone(),
            resource: "proxy_policy".into(),
            controller_epoch: "2".into(),
            command_id: id.to_string(),
            expected_policy_revision: revision.to_string(),
            source_administrator_id: source.clone(),
            mutation,
        };
        let control::Reply::Command(mut created) = call(control::Request::Command(v1(
            1,
            1,
            control::Mutation::CreateUser {
                name: "preset user".into(),
                protocols: vec![access::Protocol::Http],
                concurrent_limit: 2,
            },
        )))
        .await?
        else {
            return Err(io::Error::other("expected v1 user"));
        };
        let user = created.user.take().unwrap().id;
        assert!(created.presets.is_none() && created.receipt.preset.is_none());
        let control::Reply::Command(mut created) = call(control::Request::Command(v1(
            2,
            2,
            control::Mutation::CreateCredential {
                user_id: user.clone(),
            },
        )))
        .await?
        else {
            return Err(io::Error::other("expected v1 credential"));
        };
        let credential = created.credential.take().unwrap();
        let secret = created.secret.take().unwrap();
        let configured = model::UserPreset {
            user_id: user.clone(),
            default_preset: Some(crate::ebpf::Profile::Linux),
            allowed_presets: vec![crate::ebpf::Profile::Linux, crate::ebpf::Profile::Windows],
        };
        let issue = v3(
            3,
            3,
            control::PresetMutation::SetUserPresets {
                presets: configured.clone(),
            },
        );
        let control::Reply::Command(changed) =
            call(control::Request::PresetCommand(issue.clone())).await?
        else {
            return Err(io::Error::other("expected v3 preset receipt"));
        };
        assert!(changed.receipt.status == control::ReceiptStatus::Saved);
        assert_eq!(changed.receipt.policy_revision.as_deref(), Some("4"));
        assert!(
            changed.user.is_none()
                && changed.credential.is_none()
                && changed.secret.is_none()
                && changed.routing.is_none()
        );
        let Some(model::PresetEntity::User(value)) = changed.presets else {
            return Err(io::Error::other("expected accepted user presets"));
        };
        assert_eq!(value.user_id, configured.user_id);
        assert_eq!(value.default_preset, configured.default_preset);
        assert_eq!(
            model::allowed_mask(&value)?,
            model::allowed_mask(&configured)?
        );
        let admitted = server
            .reader()
            .authenticate(&credential.login, secret.as_bytes(), access::Protocol::Http)
            .unwrap();
        assert_eq!(
            admitted.presets.tcp().unwrap(),
            Some(crate::ebpf::Profile::Linux)
        );
        {
            assert!(matches!(
                server.reader().authenticate(
                    &format!("{}-device-ios", credential.login),
                    secret.as_bytes(),
                    access::Protocol::Http,
                ),
                Err(access::Error::Denied)
            ));
        }
        let control::Reply::Command(replayed) =
            call(control::Request::PresetCommand(issue)).await?
        else {
            return Err(io::Error::other("expected replay"));
        };
        assert!(replayed.replayed && replayed.presets.is_none() && replayed.secret.is_none());
        assert_eq!(server.reader().revision()?, 4);
        let control::Reply::UserPresets(read) = call(control::Request::UserPresets {
            user_id: user.clone(),
        })
        .await?
        else {
            return Err(io::Error::other("expected user presets"));
        };
        assert_eq!(read.revision, "4");
        assert_eq!(read.presets.user_id, configured.user_id);
        assert_eq!(read.presets.default_preset, configured.default_preset);
        assert_eq!(
            model::allowed_mask(&read.presets)?,
            model::allowed_mask(&configured)?
        );
        for version in [1, 2] {
            let error = call(control::Request::Receipt {
                version,
                controller_epoch: 2,
                command_id: 3,
            })
            .await
            .err()
            .unwrap();
            assert_eq!(
                error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<control::RemoteError>())
                    .unwrap()
                    .code,
                "resource_not_found"
            );
        }
        let control::Reply::Receipt(receipt) = call(control::Request::Receipt {
            version: 3,
            controller_epoch: 2,
            command_id: 3,
        })
        .await?
        else {
            return Err(io::Error::other("expected v3 receipt"));
        };
        assert_eq!(receipt.preset.unwrap().id, user);
        let control::Reply::Command(mut pool) =
            call(control::Request::RoutingCommand(control::RoutingCommand {
                version: 2,
                target_node_id: fixture.server_id.clone(),
                resource: "proxy_policy".into(),
                controller_epoch: "2".into(),
                command_id: "4".into(),
                expected_policy_revision: "4".into(),
                source_administrator_id: source.clone(),
                mutation: control::RoutingMutation::CreatePool {
                    name: "preset pool".into(),
                    family: access::routing::AddressFamily::V4,
                },
            }))
            .await?
        else {
            return Err(io::Error::other("expected v2 pool"));
        };
        let Some(crate::manage::views::Entity::Pool(pool)) = pool.routing.take() else {
            return Err(io::Error::other("expected typed pool"));
        };
        let preset = model::PoolPreset {
            pool_id: pool.id,
            default_preset: Some(crate::ebpf::Profile::Windows),
        };
        let control::Reply::Command(changed) = call(control::Request::PresetCommand(v3(
            5,
            5,
            control::PresetMutation::SetPoolPreset {
                preset: preset.clone(),
            },
        )))
        .await?
        else {
            return Err(io::Error::other("expected pool preset"));
        };
        assert!(matches!(changed.presets,Some(model::PresetEntity::Pool(value)) if value==preset));
        let control::Reply::PoolPreset(read) = call(control::Request::PoolPreset {
            pool_id: preset.pool_id.clone(),
        })
        .await?
        else {
            return Err(io::Error::other("expected pool preset read"));
        };
        assert_eq!(read.revision, "6");
        assert_eq!(read.preset, preset);
        let control::Reply::Command(_) = call(control::Request::PresetCommand(v3(
            6,
            6,
            control::PresetMutation::SetUserPresets {
                presets: model::UserPreset::native(user.clone()),
            },
        )))
        .await?
        else {
            return Err(io::Error::other("expected native update"));
        };
        assert_eq!(server.reader().revision()?, 7);
        assert_eq!(
            server
                .reader()
                .authenticate(&credential.login, secret.as_bytes(), access::Protocol::Http)
                .unwrap()
                .presets
                .tcp()
                .unwrap(),
            None
        );
        // Policy changes do not rewrite an already admitted flow's copied
        // selection; only new admissions consume the new native-only grant.
        assert_eq!(
            admitted.presets.tcp().unwrap(),
            Some(crate::ebpf::Profile::Linux)
        );
        let mut wrong = v3(
            7,
            7,
            control::PresetMutation::SetUserPresets {
                presets: model::UserPreset::native(user),
            },
        );
        wrong.controller_epoch = "1".into();
        let error = call(control::Request::PresetCommand(wrong))
            .await
            .err()
            .unwrap();
        assert_eq!(
            error
                .get_ref()
                .and_then(|error| error.downcast_ref::<control::RemoteError>())
                .unwrap()
                .code,
            "controller_epoch_changed"
        );
        let mut raw = client(&fixture, address, &mut tasks).await?;
        let (_, identity) = request(&mut raw, address, IDENTITY_PATH, Method::GET).await?;
        assert_eq!(
            identity["capabilities"],
            serde_json::json!(["identity_read"])
        );
        let directory = fixture.server_state.clone();
        let peer = fixture.client_id.clone();
        server
            .read(move |_| store::set_peer_active(&directory, &peer, 1, false))
            .await?;
        assert_eq!(
            request(
                &mut raw,
                address,
                "/node/v3/proxy/presets/catalog",
                Method::GET
            )
            .await?
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(server.reader().revision()?, 7);
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "preset mTLS verification timed out",
        )
    });
            shutdown.cancel();
            tasks.shutdown().await;
            result?
        }
    }
    mod search {
        //! Real node TLS and owner authorization for the additive read path. Fixture
        //! rows are nonsecret metadata in new test databases, not production migration.

        use super::*;
        use crate::manage::{
            policy::Coordinator,
            user_search::{Mode, Query},
        };
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        fn coordinator(directory: &std::path::Path) -> io::Result<Arc<Coordinator>> {
            Coordinator::new(
                directory.to_owned(),
                store::load_policy(directory)?,
                Arc::new(store::lock(directory)?),
            )
        }

        #[tokio::test]
        async fn user_search_over_real_mtls_finds_beyond_old_page_and_rechecks_snapshot_and_owner()
        -> io::Result<()> {
            let fixture = Fixture::new(true, true)?;
            let mut ids: Vec<_> = (1..=30u8)
                .map(|value| URL_SAFE_NO_PAD.encode([value; 16]))
                .collect();
            ids.sort();
            let mut connection =
                rusqlite::Connection::open(fixture.server_state.join("management.sqlite3"))
                    .map_err(io::Error::other)?;
            let administrator: String = connection
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)?;
            let transaction = connection.transaction().map_err(io::Error::other)?;
            for (index, id) in ids.iter().enumerate() {
                let deleted = index == 29;
                transaction.execute("INSERT INTO proxy_users (id,name,active,deleted,protocols,concurrent_limit,revision) VALUES (?1,?2,?3,?4,1,1,1)",
            rusqlite::params![id, if index >= 27 { "Match_% İ" } else { "Other" }, !deleted, deleted]).map_err(io::Error::other)?;
                transaction
                    .execute(
                        "INSERT INTO routing_permissions(user_id,legacy_allowed) VALUES (?1,1)",
                        [id],
                    )
                    .map_err(io::Error::other)?;
                transaction
            .execute(
                "INSERT INTO user_presets(user_id,default_preset,allowed_mask) VALUES (?1,NULL,0)",
                [id],
            )
            .map_err(io::Error::other)?;
            }
            transaction.commit().map_err(io::Error::other)?;
            drop(connection);
            let old = store::list_users(&fixture.server_state, false, None, 25)?;
            assert_eq!(old.items.len(), 25);
            assert!(old.items.iter().all(|user| user.name == "Other"));
            let server = coordinator(&fixture.server_state)?;
            let caller = coordinator(&fixture.client_state)?;
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let origin = format!("https://localhost:{}", address.port());
            let shutdown = CancellationToken::new();
            let mut tasks = Tasks::new();
            tasks.spawn(serve(
                listener,
                fixture.config(address)?,
                fixture.server_state.clone(),
                shutdown.clone(),
                Some(server.clone()),
                None,
                None,
            ));
            let outcome = timeout(Duration::from_secs(15), async {
                let call = |query| {
                    control::request(
                        &caller,
                        fixture.client_tls.clone(),
                        &origin,
                        &fixture.server_id,
                        control::Request::UsersSearch(query),
                    )
                };
                let first_query = Query::new(Mode::Name, "MATCH_%".into(), false, 1, None)?;
                assert_eq!(
                    call(first_query.clone()).await.err().unwrap().kind(),
                    io::ErrorKind::PermissionDenied
                );
                server
                    .set_owner(administrator.clone(), 1, Some(fixture.client_id.clone()))
                    .await?;
                let control::Reply::UsersSearch(first) = call(first_query.clone()).await? else {
                    return Err(io::Error::other("expected search page"));
                };
                assert_eq!(first.items[0].id, ids[27]);
                assert_eq!(first.revision, "1");
                let cursor = first
                    .next_cursor
                    .ok_or_else(|| io::Error::other("expected second search page"))?;
                let second_query =
                    Query::new(Mode::Name, "match_%".into(), false, 1, Some(cursor))?;
                let control::Reply::UsersSearch(second) = call(second_query.clone()).await? else {
                    return Err(io::Error::other("expected search continuation"));
                };
                assert_eq!(second.items[0].id, ids[28]);
                assert!(second.next_cursor.is_none());
                let control::Reply::UsersSearch(history) =
                    call(Query::new(Mode::Name, "match_%".into(), true, 50, None)?).await?
                else {
                    return Err(io::Error::other("expected search history"));
                };
                assert_eq!(history.items.len(), 3);
                assert!(history.items[2].deleted);
                let changed = control::request(
                    &caller,
                    fixture.client_tls.clone(),
                    &origin,
                    &fixture.server_id,
                    control::Request::Command(control::Command {
                        version: 1,
                        target_node_id: fixture.server_id.clone(),
                        resource: "proxy_policy".into(),
                        controller_epoch: "2".into(),
                        command_id: "1".into(),
                        expected_policy_revision: "1".into(),
                        source_administrator_id: fixture.client_id.clone(),
                        mutation: control::Mutation::CreateUser {
                            name: "Another".into(),
                            protocols: vec![crate::access::Protocol::Http],
                            concurrent_limit: 1,
                        },
                    }),
                )
                .await?;
                assert!(matches!(changed, control::Reply::Command(_)));
                let error = call(second_query)
                    .await
                    .err()
                    .ok_or_else(|| io::Error::other("expected stale search cursor rejection"))?;
                let rejected = error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<control::RemoteError>())
                    .ok_or_else(|| io::Error::other("expected typed search rejection"))?;
                assert_eq!(
                    (rejected.status, rejected.code),
                    (409, "user_search_changed")
                );
                assert!(matches!(
                    call(first_query.clone()).await?,
                    control::Reply::UsersSearch(_)
                ));
                server.set_owner(administrator, 2, None).await?;
                assert_eq!(
                    call(first_query).await.err().unwrap().kind(),
                    io::ErrorKind::PermissionDenied
                );
                Ok(())
            })
            .await;
            shutdown.cancel();
            tasks.shutdown().await;
            outcome.map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "node search fixture deadline")
            })?
        }

        #[tokio::test]
        async fn old_node_user_search_404_is_negotiated_without_changing_old_user_listing()
        -> io::Result<()> {
            let fixture = Fixture::new(true, true)?;
            let caller = coordinator(&fixture.client_state)?;
            for (operation, expected) in [
                (
                    control::Request::UsersSearch(Query::new(
                        Mode::Name,
                        "test".into(),
                        false,
                        25,
                        None,
                    )?),
                    "node_protocol_unsupported",
                ),
                (
                    control::Request::UsersPage {
                        after: None,
                        limit: 25,
                        include_deleted: false,
                    },
                    "node_request_rejected",
                ),
            ] {
                let endpoint = RawEndpoint::start(fixture.server_tls.clone(), RawReply::NotFound)?;
                let response = control::request(
                    &caller,
                    fixture.client_tls.clone(),
                    &format!("https://localhost:{}", endpoint.address.port()),
                    &fixture.server_id,
                    operation,
                )
                .await;
                let served = endpoint.wait()?;
                let error = response
                    .err()
                    .ok_or_else(|| io::Error::other("expected old-node search rejection"))?;
                let rejected = error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<control::RemoteError>())
                    .ok_or_else(|| io::Error::other("expected typed old-node rejection"))?;
                assert_eq!((rejected.status, rejected.code), (404, expected));
                assert!(served > 0);
            }
            Ok(())
        }
    }
    mod traffic {
        //! The real mandatory-mTLS listener exports only durable, transaction-authorized
        //! local statistics; the client attaches actual TLS evidence, never JSON claims.

        use super::*;
        use crate::{
            access::Protocol,
            manage::{policy::Coordinator, store::traffic as durable, traffic as collector},
            traffic::Direction,
        };

        fn coordinator(directory: &std::path::Path) -> io::Result<Arc<Coordinator>> {
            Coordinator::new(
                directory.to_owned(),
                store::load_policy(directory)?,
                Arc::new(store::lock(directory)?),
            )
        }

        fn administrator(directory: &std::path::Path) -> io::Result<String> {
            rusqlite::Connection::open(directory.join("management.sqlite3"))
                .map_err(io::Error::other)?
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)
        }

        #[tokio::test]
        async fn durable_routes_require_current_mtls_owner_and_return_real_leaf_evidence()
        -> io::Result<()> {
            let fixture = Fixture::new(true, true)?;
            let server = coordinator(&fixture.server_state)?;
            let caller = coordinator(&fixture.client_state)?;
            let administrator = administrator(&fixture.server_state)?;
            let created = server
                .change(
                    administrator.clone(),
                    1,
                    store::PolicyChange::CreateUser {
                        name: "remote traffic owner".into(),
                        protocols: vec![Protocol::Http],
                        concurrent_limit: 2,
                    },
                )
                .await?;
            let user = created.user.unwrap().id;
            let mut created = server
                .change(
                    administrator.clone(),
                    created.revision,
                    store::PolicyChange::CreateCredential {
                        user_id: user.clone(),
                    },
                )
                .await?;
            let credential = created.credential.take().unwrap();
            let secret = created.secret.take().unwrap();
            let (collector, _runner) = collector::new(server.clone()).await?;
            collector.begin().await?;
            let admission = server
                .reader()
                .authenticate(&credential.login, secret.as_bytes(), Protocol::Http)
                .unwrap();
            admission.lease.meter(Direction::Upload).add(101);
            admission.lease.meter(Direction::Download).add(55);
            let secure = server
                .reader()
                .authenticate_http(&credential.login, secret.as_bytes(), true)
                .unwrap();
            secure.lease.meter(Direction::Upload).add(77);
            secure.lease.meter(Direction::Download).add(33);
            collector.finish(false).await?;
            let durable = durable::status(&fixture.server_state)?;
            let server_leaf =
                super::super::super::tls::read_certificate_leaf(&fixture.server_cert)?;
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let origin = format!("https://localhost:{}", address.port());
            let shutdown = CancellationToken::new();
            let mut tasks = Tasks::new();
            tasks.spawn(serve(
                listener,
                fixture.config(address)?,
                fixture.server_state.clone(),
                shutdown.clone(),
                Some(server.clone()),
                None,
                None,
            ));
            let result = timeout(Duration::from_secs(15), async {
                let call = |operation| {
                    control::request(
                        &caller,
                        fixture.client_tls.clone(),
                        &origin,
                        &fixture.server_id,
                        operation,
                    )
                };
                // Registration proves identity only. Even a real Cookie/header sent by
                // the fixture cannot substitute for current controller ownership.
                assert_eq!(
                    call(control::Request::TrafficSnapshot)
                        .await
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::PermissionDenied
                );
                {
                    let gate = store::update_lock(&fixture.server_state)?;
                    store::set_owner(
                        &fixture.server_state,
                        &gate,
                        &administrator,
                        1,
                        Some(&fixture.client_id),
                    )?;
                }
                let control::Reply::TrafficSnapshot(snapshot) =
                    call(control::Request::TrafficSnapshot).await?
                else {
                    panic!("snapshot reply");
                };
                assert_eq!(snapshot.authorization.node_id, fixture.server_id);
                assert_eq!(snapshot.authorization.authorization_revision, 1);
                assert_eq!(&*snapshot.authorization.leaf, server_leaf);
                assert_eq!(snapshot.value.status.node_id, fixture.server_id);
                assert_eq!(snapshot.value.status.meter_epoch, durable.meter_epoch);
                assert_eq!(snapshot.value.status.cursor, durable.cursor);
                assert!(!snapshot.value.status.http_split);
                assert_eq!(snapshot.value.totals[0].upload, 178);
                assert_eq!(snapshot.value.totals[0].download, 88);
                assert_eq!(snapshot.value.totals[1].upload, 0);
                assert!(!snapshot.value.status.clean && !snapshot.value.status.loss_possible);
                assert_eq!(snapshot.value.minute.len(), 1);
                assert!(snapshot.value.minute[0].values[1].is_none());

                // Exercise the actual first automatic pull through the controller's
                // shared TLS/network budget, then its verified-proof import transaction.
                // Imported child bytes must never become this parent's local traffic.
                let caller_administrator = self::administrator(&fixture.client_state)?;
                store::targets::configure(
                    &fixture.client_state,
                    &caller_administrator,
                    &fixture.server_id,
                    None,
                    &origin,
                    true,
                    None,
                )?;
                let (controller, _commands) = super::super::super::controller::Service::new(
                    caller.clone(),
                    fixture.client_tls.clone(),
                    fixture.client_id.clone(),
                );
                let pull_shutdown = CancellationToken::new();
                let mut pulls = Tasks::new();
                pulls.spawn(
                    super::super::super::remote_traffic::Runner::new(caller.clone(), controller)
                        .run(pull_shutdown.clone()),
                );
                let imported = async {
                    loop {
                        let peer = fixture.server_id.clone();
                        match caller
                            .read(move |directory| store::remote_traffic::get(directory, &peer))
                            .await
                        {
                            Ok(cached) if cached.snapshot.is_some() => {
                                break Ok(cached.snapshot.unwrap());
                            }
                            Ok(_) => {}
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                            Err(error) => return Err(error),
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
                .await;
                pull_shutdown.cancel();
                pulls.shutdown().await;
                let imported = imported?;
                assert_eq!(imported.status.node_id, fixture.server_id);
                assert_eq!(imported.status.cursor, durable.cursor);
                assert!(imported.status.http_split);
                assert_eq!(imported.totals[0].upload, 0);
                assert_eq!(imported.totals[3].upload, 101);
                assert_eq!(imported.totals[3].download, 55);
                assert_eq!(imported.totals[4].upload, 77);
                assert_eq!(imported.totals[4].download, 33);
                let local = caller
                    .read(|directory| durable::totals(directory, durable::Scope::Node))
                    .await?;
                assert!(local.items.iter().all(|item| {
                    item.value.upload == 0 && item.value.download == 0 && !item.value.saturated
                }));
                for scope in [
                    durable::Scope::Node,
                    durable::Scope::User(user.clone()),
                    durable::Scope::Credential(credential.id.clone()),
                ] {
                    let control::Reply::TrafficTotals(totals) =
                        call(control::Request::TrafficTotals {
                            scope: scope.clone(),
                        })
                        .await?
                    else {
                        panic!("totals reply");
                    };
                    assert_eq!(totals.value.items[0].value.upload, 178);
                    assert_eq!(totals.value.items[0].value.download, 88);
                    assert_eq!(&*totals.authorization.leaf, server_leaf);
                    let control::Reply::TrafficTotals(split) =
                        call(control::Request::TrafficTotalsV2 { scope }).await?
                    else {
                        panic!("split totals reply")
                    };
                    assert!(split.value.status.http_split);
                    assert_eq!(split.value.items[3].value.upload, 101);
                    assert_eq!(split.value.items[4].value.upload, 77);
                    assert_eq!(&*split.authorization.leaf, server_leaf);
                }
                let control::Reply::TrafficBuckets(buckets) =
                    call(control::Request::TrafficBuckets {
                        scope: durable::Scope::User(user),
                        resolution: durable::Resolution::Minute,
                        after: None,
                        limit: 50,
                    })
                    .await?
                else {
                    panic!("buckets reply");
                };
                assert_eq!(buckets.value.items.len(), 1);
                assert_eq!(buckets.value.items[0].items.len(), 1);
                assert_eq!(buckets.value.items[0].items[0].value.upload, 178);

                let mut raw = client(&fixture, address, &mut tasks).await?;
                let (status, body) = request(&mut raw, address, IDENTITY_PATH, Method::GET).await?;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(body["capabilities"], serde_json::json!(["identity_read"]));
                for path in [
                    "/node/v1/traffic?scope=node&scope=node",
                    "/node/v1/traffic/buckets?limit=51",
                    "/node/v1/traffic/snapshot?url=anything",
                    "/node/v2/traffic?scope=node&scope=node",
                    "/node/v2/traffic/buckets?limit=51",
                    "/node/v2/traffic/snapshot?url=anything",
                ] {
                    assert_eq!(
                        request(&mut raw, address, path, Method::GET).await?.0,
                        StatusCode::BAD_REQUEST
                    );
                }
                {
                    let gate = store::update_lock(&fixture.server_state)?;
                    store::set_owner(&fixture.server_state, &gate, &administrator, 2, None)?;
                }
                let (status, body) =
                    request(&mut raw, address, "/node/v1/traffic/snapshot", Method::GET).await?;
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert_eq!(body["error"]["code"], "peer_not_authorized");
                let (status, body) =
                    request(&mut raw, address, "/node/v2/traffic/snapshot", Method::GET).await?;
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert_eq!(body["error"]["code"], "peer_not_authorized");
                Ok::<_, io::Error>(())
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "traffic route verification timed out",
                )
            });
            shutdown.cancel();
            tasks.shutdown().await;
            result?
        }

        fn snapshot_json(fixture: &Fixture) -> io::Result<serde_json::Value> {
            let status = durable::status(&fixture.server_state)?;
            Ok(serde_json::json!({"version":1,"node_id":fixture.server_id,
        "resource":"proxy_traffic","definition":"accepted_effective_payload_v1",
        "data":{"metadata":{"meter_epoch":status.meter_epoch,"run_id":status.run_id,
            "cursor":status.cursor.to_string(),"clean":status.clean,"loss_possible":status.loss_possible,
            "history_gap":status.history_gap,"time_uncertain":status.time_uncertain,
            "last_checkpoint_at":status.last_checkpoint_at,"meter_started_at":status.meter_started_at},
            "totals":[["0","0",false],["0","0",false],["0","0",false]],
            "floors":[null,null,null],"minute":[],"hour":[],"day":[]}}))
        }

        #[tokio::test]
        async fn split_negotiation_only_falls_back_for_definitive_unsupported_reads()
        -> io::Result<()> {
            let fixture = Fixture::new(true, true)?;
            let caller = coordinator(&fixture.client_state)?;
            let administrator = administrator(&fixture.client_state)?;
            let (controller, _runner) = super::super::super::controller::Service::new(
                caller,
                fixture.client_tls.clone(),
                fixture.client_id.clone(),
            );
            for (status, first, fallback) in [
                (404, serde_json::json!({"error":{"code":"not_found"}}), true),
                (
                    503,
                    serde_json::json!({"error":{"code":"traffic_protocols_unsupported"}}),
                    true,
                ),
                (
                    403,
                    serde_json::json!({"error":{"code":"peer_not_authorized"}}),
                    false,
                ),
                (
                    503,
                    serde_json::json!({"error":{"code":"traffic_unavailable"}}),
                    false,
                ),
                (
                    200,
                    serde_json::json!({"version":2,"definition":"wrong"}),
                    false,
                ),
            ] {
                let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
                let endpoint = RawEndpoint::start(
                    fixture.server_tls.clone(),
                    RawReply::TrafficNegotiation {
                        status,
                        first,
                        legacy: snapshot_json(&fixture)?,
                        requests: requests.clone(),
                    },
                )?;
                let existing = store::targets::get(&fixture.client_state, &fixture.server_id).ok();
                store::targets::configure(
                    &fixture.client_state,
                    &administrator,
                    &fixture.server_id,
                    existing.map(|target| target.revision),
                    &format!("https://localhost:{}", endpoint.address.port()),
                    true,
                    None,
                )?;
                let result = super::super::super::remote_traffic::request(
                    &controller,
                    fixture.server_id.clone(),
                    control::Request::TrafficSnapshotV2,
                )
                .await;
                endpoint.stop()?;
                if fallback {
                    let control::Reply::TrafficSnapshot(value) = result? else {
                        return Err(io::Error::other("expected legacy snapshot"));
                    };
                    assert!(!value.value.status.http_split);
                } else {
                    let error = result
                        .err()
                        .ok_or_else(|| io::Error::other("unexpected fallback success"))?;
                    assert_eq!(
                        error.kind(),
                        if status == 403 {
                            io::ErrorKind::PermissionDenied
                        } else if status == 200 {
                            io::ErrorKind::InvalidData
                        } else {
                            io::ErrorKind::Other
                        }
                    );
                }
                let requests = requests
                    .lock()
                    .map_err(|_| io::Error::other("fixture request lock"))?;
                assert_eq!(requests.len(), if fallback { 2 } else { 1 });
                assert_eq!(requests[0], "GET /node/v2/traffic/snapshot HTTP/1.1");
                if fallback {
                    assert_eq!(requests[1], "GET /node/v1/traffic/snapshot HTTP/1.1");
                }
            }
            Ok(())
        }

        #[test]
        fn traffic_client_never_returns_a_proof_for_unregistered_or_mid_body_revoked_der()
        -> io::Result<()> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            for wrong_peer in [false, true] {
                let fixture = Fixture::new(true, wrong_peer)?;
                let caller = coordinator(&fixture.client_state)?;
                let endpoint =
                    RawEndpoint::start(fixture.server_tls.clone(), RawReply::NoResponse)?;
                let expected = if wrong_peer {
                    &fixture.client_id
                } else {
                    &fixture.server_id
                };
                let error = runtime
                    .block_on(control::request(
                        &caller,
                        fixture.client_tls.clone(),
                        &format!("https://localhost:{}", endpoint.address.port()),
                        expected,
                        control::Request::TrafficSnapshot,
                    ))
                    .err()
                    .unwrap();
                assert_eq!(
                    endpoint.wait()?,
                    0,
                    "HTTP must not precede exact-DER binding"
                );
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            }
            let fixture = Fixture::new(true, true)?;
            let caller = coordinator(&fixture.client_state)?;
            let server_leaf =
                super::super::super::tls::read_certificate_leaf(&fixture.server_cert)?;
            let endpoint = RawEndpoint::start(
                fixture.server_tls.clone(),
                RawReply::RevokeThenJson {
                    value: snapshot_json(&fixture)?,
                    directory: fixture.client_state.clone(),
                    leaf: server_leaf,
                },
            )?;
            let error = runtime
                .block_on(control::request(
                    &caller,
                    fixture.client_tls.clone(),
                    &format!("https://localhost:{}", endpoint.address.port()),
                    &fixture.server_id,
                    control::Request::TrafficSnapshot,
                ))
                .err()
                .unwrap();
            assert!(endpoint.wait()? > 0);
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            runtime.block_on(caller.read(store::policy_status))?;
            Ok(())
        }

        #[test]
        fn traffic_client_enforces_body_cap_before_eof_and_rejects_a_changed_definition()
        -> io::Result<()> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let fixture = Fixture::new(true, true)?;
            let caller = coordinator(&fixture.client_state)?;
            for (operation, limit) in [
                (control::Request::TrafficSnapshot, 32 * 1024),
                (control::Request::TrafficSnapshotV2, 64 * 1024),
            ] {
                let endpoint =
                    RawEndpoint::start(fixture.server_tls.clone(), RawReply::Oversized(limit))?;
                let error = runtime
                    .block_on(control::request(
                        &caller,
                        fixture.client_tls.clone(),
                        &format!("https://localhost:{}", endpoint.address.port()),
                        &fixture.server_id,
                        operation,
                    ))
                    .err()
                    .unwrap();
                assert!(endpoint.stop()? > 0);
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert_eq!(
                    error.to_string(),
                    "node control response exceeds its size limit"
                );
            }

            let mut value = snapshot_json(&fixture)?;
            value["definition"] = serde_json::json!("wire_bytes_including_headers");
            let endpoint = RawEndpoint::start(fixture.server_tls.clone(), RawReply::Json(value))?;
            let error = runtime
                .block_on(control::request(
                    &caller,
                    fixture.client_tls.clone(),
                    &format!("https://localhost:{}", endpoint.address.port()),
                    &fixture.server_id,
                    control::Request::TrafficSnapshot,
                ))
                .err()
                .unwrap();
            assert!(endpoint.wait()? > 0);
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            Ok(())
        }
    }
    mod witness {
        //! Real mandatory-mTLS routing and durable witness state in fresh local fixtures.
        use super::*;
        use crate::manage::{
            policy::Coordinator,
            witness::{Enrollment, Phase, Record, Transition},
        };
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use http_body_util::Full;

        #[cfg(feature = "witness-journal")]
        mod source {
            //! Both directions use real PKIX/mTLS and the production router/connection
            //! handler. Only AppState construction is test-owned: public Source startup
            //! remains forbidden. The upstream node also sends synthetic downstream calls;
            //! this does not configure two mutually dependent protected Sources.
            use super::*;
            use crate::manage::store::journal::SourceFixture;

            async fn start_source(
                live: &SourceFixture,
                stop: CancellationToken,
            ) -> io::Result<(SocketAddr, tokio::task::JoinHandle<io::Result<()>>)> {
                let f = &live.fixture;
                let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
                let address = listener.local_addr()?;
                let state = Arc::new(AppState {
                    directory: f.client_state.clone(),
                    origin: PublicOrigin::parse(&format!(
                        "https://client.test:{}",
                        address.port()
                    ))?,
                    node_id: f.client_id.clone(),
                    name: "source witness fixture".into(),
                    authorization_work: Arc::new(Semaphore::new(MAX_AUTHORIZATION_WORK)),
                    policy: Some(live.source.clone()),
                    health: None,
                    alerts: None,
                });
                let app = router(state.clone());
                let tls = TlsAcceptor::from(crate::manage::tls::node_server_config(
                    &f.ca,
                    &f.client_cert,
                    &f.client_key,
                )?);
                let server = tokio::spawn(async move {
                    let mut clients = JoinSet::new();
                    loop {
                        tokio::select! {
                            biased;
                            _=stop.cancelled()=>break,
                            Some(joined)=clients.join_next(),if !clients.is_empty()=>{joined.map_err(io::Error::other)?;},
                            accepted=listener.accept()=>{
                                let (stream, _)=accepted?;
                                clients.spawn(serve_connection(stream,tls.clone(),state.clone(),app.clone(),stop.clone()));
                            }
                        }
                    }
                    drop(listener);
                    timeout(Duration::from_secs(5), async {
                        while let Some(joined) = clients.join_next().await {
                            joined.map_err(io::Error::other)?;
                        }
                        Ok::<_, io::Error>(())
                    })
                    .await
                    .map_err(io::Error::other)??;
                    Ok(())
                });
                Ok((address, server))
            }

            async fn call(
                live: &SourceFixture,
                address: SocketAddr,
                tasks: &mut Tasks,
                path: &str,
                input: Option<&Transition>,
            ) -> io::Result<(StatusCode, serde_json::Value)> {
                let f = &live.fixture;
                let client =
                    crate::manage::tls::node_client_config(&f.ca, &f.server_cert, &f.server_key)?;
                let stream = TlsConnector::from(client)
                    .connect(
                        ServerName::try_from("client.test").map_err(io::Error::other)?,
                        TcpStream::connect(address).await?,
                    )
                    .await?;
                let (mut sender, connection) =
                    hyper::client::conn::http1::handshake(TokioIo::new(stream))
                        .await
                        .map_err(io::Error::other)?;
                tasks.spawn(async move { connection.await.map_err(io::Error::other) });
                let body = input
                    .map(serde_json::to_vec)
                    .transpose()
                    .map_err(io::Error::other)?
                    .unwrap_or_default();
                let response = sender
                    .send_request(
                        http::Request::builder()
                            .method(if input.is_some() {
                                Method::POST
                            } else {
                                Method::GET
                            })
                            .uri(path)
                            .header(header::HOST, format!("client.test:{}", address.port()))
                            .header(header::CONTENT_TYPE, "application/json")
                            .header(header::CONNECTION, "close")
                            .body(Full::new(Bytes::from(body)))
                            .map_err(io::Error::other)?,
                    )
                    .await
                    .map_err(io::Error::other)?;
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                let status = response.status();
                let bytes = response
                    .into_body()
                    .collect()
                    .await
                    .map_err(io::Error::other)?
                    .to_bytes();
                Ok((
                    status,
                    serde_json::from_slice(&bytes).map_err(io::Error::other)?,
                ))
            }

            #[tokio::test]
            async fn protected_witness_router_requires_its_own_confirmation_before_remote_inspection()
            -> io::Result<()> {
                let live = SourceFixture::new_with(
                    CutResponse {
                        witness_only: true,
                        witness_confirm: true,
                        witness_sequence: Some(2),
                        ..Default::default()
                    },
                    |_| Ok(()),
                )
                .await?;
                let stop = CancellationToken::new();
                let mut server = None;
                let mut clients = Tasks::new();
                let result = async {
                    let e = Enrollment {
                        witness_node_id: live.fixture.client_id.clone(),
                        peer_node_id: live.fixture.server_id.clone(),
                        binding_id: URL_SAFE_NO_PAD.encode([71u8; 16]),
                        writer_id: URL_SAFE_NO_PAD.encode([72u8; 16]),
                        baseline: "0".repeat(64),
                    };
                    let retained = e.clone();
                    live.source
                        .source_identity_write_then(
                            live.author.clone(),
                            move |w| w.bind_witness(&retained),
                            Ok,
                        )
                        .await?;
                    let (address, task) = start_source(&live, stop.clone()).await?;
                    server = Some(task);
                    let input = Transition {
                        witness_node_id: e.witness_node_id.clone(),
                        binding_id: e.binding_id.clone(),
                        writer_id: e.writer_id.clone(),
                        sequence: "1".into(),
                        previous: e.baseline.clone(),
                        commitment: "1".repeat(64),
                    };
                    let inspect = format!("/node/v1/witness/bindings/{}", e.binding_id);
                    live.arm();
                    assert_eq!(
                        call(
                            &live,
                            address,
                            &mut clients,
                            "/node/v1/witness/reserve",
                            Some(&input)
                        )
                        .await?
                        .0,
                        StatusCode::SERVICE_UNAVAILABLE
                    );
                    // SQL contains the pending downstream record, but its own source proof
                    // is unknown. A remote GET must not bypass confirmation via a read worker.
                    assert_eq!(
                        store::witness::inspect(&live.fixture.client_state, &e.binding_id)?.phase,
                        Phase::Pending
                    );
                    assert_eq!(
                        call(&live, address, &mut clients, &inspect, None).await?.0,
                        StatusCode::SERVICE_UNAVAILABLE
                    );
                    live.source.reconcile_source().await?;
                    let (status, record) =
                        call(&live, address, &mut clients, &inspect, None).await?;
                    assert_eq!(status, StatusCode::OK);
                    assert_eq!(record["phase"], "pending");
                    assert_eq!(
                        call(
                            &live,
                            address,
                            &mut clients,
                            "/node/v1/witness/reserve",
                            Some(&input)
                        )
                        .await?
                        .0,
                        StatusCode::OK
                    );
                    assert_eq!(live.floor()?.sequence, "2");
                    let (status, record) = call(
                        &live,
                        address,
                        &mut clients,
                        "/node/v1/witness/confirm",
                        Some(&input),
                    )
                    .await?;
                    assert_eq!(status, StatusCode::OK);
                    assert_eq!(record["phase"], "confirmed");
                    assert_eq!(live.floor()?.sequence, "3");
                    Ok(())
                }
                .await;
                stop.cancel();
                let served = if let Some(server) = server {
                    server.await.map_err(io::Error::other)?
                } else {
                    Ok(())
                };
                while let Some(joined) = clients.join_next().await {
                    joined.map_err(io::Error::other)??;
                }
                let closed = live.close().await;
                result.and(served).and(closed)
            }
        }

        async fn call(
            f: &Fixture,
            address: SocketAddr,
            tasks: &mut Tasks,
            path: &str,
            method: Method,
            body: Vec<u8>,
        ) -> io::Result<(StatusCode, serde_json::Value)> {
            let stream = TcpStream::connect(address).await?;
            let stream = TlsConnector::from(f.client_tls.clone())
                .connect(
                    ServerName::try_from("localhost").map_err(io::Error::other)?,
                    stream,
                )
                .await?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .map_err(io::Error::other)?;
            tasks.spawn(async move { connection.await.map_err(io::Error::other) });
            let response = sender
                .send_request(
                    http::Request::builder()
                        .method(method)
                        .uri(path)
                        .header(header::HOST, format!("localhost:{}", address.port()))
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::CONNECTION, "close")
                        .header("x-node-id", "not-an-identity")
                        .body(Full::new(Bytes::from(body)))
                        .map_err(io::Error::other)?,
                )
                .await
                .map_err(io::Error::other)?;
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            let status = response.status();
            let bytes = response
                .into_body()
                .collect()
                .await
                .map_err(io::Error::other)?
                .to_bytes();
            Ok((
                status,
                serde_json::from_slice(&bytes).map_err(io::Error::other)?,
            ))
        }

        #[tokio::test]
        async fn witness_mtls_requires_explicit_binding_and_keeps_pending_after_reconnect()
        -> io::Result<()> {
            let f = Fixture::new(true, true)?;
            let e = Enrollment {
                witness_node_id: f.server_id.clone(),
                binding_id: URL_SAFE_NO_PAD.encode([1_u8; 16]),
                peer_node_id: f.client_id.clone(),
                writer_id: URL_SAFE_NO_PAD.encode([2_u8; 16]),
                baseline: "0".repeat(64),
            };
            store::witness::bind(&f.server_state, &e)?;
            let coordinator = Coordinator::new(
                f.server_state.clone(),
                store::load_policy(&f.server_state)?,
                Arc::new(store::lock(&f.server_state)?),
            )?;
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let stop = CancellationToken::new();
            let mut tasks = Tasks::new();
            tasks.spawn(serve(
                listener,
                f.config(address)?,
                f.server_state.clone(),
                stop.clone(),
                Some(coordinator.clone()),
                None,
                None,
            ));
            let result = timeout(Duration::from_secs(15), async {
                let path = format!("/node/v1/witness/bindings/{}", e.binding_id);
                let (status, value) =
                    call(&f, address, &mut tasks, &path, Method::GET, Vec::new()).await?;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(value["sequence"], "0");
                let wrong = format!(
                    "/node/v1/witness/bindings/{}",
                    URL_SAFE_NO_PAD.encode([3_u8; 16])
                );
                assert_eq!(
                    call(&f, address, &mut tasks, &wrong, Method::GET, Vec::new())
                        .await?
                        .0,
                    StatusCode::FORBIDDEN
                );
                assert_eq!(
                    call(
                        &f,
                        address,
                        &mut tasks,
                        &format!("{path}?x=1"),
                        Method::GET,
                        Vec::new()
                    )
                    .await?
                    .0,
                    StatusCode::BAD_REQUEST
                );
                assert_eq!(
                    call(&f, address, &mut tasks, &path, Method::GET, b"{}".to_vec())
                        .await?
                        .0,
                    StatusCode::PAYLOAD_TOO_LARGE
                );
                let input = Transition {
                    witness_node_id: e.witness_node_id.clone(),
                    binding_id: e.binding_id.clone(),
                    writer_id: e.writer_id.clone(),
                    sequence: "1".into(),
                    previous: e.baseline.clone(),
                    commitment: "1".repeat(64),
                };
                let bytes = serde_json::to_vec(&input).map_err(io::Error::other)?;
                assert_eq!(
                    call(
                        &f,
                        address,
                        &mut tasks,
                        "/node/v1/witness/confirm",
                        Method::POST,
                        bytes.clone()
                    )
                    .await?
                    .0,
                    StatusCode::CONFLICT
                );
                let (status, pending) = call(
                    &f,
                    address,
                    &mut tasks,
                    "/node/v1/witness/reserve",
                    Method::POST,
                    bytes.clone(),
                )
                .await?;
                assert_eq!(status, StatusCode::OK);
                let record: Record =
                    serde_json::from_value(pending.clone()).map_err(io::Error::other)?;
                assert_eq!(record.phase, Phase::Pending);
                assert_eq!(
                    call(&f, address, &mut tasks, &path, Method::GET, Vec::new())
                        .await?
                        .1,
                    pending
                );
                assert_eq!(
                    call(
                        &f,
                        address,
                        &mut tasks,
                        "/node/v1/witness/reserve",
                        Method::POST,
                        bytes.clone()
                    )
                    .await?
                    .1,
                    pending
                );
                let mut changed = input.clone();
                changed.commitment = "2".repeat(64);
                assert_eq!(
                    call(
                        &f,
                        address,
                        &mut tasks,
                        "/node/v1/witness/confirm",
                        Method::POST,
                        serde_json::to_vec(&changed).map_err(io::Error::other)?
                    )
                    .await?
                    .0,
                    StatusCode::CONFLICT
                );
                let (status, confirmed) = call(
                    &f,
                    address,
                    &mut tasks,
                    "/node/v1/witness/confirm",
                    Method::POST,
                    bytes.clone(),
                )
                .await?;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(confirmed["phase"], "confirmed");
                assert_eq!(
                    call(
                        &f,
                        address,
                        &mut tasks,
                        "/node/v1/witness/reserve",
                        Method::POST,
                        bytes.clone()
                    )
                    .await?
                    .1,
                    confirmed
                );
                // Revocation runs through the same coordinator writer queue; even an
                // exact replay cannot use the old connection/binding as cached authority.
                let leaf = f.client_der.clone();
                coordinator
                    .metadata_write(move |directory| store::revoke_certificate(directory, &leaf, 1))
                    .await?;
                assert_eq!(
                    call(
                        &f,
                        address,
                        &mut tasks,
                        "/node/v1/witness/reserve",
                        Method::POST,
                        bytes
                    )
                    .await?
                    .0,
                    StatusCode::FORBIDDEN
                );
                Ok::<_, io::Error>(())
            })
            .await;
            stop.cancel();
            while let Some(joined) = tasks.join_next().await {
                joined.map_err(io::Error::other)??;
            }
            result
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "witness fixture deadline"))?
        }
    }

    use std::{
        fs::{self, DirBuilder, OpenOptions},
        io::Write,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
        time::SystemTime,
    };

    use bytes::Bytes;
    use http_body_util::{BodyExt as _, Empty};
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    use rustls::{ClientConfig, RootCertStore, crypto::aws_lc_rs};
    use rustls_pki_types::ServerName;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_rustls::TlsConnector;

    use super::*;

    /// Test-only transport fault state. It never changes authentication or command
    /// behavior: the response middleware sees bytes only after the real handler
    /// has committed/published and constructed its ordinary reply.
    #[derive(Default)]
    pub(in crate::manage) struct CutResponse {
        /// Also permit one successful witness reserve reply to be truncated. This
        /// flag affects only the test response layer, never the handler/transaction.
        pub(in crate::manage) witness_reserve: bool,
        pub(in crate::manage) witness_confirm: bool,
        /// Restrict witness faults to one exact wire sequence, e.g. the metadata
        /// receipt after a successful policy confirmation. Command faults ignore it.
        pub(in crate::manage) witness_sequence: Option<u64>,
        /// A fixture may serve both witness and command roles. True leaves its
        /// command-secret replies intact and faults only the selected witness reply.
        /// Default false preserves the original one-time command fault behavior.
        pub(in crate::manage) witness_only: bool,
        /// Optional one-shot response wait instead of truncation. Only the test's
        /// owner releases it; production handler/authorization remain unchanged.
        pub(in crate::manage) pause: Option<Arc<ResponsePause>>,
        /// Explicitly truncate after a pause instead of its normal complete reply.
        /// Default false preserves all existing response-pause fixtures.
        pub(in crate::manage) cut_after_pause: bool,
        pub(in crate::manage) armed: std::sync::atomic::AtomicBool,
        pub(in crate::manage) cuts: AtomicUsize,
        pub(in crate::manage) replay_without_secret: std::sync::atomic::AtomicBool,
    }

    #[derive(Default)]
    pub(in crate::manage) struct ResponsePause {
        pub(in crate::manage) entered: tokio::sync::Notify,
        pub(in crate::manage) release: tokio::sync::Notify,
    }

    /// Serve the exact production router/TLS/identity binding with an outer,
    /// one-shot response-body fault. The fixed Content-Length promises the full
    /// reply, while a successful credential or opted-in witness transition response
    /// loses its final byte. A separate replay observation inspects only booleans,
    /// never retains secrets.
    pub(in crate::manage) async fn start_cut_response_node(
        fixture: &Fixture,
        policy: Arc<crate::manage::policy::Coordinator>,
        fault: Arc<CutResponse>,
        shutdown: CancellationToken,
    ) -> io::Result<(SocketAddr, tokio::task::JoinHandle<io::Result<()>>)> {
        use futures_util::StreamExt as _;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let config = fixture.config(address)?;
        let (state, tls) = initialize(
            fixture.server_state.clone(),
            config,
            Some(policy),
            None,
            None,
        )
        .await?;
        let app = router(state.clone()).layer(middleware::from_fn(
            move |request: Request, next: Next| {
                let fault = fault.clone();
                async move {
                    let command = request.method() == Method::POST
                        && request.uri().path() == "/node/v1/proxy/commands";
                    let witness_reserve = fault.witness_reserve
                        && request.method() == Method::POST
                        && request.uri().path() == "/node/v1/witness/reserve";
                    let witness_confirm = fault.witness_confirm
                        && request.method() == Method::POST
                        && request.uri().path() == "/node/v1/witness/confirm";
                    let response = next.run(request).await;
                    if !(command || witness_reserve || witness_confirm)
                        || !response.status().is_success()
                    {
                        return response;
                    }
                    let (parts, body) = response.into_parts();
                    let Ok(bytes) = to_bytes(body, 32 * 1024).await else {
                        return ApiError::internal().into_response();
                    };
                    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                        return ApiError::internal().into_response();
                    };
                    if value["data"]["replayed"] == true && value["data"]["secret"].is_null() {
                        fault.replay_without_secret.store(true, Ordering::Release);
                    }
                    let witness_matches = fault.witness_sequence.is_none_or(|expected| {
                        value["sequence"]
                            .as_str()
                            .and_then(|value| value.parse::<u64>().ok())
                            == Some(expected)
                    });
                    let cut = ((!fault.witness_only && value["data"]["secret"].is_string())
                        || (witness_reserve && witness_matches && value["phase"] == "pending")
                        || (witness_confirm && witness_matches && value["phase"] == "confirmed"))
                        && fault.armed.swap(false, Ordering::AcqRel);
                    if !cut {
                        return Response::from_parts(parts, Body::from(bytes));
                    }
                    if let Some(pause) = &fault.pause {
                        pause.entered.notify_one();
                        pause.release.notified().await;
                        if !fault.cut_after_pause {
                            return Response::from_parts(parts, Body::from(bytes));
                        }
                    }
                    let full_length = bytes.len();
                    let Some(length) = full_length.checked_sub(1) else {
                        return ApiError::internal().into_response();
                    };
                    fault.cuts.fetch_add(1, Ordering::AcqRel);
                    let mut response = Response::from_parts(
                        parts,
                        Body::from_stream(
                            futures_util::stream::once(async move {
                                Ok::<_, io::Error>(bytes.slice(..length))
                            })
                            .chain(futures_util::stream::once(
                                async {
                                    // One pending poll allows HTTP headers/prefix to flush
                                    // before the deliberate incomplete-body I/O failure.
                                    tokio::task::yield_now().await;
                                    Err::<Bytes, _>(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "fixture truncated response",
                                    ))
                                },
                            )),
                        ),
                    );
                    response.headers_mut().insert(
                        header::CONTENT_LENGTH,
                        HeaderValue::from_str(&full_length.to_string()).unwrap(),
                    );
                    response
                }
            },
        ));
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _=shutdown.cancelled()=>break,
                    Some(joined)=connections.join_next(),if !connections.is_empty()=>{joined.map_err(io::Error::other)?;},
                    accepted=listener.accept()=>{
                        let(stream,_)=accepted?;
                        connections.spawn(serve_connection(stream,tls.clone(),state.clone(),app.clone(),shutdown.clone()));
                    }
                }
            }
            drop(listener);
            timeout(Duration::from_secs(5), async {
                while connections.join_next().await.is_some() {}
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "fault fixture connections did not drain",
                )
            })?;
            Ok(())
        });
        Ok((address, task))
    }

    /// Exclusively owns a fresh random temporary leaf; only that test tree is removed.
    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn new() -> io::Result<Self> {
            let mut random = [0; 16];
            getrandom::fill(&mut random).map_err(|_| io::Error::other("test randomness failed"))?;
            let path = std::env::temp_dir().join(format!(
                "vproxy-node-channel-{:032x}",
                u128::from_be_bytes(random)
            ));
            let directory = DirBuilder::new();
            #[cfg(unix)]
            let directory = {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut directory = directory;
                directory.mode(0o700);
                directory
            };
            directory.create(&path)?;
            Ok(Self(path))
        }

        fn write(&self, name: &str, value: &[u8]) -> io::Result<PathBuf> {
            let path = self.0.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            options.open(&path)?.write_all(value)?;
            Ok(path)
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub(in crate::manage) struct Fixture {
        _directory: TemporaryDirectory,
        pub(in crate::manage) server_state: PathBuf,
        pub(in crate::manage) client_state: PathBuf,
        pub(in crate::manage) server_id: String,
        pub(in crate::manage) client_id: String,
        pub(in crate::manage) ca: PathBuf,
        server_cert: PathBuf,
        server_key: PathBuf,
        pub(in crate::manage) client_cert: PathBuf,
        pub(in crate::manage) client_key: PathBuf,
        client_der: Vec<u8>,
        pub(in crate::manage) server_tls: Arc<ServerConfig>,
        pub(in crate::manage) client_tls: Arc<ClientConfig>,
        certificate: super::super::certificates::State,
    }

    fn parameters(sans: Vec<String>) -> io::Result<CertificateParams> {
        let mut parameters = CertificateParams::new(sans).map_err(io::Error::other)?;
        let now = SystemTime::now();
        parameters.not_before = now
            .checked_sub(Duration::from_secs(3600))
            .ok_or_else(|| io::Error::other("test time underflow"))?
            .into();
        parameters.not_after = now
            .checked_add(Duration::from_secs(86400))
            .ok_or_else(|| io::Error::other("test time overflow"))?
            .into();
        Ok(parameters)
    }

    impl Fixture {
        pub(in crate::manage) fn new(
            register_client: bool,
            register_server: bool,
        ) -> io::Result<Self> {
            Self::new_inner(register_client, register_server, false)
        }

        /// Source staging writes private marker files directly under client-state.
        /// Prepare that new directory with the production ACL helper, never repair
        /// an already-created fixture or relax the production marker check.
        pub(in crate::manage) fn new_with_private_source(
            register_client: bool,
            register_server: bool,
        ) -> io::Result<Self> {
            Self::new_inner(register_client, register_server, true)
        }

        fn new_inner(
            register_client: bool,
            register_server: bool,
            private_source: bool,
        ) -> io::Result<Self> {
            let directory = TemporaryDirectory::new()?;
            let mut ca_parameters = parameters(Vec::new())?;
            ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let issuer = CertifiedIssuer::self_signed(
                ca_parameters,
                KeyPair::generate().map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
            let ca = directory.write("ca.pem", issuer.pem().as_bytes())?;
            let leaf = |san: &str| -> io::Result<_> {
                let mut params = parameters(vec![san.into()])?;
                params.is_ca = IsCa::ExplicitNoCa;
                params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
                params.extended_key_usages = vec![
                    ExtendedKeyUsagePurpose::ClientAuth,
                    ExtendedKeyUsagePurpose::ServerAuth,
                ];
                let key = KeyPair::generate().map_err(io::Error::other)?;
                let certificate = params.signed_by(&key, &issuer).map_err(io::Error::other)?;
                Ok((certificate, key))
            };
            let (server, server_key_pair) = leaf("localhost")?;
            let (client, client_key_pair) = leaf("client.test")?;
            let server_cert = directory.write("server.pem", server.pem().as_bytes())?;
            let server_key =
                directory.write("server-key.pem", server_key_pair.serialize_pem().as_bytes())?;
            let client_cert = directory.write("client.pem", client.pem().as_bytes())?;
            let client_key =
                directory.write("client-key.pem", client_key_pair.serialize_pem().as_bytes())?;
            let server_state = directory.0.join("server-state");
            let client_state = directory.0.join("client-state");
            if private_source {
                super::super::files::create_directory(&client_state)?;
            }
            // Node transport never authenticates an administrator, so no password
            // verifier is exercised here; these are isolated nonempty fixture PHCs.
            let server_id =
                store::initialize(&server_state, "Server fixture", "admin", "fixture-phc")?.node_id;
            let client_id =
                store::initialize(&client_state, "Client fixture", "admin", "fixture-phc")?.node_id;
            if register_client {
                store::register_peer(
                    &server_state,
                    &client_id,
                    "Client",
                    client.der().as_ref(),
                    "client.test",
                    None,
                )?;
            }
            if register_server {
                store::register_peer(
                    &client_state,
                    &server_id,
                    "Server",
                    server.der().as_ref(),
                    "localhost",
                    None,
                )?;
            }
            let server_tls = super::super::tls::node_server_config(&ca, &server_cert, &server_key)?;
            let client_tls = super::super::tls::node_client_config(&ca, &client_cert, &client_key)?;
            Ok(Self {
                _directory: directory,
                server_state,
                client_state,
                server_id,
                client_id,
                ca,
                server_cert,
                server_key,
                client_cert,
                client_key,
                client_der: client.der().as_ref().to_vec(),
                server_tls,
                client_tls,
                certificate: super::super::certificates::State::from_leaf(server.der().as_ref()),
            })
        }

        pub(in crate::manage) fn config(&self, address: SocketAddr) -> io::Result<Config> {
            Ok(Config {
                bind: address,
                origin: PublicOrigin::parse(&format!("https://localhost:{}", address.port()))?,
                tls: self.server_tls.clone(),
                client_tls: self.client_tls.clone(),
                key_sha256: super::super::tls::node_key_sha256(&self.server_key)?,
                certificate: self.certificate.clone(),
                #[cfg(feature = "witness-journal")]
                source: None,
            })
        }

        pub(in crate::manage) fn write(&self, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
            self._directory.write(name, bytes)
        }

        /// Reverse this fresh fixture's direction without sharing the other node's
        /// client identity. Used before optional source-path deletion in handoff tests.
        #[cfg(feature = "witness-journal")]
        pub(in crate::manage) fn server_identity(
            &self,
        ) -> io::Result<super::super::tls::NodeIdentity> {
            super::super::tls::node_identity(&self.ca, &self.server_cert, &self.server_key)
        }

        fn probe_args(&self, address: SocketAddr) -> ProbeArgs {
            ProbeArgs {
                endpoint: format!("https://localhost:{}", address.port()),
                peer_id: self.server_id.clone(),
                ca: self.ca.clone(),
                cert: self.client_cert.clone(),
                key: self.client_key.clone(),
                data_dir: Some(self.client_state.clone()),
            }
        }
    }

    type Tasks = JoinSet<io::Result<()>>;
    type Client = hyper::client::conn::http1::SendRequest<Empty<Bytes>>;

    async fn start(
        fixture: &Fixture,
        tasks: &mut Tasks,
        shutdown: CancellationToken,
    ) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let config = fixture.config(address)?;
        let directory = fixture.server_state.clone();
        tasks.spawn(serve(
            listener, config, directory, shutdown, None, None, None,
        ));
        Ok(address)
    }

    async fn client(
        fixture: &Fixture,
        address: SocketAddr,
        tasks: &mut Tasks,
    ) -> io::Result<Client> {
        let stream = TcpStream::connect(address).await?;
        let stream = TlsConnector::from(fixture.client_tls.clone())
            .connect(
                ServerName::try_from("localhost").map_err(io::Error::other)?,
                stream,
            )
            .await?;
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(io::Error::other)?;
        tasks.spawn(async move { connection.await.map_err(io::Error::other) });
        Ok(sender)
    }

    async fn request(
        client: &mut Client,
        address: SocketAddr,
        path: &str,
        method: Method,
    ) -> io::Result<(StatusCode, serde_json::Value)> {
        let request = http::Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, format!("localhost:{}", address.port()))
            .header(header::COOKIE, "__Host-vproxy-session=not-node-authority")
            .header("x-node-id", "attacker-selected-id")
            .body(Empty::<Bytes>::new())
            .map_err(io::Error::other)?;
        let response = client
            .send_request(request)
            .await
            .map_err(io::Error::other)?;
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(io::Error::other)?
            .to_bytes();
        let body = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        Ok((status, body))
    }

    #[test]
    fn node_settings_are_all_or_none_and_origin_must_match_the_local_certificate() -> io::Result<()>
    {
        assert!(configure(ListenArgs::default(), None)?.is_none());
        let partial = ListenArgs {
            node_bind: Some("127.0.0.1:8444".parse().map_err(io::Error::other)?),
            ..ListenArgs::default()
        };
        assert_eq!(
            configure(partial, None).err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
        let fixture = Fixture::new(true, true)?;
        let args = |origin: &str| ListenArgs {
            node_bind: Some("127.0.0.1:8444".parse().unwrap()),
            node_origin: Some(origin.into()),
            node_ca: Some(fixture.ca.clone()),
            node_cert: Some(fixture.server_cert.clone()),
            node_key: Some(fixture.server_key.clone()),
        };
        assert!(configure(args("https://localhost:8444"), None)?.is_some());
        assert!(configure(args("https://other.invalid:8444"), None).is_err());
        let key = super::super::tls::node_key_sha256(&fixture.server_key)?;
        assert!(configure(args("https://localhost:8444"), Some(key))?.is_some());
        let wrong_key = super::super::tls::node_key_sha256(&fixture.client_key)?;
        assert_ne!(key, wrong_key);
        assert_eq!(
            configure(args("https://localhost:8444"), Some(wrong_key))
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        Ok(())
    }

    #[tokio::test]
    async fn reusable_node_entry_rechecks_pending_and_the_actual_loaded_key() -> io::Result<()> {
        let fixture = tokio::task::spawn_blocking(|| Fixture::new(true, true))
            .await
            .map_err(io::Error::other)??;
        let key = super::super::tls::node_key_sha256(&fixture.server_key)?;
        let connection =
            rusqlite::Connection::open(fixture.server_state.join("management.sqlite3"))
                .map_err(io::Error::other)?;
        connection.execute(
        "UPDATE recovery_state SET kind='restored',phase='pending_review',recovery_id=?1,
         source_node_id=?2,source_schema_version=13,source_database_sha256=?3,node_key_sha256=?4,
         imported_users=0,imported_prefixes=0,imported_addresses=0,imported_pools=0 WHERE singleton=1",
        rusqlite::params!["AAAAAAAAAAAAAAAAAAAAAA", fixture.client_id, "2".repeat(64), &key[..]],
    ).map_err(io::Error::other)?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let config = fixture.config(listener.local_addr()?)?;
        let error = timeout(
            Duration::from_secs(5),
            serve(
                listener,
                config,
                fixture.server_state.clone(),
                CancellationToken::new(),
                None,
                None,
                None,
            ),
        )
        .await
        .map_err(io::Error::other)?
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        connection
            .execute("UPDATE recovery_state SET phase='ready'", [])
            .map_err(io::Error::other)?;
        let wrong = super::super::tls::node_key_sha256(&fixture.client_key)?;
        assert_ne!(wrong, key);
        let mut config = fixture.config("127.0.0.1:8444".parse().map_err(io::Error::other)?)?;
        config.key_sha256 = wrong;
        let rejected = initialize(fixture.server_state.clone(), config, None, None, None).await;
        assert_eq!(
            rejected.err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        let config = fixture.config("127.0.0.1:8444".parse().map_err(io::Error::other)?)?;
        let (accepted, _) =
            initialize(fixture.server_state.clone(), config, None, None, None).await?;
        assert_eq!(accepted.node_id, fixture.server_id);
        Ok(())
    }

    #[tokio::test]
    async fn keepalive_checks_revision_disable_reenable_and_permanent_revocation() {
        let mut tasks = Tasks::new();
        let shutdown = CancellationToken::new();
        // Like the adjacent transport fixtures, bound schema/certificate setup
        // separately; application startup and all authorization reads stay below.
        let preparation_started = Instant::now();
        let worker_started = Arc::new(std::sync::OnceLock::new());
        let entered = worker_started.clone();
        let prepared = timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(move || {
                let _ = entered.set(Instant::now());
                Fixture::new(true, true)
            }),
        )
        .await;
        let preparation_elapsed = preparation_started.elapsed();
        let queue_elapsed = worker_started
            .get()
            .map(|started| started.duration_since(preparation_started));
        assert!(
            prepared.is_ok(),
            "keepalive fixture preparation deadline, total {:?}, queue {:?}, worker-entry elapsed {:?}; blocking work is not interrupted",
            preparation_elapsed,
            queue_elapsed,
            worker_started.get().map(Instant::elapsed)
        );
        let fixture = prepared.unwrap().unwrap().unwrap();
        let mut phase = ("listener and first handshake", Instant::now());
        let result = timeout(Duration::from_secs(20), async {
            let address = start(&fixture, &mut tasks, shutdown.clone()).await.unwrap();
            let mut first = client(&fixture, address, &mut tasks).await.unwrap();
            phase = ("first identity read", Instant::now());
            let (status, identity) = request(&mut first, address, IDENTITY_PATH, Method::GET)
                .await
                .unwrap();
            assert_eq!(status, StatusCode::OK);
            assert_eq!(identity["node_id"], fixture.server_id);
            assert_eq!(identity["verified_peer"]["node_id"], fixture.client_id);
            assert_eq!(identity["verified_peer"]["authorization_revision"], 1);
            assert_eq!(
                identity["capabilities"],
                serde_json::json!(["identity_read"])
            );
            assert!(identity.get("proxy").is_none() && identity.get("health").is_none());
            phase = ("disable and existing-connection rejection", Instant::now());
            let directory = fixture.server_state.clone();
            let id = fixture.client_id.clone();
            tokio::task::spawn_blocking(move || store::set_peer_active(&directory, &id, 1, false))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                request(&mut first, address, IDENTITY_PATH, Method::GET)
                    .await
                    .unwrap()
                    .0,
                StatusCode::FORBIDDEN
            );
            phase = ("reenable and revision rejection", Instant::now());
            let directory = fixture.server_state.clone();
            let id = fixture.client_id.clone();
            tokio::task::spawn_blocking(move || store::set_peer_active(&directory, &id, 2, true))
                .await
                .unwrap()
                .unwrap();
            let (_, changed) = request(&mut first, address, IDENTITY_PATH, Method::GET)
                .await
                .unwrap();
            assert_eq!(changed["error"]["code"], "peer_authorization_changed");
            phase = ("fresh handshake and new authorization", Instant::now());
            let mut fresh = client(&fixture, address, &mut tasks).await.unwrap();
            assert_eq!(
                request(&mut fresh, address, IDENTITY_PATH, Method::GET)
                    .await
                    .unwrap()
                    .1["verified_peer"]["authorization_revision"],
                3
            );
            phase = (
                "permanent revocation and existing-connection rejection",
                Instant::now(),
            );
            let directory = fixture.server_state.clone();
            let der = fixture.client_der.clone();
            tokio::task::spawn_blocking(move || store::revoke_certificate(&directory, &der, 3))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                request(&mut fresh, address, IDENTITY_PATH, Method::GET)
                    .await
                    .unwrap()
                    .0,
                StatusCode::FORBIDDEN
            );
            phase = ("revoked new-connection rejection", Instant::now());
            let mut revoked = client(&fixture, address, &mut tasks).await.unwrap();
            assert_eq!(
                request(&mut revoked, address, IDENTITY_PATH, Method::GET)
                    .await
                    .unwrap()
                    .0,
                StatusCode::FORBIDDEN
            );
            drop((first, fresh, revoked));
        })
        .await;
        shutdown.cancel();
        tasks.shutdown().await;
        assert!(
            result.is_ok(),
            "keepalive deadline at {}, phase elapsed {:?}; fixture preparation {:?}, queue {:?}",
            phase.0,
            phase.1.elapsed(),
            preparation_elapsed,
            queue_elapsed
        );
    }

    #[tokio::test]
    async fn a_trusted_but_unregistered_certificate_and_browser_cookies_grant_no_node_permission() {
        let mut tasks = Tasks::new();
        let shutdown = CancellationToken::new();
        // Schema/certificate preparation is not the transport under test. Keep its
        // own bounded setup window, as for the adjacent TLS rejection fixtures.
        let fixture = timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(|| Fixture::new(false, true)),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let mut phase = ("listener and handshake", Instant::now());
        let result = timeout(Duration::from_secs(10), async {
            let address = start(&fixture, &mut tasks, shutdown.clone()).await.unwrap();
            let mut client = client(&fixture, address, &mut tasks).await.unwrap();
            phase = ("unregistered identity rejection", Instant::now());
            let (status, body) = request(&mut client, address, IDENTITY_PATH, Method::GET)
                .await
                .unwrap();
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["error"]["code"], "peer_not_authorized");
        })
        .await;
        shutdown.cancel();
        tasks.shutdown().await;
        assert!(
            result.is_ok(),
            "unregistered identity deadline at {}, phase elapsed {:?}",
            phase.0,
            phase.1.elapsed()
        );
    }

    #[tokio::test]
    async fn node_identity_scope_does_not_include_browser_sessions_or_wrong_targets() {
        let mut tasks = Tasks::new();
        let shutdown = CancellationToken::new();
        // Windows' concurrent SQLite fixture setup can exceed a network deadline
        // before a listener exists. Bound it separately, without extending HTTP/TLS.
        let fixture = timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(|| Fixture::new(true, true)),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let mut phase = ("listener", Instant::now());
        let result = timeout(Duration::from_secs(10), async {
            let address = start(&fixture, &mut tasks, shutdown.clone()).await.unwrap();
            phase = ("client TLS/HTTP", Instant::now());
            let mut client = client(&fixture, address, &mut tasks).await.unwrap();
            phase = ("browser path rejection", Instant::now());
            assert_eq!(
                request(&mut client, address, "/api/v1/auth/session", Method::GET)
                    .await
                    .unwrap()
                    .0,
                StatusCode::NOT_FOUND
            );
            phase = ("wrong target rejection", Instant::now());
            assert_eq!(
                request(
                    &mut client,
                    address,
                    "https://other.invalid/node/v1/identity",
                    Method::GET
                )
                .await
                .unwrap()
                .0,
                StatusCode::MISDIRECTED_REQUEST
            );
            phase = ("method rejection", Instant::now());
            let request = http::Request::builder()
                .method(Method::POST)
                .uri(IDENTITY_PATH)
                .header(header::HOST, format!("localhost:{}", address.port()))
                .body(Empty::<Bytes>::new())
                .unwrap();
            let response = client.send_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            let allowed: Vec<_> = response.headers()[header::ALLOW]
                .to_str()
                .unwrap()
                .split(',')
                .map(str::trim)
                .collect();
            assert_eq!(allowed.len(), 2);
            assert!(allowed.contains(&"GET") && allowed.contains(&"HEAD"));
            response.into_body().collect().await.unwrap();
        })
        .await;
        shutdown.cancel();
        tasks.shutdown().await;
        assert!(
            result.is_ok(),
            "identity deadline at {}, phase elapsed {:?}",
            phase.0,
            phase.1.elapsed()
        );
    }

    #[tokio::test]
    async fn a_database_failure_does_not_reuse_the_previous_permission_or_return_403() {
        let mut tasks = Tasks::new();
        let shutdown = CancellationToken::new();
        // A full-suite run can spend the old transport deadline preparing the
        // private schema. The corruption/re-authorization scenario still gets its
        // original ten seconds; preparation has a separate bounded window.
        let fixture = timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(|| Fixture::new(true, true)),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let mut phase = ("listener and handshake", Instant::now());
        let result = timeout(Duration::from_secs(10), async {
            let address = start(&fixture, &mut tasks, shutdown.clone()).await.unwrap();
            let mut client = client(&fixture, address, &mut tasks).await.unwrap();
            phase = ("first authorized identity read", Instant::now());
            assert_eq!(
                request(&mut client, address, IDENTITY_PATH, Method::GET)
                    .await
                    .unwrap()
                    .0,
                StatusCode::OK
            );
            phase = ("database corruption", Instant::now());
            let database = fixture.server_state.join("management.sqlite3");
            tokio::task::spawn_blocking(move || {
                fs::write(database, b"corrupt private test fixture")
            })
            .await
            .unwrap()
            .unwrap();
            phase = ("corrupt-storage rejection", Instant::now());
            let (status, body) = request(&mut client, address, IDENTITY_PATH, Method::GET)
                .await
                .unwrap();
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body["error"]["code"], "authorization_unavailable");
        })
        .await;
        shutdown.cancel();
        tasks.shutdown().await;
        assert!(
            result.is_ok(),
            "database failure deadline at {}, phase elapsed {:?}",
            phase.0,
            phase.1.elapsed()
        );
    }

    #[tokio::test]
    async fn missing_alpn_or_client_certificate_cannot_reach_http_identity() {
        let mut tasks = Tasks::new();
        let shutdown = CancellationToken::new();
        // Certificate/database preparation is not part of the transport under test.
        let fixture = timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(|| Fixture::new(true, true)),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let mut phase = ("listener", Instant::now());
        let result = timeout(Duration::from_secs(10), async {
        let address = start(&fixture, &mut tasks, shutdown.clone()).await.unwrap();
        phase = ("no ALPN handshake", Instant::now());
        let mut no_alpn = (*fixture.client_tls).clone();
        no_alpn.alpn_protocols.clear();
        let stream = TcpStream::connect(address).await.unwrap();
        let mut stream = TlsConnector::from(Arc::new(no_alpn)).connect(ServerName::try_from("localhost").unwrap(), stream).await.unwrap();
        assert!(stream.get_ref().1.alpn_protocol().is_none());
        phase = ("no ALPN EOF", Instant::now());
        let mut byte = [0];
        assert!(!matches!(stream.read(&mut byte).await, Ok(count) if count > 0));
        let mut roots = RootCertStore::empty();
        let pem = fs::read(&fixture.ca).unwrap();
        for cert in rustls_pemfile::certs(&mut &pem[..]) { roots.add(cert.unwrap()).unwrap(); }
        let mut anonymous = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_root_certificates(roots).with_no_client_auth();
        anonymous.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tcp = TcpStream::connect(address).await.unwrap();
        phase = ("anonymous handshake", Instant::now());
        if let Ok(mut stream) = TlsConnector::from(Arc::new(anonymous)).connect(ServerName::try_from("localhost").unwrap(), tcp).await {
            phase = ("anonymous EOF", Instant::now());
            let _ = stream.write_all(b"GET /node/v1/identity HTTP/1.1\r\nHost: localhost\r\nCookie: __Host-vproxy-session=browser-cookie\r\n\r\n").await;
            assert!(!matches!(stream.read(&mut byte).await, Ok(count) if count > 0));
        }
    }).await;
        shutdown.cancel();
        tasks.shutdown().await;
        assert!(
            result.is_ok(),
            "identity deadline at {}, phase elapsed {:?}",
            phase.0,
            phase.1.elapsed()
        );
    }

    #[test]
    fn synchronous_probe_entry_works_without_an_existing_tokio_runtime() -> io::Result<()> {
        let fixture = Fixture::new(true, true)?;
        let shutdown = CancellationToken::new();
        let stop = shutdown.clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let tls = fixture.server_tls.clone();
        let client_tls = fixture.client_tls.clone();
        let directory = fixture.server_state.clone();
        let key_sha256 = super::super::tls::node_key_sha256(&fixture.server_key)?;
        let certificate = fixture.certificate.clone();
        let thread = std::thread::spawn(move || -> io::Result<()> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async move {
                let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
                let address = listener.local_addr()?;
                let config = Config {
                    bind: address,
                    origin: PublicOrigin::parse(&format!("https://localhost:{}", address.port()))?,
                    tls,
                    client_tls,
                    key_sha256,
                    certificate,
                    #[cfg(feature = "witness-journal")]
                    source: None,
                };
                sender
                    .send(address)
                    .map_err(|_| io::Error::other("probe fixture receiver closed"))?;
                serve(listener, config, directory, stop, None, None, None).await
            })
        });
        let result = (|| {
            let address = receiver
                .recv_timeout(Duration::from_secs(5))
                .map_err(io::Error::other)?;
            probe(fixture.probe_args(address))
        })();
        shutdown.cancel();
        thread
            .join()
            .map_err(|_| io::Error::other("probe fixture server failed"))??;
        result
    }

    /// A real management TLS request publishes through the runner's only Reader;
    /// this proves more than changing a row or a desired-state test double.
    #[test]
    fn remote_commands_change_live_http_admission_and_retries_never_repeat_mutation()
    -> io::Result<()> {
        use crate::manage::{policy::Coordinator, proxy};
        use control::{Command, Mutation, Reply, Request as ControlRequest};

        let fixture = Fixture::new(true, true)?;
        let administrator = |directory: &std::path::Path| -> io::Result<String> {
            rusqlite::Connection::open(directory.join("management.sqlite3"))
                .map_err(io::Error::other)?
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)
        };
        let source = administrator(&fixture.client_state)?;
        let gate = store::update_lock(&fixture.server_state)?;
        store::set_owner(
            &fixture.server_state,
            &gate,
            &administrator(&fixture.server_state)?,
            1,
            Some(&fixture.client_id),
        )?;
        drop(gate);
        let author = Arc::new(store::lock(&fixture.server_state)?);
        let server = Coordinator::new(
            fixture.server_state.clone(),
            store::load_policy(&fixture.server_state)?,
            author.clone(),
        )?;
        let caller = Coordinator::new(
            fixture.client_state.clone(),
            store::load_policy(&fixture.client_state)?,
            Arc::new(store::lock(&fixture.client_state)?),
        )?;
        let port = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?
            .local_addr()?
            .port();
        let path = fixture._directory.write(
            "managed.json",
            format!(
                r#"{{"workers":1,"listeners":[{{"protocol":"http","bind":"127.0.0.1:{port}"}}]}}"#
            )
            .as_bytes(),
        )?;
        let mut running = proxy::start(proxy::load(&path)?, server.reader(), author)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let shutdown = CancellationToken::new();
        let result=runtime.block_on(async {
        let verification=async {
            running.ready().await?;server.activate().await?;
            let listener=TcpListener::bind((std::net::Ipv4Addr::LOCALHOST,0)).await?;
            let address=listener.local_addr()?;
            let origin=format!("https://localhost:{}",address.port());
            let mut tasks=Tasks::new();
            tasks.spawn(serve(listener,fixture.config(address)?,fixture.server_state.clone(),shutdown.clone(),Some(server.clone()),None,None));
            let echo=TcpListener::bind((std::net::Ipv4Addr::LOCALHOST,0)).await?;
            let echo_address=echo.local_addr()?;
            let stop=shutdown.clone();
            tasks.spawn(async move {
                loop {
                    let (mut stream,_)=tokio::select!{_ = stop.cancelled()=>return Ok(()),stream=echo.accept()=>stream?};
                    let mut input=[0;4096];let _=stream.read(&mut input).await?;
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await?;
                }
            });
            let issue=|id:u64,revision:u64,mutation:Mutation|Command{version:1,target_node_id:fixture.server_id.clone(),resource:"proxy_policy".into(),controller_epoch:"2".into(),command_id:id.to_string(),expected_policy_revision:revision.to_string(),source_administrator_id:source.clone(),mutation};
            let call=|operation|control::request(&caller,fixture.client_tls.clone(),&origin,&fixture.server_id,operation);
            let Reply::Command(created)=call(ControlRequest::Command(issue(1,1,Mutation::CreateUser{name:"Remote HTTP user".into(),protocols:vec![crate::access::Protocol::Http],concurrent_limit:2}))).await? else{return Err(io::Error::other("expected command reply"))};
            assert!(created.receipt.status==control::ReceiptStatus::Applied);
            let user=created.user.unwrap().id;
            let Reply::Command(mut credentials)=call(ControlRequest::Command(issue(2,2,Mutation::CreateCredential{user_id:user.clone()}))).await? else{return Err(io::Error::other("expected credential reply"))};
            let secret=credentials.secret.take().unwrap();let credential=credentials.credential.take().unwrap();
            let request=||crate::oneself::test_http_client_builder().unwrap().proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{port}")).unwrap().basic_auth(&credential.login,&secret)).timeout(Duration::from_secs(3)).build().unwrap().get(format!("http://{echo_address}/"));
            assert_eq!(request().send().await.map_err(io::Error::other)?.status(),StatusCode::OK);
            let disable=issue(3,3,Mutation::SetUserActive{id:user,active:false});
            let Reply::Command(disabled)=call(ControlRequest::Command(disable.clone())).await? else{return Err(io::Error::other("expected disable reply"))};
            assert_eq!(disabled.receipt.policy_revision.as_deref(),Some("4"));
            assert_eq!(request().send().await.map_err(io::Error::other)?.status(),StatusCode::FORBIDDEN);
            let Reply::Command(replayed)=call(ControlRequest::Command(disable)).await? else{return Err(io::Error::other("expected replay reply"))};
            assert!(replayed.replayed && replayed.secret.is_none());assert_eq!(replayed.receipt.policy_revision.as_deref(),Some("4"));
            let Reply::Policy(policy)=call(ControlRequest::Policy).await? else{return Err(io::Error::other("expected policy reply"))};
            assert_eq!(policy.saved_revision,"4");assert_eq!(policy.applied_revision.as_deref(),Some("4"));
            let Reply::UsersPage(page)=call(ControlRequest::UsersPage{after:None,limit:50,include_deleted:false}).await? else{return Err(io::Error::other("expected user page"))};assert_eq!(page.items.len(),1);
            let Reply::CredentialsPage(page)=call(ControlRequest::CredentialsPage{after:None,limit:50,user_id:None}).await? else{return Err(io::Error::other("expected credential page"))};assert_eq!(page.items.len(),1);
            let Reply::Receipt(receipt)=call(ControlRequest::Receipt{version:1,controller_epoch:2,command_id:2}).await? else{return Err(io::Error::other("expected receipt"))};assert!(receipt.credential_id.is_some());
            let mut wrong=issue(4,4,Mutation::RotateCredential{id:credential.id.clone()});wrong.controller_epoch="1".into();
            let error=call(ControlRequest::Command(wrong)).await.err().unwrap();assert_eq!(error.get_ref().and_then(|error|error.downcast_ref::<control::RemoteError>()).unwrap().code,"controller_epoch_changed");
            let mut wrong=issue(4,4,Mutation::RotateCredential{id:credential.id.clone()});wrong.target_node_id=fixture.client_id.clone();
            assert!(call(ControlRequest::Command(wrong)).await.is_err());
            let directory=fixture.server_state.clone();let der=fixture.client_der.clone();tokio::task::spawn_blocking(move||store::revoke_certificate(&directory,&der,1)).await.map_err(io::Error::other)??;
            let error=call(ControlRequest::Command(issue(4,4,Mutation::RotateCredential{id:credential.id}))).await.err().unwrap();assert_eq!(error.kind(),io::ErrorKind::PermissionDenied);
            assert_eq!(server.reader().revision()?,4);
            drop(secret);shutdown.cancel();tasks.shutdown().await;Ok::<_,io::Error>(())
        };
        timeout(Duration::from_secs(25),verification).await.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"remote live-policy test timed out"))?
    });
        shutdown.cancel();
        running.shutdown();
        let stopped = runtime.block_on(async {
            timeout(Duration::from_secs(12), running.finished())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy drain timed out"))?
        });
        let finished = running.finish().result;
        result?;
        stopped?;
        finished
    }

    /// The actual mTLS router reads the supervisor's monitor, not a new collector.
    /// No runner is started: a new monitor must honestly expose empty observations.
    #[tokio::test]
    async fn v2_health_route_uses_the_common_monitor_and_current_mtls_owner() -> io::Result<()> {
        use crate::manage::{health, policy::Coordinator};
        let fixture = Fixture::new(true, true)?;
        let coordinator = |directory: &std::path::Path| {
            Coordinator::new(
                directory.to_owned(),
                store::load_policy(directory)?,
                Arc::new(store::lock(directory)?),
            )
        };
        let server = coordinator(&fixture.server_state)?;
        let caller = coordinator(&fixture.client_state)?;
        let administrator: String =
            rusqlite::Connection::open(fixture.server_state.join("management.sqlite3"))
                .map_err(io::Error::other)?
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)?;
        let connector = crate::connect::Connector::new(
            None,
            None,
            None,
            3,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            None,
            None,
        );
        let (handle, _not_started) =
            health::new(server.clone(), connector, health::Config::default())?;
        let boot = handle.snapshot()?.boot_id;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let origin = format!("https://localhost:{}", address.port());
        let shutdown = CancellationToken::new();
        let mut tasks = Tasks::new();
        tasks.spawn(serve(
            listener,
            fixture.config(address)?,
            fixture.server_state.clone(),
            shutdown.clone(),
            Some(server.clone()),
            Some(handle),
            None,
        ));
        let result = async {
            let read = || {
                control::request(
                    &caller,
                    fixture.client_tls.clone(),
                    &origin,
                    &fixture.server_id,
                    control::Request::HealthPage {
                        after: None,
                        limit: 16,
                    },
                )
            };
            let denied = read()
                .await
                .err()
                .expect("registration alone grants no health control");
            assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
            server
                .set_owner(administrator, 1, Some(fixture.client_id.clone()))
                .await?;
            let control::Reply::HealthPage(snapshot) = read().await? else {
                return Err(io::Error::other("expected typed health page"));
            };
            assert_eq!(snapshot.boot_id, boot);
            assert_eq!(snapshot.sequence, "0");
            assert!(!snapshot.catalog_loaded && snapshot.catalog_revision.is_none());
            assert!(snapshot.entries.is_empty() && snapshot.next_cursor.is_none());
            let directory = fixture.server_state.clone();
            let peer = fixture.client_id.clone();
            server
                .read(move |_| store::set_peer_active(&directory, &peer, 1, false))
                .await?;
            let denied = read()
                .await
                .err()
                .expect("disabled exact-DER peer cannot read health");
            assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
            io::Result::Ok(())
        }
        .await;
        shutdown.cancel();
        tasks.shutdown().await;
        result
    }

    /// A real trusted TLS peer with deliberately controlled HTTP behavior. Counting
    /// application bytes independently proves registration happens before HTTP.
    enum RawReply {
        Json(serde_json::Value),
        /// Exercise a versioned traffic read followed by at most one legacy GET.
        TrafficNegotiation {
            status: u16,
            first: serde_json::Value,
            legacy: serde_json::Value,
            requests: Arc<std::sync::Mutex<Vec<String>>>,
        },
        /// An older authenticated node has no route for a new read-only resource.
        NotFound,
        /// Change the exact configured target before its missing reply completes.
        ChangeTargetThenNotFound {
            directory: PathBuf,
            administrator: String,
            peer: String,
            replacement_origin: Option<String>,
        },
        /// Commit a local revocation after a response prefix has been flushed, but
        /// before the final JSON byte can complete the body on the client.
        RevokeThenJson {
            value: serde_json::Value,
            directory: PathBuf,
            leaf: Vec<u8>,
        },
        Oversized(usize),
        NoResponse,
        ObserveEof,
    }

    struct RawEndpoint {
        address: SocketAddr,
        observed: Arc<AtomicUsize>,
        shutdown: CancellationToken,
        thread: Option<std::thread::JoinHandle<io::Result<()>>>,
    }

    impl RawEndpoint {
        fn start(tls: Arc<ServerConfig>, reply: RawReply) -> io::Result<Self> {
            let shutdown = CancellationToken::new();
            let stop = shutdown.clone();
            let observed = Arc::new(AtomicUsize::new(0));
            let count = observed.clone();
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let thread = std::thread::spawn(move || -> io::Result<()> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(async move {
                timeout(Duration::from_secs(20), async move {
                    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
                    sender.send(listener.local_addr()?).map_err(|_| io::Error::other("raw fixture receiver closed"))?;
                    let (stream, _) = tokio::select! {
                        _ = stop.cancelled() => return Ok(()),
                        accepted = listener.accept() => accepted?,
                    };
                    let acceptor = TlsAcceptor::from(tls);
                    let mut stream = acceptor.accept(stream).await?;
                    let mut request = Vec::new();
                    let mut buffer = [0; 1024];
                    while request.len() < 16 * 1024 {
                        let read = tokio::select! {
                            _ = stop.cancelled() => return Ok(()),
                            read = stream.read(&mut buffer) => read,
                        };
                        let length = match read {
                            Ok(0) => break,
                            Ok(length) => length,
                            Err(error) if matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset) => break,
                            Err(error) => return Err(error),
                        };
                        request.extend_from_slice(&buffer[..length]);
                        count.store(request.len(), Ordering::Release);
                        if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") { break; }
                    }
                    if request.is_empty() { return Ok(()); }
                    match reply {
                        RawReply::TrafficNegotiation { status, first, legacy, requests } => {
                            requests.lock().map_err(|_| io::Error::other("fixture request lock"))?.push(String::from_utf8_lossy(&request).lines().next().unwrap_or_default().to_owned());
                            let bytes = serde_json::to_vec(&first).map_err(io::Error::other)?;
                            stream.write_all(format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).as_bytes()).await?;
                            stream.write_all(&bytes).await?;
                            stream.flush().await?;
                            stream.shutdown().await?;
                            drop(stream);
                            let (stream, _) = tokio::select! { _ = stop.cancelled() => return Ok(()), accepted = listener.accept() => accepted? };
                            let mut stream = acceptor.accept(stream).await?;
                            let mut next = Vec::new();
                            while !next.ends_with(b"\r\n\r\n") && next.len() < 16 * 1024 { next.push(stream.read_u8().await?); }
                            count.fetch_add(next.len(), Ordering::Relaxed);
                            requests.lock().map_err(|_| io::Error::other("fixture request lock"))?.push(String::from_utf8_lossy(&next).lines().next().unwrap_or_default().to_owned());
                            let bytes = serde_json::to_vec(&legacy).map_err(io::Error::other)?;
                            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).as_bytes()).await?;
                            stream.write_all(&bytes).await?;
                            stream.flush().await?;
                        }
                        RawReply::NotFound => {
                            let bytes = br#"{"error":{"code":"not_found"}}"#;
                            let headers = format!("HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", bytes.len());
                            stream.write_all(headers.as_bytes()).await?;
                            stream.write_all(bytes).await?;
                            stream.flush().await?;
                        }
                        RawReply::ChangeTargetThenNotFound { directory, administrator, peer, replacement_origin } => {
                            let bytes = br#"{"error":{"code":"resource_not_found"}}"#;
                            let split = bytes.len().checked_sub(1).ok_or_else(|| io::Error::other("empty fixture error"))?;
                            let headers = format!("HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", bytes.len());
                            stream.write_all(headers.as_bytes()).await?;
                            stream.write_all(&bytes[..split]).await?;
                            stream.flush().await?;
                            tokio::task::spawn_blocking(move || {
                                match replacement_origin {
                                    Some(origin) => store::targets::configure(&directory, &administrator, &peer, Some(1), &origin, true, None),
                                    None => store::targets::set_state(&directory, &administrator, &peer, 1, false, false),
                                }
                            }).await.map_err(io::Error::other)??;
                            stream.write_all(&bytes[split..]).await?;
                            stream.flush().await?;
                        }
                        RawReply::Json(value) => {
                            let bytes = serde_json::to_vec(&value).map_err(io::Error::other)?;
                            let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", bytes.len());
                            stream.write_all(headers.as_bytes()).await?;
                            stream.write_all(&bytes).await?;
                            stream.flush().await?;
                        }
                        RawReply::RevokeThenJson { value, directory, leaf } => {
                            let bytes=serde_json::to_vec(&value).map_err(io::Error::other)?;
                            let split=bytes.len().checked_sub(1).ok_or_else(||io::Error::other("empty fixture JSON"))?;
                            let headers=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",bytes.len());
                            stream.write_all(headers.as_bytes()).await?;
                            stream.write_all(&bytes[..split]).await?;
                            stream.flush().await?;
                            tokio::task::spawn_blocking(move||store::revoke_certificate(&directory,&leaf,1)).await.map_err(io::Error::other)??;
                            stream.write_all(&bytes[split..]).await?;
                            stream.flush().await?;
                        }
                        RawReply::Oversized(limit) => {
                            // Never finish this body: an implementation which
                            // forgets the selected cap would hit the deadline instead.
                            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", limit * 2).as_bytes()).await?;
                            stream.write_all(&vec![b'x'; limit + 1]).await?;
                            stream.flush().await?;
                            stop.cancelled().await;
                        }
                        RawReply::NoResponse => stop.cancelled().await,
                        RawReply::ObserveEof => loop {
                            match stream.read(&mut buffer).await {
                                Ok(0)=>break,
                                Ok(_)=>{},
                                Err(error) if matches!(error.kind(),io::ErrorKind::UnexpectedEof|io::ErrorKind::ConnectionReset)=>break,
                                Err(error)=>return Err(error),
                            }
                        },
                    }
                    Ok::<_, io::Error>(())
                }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "raw fixture deadline exceeded"))?
            })
            });
            let mut endpoint = Self {
                address: SocketAddr::from(([127, 0, 0, 1], 0)),
                observed,
                shutdown,
                thread: Some(thread),
            };
            endpoint.address = receiver
                .recv_timeout(Duration::from_secs(5))
                .map_err(io::Error::other)?;
            Ok(endpoint)
        }

        /// For a rejected credential, wait for natural EOF instead of cancelling the
        /// reader: cancellation could otherwise hide application bytes sent too early.
        fn wait(mut self) -> io::Result<usize> {
            self.join()?;
            Ok(self.observed.load(Ordering::Acquire))
        }

        fn stop(mut self) -> io::Result<usize> {
            self.shutdown.cancel();
            self.join()?;
            Ok(self.observed.load(Ordering::Acquire))
        }

        fn join(&mut self) -> io::Result<()> {
            if let Some(thread) = self.thread.take() {
                thread
                    .join()
                    .map_err(|_| io::Error::other("raw fixture server failed"))??;
            }
            Ok(())
        }
    }

    impl Drop for RawEndpoint {
        fn drop(&mut self) {
            self.shutdown.cancel();
            let _ = self.join();
        }
    }

    fn reported_identity(fixture: &Fixture, node_id: &str) -> serde_json::Value {
        serde_json::json!({
            "protocol_version": 1,
            "node_id": node_id,
            "name": "Server fixture",
            "version": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "capabilities": ["identity_read"],
            "verified_peer": { "node_id": fixture.client_id, "authorization_revision": 1 },
        })
    }

    #[test]
    fn probe_rejects_unregistered_or_wrong_peer_der_before_sending_any_http() -> io::Result<()> {
        for wrong_id in [false, true] {
            let fixture = Fixture::new(true, wrong_id)?;
            let endpoint = RawEndpoint::start(
                fixture.server_tls.clone(),
                RawReply::Json(reported_identity(&fixture, &fixture.server_id)),
            )?;
            let mut args = fixture.probe_args(endpoint.address);
            if wrong_id {
                args.peer_id = fixture.client_id.clone();
            }
            let result = probe(args);
            let observed = endpoint.wait()?;
            let error = result.expect_err("unregistered/mismatched certificate must fail");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(
                error.to_string(),
                if wrong_id {
                    "node TLS leaf does not match the expected peer"
                } else {
                    "node TLS leaf is not registered"
                }
            );
            assert_eq!(observed, 0, "HTTP cannot precede local DER authorization");
        }
        Ok(())
    }

    #[test]
    fn control_client_rechecks_local_der_before_http_and_rejects_oversized_replies()
    -> io::Result<()> {
        use crate::manage::policy::Coordinator;
        for wrong_id in [false, true] {
            let fixture = Fixture::new(true, wrong_id)?;
            let caller = Coordinator::new(
                fixture.client_state.clone(),
                store::load_policy(&fixture.client_state)?,
                Arc::new(store::lock(&fixture.client_state)?),
            )?;
            let endpoint = RawEndpoint::start(fixture.server_tls.clone(), RawReply::NoResponse)?;
            let origin = format!("https://localhost:{}", endpoint.address.port());
            let expected = if wrong_id {
                &fixture.client_id
            } else {
                &fixture.server_id
            };
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let error = runtime
                .block_on(control::request(
                    &caller,
                    fixture.client_tls.clone(),
                    &origin,
                    expected,
                    control::Request::Policy,
                ))
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(
                endpoint.wait()?,
                0,
                "control HTTP cannot precede exact-DER authorization"
            );
        }
        let fixture = Fixture::new(true, true)?;
        let caller = Coordinator::new(
            fixture.client_state.clone(),
            store::load_policy(&fixture.client_state)?,
            Arc::new(store::lock(&fixture.client_state)?),
        )?;
        let endpoint =
            RawEndpoint::start(fixture.server_tls.clone(), RawReply::Oversized(32 * 1024))?;
        let origin = format!("https://localhost:{}", endpoint.address.port());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let error = runtime
            .block_on(control::request(
                &caller,
                fixture.client_tls.clone(),
                &origin,
                &fixture.server_id,
                control::Request::Policy,
            ))
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "node control response exceeds its size limit"
        );
        assert!(endpoint.stop()? > 0);
        Ok(())
    }

    #[test]
    fn control_client_does_not_deliver_a_secret_after_revocation_during_the_response_body()
    -> io::Result<()> {
        use crate::manage::policy::Coordinator;
        let fixture = Fixture::new(true, true)?;
        let caller = Coordinator::new(
            fixture.client_state.clone(),
            store::load_policy(&fixture.client_state)?,
            Arc::new(store::lock(&fixture.client_state)?),
        )?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let command = control::Command {
            version: 1,
            target_node_id: fixture.server_id.clone(),
            resource: "proxy_policy".into(),
            controller_epoch: "2".into(),
            command_id: "1".into(),
            expected_policy_revision: "1".into(),
            source_administrator_id: fixture.client_id.clone(),
            mutation: control::Mutation::CreateCredential {
                user_id: fixture.client_id.clone(),
            },
        };
        let value = serde_json::json!({"version":1,"node_id":fixture.server_id,"resource":"proxy_policy","data":{
            "receipt":{"controller_epoch":"2","command_id":"1","status":"applied","policy_revision":"2","rejection":null,"user_id":fixture.client_id,"credential_id":"AAAAAAAAAAAAAAAAAAAAAA"},
            "replayed":false,
            "user":{"id":fixture.client_id,"name":"Fixture user","active":true,"deleted":false,"protocols":["http"],"concurrent_limit":2,"revision":"2"},
            "credential":{"id":"AAAAAAAAAAAAAAAAAAAAAA","user_id":fixture.client_id,"login":"vp2_00000000000000000000000000000000","syntax_version":2,"active":true,"revoked":false,"verifier_revision":"2"},
            "secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","secret_available":true
        }});
        // Establish that the complete prefix/reply is otherwise accepted. A parser
        // error must not accidentally make the revocation regression pass.
        let endpoint =
            RawEndpoint::start(fixture.server_tls.clone(), RawReply::Json(value.clone()))?;
        let origin = format!("https://localhost:{}", endpoint.address.port());
        let reply = runtime.block_on(control::request(
            &caller,
            fixture.client_tls.clone(),
            &origin,
            &fixture.server_id,
            control::Request::Command(command.clone()),
        ))?;
        let control::Reply::Command(reply) = reply else {
            return Err(io::Error::other("expected fixture command result"));
        };
        assert!(reply.secret.is_some());
        drop(reply);
        assert!(endpoint.wait()? > 0);
        let endpoint = RawEndpoint::start(
            fixture.server_tls.clone(),
            RawReply::RevokeThenJson {
                value,
                directory: fixture.client_state.clone(),
                leaf: super::super::tls::read_certificate_leaf(&fixture.server_cert)?,
            },
        )?;
        let origin = format!("https://localhost:{}", endpoint.address.port());
        let error = runtime
            .block_on(control::request(
                &caller,
                fixture.client_tls.clone(),
                &origin,
                &fixture.server_id,
                control::Request::Command(command),
            ))
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(endpoint.wait()? > 0);
        Ok(())
    }

    #[test]
    fn control_client_total_deadline_cancels_its_owned_http_driver() -> io::Result<()> {
        use crate::manage::policy::Coordinator;
        let fixture = Fixture::new(true, true)?;
        let caller = Coordinator::new(
            fixture.client_state.clone(),
            store::load_policy(&fixture.client_state)?,
            Arc::new(store::lock(&fixture.client_state)?),
        )?;
        let endpoint = RawEndpoint::start(fixture.server_tls.clone(), RawReply::ObserveEof)?;
        let origin = format!("https://localhost:{}", endpoint.address.port());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let started = Instant::now();
        let result = runtime.block_on(async {
            let result = control::request(
                &caller,
                fixture.client_tls.clone(),
                &origin,
                &fixture.server_id,
                control::Request::Policy,
            )
            .await;
            // Task abortion is processed on its next poll. Let this current-thread
            // runtime process it before blocking on the independent peer's EOF.
            tokio::task::yield_now().await;
            result
        });
        let error = result.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            endpoint.wait()? > 0,
            "peer sees EOF without fixture cancellation"
        );
        assert!(started.elapsed() < Duration::from_secs(18));
        Ok(())
    }

    #[test]
    fn probe_rejects_forged_json_identity_and_limits_body_before_waiting_for_eof() -> io::Result<()>
    {
        let fixture = Fixture::new(true, true)?;
        let endpoint = RawEndpoint::start(
            fixture.server_tls.clone(),
            RawReply::Json(reported_identity(&fixture, &fixture.client_id)),
        )?;
        let result = probe(fixture.probe_args(endpoint.address));
        assert!(endpoint.wait()? > 0);
        let error =
            result.expect_err("a self-reported identity cannot replace the verified DER binding");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "node identity response does not match the verified protocol and identities"
        );

        let endpoint =
            RawEndpoint::start(fixture.server_tls.clone(), RawReply::Oversized(32 * 1024))?;
        let result = probe(fixture.probe_args(endpoint.address));
        assert!(endpoint.stop()? > 0);
        let error =
            result.expect_err("an oversized unfinished response must fail before the deadline");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "node identity response exceeds its size limit"
        );
        Ok(())
    }

    #[test]
    fn synchronous_probe_has_a_total_deadline_when_a_verified_peer_never_replies() -> io::Result<()>
    {
        let fixture = Fixture::new(true, true)?;
        let endpoint = RawEndpoint::start(fixture.server_tls.clone(), RawReply::NoResponse)?;
        let started = Instant::now();
        let result = probe(fixture.probe_args(endpoint.address));
        assert!(endpoint.stop()? > 0);
        let error = result.expect_err("a verified peer cannot keep the CLI waiting indefinitely");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(18));
        Ok(())
    }
}
