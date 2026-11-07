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
        })
    }
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
    let overview = startup_overview(&directory, &config).await?;
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

/// Refuse quarantined or protected source state before accepting requests.
async fn startup_overview(
    directory: &std::path::Path,
    config: &Config,
) -> io::Result<store::Overview> {
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

    mod witness {
        //! Real mandatory-mTLS routing and durable witness state in fresh local fixtures.
        use super::*;
        use crate::manage::{
            policy::Coordinator,
            witness::{Enrollment, Phase, Record, Transition},
        };
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use http_body_util::Full;

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
                let input = Transition {
                    witness_node_id: e.witness_node_id.clone(),
                    binding_id: e.binding_id.clone(),
                    writer_id: e.writer_id.clone(),
                    sequence: "1".into(),
                    previous: e.baseline.clone(),
                    commitment: "1".repeat(64),
                };
                let bytes = serde_json::to_vec(&input).map_err(io::Error::other)?;
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
    use rustls::ClientConfig;
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
        server_cert: PathBuf,
        server_key: PathBuf,
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
                server_cert,
                server_key,
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
            })
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

    #[tokio::test]
    async fn keepalive_checks_revision_disable_reenable_and_permanent_revocation() {
        let mut tasks = Tasks::new();
        let shutdown = CancellationToken::new();
        let fixture = timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(|| Fixture::new(true, true)),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let result = timeout(Duration::from_secs(20), async {
            let address = start(&fixture, &mut tasks, shutdown.clone()).await.unwrap();
            let mut first = client(&fixture, address, &mut tasks).await.unwrap();
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
            let mut fresh = client(&fixture, address, &mut tasks).await.unwrap();
            assert_eq!(
                request(&mut fresh, address, IDENTITY_PATH, Method::GET)
                    .await
                    .unwrap()
                    .1["verified_peer"]["authorization_revision"],
                3
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
        result.unwrap();
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
        let result = timeout(Duration::from_secs(10), async {
            let address = start(&fixture, &mut tasks, shutdown.clone()).await.unwrap();
            let mut client = client(&fixture, address, &mut tasks).await.unwrap();
            let (status, body) = request(&mut client, address, IDENTITY_PATH, Method::GET)
                .await
                .unwrap();
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["error"]["code"], "peer_not_authorized");
        })
        .await;
        shutdown.cancel();
        tasks.shutdown().await;
        result.unwrap();
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
        for revoke in [false, true] {
            let listener =
                runtime.block_on(TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)))?;
            let origin = format!("https://localhost:{}", listener.local_addr()?.port());
            let tls = fixture.server_tls.clone();
            let bytes = serde_json::to_vec(&value).map_err(io::Error::other)?;
            let directory = fixture.client_state.clone();
            let leaf = super::super::tls::read_certificate_leaf(&fixture.server_cert)?;
            let peer = runtime.spawn(async move {
                timeout(Duration::from_secs(20), async move {
                    let (stream, _) = listener.accept().await?;
                    let mut stream = TlsAcceptor::from(tls).accept(stream).await?;
                    let mut request = Vec::new();
                    let mut buffer = [0; 1024];
                    while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        let length = stream.read(&mut buffer).await?;
                        if length == 0 {
                            return Err(io::ErrorKind::UnexpectedEof.into());
                        }
                        request.extend_from_slice(&buffer[..length]);
                    }
                    let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", bytes.len());
                    stream.write_all(headers.as_bytes()).await?;
                    if revoke {
                        let split = bytes.len() - 1;
                        stream.write_all(&bytes[..split]).await?;
                        stream.flush().await?;
                        tokio::task::spawn_blocking(move || store::revoke_certificate(&directory, &leaf, 1))
                            .await.map_err(io::Error::other)??;
                        stream.write_all(&bytes[split..]).await?;
                    } else {
                        stream.write_all(&bytes).await?;
                    }
                    stream.flush().await
                }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "raw fixture deadline exceeded"))?
            });
            let result = runtime.block_on(control::request(
                &caller,
                fixture.client_tls.clone(),
                &origin,
                &fixture.server_id,
                control::Request::Command(command.clone()),
            ));
            runtime.block_on(peer).map_err(io::Error::other)??;
            if !revoke {
                let control::Reply::Command(reply) = result? else {
                    return Err(io::Error::other("expected fixture command result"));
                };
                assert!(reply.secret.is_some());
            } else {
                let error = result.err().unwrap();
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            }
        }
        Ok(())
    }
}
