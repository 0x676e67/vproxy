//! Browser access to fixed remote traffic scopes. Cached node facts retain
//! their source and age; unavailable fine-grained reads never become local or
//! fabricated zero data. Only the controller selects the enrolled TLS origin.

use axum::extract::{Path, rejection::PathRejection};
use serde_json::Value;

use super::{
    traffic::{self, Query},
    *,
};
use crate::{
    access::traffic::PROTOCOLS,
    manage::{
        node::control::{self, Reply, Request as Operation},
        remote_traffic,
        store::{
            self, remote_traffic as cache,
            traffic::{self as durable, Scope},
        },
    },
};

const MAX_BYTES: usize = 64 * 1024;
const FRESH_MILLIS: u64 = 90_000;

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/targets/{id}/traffic", get(totals))
        .route("/api/v1/targets/{id}/traffic/buckets", get(buckets))
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

#[derive(Serialize)]
struct Source {
    origin_node_id: String,
    cached: bool,
    collector_available: bool,
    state: &'static str,
    last_success_at_unix_ms: Option<u64>,
    age_millis: Option<u64>,
    target_revision: String,
}

fn peer_id(path: Result<Path<String>, PathRejection>) -> Result<String, ApiError> {
    let peer = users::resource_id(path)?;
    let mut decoded = [0; 16];
    if !matches!(URL_SAFE_NO_PAD.decode_slice(&peer, &mut decoded), Ok(16))
        || URL_SAFE_NO_PAD.encode(decoded) != peer
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_resource_id",
        ));
    }
    Ok(peer)
}

fn coordinator(state: &AppState) -> Result<Arc<super::super::policy::Coordinator>, ApiError> {
    // Target metadata is local schema state. Do not report an unmigrated
    // controller as a remote node that lacks traffic support.
    if state.schema_version < 10 {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        ));
    }
    state.policy.clone().ok_or_else(unavailable)
}

fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "remote_traffic_unavailable",
    )
}

fn failure(error: io::Error) -> ApiError {
    // OS/filesystem/transport failures are not evidence that a remote entity
    // is absent or that the child rejected its controller's authorization.
    if error.raw_os_error().is_some()
        || error
            .get_ref()
            .is_some_and(|source| source.is::<control::TransportError>())
    {
        return unavailable();
    }
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<control::RemoteError>())
        && error.code == "resource_not_found"
    {
        return ApiError::new(StatusCode::NOT_FOUND, "resource_not_found");
    }
    if error.kind() == io::ErrorKind::NotFound {
        return ApiError::new(StatusCode::NOT_FOUND, "resource_not_found");
    }
    let code = match remote_traffic::classify(&error) {
        cache::Failure::Unsupported => "remote_traffic_unsupported",
        cache::Failure::NotAuthorized => "remote_traffic_not_authorized",
        cache::Failure::Unavailable | cache::Failure::Continuity => "remote_traffic_unavailable",
    };
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, code)
}

/// Read target, current peer generation and cache under one SQLite snapshot.
/// Local admin access to old facts is not renewed authority to contact a peer.
async fn cached(
    state: &AppState,
    peer: String,
) -> Result<(Source, Option<durable::NodeSnapshot>), ApiError> {
    let current = coordinator(state)?
        .read(move |directory| cache::browser_read(directory, &peer))
        .await
        .map_err(failure)?;
    Ok(cached_view(
        current,
        state.controller.is_some(),
        super::super::traffic::now(),
    ))
}

fn cached_view(
    current: cache::BrowserRead,
    available: bool,
    observed: Option<u64>,
) -> (Source, Option<durable::NodeSnapshot>) {
    let captured = current.cache.source.last_success_at;
    let age = observed
        .zip(captured)
        .and_then(|(now, then)| now.checked_sub(then));
    let state_name = if current.cache.source.quarantined {
        "continuity_error"
    } else if !current.target.active || current.target.retired {
        "paused"
    } else if !current.peer_active {
        "not_authorized"
    } else if current.target.rollback_detected {
        "continuity_error"
    } else if current.cache.source.target_revision != current.target.revision
        || current
            .cache
            .source
            .authorization_revision
            .is_some_and(|revision| revision != current.authorization_revision)
    {
        if current.cache.snapshot.is_some() {
            "stale"
        } else {
            "pending"
        }
    } else if let Some(error) = current.cache.source.error {
        error.code()
    } else if current.cache.snapshot.is_none() {
        "pending"
    } else if !available || age.is_none_or(|age| age > FRESH_MILLIS) {
        "stale"
    } else {
        "ready"
    };
    (
        Source {
            origin_node_id: current.target.peer_id,
            cached: true,
            collector_available: available,
            state: state_name,
            last_success_at_unix_ms: captured,
            age_millis: age,
            target_revision: current.target.revision.to_string(),
        },
        current.cache.snapshot,
    )
}

async fn demand(
    state: &AppState,
    peer: String,
    operation: Operation,
) -> Result<(Source, Reply), ApiError> {
    let policy = coordinator(state)?;
    let id = peer.clone();
    let target = policy
        .read(move |directory| store::targets::get(directory, &id))
        .await
        .map_err(failure)?;
    let controller = state.controller.as_ref().ok_or_else(unavailable)?;
    let reply = super::super::remote_traffic::request(controller, peer.clone(), operation)
        .await
        .map_err(failure)?;
    let current = policy
        .read(move |directory| store::targets::get(directory, &peer))
        .await
        .map_err(failure)?;
    if current.revision != target.revision
        || !current.active
        || current.retired
        || current.rollback_detected
    {
        return Err(unavailable());
    }
    let observed = super::super::traffic::now();
    Ok((
        Source {
            origin_node_id: current.peer_id,
            cached: false,
            collector_available: true,
            state: "ready",
            last_success_at_unix_ms: observed,
            age_millis: observed.map(|_| 0),
            target_revision: current.revision.to_string(),
        },
        reply,
    ))
}

fn node_totals(snapshot: durable::NodeSnapshot) -> durable::Totals {
    durable::Totals {
        status: snapshot.status,
        items: PROTOCOLS
            .into_iter()
            .zip(snapshot.totals)
            .map(|(protocol, value)| durable::ProtocolTotal { protocol, value })
            .collect(),
    }
}

/// Slice complete windows, not individual protocol rows. A missing protocol is
/// retained as absence; an empty page and explicit retention floor are distinct.
fn node_buckets(query: &Query, snapshot: durable::NodeSnapshot) -> durable::BucketPage {
    let (windows, floor) = match query.resolution {
        durable::Resolution::Minute => (snapshot.minute, snapshot.floors[0]),
        durable::Resolution::Hour => (snapshot.hour, snapshot.floors[1]),
        durable::Resolution::Day => (snapshot.day, snapshot.floors[2]),
    };
    let floor = floor.or_else(|| windows.first().map(|window| window.window_id));
    let mut windows = windows
        .into_iter()
        .filter(|window| query.after.is_none_or(|after| window.window_id > after));
    let items: Vec<_> = windows
        .by_ref()
        .take(usize::try_from(query.limit).unwrap_or(50))
        .map(|window| durable::Bucket {
            window_id: window.window_id,
            items: PROTOCOLS
                .into_iter()
                .zip(window.values)
                .filter_map(|(protocol, value)| {
                    value.map(|value| durable::ProtocolTotal { protocol, value })
                })
                .collect(),
        })
        .collect();
    let next_cursor = windows
        .next()
        .and_then(|_| items.last().map(|window| window.window_id));
    durable::BucketPage {
        status: snapshot.status,
        items,
        floor,
        next_cursor,
    }
}

async fn totals(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let peer = peer_id(path)?;
    let query = traffic::query(&uri, false)?;
    let (source, projection) = if matches!(query.scope, Scope::Node) {
        let (source, snapshot) = cached(&state, peer).await?;
        (
            source,
            snapshot
                .map(|snapshot| traffic::durable_totals_response(&query, node_totals(snapshot))),
        )
    } else {
        let (source, reply) = demand(
            &state,
            peer,
            if query.split {
                Operation::TrafficTotalsV2 {
                    scope: query.scope.clone(),
                }
            } else {
                Operation::TrafficTotals {
                    scope: query.scope.clone(),
                }
            },
        )
        .await?;
        let Reply::TrafficTotals(value) = reply else {
            return Err(unavailable());
        };
        (
            source,
            Some(traffic::durable_totals_response(&query, value.value)),
        )
    };
    response(source, projection).await
}

async fn buckets(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let peer = peer_id(path)?;
    let query = traffic::query(&uri, true)?;
    let (source, page) = if matches!(query.scope, Scope::Node) {
        let (source, snapshot) = cached(&state, peer).await?;
        (
            source,
            snapshot.map(|snapshot| node_buckets(&query, snapshot)),
        )
    } else {
        let (source, reply) = demand(
            &state,
            peer,
            if query.split {
                Operation::TrafficBucketsV2 {
                    scope: query.scope.clone(),
                    resolution: query.resolution,
                    after: query.after,
                    limit: query.limit,
                }
            } else {
                Operation::TrafficBuckets {
                    scope: query.scope.clone(),
                    resolution: query.resolution,
                    after: query.after,
                    limit: query.limit,
                }
            },
        )
        .await?;
        let Reply::TrafficBuckets(value) = reply else {
            return Err(unavailable());
        };
        (source, Some(value.value))
    };
    response(
        source,
        page.map(|page| traffic::bucket_response(&query, page)),
    )
    .await
}

/// Reuse the local fixed DTO, then enforce the cap on the entire wrapper. This
/// small cold-path conversion avoids two diverging local/remote byte contracts.
async fn response(source: Source, data: Option<Response>) -> Result<Response, ApiError> {
    let data: Option<Value> = match data {
        Some(data) => {
            if data.status() != StatusCode::OK {
                return Err(unavailable());
            }
            let bytes = to_bytes(data.into_body(), MAX_BYTES)
                .await
                .map_err(|_| unavailable())?;
            Some(serde_json::from_slice(&bytes).map_err(|_| unavailable())?)
        }
        None => None,
    };
    #[derive(Serialize)]
    struct View {
        source: Source,
        data: Option<Value>,
    }
    let bytes = serde_json::to_vec(&View { source, data }).map_err(|_| unavailable())?;
    if bytes.len() > MAX_BYTES {
        return Err(unavailable());
    }
    Ok(([(header::CONTENT_TYPE, "application/json")], bytes).into_response())
}
