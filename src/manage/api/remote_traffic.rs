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

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt as _;

    use super::*;
    use crate::traffic::Snapshot;

    fn id(byte: u8) -> String {
        URL_SAFE_NO_PAD.encode([byte; 16])
    }

    fn snapshot(count: u64) -> durable::NodeSnapshot {
        let zero = Snapshot {
            upload: 0,
            download: 0,
            saturated: false,
        };
        let value = Snapshot {
            upload: u64::MAX,
            download: u64::MAX,
            saturated: true,
        };
        durable::NodeSnapshot {
            status: durable::Status {
                http_split: false,
                node_id: id(1),
                meter_epoch: id(2),
                run_id: Some(id(3)),
                cursor: 4,
                clean: false,
                loss_possible: false,
                history_gap: true,
                time_uncertain: false,
                last_checkpoint_at: Some(9_007_199_254_740_991),
                meter_started_at: Some(0),
            },
            totals: [value, value, value, zero, zero],
            floors: [Some(0); 3],
            minute: (0..count)
                .map(|index| durable::Window {
                    window_id: index * 60_000,
                    values: [
                        Some(value),
                        if index == 1 { None } else { Some(value) },
                        Some(value),
                        None,
                        None,
                    ],
                })
                .collect(),
            hour: vec![],
            day: vec![],
        }
    }

    fn query(after: Option<u64>, limit: u32) -> Query {
        Query {
            split: false,
            scope: Scope::Node,
            protocol: None,
            resolution: durable::Resolution::Minute,
            after,
            limit,
        }
    }

    fn source() -> Source {
        Source {
            origin_node_id: id(1),
            cached: true,
            collector_available: false,
            state: "stale",
            last_success_at_unix_ms: None,
            age_millis: None,
            target_revision: "1".into(),
        }
    }

    fn cached_facts() -> cache::BrowserRead {
        cache::BrowserRead {
            cache: cache::Cached {
                source: cache::Source {
                    quarantined: false,
                    target_revision: 7,
                    authorization_revision: Some(4),
                    last_success_at: Some(1000),
                    error: None,
                },
                snapshot: Some(snapshot(0)),
            },
            target: store::targets::Target {
                peer_id: id(1),
                name: "source".into(),
                origin: "https://source.invalid".into(),
                server_ip: None,
                active: true,
                retired: false,
                revision: 7,
                observed_epoch: None,
                observed_command: None,
                observed_policy_revision: None,
                rollback_detected: false,
            },
            peer_active: true,
            authorization_revision: 4,
        }
    }

    #[test]
    fn cache_source_state_respects_peer_generation_pause_age_and_keeps_last_good() {
        let (ready, data) = cached_view(cached_facts(), true, Some(2000));
        assert_eq!(ready.state, "ready");
        assert_eq!(ready.age_millis, Some(1000));
        assert!(data.is_some());
        let mut isolated = cached_facts();
        isolated.cache.source.quarantined = true;
        isolated.cache.source.error = Some(cache::Failure::Unavailable);
        isolated.target.active = false;
        assert_eq!(
            cached_view(isolated, true, None).0.state,
            "continuity_error"
        );
        for (available, clock) in [
            (false, Some(2000)),
            (true, None),
            (true, Some(999)),
            (true, Some(91_001)),
        ] {
            let (source, data) = cached_view(cached_facts(), available, clock);
            assert_eq!(source.state, "stale");
            assert!(data.is_some());
        }
        for failure in [
            cache::Failure::Unavailable,
            cache::Failure::Unsupported,
            cache::Failure::NotAuthorized,
            cache::Failure::Continuity,
        ] {
            let mut facts = cached_facts();
            facts.cache.source.error = Some(failure);
            let (source, data) = cached_view(facts, true, Some(2000));
            assert_eq!(source.state, failure.code());
            assert!(data.is_some());
        }
        let mut facts = cached_facts();
        facts.authorization_revision += 1;
        assert_eq!(cached_view(facts, true, Some(2000)).0.state, "stale");
        let mut facts = cached_facts();
        facts.peer_active = false;
        assert_eq!(
            cached_view(facts, true, Some(2000)).0.state,
            "not_authorized"
        );
        let mut facts = cached_facts();
        facts.target.active = false;
        assert_eq!(cached_view(facts, true, Some(2000)).0.state, "paused");
        let mut facts = cached_facts();
        facts.cache.snapshot = None;
        facts.cache.source.target_revision = 0;
        facts.cache.source.authorization_revision = None;
        facts.cache.source.last_success_at = None;
        let (source, data) = cached_view(facts, true, Some(2000));
        assert_eq!(source.state, "pending");
        assert!(source.cached && source.age_millis.is_none() && data.is_none());
    }

    #[test]
    fn failure_distinguishes_transport_entities_and_remote_capabilities() {
        let error = failure(io::Error::from_raw_os_error(2));
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.code, "remote_traffic_unavailable");
        let error = failure(io::Error::new(
            io::ErrorKind::NotFound,
            "fixed entity result",
        ));
        assert_eq!(error.status, StatusCode::NOT_FOUND);
        assert_eq!(error.code, "resource_not_found");
        let error = failure(io::Error::new(
            io::ErrorKind::Unsupported,
            control::RemoteError {
                status: 503,
                code: "traffic_unsupported",
            },
        ));
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.code, "remote_traffic_unsupported");
    }

    async fn value(response: Response) -> Value {
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.len() <= MAX_BYTES);
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn complete_window_paging_keeps_absent_protocols_and_retention_without_zero_rows() {
        let q = query(None, 2);
        let page = node_buckets(&q, snapshot(3));
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.next_cursor, Some(60_000));
        assert_eq!(page.floor, Some(0));
        assert_eq!(page.items[1].items.len(), 2);
        let next = node_buckets(&query(page.next_cursor, 2), snapshot(3));
        assert_eq!(next.items.len(), 1);
        assert_eq!(next.items[0].window_id, 120_000);
        assert!(next.next_cursor.is_none());
        let empty = node_buckets(&query(Some(180_000), 50), snapshot(3));
        assert!(empty.items.is_empty());
        assert_eq!(empty.floor, Some(0));
        let body = value(
            response(source(), Some(traffic::bucket_response(&q, page)))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["source"]["state"], "stale");
        assert_eq!(
            body["data"]["items"][1]["items"].as_array().unwrap().len(),
            2
        );
    }

    #[tokio::test]
    async fn full_browser_wrapper_fits_cap_preserves_u64_and_does_not_invent_live_health() {
        let q = query(None, 50);
        let body = value(
            response(
                source(),
                Some(traffic::bucket_response(&q, node_buckets(&q, snapshot(60)))),
            )
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(body["data"]["items"].as_array().unwrap().len(), 50);
        assert_eq!(
            body["data"]["items"][0]["items"][0]["upload_bytes"],
            u64::MAX.to_string()
        );
        let body = value(
            response(
                source(),
                Some(traffic::durable_totals_response(
                    &q,
                    node_totals(snapshot(0)),
                )),
            )
            .await
            .unwrap(),
        )
        .await;
        // No local active-run proof can decide whether the remote process stopped.
        // Preserve its durable fact and keep the separate open marker visible.
        assert_eq!(body["data"]["loss_possible"], false);
        assert_eq!(body["data"]["last_run_clean"], false);
        assert!(body["data"]["active_run_id"].is_null());
        assert!(body["data"]["last_completed_cycle_age_millis"].is_null());
        for row in body["data"]["items"].as_array().unwrap() {
            assert!(row["live_upload_bytes"].is_null());
            assert!(row["live_download_bytes"].is_null());
            assert!(row["live_saturated"].is_null());
        }
        let pending = value(response(source(), None).await.unwrap()).await;
        assert!(pending["data"].is_null());
        assert!(pending["source"]["last_success_at_unix_ms"].is_null());
        // The budget covers source + data, not only the nested local projection.
        let oversized = Json(serde_json::json!({"padding":"x".repeat(MAX_BYTES)})).into_response();
        assert!(response(source(), Some(oversized)).await.is_err());
    }

    #[tokio::test]
    async fn router_auth_and_canonical_queries_precede_configured_target_lookup() {
        use crate::manage::api::tests::{call, managed_state, request};
        let (_directory, state, cookie) = managed_state();
        let path = format!("/api/v1/targets/{}/traffic", id(8));
        let forbidden = call(state.clone(), request(Method::GET, &path, "")).await;
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
        assert_eq!(forbidden.headers()[header::CACHE_CONTROL], "no-store");
        for (suffix, expected) in [
            ("", StatusCode::NOT_FOUND),
            ("?scope=node&%73cope=node", StatusCode::BAD_REQUEST),
            ("/buckets?scope=credential", StatusCode::BAD_REQUEST),
        ] {
            let mut request = request(Method::GET, &(path.clone() + suffix), "");
            request
                .headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            let result = call(state.clone(), request).await;
            assert_eq!(result.status(), expected);
            assert_eq!(result.headers()[header::CACHE_CONTROL], "no-store");
        }
        let mut invalid = request(
            Method::GET,
            "/api/v1/targets/AAAAAAAAAAAAAAAAAAAAAB/traffic",
            "",
        );
        invalid
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(call(state, invalid).await.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn schema_nine_remote_traffic_reads_require_local_management_upgrade() {
        use crate::manage::api::tests::{call, managed_state, request};
        let (_directory, mut state, cookie) = managed_state();
        let connection =
            rusqlite::Connection::open(state.directory.join("management.sqlite3")).unwrap();
        store::recovery::remove_schema_for_test(&connection).unwrap();
        connection
            .execute_batch(
                "ALTER TABLE managed_targets DROP COLUMN server_ip; PRAGMA user_version=9;",
            )
            .unwrap();
        Arc::get_mut(&mut state).unwrap().schema_version = 9;
        let path = format!("/api/v1/targets/{}/traffic", id(8));
        // Cached node reads and on-demand entity reads use different lookup paths;
        // neither may mislabel the controller's old schema as child incompatibility.
        for suffix in [
            String::new(),
            "/buckets?scope=node".to_owned(),
            format!("?scope=user&id={}", id(9)),
            format!("/buckets?scope=pool&id={}", id(10)),
        ] {
            let mut request = request(Method::GET, &(path.clone() + &suffix), "");
            request
                .headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            let response = call(state.clone(), request).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["error"]["code"], "management_upgrade_required");
        }
        assert_eq!(store::inspect(&state.directory).unwrap().schema_version, 9);
    }
}
