//! Live operations incidents and separate durable event history. Reads perform
//! no collection or remediation; an explicit acknowledgement only records review.

use super::*;
use crate::manage::alerts::{PageError, Query};

mod history;

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .merge(history::routes())
        .route("/api/v1/alerts", get(observations))
        .route("/api/v1/operations-alerts", get(node_observations))
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

/// Only this resource's state and cursor are accepted. A cursor belongs to one
/// boot, filter and evidence revision, not the inventory/search pagination APIs.
fn query(uri: &Uri) -> Result<Query, ApiError> {
    Query::parse(uri.query()).map_err(page_error)
}

async fn observations(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    let query = query(&uri)?;
    let monitor = state.alerts.as_ref().ok_or_else(unavailable)?;
    let page = monitor
        .page(query.filter, query.after.as_deref(), query.limit)
        .map_err(page_error)?;
    Ok(Json(page).into_response())
}

/// The fleet's local card uses the same own-node projection as remote cards;
/// cached observations about managed peers must not inflate its incident count.
async fn node_observations(
    State(state): State<Arc<AppState>>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let query = query(&uri)?;
    let monitor = state.alerts.as_ref().ok_or_else(unavailable)?;
    let page = monitor
        .node_page(query.filter, query.after.as_deref(), query.limit)
        .map_err(page_error)?;
    Ok(Json(page).into_response())
}

fn invalid() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid_alert_query")
}

fn unavailable() -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "alerts_unavailable")
}

pub(super) fn page_error(error: PageError) -> ApiError {
    match error {
        PageError::InvalidQuery => invalid(),
        PageError::Changed => ApiError::new(StatusCode::CONFLICT, "alerts_changed"),
        PageError::Unavailable => unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::{
        alerts::{self as monitor, Alert, Coverage, Kind, Page, Status},
        api::tests::{call, managed_state, request},
        health::CheckKind,
        store,
    };
    use http_body_util::BodyExt as _;
    use serde_json::Value;

    fn authorized(cookie: &str, method: Method, query: &str) -> Request {
        let mut request = request(method, &format!("/api/v1/alerts{query}"), "");
        request
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        request
    }

    async fn body(response: Response, status: StatusCode) -> Value {
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.len() <= 32 * 1024);
        serde_json::from_slice(&bytes).unwrap()
    }

    fn attach(state: &mut Arc<AppState>) -> monitor::Runner {
        let node_id = store::inspect(&state.directory).unwrap().node_id;
        let (handle, runner) = monitor::new(
            state.policy.as_ref().unwrap().clone(),
            node_id,
            None,
            None,
            false,
            false,
            None,
            None,
        )
        .unwrap();
        Arc::get_mut(state).unwrap().alerts = Some(handle);
        runner
    }

    #[tokio::test]
    async fn own_node_projection_requires_session_and_distinguishes_uncollected_from_sampled() {
        let (_directory, mut state, cookie) = managed_state();
        let path = "/api/v1/operations-alerts";
        let browser = |method, query: &str| {
            let mut value = authorized(&cookie, method, "");
            *value.uri_mut() = format!("{path}{query}").parse().unwrap();
            value
        };
        assert_eq!(
            body(
                call(state.clone(), browser(Method::GET, "")).await,
                StatusCode::SERVICE_UNAVAILABLE
            )
            .await["error"]["code"],
            "alerts_unavailable"
        );
        let mut runner = attach(&mut state);
        let before = store::inspect(&state.directory).unwrap();
        let initial = body(
            call(state.clone(), browser(Method::GET, "?limit=1")).await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(initial["node_id"], before.node_id);
        assert!(initial["age_millis"].is_null());
        assert_eq!(initial["coverage"].as_object().unwrap().len(), 6);
        assert!(initial["coverage"].get("remote_cached").is_none());
        assert_eq!(initial["dropped"], "0");
        assert_eq!(initial["items"], serde_json::json!([]));
        assert_eq!(
            body(
                call(state.clone(), request(Method::GET, path, "")).await,
                StatusCode::FORBIDDEN
            )
            .await["error"]["code"],
            "authentication_required"
        );
        let mut bearer = request(Method::GET, path, "");
        bearer.headers_mut().insert(
            header::AUTHORIZATION,
            "Bearer not-a-session".parse().unwrap(),
        );
        assert_eq!(
            body(call(state.clone(), bearer).await, StatusCode::FORBIDDEN).await["error"]["code"],
            "automation_route_denied"
        );
        let wrong_scope = format!("?after={}:1:active:0", initial["boot_id"].as_str().unwrap());
        for query in [
            "?limit=0",
            "?limit=17",
            "?node=foreign",
            "?state=active&state=recent",
            &wrong_scope,
        ] {
            assert_eq!(
                body(
                    call(state.clone(), browser(Method::GET, query)).await,
                    StatusCode::BAD_REQUEST
                )
                .await["error"]["code"],
                "invalid_alert_query"
            );
        }
        let head = call(state.clone(), browser(Method::HEAD, "?limit=1")).await;
        assert_eq!(head.status(), StatusCode::OK);
        assert!(
            head.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        runner.collect_once().await.unwrap();
        let fresh = body(
            call(state.clone(), browser(Method::GET, "?limit=1")).await,
            StatusCode::OK,
        )
        .await;
        assert!(fresh["age_millis"].is_string());
        assert_eq!(fresh["collection_error"], false);
        assert_eq!(fresh["active_count"], 0);
        assert_eq!(
            store::inspect(&state.directory).unwrap().schema_version,
            before.schema_version
        );
    }

    #[tokio::test]
    async fn incidents_require_browser_identity_and_missing_collection_is_not_health() {
        let (_directory, mut state, cookie) = managed_state();
        let absent = call(state.clone(), authorized(&cookie, Method::GET, "")).await;
        assert_eq!(
            body(absent, StatusCode::SERVICE_UNAVAILABLE).await["error"]["code"],
            "alerts_unavailable"
        );
        let unavailable_head = call(state.clone(), authorized(&cookie, Method::HEAD, "")).await;
        assert_eq!(unavailable_head.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            unavailable_head
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        let mut runner = attach(&mut state);
        let rejected = call(
            state.clone(),
            request(Method::GET, "/api/v1/alerts?limit=0", ""),
        )
        .await;
        assert_eq!(
            body(rejected, StatusCode::FORBIDDEN).await["error"]["code"],
            "authentication_required"
        );
        let unauthenticated_head =
            call(state.clone(), request(Method::HEAD, "/api/v1/alerts", "")).await;
        assert_eq!(unauthenticated_head.status(), StatusCode::FORBIDDEN);
        assert!(
            unauthenticated_head
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        // Even a correctly shaped machine token is denied at the resource boundary
        // before lookup; the users:read grant does not include operations incidents.
        let mut bearer = request(Method::GET, "/api/v1/alerts", "");
        bearer.headers_mut().insert(
            header::AUTHORIZATION,
            format!(
                "Bearer vpa1.{}.1.{}",
                URL_SAFE_NO_PAD.encode([1; 16]),
                URL_SAFE_NO_PAD.encode([2; 32]),
            )
            .parse()
            .unwrap(),
        );
        let response = call(state.clone(), bearer).await;
        assert_eq!(
            body(response, StatusCode::FORBIDDEN).await["error"]["code"],
            "automation_route_denied"
        );
        let value = body(
            call(state.clone(), authorized(&cookie, Method::GET, "")).await,
            StatusCode::OK,
        )
        .await;
        assert!(store::valid_id(value["boot_id"].as_str().unwrap()));
        assert_eq!(value["revision"], "1");
        assert_eq!(value["dropped"], "0");
        assert!(value["observed_at_unix_ms"].is_null());
        assert!(value["age_millis"].is_null());
        assert_eq!(value["collection_error"], false);
        assert_eq!(value["coverage"]["local_proxy_expected"], false);
        assert_eq!(value["coverage"]["local_traffic"], false);
        assert_eq!(value["coverage"]["remote_egress"], false);
        assert!(value["items"].as_array().unwrap().is_empty());
        // Run exactly one real local collection with no health/traffic/network
        // source. Fresh empty evidence is distinct from the uncollected page.
        runner.collect_once().await.unwrap();
        let value = body(
            call(state, authorized(&cookie, Method::GET, "")).await,
            StatusCode::OK,
        )
        .await;
        assert!(value["age_millis"].is_string());
        assert_eq!(value["collection_error"], false);
        assert_eq!(value["active_count"], 0);
        assert!(value["items"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn strict_query_and_snapshot_cursor_have_bodyless_heads_without_storage_writes() {
        let (_directory, mut state, cookie) = managed_state();
        let before = store::inspect(&state.directory).unwrap();
        let _runner = attach(&mut state);
        let first = body(
            call(
                state.clone(),
                authorized(&cookie, Method::GET, "?state=active&limit=1"),
            )
            .await,
            StatusCode::OK,
        )
        .await;
        let boot = first["boot_id"].as_str().unwrap();
        for query in [
            "?state=",
            "?state=all",
            "?state=active&state=recent",
            "?after=",
            "?after=x&after=y",
            "?limit=0",
            "?limit=17",
            "?limit=01",
            "?limit=%2B1",
            "?limit=1&limit=1",
            "?unknown=true",
            "?after=%FF",
            "?after=not-a-cursor",
        ]
        .into_iter()
        .map(str::to_owned)
        .chain([
            format!("?after={}", "a".repeat(161)),
            format!("?{}", "x".repeat(769)),
            format!("?after={boot}:01:active:0"),
            format!("?after={boot}:1:active:1"),
        ]) {
            let response = call(state.clone(), authorized(&cookie, Method::GET, &query)).await;
            assert_eq!(
                body(response, StatusCode::BAD_REQUEST).await["error"]["code"],
                "invalid_alert_query",
                "query {query}"
            );
        }
        for query in [
            format!("?after={boot}:2:active:0"),
            format!("?state=recent&after={boot}:1:active:0"),
            format!("?after={}:1:active:0", URL_SAFE_NO_PAD.encode([42; 16])),
        ] {
            let response = call(state.clone(), authorized(&cookie, Method::GET, &query)).await;
            assert_eq!(
                body(response, StatusCode::CONFLICT).await["error"]["code"],
                "alerts_changed"
            );
        }
        for (query, status) in [
            (format!("?after={boot}:1:active:0&limit=16"), StatusCode::OK),
            ("?state=recent".into(), StatusCode::OK),
            ("?limit=0".into(), StatusCode::BAD_REQUEST),
            (format!("?after={boot}:2:active:0"), StatusCode::CONFLICT),
        ] {
            let response = call(state.clone(), authorized(&cookie, Method::HEAD, &query)).await;
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
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
        let after = store::inspect(&state.directory).unwrap();
        assert_eq!(after.node_id, before.node_id);
        assert_eq!(after.schema_version, before.schema_version);
        assert_eq!(
            state
                .policy
                .as_ref()
                .unwrap()
                .status()
                .await
                .unwrap()
                .saved_revision,
            1
        );
    }

    #[test]
    fn maximum_incident_page_preserves_exact_counters_within_browser_budget() {
        let max = u64::MAX.to_string();
        let items = (0..16)
            .map(|_| Alert {
                id: max.clone(),
                kind: Kind::EgressCheck,
                origin_node_id: URL_SAFE_NO_PAD.encode([255; 16]),
                resource_id: Some(URL_SAFE_NO_PAD.encode([255; 16])),
                check: Some(CheckKind::Tcp),
                target: Some(
                    "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"
                        .parse()
                        .unwrap(),
                ),
                status: Status::Recovered,
                code: "remote_traffic_continuity_error".into(),
                first_observed_at_unix_ms: Some(max.clone()),
                last_observed_at_unix_ms: Some(max.clone()),
                ended_at_unix_ms: Some(max.clone()),
                age_millis: max.clone(),
                evidence_sequence: Some(max.clone()),
                evidence_fresh: false,
            })
            .collect();
        let page = Page {
            boot_id: URL_SAFE_NO_PAD.encode([255; 16]),
            revision: max.clone(),
            observed_at_unix_ms: Some(max.clone()),
            age_millis: Some(max.clone()),
            collection_error: true,
            coverage: Coverage {
                local_egress: true,
                local_traffic: true,
                local_proxy_expected: true,
                local_management_https: false,
                local_node_tls: false,
                local_proxy_tls: false,
                remote_cached: true,
                remote_egress: false,
                remote_observation: false,
            },
            active_count: 6_144,
            recent_count: 256,
            dropped: max.clone(),
            items,
            next_cursor: Some("a".repeat(160)),
        };
        let bytes = serde_json::to_vec(&page).unwrap();
        assert!(bytes.len() <= 32 * 1024);
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["dropped"], max);
        assert_eq!(value["items"][0]["evidence_sequence"], u64::MAX.to_string());
    }
}
