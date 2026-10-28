//! Local, non-secret event history. Historical origin does not grant remote
//! control; administrator checks also run inside the store snapshot/transaction.

use axum::extract::{Path, rejection::PathRejection};

use super::*;
use crate::manage::{
    health::CheckKind,
    policy::Coordinator,
    store::{self, alerts::history as storage},
};

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/alert-events", get(list))
        .route("/api/v1/alert-events/{id}", get(event))
        .route("/api/v1/alert-episodes", get(unread))
        .route(
            "/api/v1/alert-episodes/acknowledge",
            post(acknowledge_batch),
        )
        .route("/api/v1/alert-episodes/{id}", get(episode))
        .route("/api/v1/alert-episodes/{id}/acknowledge", post(acknowledge))
        .route("/api/v1/alert-summary", get(summary))
}

/// Wall times are nullable display values. Decimal counters preserve the full
/// u64 observation domain without rounding through JavaScript Number.
#[derive(Serialize)]
struct Source {
    incident_id: String,
    kind: crate::manage::alerts::Kind,
    origin_node_id: String,
    resource_id: Option<String>,
    check: Option<CheckKind>,
    target: Option<std::net::SocketAddr>,
    code: String,
    first_observed_at_unix_ms: Option<String>,
    last_observed_at_unix_ms: Option<String>,
    evidence_sequence: Option<String>,
}

impl From<storage::Observation> for Source {
    fn from(value: storage::Observation) -> Self {
        Self {
            incident_id: value.incident_id.to_string(),
            kind: value.kind,
            origin_node_id: value.origin_node_id,
            resource_id: value.resource_id,
            check: value.check,
            target: value.target,
            code: value.code,
            first_observed_at_unix_ms: decimal(value.first_observed_at_unix_ms),
            last_observed_at_unix_ms: decimal(value.last_observed_at_unix_ms),
            evidence_sequence: decimal(value.evidence_sequence),
        }
    }
}

#[derive(Serialize)]
struct Event {
    sequence: String,
    node_id: String,
    episode_id: String,
    boot_id: String,
    transition: storage::EventKind,
    #[serde(flatten)]
    source: Source,
    observed_at_unix_ms: Option<String>,
    recorded_at_unix_ms: Option<String>,
    end_reason: Option<storage::EndReason>,
    administrator_id: Option<String>,
    acknowledged_transition_sequence: Option<String>,
}

impl From<storage::Event> for Event {
    fn from(value: storage::Event) -> Self {
        Self {
            sequence: value.sequence.to_string(),
            node_id: value.observer_node_id,
            episode_id: value.episode_id.to_string(),
            boot_id: value.boot_id,
            transition: value.kind,
            source: value.observation.into(),
            observed_at_unix_ms: decimal(value.observed_at_unix_ms),
            recorded_at_unix_ms: decimal(value.recorded_at_unix_ms),
            end_reason: value.ended_reason,
            administrator_id: value.administrator_id,
            acknowledged_transition_sequence: (value.kind == storage::EventKind::Acknowledged)
                .then(|| value.transition_sequence.to_string()),
        }
    }
}

/// Last retained incident projection, separate from the live monitor. An old
/// acknowledgement remains visible when a new transition needs another review.
#[derive(Serialize)]
struct Episode {
    id: String,
    node_id: String,
    boot_id: String,
    #[serde(flatten)]
    source: Source,
    status: crate::manage::alerts::Status,
    ended_at_unix_ms: Option<String>,
    end_reason: Option<storage::EndReason>,
    latest_transition_sequence: String,
    acknowledged_transition_sequence: Option<String>,
    acknowledged_by: Option<String>,
    acknowledged_at_unix_ms: Option<String>,
    acknowledgement_event_sequence: Option<String>,
    is_acknowledged: bool,
}

impl From<storage::Episode> for Episode {
    fn from(value: storage::Episode) -> Self {
        let acknowledgement = value.acknowledgement;
        Self {
            id: value.id.to_string(),
            node_id: value.observer_node_id,
            boot_id: value.boot_id,
            source: value.observation.into(),
            status: value.status,
            ended_at_unix_ms: decimal(value.ended_at_unix_ms),
            end_reason: value.ended_reason,
            latest_transition_sequence: value.last_transition_sequence.to_string(),
            acknowledged_transition_sequence: acknowledgement
                .as_ref()
                .map(|value| value.transition_sequence.to_string()),
            acknowledged_by: acknowledgement
                .as_ref()
                .map(|value| value.administrator_id.clone()),
            acknowledged_at_unix_ms: acknowledgement
                .as_ref()
                .and_then(|value| decimal(value.observed_at_unix_ms)),
            acknowledgement_event_sequence: acknowledgement
                .map(|value| value.event_sequence.to_string()),
            is_acknowledged: value.is_acknowledged,
        }
    }
}

fn decimal(value: Option<u64>) -> Option<String> {
    value.map(|value| value.to_string())
}

#[derive(Serialize)]
struct Page {
    node_id: String,
    items: Vec<Event>,
    next_cursor: Option<String>,
    oldest_sequence: Option<String>,
    trimmed: String,
}

#[derive(Serialize)]
struct Summary {
    node_id: String,
    retained_episode_count: u32,
    retained_event_count: u32,
    unacknowledged_count: u32,
    oldest_sequence: Option<String>,
    trimmed: String,
}

fn coordinator(state: &AppState) -> Result<Arc<Coordinator>, ApiError> {
    if state.schema_version < 21 {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        ));
    }
    state.policy.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    })
}

fn invalid() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid_alert_history")
}

fn missing() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "alert_history_not_queryable")
}

fn storage_error(error: io::Error) -> ApiError {
    if let Some(value) = error
        .get_ref()
        .and_then(|value| value.downcast_ref::<storage::Error>())
    {
        let status = match value {
            storage::Error::Invalid => StatusCode::BAD_REQUEST,
            storage::Error::Conflict => StatusCode::CONFLICT,
            storage::Error::NotQueryable => StatusCode::NOT_FOUND,
            storage::Error::Denied => StatusCode::FORBIDDEN,
            storage::Error::UpgradeRequired | storage::Error::Capacity => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        };
        return ApiError::new(status, value.code());
    }
    users::storage_error(error)
}

fn id(value: &str) -> Result<u64, ApiError> {
    users::revision(value).map_err(|_| invalid())
}

fn resource(path: Result<Path<String>, PathRejection>) -> Result<u64, ApiError> {
    let Path(value) = path.map_err(|_| invalid())?;
    id(&value)
}

fn no_query(uri: &Uri) -> Result<(), ApiError> {
    if uri.query().is_some() {
        return Err(invalid());
    }
    Ok(())
}

/// Decode names before duplicate checks; signed, rounded, padded or foreign
/// cursor forms must not change a retained-event page's bounds.
fn query(uri: &Uri) -> Result<storage::Query, ApiError> {
    let raw = uri.query().unwrap_or_default();
    if raw.len() > 1024 {
        return Err(invalid());
    }
    let mut before = None;
    let mut limit = None;
    let mut origin_node_id = None;
    let mut episode_id = None;
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        match key.as_ref() {
            "before" if before.is_none() => before = Some(id(&value)?),
            "limit" if limit.is_none() => {
                limit = Some(
                    u32::try_from(id(&value)?)
                        .ok()
                        .filter(|value| *value <= 50)
                        .ok_or_else(invalid)?,
                )
            }
            "origin_node_id" if origin_node_id.is_none() && store::valid_id(&value) => {
                origin_node_id = Some(value.into_owned());
            }
            "episode_id" if episode_id.is_none() => episode_id = Some(id(&value)?),
            _ => return Err(invalid()),
        }
    }
    Ok(storage::Query {
        before,
        limit: limit.unwrap_or(25),
        origin_node_id,
        episode_id,
    })
}

async fn list(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let query = query(&uri)?;
    let page = coordinator(&state)?
        .read(move |directory| storage::list(directory, &actor, &query))
        .await
        .map_err(storage_error)?;
    Ok(Json(Page {
        node_id: state.node.node_id.clone(),
        items: page.items.into_iter().map(Event::from).collect(),
        next_cursor: decimal(page.next_cursor),
        oldest_sequence: decimal(page.oldest_event_sequence),
        trimmed: page.trimmed.to_string(),
    })
    .into_response())
}

async fn event(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource(path)?;
    let value = coordinator(&state)?
        .read(move |directory| storage::get(directory, &actor, id))
        .await
        .map_err(storage_error)?
        .ok_or_else(missing)?;
    Ok(Json(Event::from(value)).into_response())
}

async fn episode(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource(path)?;
    let value = coordinator(&state)?
        .read(move |directory| storage::episode(directory, &actor, id))
        .await
        .map_err(storage_error)?
        .ok_or_else(missing)?;
    Ok(Json(Episode::from(value)).into_response())
}

async fn summary(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let value = coordinator(&state)?
        .read(move |directory| storage::summary(directory, &actor))
        .await
        .map_err(storage_error)?;
    let count = value
        .active_count
        .checked_add(value.closed_count)
        .ok_or_else(|| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable"))?;
    Ok(Json(Summary {
        node_id: value.observer_node_id,
        retained_episode_count: count,
        retained_event_count: value.event_count,
        unacknowledged_count: value.unacknowledged_count,
        oldest_sequence: decimal(value.oldest_event_sequence),
        trimmed: value.trimmed.to_string(),
    })
    .into_response())
}

#[derive(Serialize)]
struct UnreadPage {
    node_id: String,
    items: Vec<Episode>,
    next_cursor: Option<String>,
    through_sequence: String,
}

/// Inbox pages share an explicit transition watermark. Only retained unread
/// episodes are returned; origins are facts, not a reason to contact a peer.
async fn unread(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let raw = uri.query().unwrap_or_default();
    if raw.len() > 256 {
        return Err(invalid());
    }
    let mut query = storage::UnreadQuery {
        before: None,
        through: None,
    };
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        match key.as_ref() {
            "before" if query.before.is_none() => query.before = Some(id(&value)?),
            "through" if query.through.is_none() => {
                query.through = Some(if value == "0" { 0 } else { id(&value)? });
            }
            _ => return Err(invalid()),
        }
    }
    let page = coordinator(&state)?
        .read(move |directory| storage::unread(directory, &actor, &query))
        .await
        .map_err(storage_error)?;
    Ok(Json(UnreadPage {
        node_id: state.node.node_id.clone(),
        items: page.items.into_iter().map(Episode::from).collect(),
        next_cursor: decimal(page.next_cursor),
        through_sequence: page.through_sequence.to_string(),
    })
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchInput {
    expected_node_id: String,
    items: Vec<BatchItem>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchItem {
    episode_id: String,
    expected_transition_sequence: String,
}
#[derive(Serialize)]
struct BatchResult {
    node_id: String,
    items: Vec<Episode>,
}

/// At most 32 exact transitions per transaction. There is no server-side
/// "whatever is current" acknowledgement, so concurrently arriving events are
/// never marked read by an old inbox. Session/CSRF/Origin guards remain shared.
async fn acknowledge_batch(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(request.uri())?;
    let input: BatchInput = json(request).await?;
    if !store::valid_id(&input.expected_node_id)
        || input.items.is_empty()
        || input.items.len() > storage::MAX_ACK_BATCH
    {
        return Err(invalid());
    }
    let inputs = input
        .items
        .into_iter()
        .map(|value| {
            Ok(storage::Ack {
                expected_node_id: input.expected_node_id.clone(),
                episode_id: id(&value.episode_id)?,
                expected_transition_sequence: id(&value.expected_transition_sequence)?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let values = coordinator(&state)?
        .history_write(move |writer| writer.acknowledge_batch(&actor, &inputs))
        .await
        .map_err(storage_error)?;
    Ok(Json(BatchResult {
        node_id: state.node.node_id.clone(),
        items: values.into_iter().map(Episode::from).collect(),
    })
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    expected_node_id: String,
    expected_transition_sequence: String,
}

/// A lost answer is unknown: this route never invents another operation or
/// changes the expected transition. Same-state idempotency is enforced in SQL.
async fn acknowledge(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(request.uri())?;
    let episode_id = resource(path)?;
    let input: Input = json(request).await?;
    if !store::valid_id(&input.expected_node_id) {
        return Err(invalid());
    }
    let input = storage::Ack {
        expected_node_id: input.expected_node_id,
        episode_id,
        expected_transition_sequence: id(&input.expected_transition_sequence)?,
    };
    let value = coordinator(&state)?
        .history_write(move |writer| writer.acknowledge(&actor, &input))
        .await
        .map_err(storage_error)?;
    Ok(Json(Episode::from(value)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::{
        alerts::{Kind, Status},
        api::tests::{call, managed_state, request},
    };
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};

    fn authorized(cookie: &str, method: Method, path: &str, value: &str) -> Request {
        let mut value = request(method, path, value);
        value
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        value
            .headers_mut()
            .insert("x-csrf-token", "c".repeat(43).parse().unwrap());
        value
    }

    async fn body(response: Response, status: StatusCode) -> Value {
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.len() <= 128 * 1024);
        serde_json::from_slice(&bytes).unwrap()
    }

    fn observation(node: &str) -> storage::Observation {
        storage::Observation {
            incident_id: u64::MAX,
            kind: Kind::HealthCatalog,
            origin_node_id: node.to_owned(),
            resource_id: None,
            slot: "catalog".into(),
            check: None,
            target: None,
            code: "health_catalog_unavailable".into(),
            first_observed_at_unix_ms: Some(u64::MAX),
            last_observed_at_unix_ms: Some(u64::MAX),
            evidence_sequence: Some(u64::MAX),
        }
    }

    fn random_id() -> String {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).unwrap();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn seed(state: &mut Arc<AppState>) -> (String, storage::Observation) {
        let node = store::inspect(&state.directory).unwrap().node_id;
        Arc::get_mut(state).unwrap().node.node_id = node.clone();
        let boot = random_id();
        let gate = store::update_lock(&state.directory).unwrap();
        storage::start(&state.directory, &gate, &boot).unwrap();
        let value = observation(&node);
        storage::record(
            &state.directory,
            &gate,
            &storage::Batch {
                boot_id: boot.clone(),
                sequence: 1,
                transitions: vec![storage::Transition {
                    kind: storage::TransitionKind::Opened,
                    observation: value.clone(),
                    observed_at_unix_ms: Some(u64::MAX),
                    ended_reason: None,
                }],
            },
        )
        .unwrap();
        (boot, value)
    }

    #[tokio::test]
    async fn history_is_session_only_and_queries_are_strict_and_bodyless_for_head() {
        let (_directory, mut state, cookie) = managed_state();
        seed(&mut state);
        for path in [
            "/api/v1/alert-events",
            "/api/v1/alert-events/1",
            "/api/v1/alert-episodes",
            "/api/v1/alert-episodes/1",
            "/api/v1/alert-summary",
        ] {
            let value = body(
                call(state.clone(), request(Method::GET, path, "")).await,
                StatusCode::FORBIDDEN,
            )
            .await;
            assert_eq!(value["error"]["code"], "authentication_required");
            let mut bearer = request(Method::GET, path, "");
            bearer.headers_mut().insert(
                header::AUTHORIZATION,
                format!(
                    "Bearer vpa1.{}.1.{}",
                    URL_SAFE_NO_PAD.encode([1; 16]),
                    URL_SAFE_NO_PAD.encode([2; 32])
                )
                .parse()
                .unwrap(),
            );
            assert_eq!(
                body(call(state.clone(), bearer).await, StatusCode::FORBIDDEN).await["error"]["code"],
                "automation_route_denied"
            );
            let head = call(state.clone(), authorized(&cookie, Method::HEAD, path, "")).await;
            assert_eq!(head.status(), StatusCode::OK);
            assert!(
                head.into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .is_empty()
            );
        }
        for query in [
            "limit=0",
            "limit=51",
            "limit=01",
            "limit=1&%6cimit=2",
            "before=0",
            "before=9223372036854775808",
            "before=1&before=2",
            "origin_node_id=bad",
            "episode_id=01",
            "episode_id=1&episode_id=2",
            "state=recent",
            "after=opaque",
            "origin_node_id=%FF",
        ] {
            let response = call(
                state.clone(),
                authorized(
                    &cookie,
                    Method::GET,
                    &format!("/api/v1/alert-events?{query}"),
                    "",
                ),
            )
            .await;
            assert_eq!(
                body(response, StatusCode::BAD_REQUEST).await["error"]["code"],
                "invalid_alert_history",
                "{query}"
            );
        }
        for path in [
            "/api/v1/alert-events/01",
            "/api/v1/alert-events/9223372036854775808",
            "/api/v1/alert-events/1?",
            "/api/v1/alert-episodes/1?x=1",
            "/api/v1/alert-summary?",
        ] {
            let head = call(state.clone(), authorized(&cookie, Method::HEAD, path, "")).await;
            assert_eq!(head.status(), StatusCode::BAD_REQUEST, "{path}");
            assert!(
                head.into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .is_empty()
            );
        }
        let missing = body(
            call(
                state.clone(),
                authorized(
                    &cookie,
                    Method::GET,
                    "/api/v1/alert-events/9223372036854775807",
                    "",
                ),
            )
            .await,
            StatusCode::NOT_FOUND,
        )
        .await;
        assert_eq!(missing["error"]["code"], "alert_history_not_queryable");
        let page = body(
            call(
                state,
                authorized(&cookie, Method::GET, "/api/v1/alert-events?limit=1", ""),
            )
            .await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(page["items"][0]["incident_id"], u64::MAX.to_string());
        assert_eq!(page["items"][0]["evidence_sequence"], u64::MAX.to_string());
        assert_eq!(page["trimmed"], "0");
        assert!(page["items"][0].get("slot").is_none());
        assert!(page["items"][0].get("evidence_fresh").is_none());
        assert!(page["items"][0].get("status").is_none());
    }

    #[tokio::test]
    async fn unread_inbox_batch_is_atomic_bounded_and_keeps_later_transitions_unread() {
        let (_directory, mut state, cookie) = managed_state();
        let (boot, mut observation) = seed(&mut state);
        let list = "/api/v1/alert-episodes";
        let path = "/api/v1/alert-episodes/acknowledge";
        let first = body(
            call(state.clone(), authorized(&cookie, Method::GET, list, "")).await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(first["through_sequence"], "1");
        assert_eq!(first["items"][0]["id"], "1");
        assert_eq!(first["items"][0]["is_acknowledged"], false);
        for query in [
            "?before=0",
            "?through=01",
            "?through=1&%74hrough=1",
            "?unknown=1",
        ] {
            assert_eq!(
                call(
                    state.clone(),
                    authorized(&cookie, Method::GET, &format!("{list}{query}"), "")
                )
                .await
                .status(),
                StatusCode::BAD_REQUEST
            );
        }
        let input = json!({"expected_node_id":state.node.node_id,"items":[{"episode_id":"1","expected_transition_sequence":"1"}]}).to_string();
        let mut no_csrf = authorized(&cookie, Method::POST, path, &input);
        no_csrf.headers_mut().remove("x-csrf-token");
        assert_eq!(
            call(state.clone(), no_csrf).await.status(),
            StatusCode::FORBIDDEN
        );
        let partial = json!({"expected_node_id":state.node.node_id,"items":[
            {"episode_id":"1","expected_transition_sequence":"1"},
            {"episode_id":"99","expected_transition_sequence":"99"}
        ]})
        .to_string();
        assert_eq!(
            call(
                state.clone(),
                authorized(&cookie, Method::POST, path, &partial)
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        let after = body(
            call(state.clone(), authorized(&cookie, Method::GET, list, "")).await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(
            after, first,
            "a later missing row must roll back the first acknowledgement"
        );
        for items in [
            json!([]),
            json!([
                {"episode_id":"1","expected_transition_sequence":"1"},
                {"episode_id":"1","expected_transition_sequence":"1"}
            ]),
            json!(vec![
                json!({"episode_id":"1","expected_transition_sequence":"1"});
                33
            ]),
        ] {
            let invalid = json!({"expected_node_id":state.node.node_id,"items":items}).to_string();
            assert_eq!(
                call(
                    state.clone(),
                    authorized(&cookie, Method::POST, path, &invalid)
                )
                .await
                .status(),
                StatusCode::BAD_REQUEST
            );
        }
        for _ in 0..2 {
            let response = body(
                call(
                    state.clone(),
                    authorized(&cookie, Method::POST, path, &input),
                )
                .await,
                StatusCode::OK,
            )
            .await;
            assert_eq!(response["items"][0]["is_acknowledged"], true);
            assert_eq!(response["items"][0]["status"], "active");
            assert_eq!(response["items"][0]["acknowledgement_event_sequence"], "2");
        }
        observation.code = "health_catalog_stale".into();
        {
            let gate = store::update_lock(&state.directory).unwrap();
            storage::record(
                &state.directory,
                &gate,
                &storage::Batch {
                    boot_id: boot,
                    sequence: 2,
                    transitions: vec![storage::Transition {
                        kind: storage::TransitionKind::ReasonChanged,
                        observation,
                        observed_at_unix_ms: None,
                        ended_reason: None,
                    }],
                },
            )
            .unwrap();
        }
        let old = body(
            call(
                state.clone(),
                authorized(&cookie, Method::GET, &format!("{list}?through=1"), ""),
            )
            .await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(old["items"], json!([]));
        let fresh = body(
            call(state.clone(), authorized(&cookie, Method::GET, list, "")).await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(fresh["items"][0]["latest_transition_sequence"], "3");
        assert_eq!(fresh["items"][0]["is_acknowledged"], false);
        assert_eq!(
            call(
                state.clone(),
                authorized(&cookie, Method::POST, path, &input)
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let unchanged = body(
            call(state, authorized(&cookie, Method::GET, list, "")).await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(fresh, unchanged);
    }

    #[tokio::test]
    async fn acknowledgement_is_csrf_bound_cas_idempotent_and_not_recovery() {
        let (_directory, mut state, cookie) = managed_state();
        let (boot, mut value) = seed(&mut state);
        let input =
            json!({"expected_node_id":state.node.node_id,"expected_transition_sequence":"1"})
                .to_string();
        let path = "/api/v1/alert-episodes/1/acknowledge";
        let mut no_csrf = authorized(&cookie, Method::POST, path, &input);
        no_csrf.headers_mut().remove("x-csrf-token");
        assert_eq!(
            body(call(state.clone(), no_csrf).await, StatusCode::FORBIDDEN).await["error"]["code"],
            "invalid_csrf"
        );
        let mut foreign = authorized(&cookie, Method::POST, path, &input);
        foreign
            .headers_mut()
            .insert(header::ORIGIN, "https://foreign.invalid".parse().unwrap());
        assert_eq!(
            call(state.clone(), foreign).await.status(),
            StatusCode::FORBIDDEN
        );
        let wrong =
            json!({"expected_node_id":random_id(),"expected_transition_sequence":"1"}).to_string();
        assert_eq!(
            body(
                call(
                    state.clone(),
                    authorized(&cookie, Method::POST, path, &wrong)
                )
                .await,
                StatusCode::CONFLICT
            )
            .await["error"]["code"],
            "alert_history_conflict"
        );
        for _ in 0..2 {
            let result = body(
                call(
                    state.clone(),
                    authorized(&cookie, Method::POST, path, &input),
                )
                .await,
                StatusCode::OK,
            )
            .await;
            assert_eq!(result["status"], "active");
            assert_eq!(result["code"], "health_catalog_unavailable");
            assert_eq!(result["latest_transition_sequence"], "1");
            assert_eq!(result["acknowledgement_event_sequence"], "2");
            assert_eq!(result["is_acknowledged"], true);
        }
        let summary = body(
            call(
                state.clone(),
                authorized(&cookie, Method::GET, "/api/v1/alert-summary", ""),
            )
            .await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(summary["retained_event_count"], 2);
        assert_eq!(summary["unacknowledged_count"], 0);
        let ack = body(
            call(
                state.clone(),
                authorized(&cookie, Method::GET, "/api/v1/alert-events/2", ""),
            )
            .await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(ack["transition"], "acknowledged");
        assert_eq!(ack["acknowledged_transition_sequence"], "1");
        assert!(ack["end_reason"].is_null());
        value.code = "health_catalog_stale".into();
        {
            let gate = store::update_lock(&state.directory).unwrap();
            storage::record(
                &state.directory,
                &gate,
                &storage::Batch {
                    boot_id: boot,
                    sequence: 2,
                    transitions: vec![storage::Transition {
                        kind: storage::TransitionKind::ReasonChanged,
                        observation: value,
                        observed_at_unix_ms: None,
                        ended_reason: None,
                    }],
                },
            )
            .unwrap();
        }
        // The old acknowledgement remains historical; a stale POST cannot review
        // the new transition, even if the client lost the first response.
        assert_eq!(
            body(
                call(
                    state.clone(),
                    authorized(&cookie, Method::POST, path, &input)
                )
                .await,
                StatusCode::CONFLICT
            )
            .await["error"]["code"],
            "alert_history_conflict"
        );
        let result = body(
            call(
                state.clone(),
                authorized(&cookie, Method::GET, "/api/v1/alert-episodes/1", ""),
            )
            .await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(result["latest_transition_sequence"], "3");
        assert_eq!(result["acknowledged_transition_sequence"], "1");
        assert_eq!(result["is_acknowledged"], false);
        let summary = body(
            call(
                state,
                authorized(&cookie, Method::GET, "/api/v1/alert-summary", ""),
            )
            .await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(summary["retained_event_count"], 3);
        assert_eq!(summary["unacknowledged_count"], 1);
    }

    #[tokio::test]
    async fn a_cached_browser_session_cannot_read_or_ack_after_administrator_removal() {
        let (_directory, mut state, cookie) = managed_state();
        seed(&mut state);
        let input =
            json!({"expected_node_id":state.node.node_id,"expected_transition_sequence":"1"})
                .to_string();
        let database =
            rusqlite::Connection::open(state.directory.join("management.sqlite3")).unwrap();
        let actor: String = database
            .query_row("SELECT id FROM administrators", [], |row| row.get(0))
            .unwrap();
        // An empty administrator table is a damaged database, not withdrawal of
        // one actor. Keep another valid administrator so the same snapshot reaches
        // the removed actor's authorization check rather than the overview guard.
        database.execute("INSERT INTO administrators(id,username,password_hash) SELECT ?1,'remaining-admin',password_hash FROM administrators WHERE id=?2", rusqlite::params![random_id(),actor]).unwrap();
        database
            .execute("DELETE FROM administrators WHERE id=?1", [&actor])
            .unwrap();
        drop(database);
        for (method, path, input) in [
            (Method::GET, "/api/v1/alert-events", ""),
            (Method::GET, "/api/v1/alert-events/1", ""),
            (Method::GET, "/api/v1/alert-episodes/1", ""),
            (Method::GET, "/api/v1/alert-summary", ""),
            (
                Method::POST,
                "/api/v1/alert-episodes/1/acknowledge",
                input.as_str(),
            ),
        ] {
            assert_eq!(
                body(
                    call(state.clone(), authorized(&cookie, method, path, input)).await,
                    StatusCode::FORBIDDEN
                )
                .await["error"]["code"],
                "alert_history_denied"
            );
        }
    }

    #[tokio::test]
    async fn old_schema_does_not_silently_create_persistent_history() {
        let (_directory, mut state, cookie) = managed_state();
        let database =
            rusqlite::Connection::open(state.directory.join("management.sqlite3")).unwrap();
        store::recovery::restore_schema_twenty_for_test(&database).unwrap();
        let catalog = |database: &rusqlite::Connection| -> String {
            database
            .query_row(
                "SELECT group_concat(name,',') FROM (SELECT name FROM sqlite_schema ORDER BY name)",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };
        let before = catalog(&database);
        let overview = store::inspect(&state.directory).unwrap();
        assert_eq!(overview.schema_version, 20);
        let (handle, mut monitor) = crate::manage::alerts::new(
            state.policy.as_ref().unwrap().clone(),
            overview.node_id.clone(),
            None,
            None,
            false,
            false,
            None,
            None,
        )
        .unwrap();
        let mutable = Arc::get_mut(&mut state).unwrap();
        mutable.schema_version = overview.schema_version;
        mutable.node.node_id = overview.node_id;
        mutable.alerts = Some(handle);
        // The same real schema20 database still supports its RAM-only monitor.
        monitor.collect_once().await.unwrap();
        for path in [
            "/api/v1/alert-events",
            "/api/v1/alert-events/1",
            "/api/v1/alert-episodes/1",
            "/api/v1/alert-summary",
        ] {
            assert_eq!(
                body(
                    call(state.clone(), authorized(&cookie, Method::GET, path, "")).await,
                    StatusCode::SERVICE_UNAVAILABLE
                )
                .await["error"]["code"],
                "management_upgrade_required"
            );
        }
        let live = body(
            call(
                state.clone(),
                authorized(&cookie, Method::GET, "/api/v1/alerts", ""),
            )
            .await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(live["collection_error"], false);
        assert!(live["observed_at_unix_ms"].is_string());
        assert_eq!(store::inspect(&state.directory).unwrap().schema_version, 20);
        assert_eq!(catalog(&database), before);
        let count: i64 = database
        .query_row("SELECT count(*) FROM sqlite_schema WHERE name IN ('alert_history_state','alert_episodes','alert_events')", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn worst_case_event_page_fits_only_its_specific_response_budget() {
        let node = URL_SAFE_NO_PAD.encode([255; 16]);
        let source = storage::Observation {
            kind: Kind::EgressCheck,
            resource_id: Some(node.clone()),
            slot: String::new(),
            check: Some(CheckKind::Tcp),
            target: Some(
                "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"
                    .parse()
                    .unwrap(),
            ),
            code: "egress_network_unreachable".into(),
            ..observation(&node)
        };
        let page = Page {
            node_id: node.clone(),
            items: (0..50)
                .map(|_| {
                    Event::from(storage::Event {
                        sequence: i64::MAX as u64,
                        observer_node_id: node.clone(),
                        episode_id: i64::MAX as u64 - 1,
                        boot_id: node.clone(),
                        kind: storage::EventKind::Acknowledged,
                        observation: source.clone(),
                        observed_at_unix_ms: Some(u64::MAX),
                        recorded_at_unix_ms: Some(u64::MAX),
                        ended_reason: None,
                        administrator_id: Some(node.clone()),
                        transition_sequence: i64::MAX as u64 - 1,
                    })
                })
                .collect(),
            next_cursor: Some(i64::MAX.to_string()),
            oldest_sequence: Some("1".into()),
            trimmed: u64::MAX.to_string(),
        };
        let bytes = serde_json::to_vec(&page).unwrap();
        assert!(bytes.len() > 32 * 1024);
        assert!(bytes.len() <= 128 * 1024);
        let episode = Episode::from(storage::Episode {
            id: 1,
            observer_node_id: node.clone(),
            boot_id: node,
            observation: source,
            status: Status::Unmonitored,
            last_transition_sequence: 2,
            ended_at_unix_ms: None,
            ended_reason: Some(storage::EndReason::MonitorRestarted),
            acknowledgement: None,
            is_acknowledged: false,
        });
        assert!(serde_json::to_vec(&episode).unwrap().len() < 32 * 1024);
    }
}
