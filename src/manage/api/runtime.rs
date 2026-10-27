//! Session/CSRF-only process-local maintenance. Admission pause is a separate
//! durable action; no endpoint waits for or retries a forwarding drain.

use super::*;
use crate::manage::{drain, policy::Coordinator, proxy, store};
use axum::extract::{Path, rejection::PathRejection};

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/proxy/runtime", get(status))
        .route("/api/v1/proxy/runtime/drain", post(start))
        .route(
            "/api/v1/proxy/runtime/drains/{runtime_id}/{request_id}",
            get(original),
        )
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

fn policy(state: &AppState) -> Result<Arc<Coordinator>, ApiError> {
    state.policy.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    })
}

fn no_query(uri: &Uri) -> Result<(), ApiError> {
    if uri.query().is_some() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_query"));
    }
    Ok(())
}

pub(super) fn storage_error(error: io::Error) -> ApiError {
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<drain::Error>())
    {
        return ApiError::new(StatusCode::CONFLICT, error.code());
    }
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<proxy::Error>())
    {
        return ApiError::new(
            StatusCode::CONFLICT,
            match error {
                proxy::Error::RuntimeChanged => "proxy_runtime_changed",
                proxy::Error::AlreadyDraining => "proxy_already_draining",
                proxy::Error::Stopping => "proxy_runtime_stopping",
            },
        );
    }
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<store::admission::Error>())
    {
        return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error.code());
    }
    users::storage_error(error)
}

async fn status(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let value = policy(&state)?
        .runtime_status(actor, None)
        .await
        .map_err(storage_error)?;
    value.validate(&state.node.node_id).map_err(storage_error)?;
    Ok(Json(value).into_response())
}

async fn original(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let Path((runtime_id, request_id)) =
        path.map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_request"))?;
    if !store::valid_id(&runtime_id) || !store::valid_id(&request_id) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_request"));
    }
    let value = policy(&state)?
        .runtime_status(actor, Some((runtime_id, request_id)))
        .await
        .map_err(storage_error)?;
    value.validate(&state.node.node_id).map_err(storage_error)?;
    Ok(Json(value).into_response())
}

async fn start(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(request.uri())?;
    let input: drain::Request = json(request).await?;
    if input.expected_node_id != state.node.node_id {
        return Err(ApiError::new(StatusCode::CONFLICT, "target_mismatch"));
    }
    input.numbers().map_err(storage_error)?;
    let value = policy(&state)?
        .request_drain(actor, input)
        .await
        .map_err(storage_error)?;
    value.validate(&state.node.node_id).map_err(storage_error)?;
    Ok((StatusCode::ACCEPTED, Json(value)).into_response())
}

#[cfg(test)]
mod tests {
    //! These route fixtures exercise real policy/SQL publication and a retained
    //! control handle. Network listener quiescence is covered by protocol/mTLS tests.

    use super::*;
    use crate::{
        manage::api::tests::{TestDirectory, call, managed_state, request},
        server::Handle,
    };
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};

    const PATH: &str = "/api/v1/proxy/runtime";

    fn fixture() -> (
        TestDirectory,
        Arc<AppState>,
        String,
        proxy::Lifecycle,
        Handle,
    ) {
        let (directory, mut state, cookie) = managed_state();
        let node_id = store::inspect(&state.directory).unwrap().node_id;
        Arc::get_mut(&mut state).unwrap().node.node_id = node_id;
        let handle = Handle::new();
        let lifecycle = proxy::Lifecycle::new(handle.clone()).unwrap();
        policy(&state)
            .unwrap()
            .configure_runtime(lifecycle.clone())
            .unwrap();
        (directory, state, cookie, lifecycle, handle)
    }

    async fn invoke(
        state: Arc<AppState>,
        cookie: &str,
        method: Method,
        path: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut input = request(method, path, &body.to_string());
        input
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        input
            .headers_mut()
            .insert("x-csrf-token", "c".repeat(43).parse().unwrap());
        let response = call(state, input).await;
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn input(state: &AppState, lifecycle: &proxy::Lifecycle) -> Value {
        json!({"expected_node_id":state.node.node_id,"expected_epoch":"1","expected_revision":"2",
        "runtime_id":lifecycle.snapshot().unwrap().runtime_id,"request_id":URL_SAFE_NO_PAD.encode([17;16])})
    }

    async fn pause(state: Arc<AppState>, cookie: &str) {
        policy(&state).unwrap().activate().await.unwrap();
        let body = json!({"expected_node_id":state.node.node_id,"expected_epoch":"1","expected_revision":"1","accepting":false});
        let (status, _) = invoke(
            state,
            cookie,
            Method::POST,
            "/api/v1/proxy/maintenance",
            body,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn explicit_drain_requires_applied_pause_and_preserves_exact_original_identity() {
        let (_directory, state, cookie, lifecycle, handle) = fixture();
        let mut body = input(&state, &lifecycle);
        body["expected_revision"] = json!("1");
        let (status, rejected) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("{PATH}/drain"),
            body,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(rejected["error"]["code"], "proxy_admission_not_paused");
        assert!(!handle.is_quiescing());
        pause(state.clone(), &cookie).await;
        let body = input(&state, &lifecycle);
        let (status, accepted) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("{PATH}/drain"),
            body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(accepted["runtime"]["phase"], "draining");
        assert!(handle.is_quiescing());
        assert!(!policy(&state).unwrap().status().await.unwrap().running);
        assert!(accepted.get("runtime_stopped").is_none());
        let original = format!(
            "{PATH}/drains/{}/{}",
            body["runtime_id"].as_str().unwrap(),
            body["request_id"].as_str().unwrap()
        );
        assert_eq!(
            invoke(state.clone(), &cookie, Method::GET, &original, Value::Null)
                .await
                .1["runtime"]["request"],
            body
        );
        // A duplicate acknowledges only the same retained intent. It does not
        // change the durable policy revision or install a new runtime/operation.
        assert_eq!(
            invoke(
                state.clone(),
                &cookie,
                Method::POST,
                &format!("{PATH}/drain"),
                body.clone()
            )
            .await
            .0,
            StatusCode::ACCEPTED
        );
        assert_eq!(
            store::admission::snapshot(&state.directory)
                .unwrap()
                .saved_revision,
            2
        );
        let mut replacement = body.clone();
        replacement["request_id"] = json!(URL_SAFE_NO_PAD.encode([18; 16]));
        assert_eq!(
            invoke(
                state.clone(),
                &cookie,
                Method::POST,
                &format!("{PATH}/drain"),
                replacement
            )
            .await
            .1["error"]["code"],
            "proxy_already_draining"
        );
        let resume = json!({"expected_node_id":state.node.node_id,"expected_epoch":"1","expected_revision":"2","accepting":true});
        let (status, rejected) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            "/api/v1/proxy/maintenance",
            resume,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(rejected["error"]["code"], "proxy_restart_required");
        assert!(
            !store::admission::snapshot(&state.directory)
                .unwrap()
                .accepting
        );
        lifecycle.complete(&Ok(())).unwrap();
        let (_, completed) =
            invoke(state.clone(), &cookie, Method::GET, &original, Value::Null).await;
        assert_eq!(completed["runtime"]["phase"], "drained");
        assert_eq!(completed["runtime"]["request"], body);
        let missing = format!(
            "{PATH}/drains/{}/{}",
            URL_SAFE_NO_PAD.encode([99; 16]),
            body["request_id"].as_str().unwrap()
        );
        assert_eq!(
            invoke(state, &cookie, Method::GET, &missing, Value::Null)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn runtime_csrf_strict_assertions_and_machine_scope_fail_without_transition() {
        let (_directory, state, cookie, lifecycle, handle) = fixture();
        pause(state.clone(), &cookie).await;
        let path = format!("{PATH}/drain");
        let body = input(&state, &lifecycle);
        assert_eq!(
            call(state.clone(), request(Method::GET, PATH, ""))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut no_csrf = request(Method::POST, &path, &body.to_string());
        no_csrf
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(
            call(state.clone(), no_csrf).await.status(),
            StatusCode::FORBIDDEN
        );
        for (field, value, status) in [
            (
                "expected_node_id",
                json!(URL_SAFE_NO_PAD.encode([44; 16])),
                StatusCode::CONFLICT,
            ),
            ("expected_epoch", json!("2"), StatusCode::CONFLICT),
            ("expected_revision", json!("1"), StatusCode::CONFLICT),
            (
                "runtime_id",
                json!(URL_SAFE_NO_PAD.encode([45; 16])),
                StatusCode::CONFLICT,
            ),
            ("request_id", json!(""), StatusCode::BAD_REQUEST),
            ("expected_epoch", json!("01"), StatusCode::BAD_REQUEST),
            (
                "expected_revision",
                json!("9223372036854775808"),
                StatusCode::BAD_REQUEST,
            ),
            ("unknown", json!(true), StatusCode::BAD_REQUEST),
        ] {
            let mut invalid = body.clone();
            invalid[field] = value;
            assert_eq!(
                invoke(state.clone(), &cookie, Method::POST, &path, invalid)
                    .await
                    .0,
                status,
                "field {field}"
            );
        }
        for method in [Method::GET, Method::POST] {
            let endpoint = if method == Method::GET { PATH } else { &path };
            assert_eq!(
                invoke(
                    state.clone(),
                    &cookie,
                    method,
                    &format!("{endpoint}?"),
                    body.clone()
                )
                .await
                .0,
                StatusCode::BAD_REQUEST
            );
        }
        let mut token = Zeroizing::new(String::new());
        store::automation::create(
            &state.directory,
            "Runtime denial",
            store::automation::Scope::UsersWrite,
            3600,
            |value| {
                token.push_str(value);
                Ok(())
            },
        )
        .unwrap();
        for (method, endpoint) in [(Method::GET, PATH), (Method::POST, path.as_str())] {
            let mut input = request(method, endpoint, &body.to_string());
            input
                .headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            input.headers_mut().insert(
                header::AUTHORIZATION,
                format!("Bearer {}", token.as_str()).parse().unwrap(),
            );
            input
                .headers_mut()
                .insert("x-csrf-token", "c".repeat(43).parse().unwrap());
            assert!(!call(state.clone(), input).await.status().is_success());
        }
        assert!(!handle.is_quiescing());
        assert!(lifecycle.snapshot().unwrap().intent.is_none());
        assert_eq!(
            store::admission::snapshot(&state.directory)
                .unwrap()
                .saved_revision,
            2
        );
    }

    #[tokio::test]
    async fn unavailable_publication_or_no_runtime_never_quiesces_or_changes_saved_pause() {
        let (_directory, state, cookie, lifecycle, handle) = fixture();
        pause(state.clone(), &cookie).await;
        policy(&state).unwrap().reader().fail_closed();
        let body = input(&state, &lifecycle);
        let (_, refusal) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("{PATH}/drain"),
            body,
        )
        .await;
        assert_eq!(refusal["error"]["code"], "proxy_policy_unavailable");
        assert!(!handle.is_quiescing());
        let (_other, mut bare, cookie) = managed_state();
        let node_id = store::inspect(&bare.directory).unwrap().node_id;
        Arc::get_mut(&mut bare).unwrap().node.node_id = node_id;
        let (_, observed) = invoke(bare, &cookie, Method::GET, PATH, Value::Null).await;
        assert!(observed["runtime"].is_null());
    }
}
