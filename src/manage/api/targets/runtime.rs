//! Session/CSRF adapter for one transient remote drain and exact GET recovery.

use super::*;
use crate::manage::drain;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/targets/{id}/proxy/runtime", get(status))
        .route("/api/v1/targets/{id}/proxy/runtime/drain", post(start))
        .route(
            "/api/v1/targets/{id}/proxy/runtime/drains/{runtime_id}/{request_id}",
            get(original),
        )
}

async fn status(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    match service(&state)?
        .remote(resource_id(path)?, control::Request::Runtime)
        .await
        .map_err(remote_error)?
    {
        control::Reply::Runtime(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

async fn original(
    State(state): State<Arc<AppState>>,
    path: Result<Path<(String, String, String)>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let Path((peer, runtime_id, request_id)) = path.map_err(|_| invalid())?;
    if ![&peer, &runtime_id, &request_id]
        .into_iter()
        .all(|value| store::valid_id(value))
    {
        return Err(invalid());
    }
    match service(&state)?
        .remote(
            peer,
            control::Request::RuntimeDrainStatus {
                runtime_id,
                request_id,
            },
        )
        .await
        .map_err(remote_error)?
    {
        control::Reply::Runtime(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    expected_target_revision: String,
    request: drain::Request,
}

async fn start(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(request.uri())?;
    let peer = resource_id(path)?;
    let input: Input = json(request).await?;
    input.request.numbers().map_err(|_| invalid())?;
    if input.request.expected_node_id != peer {
        return Err(invalid());
    }
    let target_revision = revision(&input.expected_target_revision)?;
    let location = format!(
        "/api/v1/targets/{peer}/proxy/runtime/drains/{}/{}",
        input.request.runtime_id, input.request.request_id
    );
    let value = service(&state)?
        .drain_runtime(actor, peer, target_revision, input.request)
        .await
        .map_err(runtime_error)?;
    let mut response = (StatusCode::ACCEPTED, Json(value)).into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&location).map_err(|_| ApiError::internal())?,
    );
    Ok(response)
}

fn invalid() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid_request")
}

fn runtime_error(error: io::Error) -> ApiError {
    if error
        .get_ref()
        .is_some_and(|error| error.is::<controller::RuntimeOutcomeUnknown>())
    {
        return ApiError::new(StatusCode::BAD_GATEWAY, "runtime_outcome_unknown");
    }
    if let Some(remote) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<control::RemoteError>())
    {
        if remote.status == 409 {
            return ApiError::new(StatusCode::CONFLICT, remote.code);
        }
        return remote_error(error);
    }
    if error.kind() == io::ErrorKind::AlreadyExists {
        return ApiError::new(StatusCode::CONFLICT, "policy_conflict");
    }
    remote_error(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::api::tests::{call, managed_state, request};
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};

    fn id(value: u8) -> String {
        URL_SAFE_NO_PAD.encode([value; 16])
    }

    #[tokio::test]
    async fn runtime_target_routes_keep_session_csrf_and_exact_nonsecret_input_boundaries() {
        let (_directory, state, cookie) = managed_state();
        let peer = id(1);
        let base = format!("/api/v1/targets/{peer}/proxy/runtime");
        let body = json!({"expected_target_revision":"1","request":{
            "expected_node_id":peer,"expected_epoch":"2","expected_revision":"2",
            "runtime_id":id(2),"request_id":id(3)
        }});
        for path in [&base, &format!("{base}/drains/{}/{}", id(2), id(3))] {
            assert_eq!(
                call(state.clone(), request(Method::GET, path, ""))
                    .await
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        let path = format!("{base}/drain");
        let mut missing_csrf = request(Method::POST, &path, &body.to_string());
        missing_csrf
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(
            call(state.clone(), missing_csrf).await.status(),
            StatusCode::FORBIDDEN
        );
        for input in [
            json!({}),
            json!({"target_revision":"1","request":body["request"]}),
            json!({"expected_target_revision":"1","request":body["request"],"source_administrator_id":id(4)}),
            json!({"expected_target_revision":"1","request":body["request"],"origin":"https://unregistered.example"}),
            json!({"expected_target_revision":"1","request":null}),
        ] {
            assert_eq!(
                invoke(state.clone(), &cookie, Method::POST, &path, input)
                    .await
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        for (pointer, value) in [
            ("/request/expected_node_id", json!(id(9))),
            ("/request/runtime_id", json!("wrong")),
            ("/request/request_id", Value::Null),
            ("/request/expected_epoch", json!("02")),
            ("/request/expected_revision", json!("0")),
            ("/expected_target_revision", json!("0")),
        ] {
            let mut input = body.clone();
            *input.pointer_mut(pointer).unwrap() = value;
            assert_eq!(
                invoke(state.clone(), &cookie, Method::POST, &path, input)
                    .await
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        for path in [
            format!("{base}?origin=ignored"),
            format!("{base}/drains/wrong/{}", id(3)),
            format!("{base}/drains/{}/{}?request_id=other", id(2), id(3)),
        ] {
            assert_eq!(
                invoke(state.clone(), &cookie, Method::GET, &path, Value::Null)
                    .await
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        let (status, value) = invoke(state.clone(), &cookie, Method::POST, &path, body).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(value["error"]["code"], "node_control_unavailable");
        assert!(storage::job(&state.directory, &peer).unwrap().is_none());
        assert_eq!(store::policy_status(&state.directory).unwrap().revision, 1);
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

    #[test]
    fn unknown_runtime_outcome_is_not_relabelled_as_a_definite_permission_or_target_refusal() {
        let error = runtime_error(io::Error::new(
            io::ErrorKind::PermissionDenied,
            controller::RuntimeOutcomeUnknown,
        ));
        assert_eq!(
            (error.status, error.code),
            (StatusCode::BAD_GATEWAY, "runtime_outcome_unknown")
        );
        let error = runtime_error(io::Error::other(control::RemoteError {
            status: 409,
            code: "proxy_runtime_changed",
        }));
        assert_eq!(
            (error.status, error.code),
            (StatusCode::CONFLICT, "proxy_runtime_changed")
        );
        let error = runtime_error(io::Error::other(control::RemoteError {
            status: 404,
            code: "node_protocol_unsupported",
        }));
        assert_eq!(
            (error.status, error.code),
            (StatusCode::BAD_GATEWAY, "node_protocol_unsupported")
        );
    }
}
