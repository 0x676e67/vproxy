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
