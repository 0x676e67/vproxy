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
