//! Maintenance keeps the target's existing durable command identity. Reading
//! current runtime facts never acknowledges or replays a lost write.

use super::*;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/targets/{id}/proxy/maintenance", get(status))
        .route("/api/v1/targets/{id}/maintenance/commands", post(command))
        .route(
            "/api/v1/targets/{id}/maintenance/commands/refresh",
            post(refresh),
        )
}

async fn status(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    match service(&state)?
        .remote(resource_id(path)?, control::Request::Maintenance)
        .await
        .map_err(remote_error)?
    {
        control::Reply::Maintenance(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

async fn command(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let peer = resource_id(path)?;
    let input: CommandInput<control::MaintenanceMutation> = json(request).await?;
    submit(&state, actor, peer, input).await
}

/// Read only the original retained maintenance receipt. A replaced per-target
/// slot must be rejected before contacting a different command's receipt.
async fn refresh(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let peer = resource_id(path)?;
    let input: JobInput = json(request).await?;
    if !store::valid_id(&input.job_id) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_request"));
    }
    let job = service(&state)?
        .refresh_maintenance(peer, input.job_id)
        .await
        .map_err(remote_error)?;
    Ok(Json(JobView::from(job)).into_response())
}
