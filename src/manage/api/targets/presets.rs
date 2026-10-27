//! Fixed v3 preset operations reuse the existing peer queue and authorization.
//! The browser supplies no origin, certificate, device template or kernel code.

use super::*;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/targets/{id}/proxy/presets", get(catalog))
        .route(
            "/api/v1/targets/{id}/proxy/users/{resource}/presets",
            get(user),
        )
        .route(
            "/api/v1/targets/{id}/proxy/pools/{resource}/presets",
            get(pool),
        )
        .route("/api/v1/targets/{id}/preset/commands", post(command))
}

async fn catalog(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    match service(&state)?
        .remote(id, control::Request::PresetCatalog)
        .await
        .map_err(remote_error)?
    {
        control::Reply::PresetCatalog(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

async fn user(
    State(state): State<Arc<AppState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let (peer, user_id) = routing::resource_pair(path)?;
    match service(&state)?
        .remote(peer, control::Request::UserPresets { user_id })
        .await
        .map_err(remote_error)?
    {
        control::Reply::UserPresets(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

async fn pool(
    State(state): State<Arc<AppState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let (peer, pool_id) = routing::resource_pair(path)?;
    match service(&state)?
        .remote(peer, control::Request::PoolPreset { pool_id })
        .await
        .map_err(remote_error)?
    {
        control::Reply::PoolPreset(value) => Ok(Json(value).into_response()),
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
    let input: CommandInput<control::PresetMutation> = json(request).await?;
    submit(&state, actor, peer, input).await
}
