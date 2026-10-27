//! Browser access to the fixed v2 inventory vocabulary. A path selects only a
//! locally enrolled target; it never supplies an outbound origin or probe URL.
//! Reads use the controller's same per-peer claim and total network budget.

use super::*;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/targets/{id}/proxy/prefixes", get(prefixes))
        .route("/api/v1/targets/{id}/proxy/addresses", get(addresses))
        .route(
            "/api/v1/targets/{id}/proxy/addresses/{resource}",
            get(address),
        )
        .route("/api/v1/targets/{id}/proxy/pools", get(pools))
        .route(
            "/api/v1/targets/{id}/proxy/pools/{resource}/members",
            get(members),
        )
        .route(
            "/api/v1/targets/{id}/proxy/users/{resource}/routing",
            get(permission),
        )
        .route("/api/v1/targets/{id}/proxy/health", get(health))
        .route("/api/v1/targets/{id}/routing/commands", post(command))
}

async fn prefixes(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let page = crate::manage::api::routing::pagination(&uri)?;
    let peer = resource_id(path)?;
    match service(&state)?
        .remote(
            peer,
            control::Request::PrefixesPage {
                after: page.after,
                limit: page.limit,
            },
        )
        .await
        .map_err(remote_error)?
    {
        control::Reply::PrefixesPage(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

async fn addresses(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let page = crate::manage::api::routing::pagination(&uri)?;
    let peer = resource_id(path)?;
    match service(&state)?
        .remote(
            peer,
            control::Request::AddressesPage {
                after: page.after,
                limit: page.limit,
            },
        )
        .await
        .map_err(remote_error)?
    {
        control::Reply::AddressesPage(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

async fn address(
    State(state): State<Arc<AppState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let (peer, address_id) = resource_pair(path)?;
    match service(&state)?
        .remote(peer, control::Request::Address { address_id })
        .await
        .map_err(address_error)?
    {
        control::Reply::Address(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

pub(super) fn address_error(error: io::Error) -> ApiError {
    if let Some(remote) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<control::RemoteError>())
    {
        match (remote.status, remote.code) {
            (404, "node_protocol_unsupported") => {
                return ApiError::new(StatusCode::BAD_GATEWAY, "address_lookup_unsupported");
            }
            (404, "resource_not_found") => {
                return ApiError::new(StatusCode::NOT_FOUND, "resource_not_found");
            }
            _ => {}
        }
    }
    remote_error(error)
}

async fn pools(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let page = crate::manage::api::routing::pagination(&uri)?;
    let peer = resource_id(path)?;
    match service(&state)?
        .remote(
            peer,
            control::Request::PoolsPage {
                after: page.after,
                limit: page.limit,
            },
        )
        .await
        .map_err(remote_error)?
    {
        control::Reply::PoolsPage(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

/// Decode both identities with the same canonical-ID guard as single paths;
/// neither percent-decoded component can introduce an arbitrary request path.
pub(super) fn resource_pair(
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<(String, String), ApiError> {
    let Path((peer, resource)) =
        path.map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_resource_id"))?;
    Ok((
        resource_id(Ok(Path(peer)))?,
        resource_id(Ok(Path(resource)))?,
    ))
}

async fn members(
    State(state): State<Arc<AppState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let page = crate::manage::api::routing::pagination(&uri)?;
    let (peer, pool_id) = resource_pair(path)?;
    match service(&state)?
        .remote(
            peer,
            control::Request::PoolMembersPage {
                pool_id,
                after: page.after,
                limit: page.limit,
            },
        )
        .await
        .map_err(remote_error)?
    {
        control::Reply::PoolMembersPage(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

async fn permission(
    State(state): State<Arc<AppState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let (peer, user_id) = resource_pair(path)?;
    match service(&state)?
        .remote(peer, control::Request::UserRouting { user_id })
        .await
        .map_err(remote_error)?
    {
        control::Reply::UserRouting(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

async fn health(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let mut page = crate::manage::api::routing::pagination(&uri)?;
    if !url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
        .any(|(key, _)| key == "limit")
    {
        page.limit = 10;
    }
    if page.limit > 16 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_pagination"));
    }
    let peer = resource_id(path)?;
    match service(&state)?
        .remote(
            peer,
            control::Request::HealthPage {
                after: page.after,
                limit: page.limit,
            },
        )
        .await
        .map_err(remote_error)?
    {
        control::Reply::HealthPage(value) => Ok(Json(value).into_response()),
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
    let id = resource_id(path)?;
    // A separate enum keeps the old eight-action endpoint closed: a v1
    // request cannot accidentally gain new authority after a software upgrade.
    let input: CommandInput<control::RoutingMutation> = json(request).await?;
    submit(&state, actor, id, input).await
}
