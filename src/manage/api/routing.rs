//! Local finite IP inventory and grants. All changes use the same policy owner,
//! global CAS, commit/publication queue and browser session/CSRF as user changes.
//! Registration never installs addresses/routes or asserts their health.

use super::{
    users::{Administrator, resource_id, revision, storage_error},
    *,
};
use crate::access::routing::{AddressFamily, ResourceState, RoutePermission, RoutingData};
use crate::manage::views::{Address, AddressView, Entity, Page, PermissionView, Pool, Prefix};
use crate::manage::{
    contract,
    store::{self, PolicyChange},
};
use axum::extract::{Path, rejection::PathRejection};

#[derive(utoipa::OpenApi)]
#[openapi(components(schemas(
    PrefixInput,
    AddressInput,
    PoolInput,
    RevisionInput,
    StateInput,
    MemberInput,
    PermissionInput
)))]
pub(super) struct Contract;

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/proxy/prefixes", get(prefixes).post(create_prefix))
        .route("/api/v1/proxy/prefixes/{id}/retire", post(retire_prefix))
        .route(
            "/api/v1/proxy/addresses",
            get(addresses).post(create_address),
        )
        .route("/api/v1/proxy/addresses/{id}", get(address))
        .route("/api/v1/proxy/addresses/{id}/state", post(address_state))
        .route("/api/v1/proxy/pools", get(pools).post(create_pool))
        .route("/api/v1/proxy/pools/{id}/state", post(pool_state))
        .route(
            "/api/v1/proxy/pools/{id}/members",
            get(members).post(add_member),
        )
        .route(
            "/api/v1/proxy/pools/{id}/members/remove",
            post(remove_member),
        )
        .route(
            "/api/v1/proxy/users/{id}/routing",
            get(permission).put(set_permission),
        )
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

fn coordinator(state: &AppState) -> Result<Arc<crate::manage::policy::Coordinator>, ApiError> {
    state.policy.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    })
}

async fn catalog(state: &AppState) -> Result<(u64, RoutingData), ApiError> {
    coordinator(state)?
        .read(store::routing_data)
        .await
        .map_err(storage_error)
}

/// Lists return bounded metadata, not a full pool's potentially large membership.
/// Each page is a consistent snapshot; its global revision is not a multi-page
/// snapshot token. Callers must refresh before a CAS mutation after other writes.
pub(super) fn pagination(uri: &Uri) -> Result<users::Pagination, ApiError> {
    if url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
        .any(|(key, _)| !matches!(key.as_ref(), "after" | "limit"))
    {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_pagination"));
    }
    users::pagination(uri, false)
}

fn page<T>(mut items: Vec<(String, T)>, revision: u64, pagination: users::Pagination) -> Page<T> {
    items.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let mut selected = items
        .into_iter()
        .filter(|(id, _)| pagination.after.as_ref().is_none_or(|after| id > after));
    let mut items = Vec::new();
    let mut last = None;
    for _ in 0..pagination.limit {
        let Some((id, item)) = selected.next() else {
            break;
        };
        last = Some(id);
        items.push(item);
    }
    let next_cursor = if selected.next().is_some() {
        last
    } else {
        None
    };
    Page {
        revision: revision.to_string(),
        items,
        next_cursor,
    }
}

async fn prefixes(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    let pagination = pagination(&uri)?;
    let (revision, data) = catalog(&state).await?;
    Ok(Json(page(
        data.prefixes
            .into_iter()
            .map(|value| (value.id.clone(), Prefix::from(value)))
            .collect(),
        revision,
        pagination,
    ))
    .into_response())
}
async fn addresses(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    let pagination = pagination(&uri)?;
    let (revision, data) = catalog(&state).await?;
    Ok(Json(page(
        data.addresses
            .into_iter()
            .map(|value| (value.id.clone(), Address::from(value)))
            .collect(),
        revision,
        pagination,
    ))
    .into_response())
}
async fn address(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let (revision, data) = catalog(&state).await?;
    let address = data
        .addresses
        .into_iter()
        .find(|value| value.id == id)
        .ok_or_else(missing)?;
    Ok(Json(AddressView {
        revision: revision.to_string(),
        address: address.into(),
    })
    .into_response())
}

async fn pools(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    let pagination = pagination(&uri)?;
    let (revision, data) = catalog(&state).await?;
    Ok(Json(page(
        data.pools
            .into_iter()
            .map(|value| (value.id.clone(), Pool::from(value)))
            .collect(),
        revision,
        pagination,
    ))
    .into_response())
}
async fn members(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let id = resource_id(path)?;
    let pagination = pagination(&uri)?;
    let (revision, data) = catalog(&state).await?;
    let pool = data
        .pools
        .into_iter()
        .find(|pool| pool.id == id)
        .ok_or_else(missing)?;
    Ok(Json(page(
        pool.members
            .into_iter()
            .map(|id| (id.clone(), id))
            .collect(),
        revision,
        pagination,
    ))
    .into_response())
}
async fn permission(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let (revision, data) = catalog(&state).await?;
    let permission = data
        .permissions
        .into_iter()
        .find(|value| value.user_id == id)
        .ok_or_else(missing)?;
    Ok(Json(PermissionView {
        revision: revision.to_string(),
        permission: permission.into(),
    })
    .into_response())
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = RoutingPrefixInput)]
struct PrefixInput {
    #[schema(schema_with = contract::revision)]
    expected_revision: String,
    #[schema(schema_with = contract::name)]
    name: String,
    #[schema(schema_with = contract::routing_cidr)]
    cidr: String,
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = RoutingAddressInput, description = "Missing or null prefix_id means no prefix association; a supplied prefix must exist and contain this IP.")]
struct AddressInput {
    #[schema(schema_with = contract::revision)]
    expected_revision: String,
    #[schema(schema_with = contract::name)]
    name: String,
    #[schema(schema_with = contract::routing_ip)]
    ip: IpAddr,
    #[schema(schema_with = contract::nullable_id)]
    prefix_id: Option<String>,
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = RoutingPoolInput)]
struct PoolInput {
    #[schema(schema_with = contract::revision)]
    expected_revision: String,
    #[schema(schema_with = contract::name)]
    name: String,
    #[schema(schema_with = contract::address_family)]
    family: AddressFamily,
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = RoutingRevisionInput)]
struct RevisionInput {
    #[schema(schema_with = contract::revision)]
    expected_revision: String,
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = RoutingStateInput)]
struct StateInput {
    #[schema(schema_with = contract::revision)]
    expected_revision: String,
    #[schema(schema_with = contract::resource_state)]
    state: ResourceState,
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = RoutingMemberInput)]
struct MemberInput {
    #[schema(schema_with = contract::revision)]
    expected_revision: String,
    #[schema(schema_with = contract::id)]
    address_id: String,
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = RoutingPermissionInput)]
struct PermissionInput {
    #[schema(schema_with = contract::revision)]
    expected_revision: String,
    legacy_allowed: bool,
    #[schema(schema_with = contract::route_ids)]
    exits: Vec<String>,
    #[schema(schema_with = contract::route_ids)]
    pools: Vec<String>,
}

async fn create_prefix(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    request: Request,
) -> Result<Response, ApiError> {
    let input: PrefixInput = json(request).await?;
    let cidr: cidr::IpCidr = input.cidr.parse().map_err(|_| bad())?;
    // Display omits a host's /32 or /128. Accept the explicit mask as input,
    // while keeping the existing stored and response spelling unchanged.
    if cidr.to_string() != input.cidr && format!("{cidr:#}") != input.cidr {
        return Err(bad());
    }
    mutate(
        &state,
        actor,
        input.expected_revision,
        PolicyChange::CreatePrefix {
            name: input.name,
            cidr,
        },
        StatusCode::CREATED,
    )
    .await
}
async fn retire_prefix(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let id = resource_id(path)?;
    let input: RevisionInput = json(request).await?;
    mutate(
        &state,
        actor,
        input.expected_revision,
        PolicyChange::RetirePrefix { id },
        StatusCode::OK,
    )
    .await
}
async fn create_address(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    request: Request,
) -> Result<Response, ApiError> {
    let input: AddressInput = json(request).await?;
    mutate(
        &state,
        actor,
        input.expected_revision,
        PolicyChange::CreateAddress {
            name: input.name,
            ip: input.ip,
            prefix_id: input.prefix_id,
        },
        StatusCode::CREATED,
    )
    .await
}
async fn address_state(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let id = resource_id(path)?;
    let input: StateInput = json(request).await?;
    mutate(
        &state,
        actor,
        input.expected_revision,
        PolicyChange::SetAddressState {
            id,
            state: input.state,
        },
        StatusCode::OK,
    )
    .await
}
async fn create_pool(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    request: Request,
) -> Result<Response, ApiError> {
    let input: PoolInput = json(request).await?;
    mutate(
        &state,
        actor,
        input.expected_revision,
        PolicyChange::CreatePool {
            name: input.name,
            family: input.family,
        },
        StatusCode::CREATED,
    )
    .await
}
async fn pool_state(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let id = resource_id(path)?;
    let input: StateInput = json(request).await?;
    mutate(
        &state,
        actor,
        input.expected_revision,
        PolicyChange::SetPoolState {
            id,
            state: input.state,
        },
        StatusCode::OK,
    )
    .await
}
async fn add_member(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let pool_id = resource_id(path)?;
    let input: MemberInput = json(request).await?;
    mutate(
        &state,
        actor,
        input.expected_revision,
        PolicyChange::AddPoolMember {
            pool_id,
            address_id: input.address_id,
        },
        StatusCode::OK,
    )
    .await
}
async fn remove_member(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let pool_id = resource_id(path)?;
    let input: MemberInput = json(request).await?;
    mutate(
        &state,
        actor,
        input.expected_revision,
        PolicyChange::RemovePoolMember {
            pool_id,
            address_id: input.address_id,
        },
        StatusCode::OK,
    )
    .await
}
async fn set_permission(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let user_id = resource_id(path)?;
    let input: PermissionInput = json(request).await?;
    mutate(
        &state,
        actor,
        input.expected_revision,
        PolicyChange::SetRoutePermission(RoutePermission {
            user_id,
            legacy_allowed: input.legacy_allowed,
            exits: input.exits,
            pools: input.pools,
        }),
        StatusCode::OK,
    )
    .await
}

async fn mutate(
    state: &AppState,
    actor: String,
    expected: String,
    change: PolicyChange,
    status: StatusCode,
) -> Result<Response, ApiError> {
    let result = coordinator(state)?
        .change(actor, revision(&expected)?, change)
        .await
        .map_err(storage_error)?;
    let entity = result
        .routing
        .ok_or_else(|| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable"))?;
    #[derive(Serialize)]
    struct Change {
        revision: String,
        entity: Entity,
    }
    Ok((
        status,
        Json(Change {
            revision: result.revision.to_string(),
            entity: entity.into(),
        }),
    )
        .into_response())
}
fn bad() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid_policy")
}
fn missing() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "resource_not_found")
}
fn no_query(uri: &Uri) -> Result<(), ApiError> {
    if uri.query().is_some() {
        Err(bad())
    } else {
        Ok(())
    }
}
