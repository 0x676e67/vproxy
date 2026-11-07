//! Browser adapter for locally configured mTLS targets and their durable jobs.
//! Session and CSRF identity are shared with local policy administration; a
//! remote actor, endpoint or certificate cannot be supplied in command JSON.

mod alerts;
mod history;
mod maintenance;
mod presets;
mod routing;
mod runtime;
mod secrets;

use axum::extract::{Path, rejection::PathRejection};

use super::users::{
    Administrator, pagination, resource_id, revision, storage_error as policy_error,
};
use super::*;
use crate::manage::views::{JobInput, RevisionInput, StateInput};
use crate::manage::{
    contract, controller,
    node::control,
    policy::Coordinator,
    store::{self, targets as storage},
};

#[derive(utoipa::OpenApi)]
#[openapi(components(schemas(TargetView, Page, RegisterInput, ConfigureInput)))]
pub(super) struct Contract;

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/targets", get(list).post(register))
        .route("/api/v1/targets/{id}", get(target).put(configure))
        .route("/api/v1/targets/{id}/state", post(set_state))
        .route("/api/v1/targets/{id}/retire", post(retire))
        .route("/api/v1/targets/{id}/policy", get(policy))
        .route("/api/v1/targets/{id}/users", get(users))
        .route("/api/v1/targets/{id}/users/search", get(search_users))
        .route("/api/v1/targets/{id}/credentials", get(credentials))
        .route("/api/v1/targets/{id}/commands", post(command))
        .route("/api/v1/targets/{id}/command", get(job))
        .route("/api/v1/targets/{id}/command/retry", post(retry))
        .route("/api/v1/targets/{id}/command/supersede", post(supersede))
        .route("/api/v1/targets/{id}/command/refresh", post(refresh))
        .route(
            "/api/v1/targets/{id}/command/user-result",
            post(user_result),
        )
        .merge(routing::routes())
        .merge(presets::routes())
        .merge(alerts::routes())
        .merge(history::routes())
        .merge(maintenance::routes())
        .merge(runtime::routes())
        .merge(secrets::routes())
        .route_layer(middleware::from_fn_with_state(
            state,
            super::users::authenticated,
        ))
}

fn coordinator(state: &AppState) -> Result<Arc<Coordinator>, ApiError> {
    state.policy.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    })
}
fn storage_error(error: io::Error) -> ApiError {
    if error.kind() == io::ErrorKind::Unsupported {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    } else {
        policy_error(error)
    }
}
pub(super) fn service(state: &AppState) -> Result<Arc<controller::Service>, ApiError> {
    if state.schema_version < 10 {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        ));
    }
    state
        .controller
        .clone()
        .ok_or_else(|| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "node_control_unavailable"))
}
fn no_query(uri: &Uri) -> Result<(), ApiError> {
    if uri.query().is_some() {
        Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_query"))
    } else {
        Ok(())
    }
}

/// Observation values are historical rollback floors, not current health.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = Target, description = "Controller-local registration. Observed values are historical rollback floors, never live remote status.")]
struct TargetView {
    #[schema(schema_with = contract::id)]
    node_id: String,
    #[schema(schema_with = contract::name)]
    name: String,
    #[schema(schema_with = contract::target_origin)]
    origin: String,
    #[schema(schema_with = contract::target_server_ip, required)]
    server_ip: Option<std::net::IpAddr>,
    active: bool,
    retired: bool,
    #[schema(schema_with = contract::revision)]
    revision: String,
    #[schema(schema_with = contract::nullable_revision, required)]
    observed_epoch: Option<String>,
    #[schema(schema_with = contract::nullable_sequence, required)]
    observed_command: Option<String>,
    #[schema(schema_with = contract::nullable_revision, required)]
    observed_policy_revision: Option<String>,
    rollback_detected: bool,
}
impl From<storage::Target> for TargetView {
    fn from(value: storage::Target) -> Self {
        Self {
            node_id: value.peer_id,
            name: value.name,
            origin: value.origin,
            server_ip: value.server_ip,
            active: value.active,
            retired: value.retired,
            revision: value.revision.to_string(),
            observed_epoch: value.observed_epoch.map(|v| v.to_string()),
            observed_command: value.observed_command.map(|v| v.to_string()),
            observed_policy_revision: value.observed_policy_revision.map(|v| v.to_string()),
            rollback_detected: value.rollback_detected,
        }
    }
}
#[derive(Serialize)]
pub(super) struct JobView {
    node_id: String,
    job_id: String,
    controller_epoch: String,
    command_id: String,
    expected_policy_revision: Option<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    metadata: Option<MetadataJobView>,
    state: &'static str,
    policy_revision: Option<String>,
    outcome_code: Option<String>,
    attempts: u32,
    next_attempt: String,
    /// The retained intent creates a user; this does not promise receipt retention.
    user_creation: bool,
    /// Durable non-secret ID survives loss of a v2 command's first response.
    #[serde(skip_serializing_if = "Option::is_none")]
    routing: Option<store::RoutingReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preset: Option<store::PresetReceipt>,
    /// Present only for a retained typed version-five maintenance intent.
    #[serde(skip_serializing_if = "Option::is_none")]
    maintenance: Option<crate::manage::maintenance::Intent>,
}
#[derive(Serialize)]
struct MetadataJobView {
    resource: &'static str,
    expected_metadata_revision: String,
    metadata_revision: Option<String>,
    endpoint: store::endpoint_control::Reference,
}
impl From<storage::Job> for JobView {
    fn from(value: storage::Job) -> Self {
        Self {
            node_id: value.peer_id,
            job_id: value.job_id,
            controller_epoch: value.epoch.to_string(),
            command_id: value.command_id.to_string(),
            expected_policy_revision: value.expected_policy_revision.map(|n| n.to_string()),
            metadata: value.expected_metadata_revision.zip(value.endpoint).map(
                |(expected, endpoint)| MetadataJobView {
                    resource: "proxy_endpoints",
                    expected_metadata_revision: expected.to_string(),
                    metadata_revision: value.metadata_revision.map(|n| n.to_string()),
                    endpoint,
                },
            ),
            state: value.state.as_str(),
            policy_revision: value.policy_revision.map(|v| v.to_string()),
            outcome_code: value.outcome_code,
            attempts: value.attempts,
            next_attempt: value.next_attempt.to_string(),
            user_creation: value.user_creation,
            routing: value.routing,
            preset: value.preset,
            maintenance: value
                .maintenance
                .map(|accepting| crate::manage::maintenance::Intent { accepting }),
        }
    }
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = TargetPage)]
struct Page {
    #[schema(max_items = 25)]
    items: Vec<TargetView>,
    #[schema(schema_with = contract::nullable_id, required)]
    next_cursor: Option<String>,
    controller_available: bool,
}

async fn list(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    let mut after = None;
    let mut limit = 25;
    let mut include_retired = false;
    let mut query = None;
    let mut seen = [false; 4];
    let invalid = || ApiError::new(StatusCode::BAD_REQUEST, "invalid_pagination");
    if uri.query().is_some_and(|q| q.len() > 1024) {
        return Err(invalid());
    }
    for pair in uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = super::super::user_search::decode_component(key).map_err(|_| invalid())?;
        let value = super::super::user_search::decode_component(value).map_err(|_| invalid())?;
        let index = match key.as_str() {
            "after" => 0,
            "limit" => 1,
            "include_retired" => 2,
            "q" => 3,
            _ => return Err(invalid()),
        };
        if seen[index] {
            return Err(invalid());
        }
        seen[index] = true;
        match index {
            0 => {
                let mut bytes = [0; 16];
                if value.len() != 22
                    || !matches!(
                        URL_SAFE_NO_PAD.decode_slice(value.as_bytes(), &mut bytes),
                        Ok(16)
                    )
                {
                    return Err(invalid());
                }
                after = Some(value);
            }
            1 => {
                limit = revision(&value)
                    .map_err(|_| invalid())?
                    .try_into()
                    .ok()
                    .filter(|v| (1..=25).contains(v))
                    .ok_or_else(invalid)?;
            }
            2 => {
                include_retired = match value.as_str() {
                    "true" => true,
                    "false" => false,
                    _ => return Err(invalid()),
                };
            }
            3 => {
                query = Some(
                    storage::query_filter(&value)
                        .map_err(|_| invalid())?
                        .to_owned(),
                )
            }
            _ => return Err(invalid()),
        }
    }
    let page = coordinator(&state)?
        .read(move |dir| {
            storage::list_filtered(
                dir,
                after.as_deref(),
                limit,
                include_retired,
                query.as_deref(),
            )
        })
        .await
        .map_err(storage_error)?;
    Ok(Json(Page {
        items: page.items.into_iter().map(TargetView::from).collect(),
        next_cursor: page.next_cursor,
        controller_available: state.controller.is_some(),
    })
    .into_response())
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = TargetRegisterInput, description = "New enrollment is not performed here. Omitted server_ip stores null for a new registration; null explicitly clears the display metadata.")]
struct RegisterInput {
    #[schema(schema_with = contract::id)]
    node_id: String,
    #[schema(schema_with = contract::target_origin)]
    origin: String,
    active: bool,
    #[serde(default, deserialize_with = "server_ip_update")]
    #[schema(schema_with = contract::target_server_ip, required = false)]
    server_ip: Option<Option<std::net::IpAddr>>,
}

/// Presence is distinct from null so older clients preserve display metadata.
/// Validation is deliberately unrelated to origin, TLS and node authorization.
fn server_ip_update<'de, D>(deserializer: D) -> Result<Option<Option<std::net::IpAddr>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|value| {
            storage::parse_server_ip(&value)
                .map_err(|_| serde::de::Error::custom("invalid server IP"))
        })
        .transpose()
        .map(Some)
}
async fn register(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let input: RegisterInput = json(request).await?;
    let target = coordinator(&state)?
        .targets_write(move |dir| {
            crate::manage::store::targets::configure(
                dir,
                &actor,
                &input.node_id,
                None,
                &input.origin,
                input.active,
                input.server_ip,
            )
        })
        .await
        .map_err(storage_error)?;
    Ok((StatusCode::CREATED, Json(TargetView::from(target))).into_response())
}
async fn target(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let target = coordinator(&state)?
        .read(move |dir| storage::get(dir, &id))
        .await
        .map_err(storage_error)?;
    Ok(Json(TargetView::from(target)).into_response())
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = TargetConfigureInput, description = "Omitting server_ip preserves the saved display value; null clears it. Target revision CAS is separate from remote policy CAS.")]
struct ConfigureInput {
    #[schema(schema_with = contract::revision)]
    expected_revision: String,
    #[schema(schema_with = contract::target_origin)]
    origin: String,
    active: bool,
    #[serde(default, deserialize_with = "server_ip_update")]
    #[schema(schema_with = contract::target_server_ip, required = false)]
    server_ip: Option<Option<std::net::IpAddr>>,
}
async fn configure(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let input: ConfigureInput = json(request).await?;
    let expected = revision(&input.expected_revision)?;
    let target = coordinator(&state)?
        .targets_write(move |dir| {
            crate::manage::store::targets::configure(
                dir,
                &actor,
                &id,
                Some(expected),
                &input.origin,
                input.active,
                input.server_ip,
            )
        })
        .await
        .map_err(storage_error)?;
    Ok(Json(TargetView::from(target)).into_response())
}
async fn set_state(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let input: StateInput = json(request).await?;
    let expected = revision(&input.expected_revision)?;
    let target = coordinator(&state)?
        .targets_write(move |dir| {
            crate::manage::store::targets::set_state(
                dir,
                &actor,
                &id,
                expected,
                input.active,
                false,
            )
        })
        .await
        .map_err(storage_error)?;
    Ok(Json(TargetView::from(target)).into_response())
}
async fn retire(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let input: RevisionInput = json(request).await?;
    let expected = revision(&input.expected_revision)?;
    let target = coordinator(&state)?
        .targets_write(move |dir| {
            crate::manage::store::targets::set_state(dir, &actor, &id, expected, false, true)
        })
        .await
        .map_err(storage_error)?;
    Ok(Json(TargetView::from(target)).into_response())
}
async fn policy(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    match service(&state)?
        .remote(resource_id(path)?, control::Request::Policy)
        .await
        .map_err(remote_error)?
    {
        control::Reply::Policy(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}
async fn users(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let page = pagination(&uri, false)?;
    match service(&state)?
        .remote(
            resource_id(path)?,
            control::Request::UsersPage {
                after: page.after,
                limit: page.limit,
                include_deleted: page.include_deleted,
            },
        )
        .await
        .map_err(remote_error)?
    {
        control::Reply::UsersPage(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}
async fn search_users(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let query = crate::manage::user_search::Query::parse(uri.query())
        .map_err(control::search::storage_error)?;
    match service(&state)?
        .remote(resource_id(path)?, control::Request::UsersSearch(query))
        .await
        .map_err(search_error)?
    {
        control::Reply::UsersSearch(page) => Ok(Json(page).into_response()),
        _ => Err(ApiError::internal()),
    }
}

/// Only this additive search route can negotiate its absence. A peer's login
/// rejection never invalidates the browser session or selects another node.
fn search_error(error: io::Error) -> ApiError {
    if let Some(remote) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<control::RemoteError>())
    {
        match (remote.status, remote.code) {
            (404, "node_protocol_unsupported") => {
                return ApiError::new(StatusCode::BAD_GATEWAY, "user_search_unsupported");
            }
            (409, "user_search_changed") => {
                return ApiError::new(StatusCode::CONFLICT, "user_search_changed");
            }
            (400, "invalid_user_search" | "invalid_user_search_cursor") => {
                return ApiError::new(StatusCode::BAD_REQUEST, remote.code);
            }
            _ => {}
        }
    }
    remote_error(error)
}

async fn credentials(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let page = pagination(&uri, true)?;
    match service(&state)?
        .remote(
            resource_id(path)?,
            control::Request::CredentialsPage {
                after: page.after,
                limit: page.limit,
                user_id: page.user_id,
            },
        )
        .await
        .map_err(remote_error)?
    {
        control::Reply::CredentialsPage(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandInput<M = control::Mutation> {
    expected_target_revision: String,
    controller_epoch: String,
    command_id: String,
    expected_policy_revision: String,
    mutation: M,
}
#[derive(Serialize)]
struct Submission {
    job: JobView,
    response: Option<control::CommandReply>,
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
    let input: CommandInput = json(request).await?;
    submit(&state, actor, id, input).await
}

/// Both allowlisted vocabularies share one durable per-peer queue and policy
/// CAS. The endpoint-specific DTO is parsed before any intent can be stored.
async fn submit<M: Into<store::PolicyChange>>(
    state: &Arc<AppState>,
    actor: String,
    id: String,
    input: CommandInput<M>,
) -> Result<Response, ApiError> {
    let submitted = service(state)?
        .submit(
            actor.clone(),
            revision(&input.expected_target_revision)?,
            store::Command {
                target_node_id: id,
                epoch: revision(&input.controller_epoch)?,
                command_id: revision(&input.command_id)?,
                expected_policy_revision: revision(&input.expected_policy_revision)?,
                source_administrator_id: actor,
                change: input.mutation.into(),
            },
        )
        .await
        .map_err(storage_error)?;
    // A deadline/cancelled first answer never becomes an automatic new command.
    // The durable ticket remains queryable; its receipt cannot recover secrets.
    let response = match timeout(Duration::from_secs(7), submitted.response).await {
        Ok(Ok(Ok(control::DeliveryReply::Policy(response)))) => Some(*response),
        _ => None,
    };
    let status = if response.is_some() {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    let location = format!("/api/v1/targets/{}/command", submitted.job.peer_id);
    let peer = submitted.job.peer_id.clone();
    let current = coordinator(state)?
        .read(move |dir| storage::job(dir, &peer))
        .await
        .ok()
        .flatten();
    let mut response = (
        status,
        Json(Submission {
            job: matching_ticket(submitted.job, current).into(),
            response,
        }),
    )
        .into_response();
    if status == StatusCode::ACCEPTED {
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&location).map_err(|_| ApiError::internal())?,
        );
    }
    Ok(response)
}

/// A later command may replace the per-peer row before this response is built.
/// Keep our historical ticket rather than attaching its secret to another job.
fn matching_ticket(submitted: storage::Job, current: Option<storage::Job>) -> storage::Job {
    current
        .filter(|current| current.job_id == submitted.job_id)
        .unwrap_or(submitted)
}
async fn job(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let job = coordinator(&state)?
        .read(move |dir| storage::job(dir, &id))
        .await
        .map_err(storage_error)?;
    Ok(Json(job.map(JobView::from)).into_response())
}

/// Non-secret receipt metadata for one explicitly selected retained command.
#[derive(Serialize)]
struct UserResultView {
    job: JobView,
    user_id: String,
}

/// Refreshes only the selected creation receipt. A lost one-time credential is
/// never recreated, and an expired receipt does not imply the command failed.
async fn user_result(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let input: JobInput = json(request).await?;
    if !store::valid_id(&input.job_id) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_request"));
    }
    let result = service(&state)?
        .user_result(id, input.job_id)
        .await
        .map_err(|error| match error.kind() {
            io::ErrorKind::AlreadyExists => ApiError::new(StatusCode::CONFLICT, "policy_conflict"),
            io::ErrorKind::InvalidInput => {
                ApiError::new(StatusCode::BAD_REQUEST, "invalid_request")
            }
            _ => remote_error(error),
        })?;
    Ok(Json(UserResultView {
        job: result.job.into(),
        user_id: result.user_id,
    })
    .into_response())
}
async fn retry(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let input: JobInput = json(request).await?;
    let job = coordinator(&state)?
        .targets_write(move |dir| {
            crate::manage::store::targets::retry(dir, &actor, &id, &input.job_id)
        })
        .await
        .map_err(storage_error)?;
    Ok(Json(JobView::from(job)).into_response())
}
async fn supersede(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let input: JobInput = json(request).await?;
    let job = coordinator(&state)?
        .targets_write(move |dir| {
            crate::manage::store::targets::supersede(dir, &actor, &id, &input.job_id)
        })
        .await
        .map_err(storage_error)?;
    Ok(Json(JobView::from(job)).into_response())
}
async fn refresh(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let _: EmptyInput = json(request).await?;
    let job = service(&state)?
        .refresh(resource_id(path)?)
        .await
        .map_err(remote_error)?;
    Ok(Json(JobView::from(job)).into_response())
}
pub(super) fn remote_error(error: io::Error) -> ApiError {
    if let Some(remote) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<control::RemoteError>())
    {
        // Remote status is diagnostic, not this browser's login state.
        return ApiError::new(StatusCode::BAD_GATEWAY, remote.code);
    }
    match error.kind() {
        io::ErrorKind::TimedOut => ApiError::new(StatusCode::GATEWAY_TIMEOUT, "node_timeout"),
        io::ErrorKind::WouldBlock => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "node_busy"),
        io::ErrorKind::PermissionDenied => {
            ApiError::new(StatusCode::FORBIDDEN, "node_control_denied")
        }
        io::ErrorKind::NotFound => ApiError::new(StatusCode::NOT_FOUND, "resource_not_found"),
        _ => ApiError::new(StatusCode::BAD_GATEWAY, "node_unavailable"),
    }
}
