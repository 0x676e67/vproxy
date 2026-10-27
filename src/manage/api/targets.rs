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
use crate::manage::{
    controller,
    node::control,
    policy::Coordinator,
    store::{self, targets as storage},
};

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
#[derive(Serialize)]
struct TargetView {
    node_id: String,
    name: String,
    origin: String,
    server_ip: Option<std::net::IpAddr>,
    active: bool,
    retired: bool,
    revision: String,
    observed_epoch: Option<String>,
    observed_command: Option<String>,
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

#[derive(Serialize)]
struct Page {
    items: Vec<TargetView>,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterInput {
    node_id: String,
    origin: String,
    active: bool,
    #[serde(default, deserialize_with = "server_ip_update")]
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
        .targets_write(move |writer| {
            writer.configure(
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigureInput {
    expected_revision: String,
    origin: String,
    active: bool,
    #[serde(default, deserialize_with = "server_ip_update")]
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
        .targets_write(move |writer| {
            writer.configure(
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateInput {
    expected_revision: String,
    active: bool,
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
        .targets_write(move |writer| writer.set_state(&actor, &id, expected, input.active, false))
        .await
        .map_err(storage_error)?;
    Ok(Json(TargetView::from(target)).into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionInput {
    expected_revision: String,
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
        .targets_write(move |writer| writer.set_state(&actor, &id, expected, false, true))
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobInput {
    job_id: String,
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
        .targets_write(move |writer| writer.retry(&actor, &id, &input.job_id))
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
        .targets_write(move |writer| writer.supersede(&actor, &id, &input.job_id))
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

#[cfg(test)]
mod tests {
    use super::*;

    mod address_lookup {
        //! Session adapter through the real registered-target service and node mTLS.

        use super::*;
        use crate::{
            access::routing::ResourceState,
            manage::{node, policy::Coordinator},
        };
        use futures_util::FutureExt as _;
        use std::panic::{AssertUnwindSafe, resume_unwind};
        use std::time::{Duration, Instant};
        use tokio::{net::TcpListener, time::timeout};
        use tokio_util::sync::CancellationToken;

        fn administrator(directory: &std::path::Path) -> io::Result<String> {
            rusqlite::Connection::open(directory.join("management.sqlite3"))
                .map_err(io::Error::other)?
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)
        }

        #[test]
        fn address_lookup_errors_distinguish_missing_from_unsupported_without_changing_old_routes()
        {
            for (status, code, expected_status, expected_code) in [
                (
                    404,
                    "node_protocol_unsupported",
                    StatusCode::BAD_GATEWAY,
                    "address_lookup_unsupported",
                ),
                (
                    404,
                    "resource_not_found",
                    StatusCode::NOT_FOUND,
                    "resource_not_found",
                ),
                (
                    404,
                    "node_request_rejected",
                    StatusCode::BAD_GATEWAY,
                    "node_request_rejected",
                ),
                (
                    403,
                    "peer_not_authorized",
                    StatusCode::BAD_GATEWAY,
                    "peer_not_authorized",
                ),
                (
                    503,
                    "management_upgrade_required",
                    StatusCode::BAD_GATEWAY,
                    "management_upgrade_required",
                ),
            ] {
                let error =
                    routing::address_error(io::Error::other(control::RemoteError { status, code }));
                assert_eq!((error.status, error.code), (expected_status, expected_code));
            }
            let old = remote_error(io::Error::other(control::RemoteError {
                status: 404,
                code: "resource_not_found",
            }));
            assert_eq!(old.status, StatusCode::BAD_GATEWAY);
        }

        #[tokio::test]
        async fn exact_address_target_adapter_preserves_node_scope_retirement_and_browser_session()
        -> io::Result<()> {
            let fixture = node::tests::Fixture::new(true, true)?;
            let child_administrator = administrator(&fixture.server_state)?;
            let child = Coordinator::new(
                fixture.server_state.clone(),
                store::load_policy(&fixture.server_state)?,
                Arc::new(store::lock(&fixture.server_state)?),
            )?;
            child
                .change(
                    child_administrator.clone(),
                    1,
                    store::PolicyChange::CreateAddress {
                        name: "Remote retired address".into(),
                        ip: "127.0.0.2".parse().unwrap(),
                        prefix_id: None,
                    },
                )
                .await?;
            let id = store::routing_data(&fixture.server_state)?
                .1
                .addresses
                .remove(0)
                .id;
            child
                .change(
                    child_administrator.clone(),
                    2,
                    store::PolicyChange::SetAddressState {
                        id: id.clone(),
                        state: ResourceState::Retired,
                    },
                )
                .await?;
            child
                .set_owner(
                    child_administrator.clone(),
                    1,
                    Some(fixture.client_id.clone()),
                )
                .await?;
            let mut state = crate::manage::api::initialize(
                fixture.client_state.clone(),
                PublicOrigin::parse("https://localhost:8443")?,
                Arc::new(store::lock(&fixture.client_state)?),
            )
            .await?;
            let caller = state
                .policy
                .clone()
                .ok_or_else(|| io::Error::other("missing fixture caller policy"))?;
            let administrator = administrator(&fixture.client_state)?;
            caller
                .change(
                    administrator.clone(),
                    1,
                    store::PolicyChange::CreateAddress {
                        name: "Local decoy".into(),
                        ip: "127.0.0.3".parse().unwrap(),
                        prefix_id: None,
                    },
                )
                .await?;
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            store::targets::configure(
                &fixture.client_state,
                &administrator,
                &fixture.server_id,
                None,
                &format!("https://localhost:{}", address.port()),
                true,
                None,
            )?;
            let (service, _runner) = crate::manage::controller::Service::new(
                caller.clone(),
                fixture.client_tls.clone(),
                fixture.client_id.clone(),
            );
            Arc::get_mut(&mut state)
                .ok_or_else(|| io::Error::other("shared fixture state"))?
                .controller = Some(service);
            let token = "t".repeat(43);
            let mut session = crate::manage::api::tests::fixture_session(Instant::now());
            session.administrator.id = administrator.clone();
            state
                .security()
                .map_err(|_| io::Error::other("fixture security unavailable"))?
                .insert_session(None, token.clone(), session)
                .map_err(|_| io::Error::other("fixture session rejected"))?;
            let cookie = format!("{COOKIE_NAME}={token}");
            let shutdown = CancellationToken::new();
            let mut node = tokio::spawn(node::serve(
                listener,
                fixture.config(address)?,
                fixture.server_state.clone(),
                shutdown.clone(),
                Some(child.clone()),
                None,
                None,
            ));
            let outcome = AssertUnwindSafe(timeout(Duration::from_secs(15), async {
                let path = format!("/api/v1/targets/{}/proxy/addresses/{id}", fixture.server_id);
                let (status, view) =
                    invoke(state.clone(), &cookie, Method::GET, &path, Value::Null).await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(view["revision"], "3");
                assert_eq!(view["address"]["id"], id);
                assert_eq!(view["address"]["name"], "Remote retired address");
                assert_eq!(view["address"]["state"], "retired");
                let mut head = request(Method::HEAD, &path, "");
                head.headers_mut()
                    .insert(header::COOKIE, cookie.parse().unwrap());
                let response = call(state.clone(), head).await;
                assert_eq!(response.status(), StatusCode::OK);
                assert!(
                    response
                        .into_body()
                        .collect()
                        .await
                        .unwrap()
                        .to_bytes()
                        .is_empty()
                );
                let missing_path = format!(
                    "/api/v1/targets/{}/proxy/addresses/AAAAAAAAAAAAAAAAAAAAAA",
                    fixture.server_id
                );
                let (status, missing) = invoke(
                    state.clone(),
                    &cookie,
                    Method::GET,
                    &missing_path,
                    Value::Null,
                )
                .await;
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert_eq!(missing["error"]["code"], "resource_not_found");
                child.set_owner(child_administrator, 2, None).await?;
                let (status, denied) =
                    invoke(state.clone(), &cookie, Method::GET, &path, Value::Null).await;
                assert_eq!(status, StatusCode::BAD_GATEWAY);
                assert_eq!(denied["error"]["code"], "peer_not_authorized");
                let (status, _) = invoke(
                    state.clone(),
                    &cookie,
                    Method::GET,
                    "/api/v1/auth/session",
                    Value::Null,
                )
                .await;
                assert_eq!(status, StatusCode::OK);
                store::targets::set_state(
                    &fixture.client_state,
                    &administrator,
                    &fixture.server_id,
                    1,
                    false,
                    false,
                )?;
                let (status, denied) =
                    invoke(state.clone(), &cookie, Method::GET, &path, Value::Null).await;
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert_eq!(denied["error"]["code"], "node_control_denied");
                assert_eq!(store::policy_status(&fixture.client_state)?.revision, 2);
                assert_eq!(store::policy_status(&fixture.server_state)?.revision, 3);
                Ok::<_, io::Error>(())
            }))
            .catch_unwind()
            .await;
            shutdown.cancel();
            let stopped = match timeout(Duration::from_secs(10), &mut node).await {
                Ok(stopped) => stopped.map_err(io::Error::other).and_then(|result| result),
                Err(_) => {
                    node.abort();
                    let _aborted = node.await;
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "exact address adapter cleanup deadline",
                    ))
                }
            };
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(payload) => {
                    if let Err(error) = &stopped {
                        eprintln!(
                            "exact address adapter cleanup failed: kind={:?}",
                            error.kind()
                        );
                    }
                    resume_unwind(payload)
                }
            };
            stopped?;
            outcome.map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "exact address adapter deadline")
            })??;
            Ok(())
        }

        #[tokio::test]
        async fn exact_address_target_rejects_empty_query_and_noncanonical_paths_before_admission()
        {
            let (_directory, state, cookie) = managed_state();
            let id = peer();
            for path in [
                format!("/api/v1/targets/{id}/proxy/addresses/{id}?"),
                format!("/api/v1/targets/not-an-id/proxy/addresses/{id}"),
                format!("/api/v1/targets/{id}/proxy/addresses/AAAAAAAAAAAAAAAAAAAAAB"),
            ] {
                assert_eq!(
                    invoke(state.clone(), &cookie, Method::GET, &path, Value::Null)
                        .await
                        .0,
                    StatusCode::BAD_REQUEST
                );
            }
        }
    }
    mod search {
        //! In-process browser HTTP routing through a real Service and node mTLS.
        //! Login itself and browser-to-controller TLS are covered elsewhere, not mocked
        //! here as part of the new search operation.

        use super::*;
        use crate::manage::{node, policy::Coordinator, store};
        use std::time::{Duration, Instant};
        use tokio::net::TcpListener;
        use tokio_util::sync::CancellationToken;

        fn administrator(directory: &std::path::Path) -> io::Result<String> {
            rusqlite::Connection::open(directory.join("management.sqlite3"))
                .map_err(io::Error::other)?
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)
        }

        #[tokio::test]
        async fn user_result_and_search_routes_read_exact_target_and_preserve_session_after_peer_denial()
        -> io::Result<()> {
            let prepare_started = Instant::now();
            let fixture = node::tests::Fixture::new(true, true)?;
            let fixture_prepare_elapsed = prepare_started.elapsed();
            let child_administrator = administrator(&fixture.server_state)?;
            let child = Coordinator::new(
                fixture.server_state.clone(),
                store::load_policy(&fixture.server_state)?,
                Arc::new(store::lock(&fixture.server_state)?),
            )?;
            child
                .change(
                    child_administrator.clone(),
                    1,
                    store::PolicyChange::CreateUser {
                        name: "Remote_% +".into(),
                        protocols: vec![crate::access::Protocol::Http],
                        concurrent_limit: 1,
                    },
                )
                .await?;
            let expected_user = store::list_users(&fixture.server_state, false, None, 1)?
                .items
                .remove(0)
                .id;
            child
                .set_owner(
                    child_administrator.clone(),
                    1,
                    Some(fixture.client_id.clone()),
                )
                .await?;

            let author = Arc::new(store::lock(&fixture.client_state)?);
            let mut state = crate::manage::api::initialize(
                fixture.client_state.clone(),
                PublicOrigin::parse("https://localhost:8443")?,
                author,
            )
            .await?;
            let caller = state
                .policy
                .clone()
                .ok_or_else(|| io::Error::other("expected controller policy"))?;
            let administrator = administrator(&fixture.client_state)?;
            caller
                .change(
                    administrator.clone(),
                    1,
                    store::PolicyChange::CreateUser {
                        name: "Local only".into(),
                        protocols: vec![crate::access::Protocol::Http],
                        concurrent_limit: 1,
                    },
                )
                .await?;
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let target_origin = format!("https://localhost:{}", address.port());
            store::targets::configure(
                &fixture.client_state,
                &administrator,
                &fixture.server_id,
                None,
                &target_origin,
                true,
                None,
            )?;
            let (service, _runner) = crate::manage::controller::Service::new(
                caller.clone(),
                fixture.client_tls.clone(),
                fixture.client_id.clone(),
            );
            Arc::get_mut(&mut state)
                .ok_or_else(|| io::Error::other("fixture API state is shared"))?
                .controller = Some(service);
            let token = "t".repeat(43);
            let mut session = crate::manage::api::tests::fixture_session(Instant::now());
            session.administrator.id = administrator.clone();
            state
                .security()
                .map_err(|_| io::Error::other("fixture API security unavailable"))?
                .insert_session(None, token.clone(), session)
                .map_err(|_| io::Error::other("cannot insert fixture session"))?;
            let cookie = format!("{COOKIE_NAME}={token}");
            let shutdown = CancellationToken::new();
            let node = tokio::spawn(node::serve(
                listener,
                fixture.config(address)?,
                fixture.server_state.clone(),
                shutdown.clone(),
                Some(child.clone()),
                None,
                None,
            ));
            let prepare_elapsed = prepare_started.elapsed();
            // Fixed test-local labels distinguish each existing operation without
            // logging request data or adding observations that contend with the peer.
            const STAGES: [&str; 13] = [
                "name_search",
                "policy_read",
                "enqueue_intent",
                "command_delivery",
                "wrong_job_result",
                "first_user_result",
                "repeat_user_result",
                "remote_user_count",
                "exact_user_search",
                "owner_revocation",
                "denied_user_result",
                "denied_search",
                "session_read",
            ];
            let scenario_started = Instant::now();
            let mut stage = 0;
            let mut entered = scenario_started;
            let mut stage_elapsed = [Duration::ZERO; STAGES.len()];
            macro_rules! enter {
                ($next:expr) => {{
                    let now = Instant::now();
                    stage_elapsed[stage] = now.duration_since(entered);
                    stage = $next;
                    entered = now;
                }};
            }
            let outcome = tokio::time::timeout(Duration::from_secs(15), async {
                let path = format!(
                    "/api/v1/targets/{}/users/search?mode=name&q=remote_%25+%2B&limit=1",
                    fixture.server_id
                );
                let (status, found) =
                    invoke(state.clone(), &cookie, Method::GET, &path, Value::Null).await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(found["revision"], "2");
                assert_eq!(found["items"].as_array().unwrap().len(), 1);
                assert_eq!(found["items"][0]["id"], expected_user);
                assert_eq!(found["items"][0]["name"], "Remote_% +");
                assert!(found["next_cursor"].is_null());
                assert_eq!(store::policy_status(&fixture.client_state)?.revision, 2);
                assert_eq!(store::policy_status(&fixture.server_state)?.revision, 2);

                enter!(1);
                let base = format!("/api/v1/targets/{}", fixture.server_id);
                let (status, _) = invoke(
                    state.clone(),
                    &cookie,
                    Method::GET,
                    &format!("{base}/policy"),
                    Value::Null,
                )
                .await;
                assert_eq!(status, StatusCode::OK);
                enter!(2);
                let command = store::Command {
                    target_node_id: fixture.server_id.clone(),
                    epoch: 2,
                    command_id: 1,
                    expected_policy_revision: 2,
                    source_administrator_id: administrator.clone(),
                    change: store::PolicyChange::CreateUser {
                        name: "Recovered exact user".into(),
                        protocols: vec![crate::access::Protocol::Http],
                        concurrent_limit: 1,
                    },
                };
                let wire_command = control::Command {
                    version: 1,
                    target_node_id: command.target_node_id.clone(),
                    resource: "proxy_policy".into(),
                    controller_epoch: command.epoch.to_string(),
                    command_id: command.command_id.to_string(),
                    expected_policy_revision: command.expected_policy_revision.to_string(),
                    source_administrator_id: command.source_administrator_id.clone(),
                    mutation: store::PolicyChange::CreateUser {
                        name: "Recovered exact user".into(),
                        protocols: vec![crate::access::Protocol::Http],
                        concurrent_limit: 1,
                    }
                    .try_into()?,
                };
                let queued = storage::enqueue(&fixture.client_state, &administrator, 1, command)?;
                enter!(3);
                let control::Reply::Command(delivered) = control::request(
                    &caller,
                    fixture.client_tls.clone(),
                    &target_origin,
                    &fixture.server_id,
                    control::Request::Command(wire_command),
                )
                .await?
                else {
                    return Err(io::Error::other("expected user creation reply"));
                };
                let created_id = delivered
                    .receipt
                    .user_id
                    .clone()
                    .ok_or_else(|| io::Error::other("expected created user reference"))?;
                assert!(delivered.secret.is_none());
                drop(delivered); // The controller never receives this first response.
                enter!(4);
                let result_path = format!("{base}/command/user-result");
                let (status, _) = invoke(
                    state.clone(),
                    &cookie,
                    Method::POST,
                    &result_path,
                    json!({"job_id":URL_SAFE_NO_PAD.encode([91;16])}),
                )
                .await;
                assert_eq!(status, StatusCode::CONFLICT);
                for attempt in 0..2 {
                    enter!(if attempt == 0 { 5 } else { 6 });
                    let (status, result) = invoke(
                        state.clone(),
                        &cookie,
                        Method::POST,
                        &result_path,
                        json!({"job_id":queued.job_id}),
                    )
                    .await;
                    assert_eq!(status, StatusCode::OK);
                    assert_eq!(result["user_id"], created_id);
                    assert_eq!(result["job"]["job_id"], queued.job_id);
                    assert_eq!(result["job"]["user_creation"], true);
                    assert_eq!(result["job"]["policy_revision"], "3");
                    assert_eq!(result.as_object().unwrap().len(), 2);
                }
                enter!(7);
                assert_eq!(
                    store::list_users(&fixture.server_state, false, None, 25)?
                        .items
                        .len(),
                    2
                );
                enter!(8);
                let (status, exact) = invoke(
                    state.clone(),
                    &cookie,
                    Method::GET,
                    &format!("{base}/users/search?mode=id&q={created_id}&limit=1"),
                    Value::Null,
                )
                .await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(exact["items"][0]["id"], created_id);
                assert_eq!(exact["revision"], "3");

                enter!(9);
                child.set_owner(child_administrator, 2, None).await?;
                enter!(10);
                let (status, denied_result) = invoke(
                    state.clone(),
                    &cookie,
                    Method::POST,
                    &result_path,
                    json!({"job_id":queued.job_id}),
                )
                .await;
                assert_eq!(status, StatusCode::BAD_GATEWAY);
                assert_eq!(denied_result["error"]["code"], "peer_not_authorized");
                enter!(11);
                let (status, denied) =
                    invoke(state.clone(), &cookie, Method::GET, &path, Value::Null).await;
                assert_eq!(status, StatusCode::BAD_GATEWAY);
                assert_eq!(denied["error"]["code"], "peer_not_authorized");
                enter!(12);
                let (status, _) = invoke(
                    state.clone(),
                    &cookie,
                    Method::GET,
                    "/api/v1/auth/session",
                    Value::Null,
                )
                .await;
                assert_eq!(status, StatusCode::OK);
                Ok::<_, io::Error>(())
            })
            .await;
            // Snapshot before cancellation/join: cleanup must not inflate the operation
            // that was active when the original scenario budget ended.
            let observed = Instant::now();
            let scenario_elapsed = observed.duration_since(scenario_started);
            let active_elapsed = observed.duration_since(entered);
            stage_elapsed[stage] = active_elapsed;
            let stage_times: [(&str, u128); STAGES.len()] =
                std::array::from_fn(|index| (STAGES[index], stage_elapsed[index].as_millis()));
            eprintln!(
                "browser target adapter fixture timing: prepare_ms={} fixture_prepare_ms={} scenario_ms={} stage={} stage_ms={} stages_ms={:?}",
                prepare_elapsed.as_millis(),
                fixture_prepare_elapsed.as_millis(),
                scenario_elapsed.as_millis(),
                STAGES[stage],
                active_elapsed.as_millis(),
                &stage_times[..=stage],
            );
            shutdown.cancel();
            let stopped = node.await.map_err(io::Error::other)?;
            outcome.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "browser target adapter fixture deadline: stage={} prepare_ms={} scenario_ms={} stage_ms={}",
                STAGES[stage],
                prepare_elapsed.as_millis(),
                scenario_elapsed.as_millis(),
                active_elapsed.as_millis(),
            ),
        )
    })??;
            stopped
        }
    }
    mod secrets {
        //! Real Session/CSRF routing to a child over its registered mTLS identity.
        use super::*;
        use crate::manage::{controller::tests::tasks::OwnedTasks, node, policy::Coordinator};
        use std::{
            io,
            time::{Duration, Instant},
        };
        use tokio::net::TcpListener;
        use tokio_util::sync::CancellationToken;

        #[tokio::test]
        async fn remote_saved_password_requires_session_current_owner_and_exact_selection()
        -> io::Result<()> {
            let fixture = node::tests::Fixture::new(true, true)?;
            let admin = |directory: &std::path::Path| -> io::Result<String> {
                rusqlite::Connection::open(directory.join("management.sqlite3"))
                    .map_err(io::Error::other)?
                    .query_row("SELECT id FROM administrators", [], |r| r.get(0))
                    .map_err(io::Error::other)
            };
            let child_admin = admin(&fixture.server_state)?;
            let child = Coordinator::new(
                fixture.server_state.clone(),
                store::load_policy(&fixture.server_state)?,
                Arc::new(store::lock(&fixture.server_state)?),
            )?;
            let created = child
                .change(
                    child_admin.clone(),
                    1,
                    store::PolicyChange::CreateUser {
                        name: "Remote password fixture".into(),
                        protocols: vec![crate::access::Protocol::Http],
                        concurrent_limit: 1,
                    },
                )
                .await?;
            let user = created.user.unwrap().id;
            let mut created = child
                .change(
                    child_admin.clone(),
                    2,
                    store::PolicyChange::CreateCredential {
                        user_id: user.clone(),
                    },
                )
                .await?;
            let credential = created.credential.take().unwrap();
            let secret = created.secret.take().unwrap();
            child
                .set_owner(child_admin.clone(), 1, Some(fixture.client_id.clone()))
                .await?;
            let mut state = crate::manage::api::initialize(
                fixture.client_state.clone(),
                PublicOrigin::parse("https://localhost:8443")?,
                Arc::new(store::lock(&fixture.client_state)?),
            )
            .await?;
            let source_admin = admin(&fixture.client_state)?;
            let caller = state.policy.clone().unwrap();
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            store::targets::configure(
                &fixture.client_state,
                &source_admin,
                &fixture.server_id,
                None,
                &format!("https://localhost:{}", address.port()),
                true,
                None,
            )?;
            let (service, _runner) = crate::manage::controller::Service::new(
                caller,
                fixture.client_tls.clone(),
                fixture.client_id.clone(),
            );
            Arc::get_mut(&mut state).unwrap().controller = Some(service);
            let token = "t".repeat(43);
            let mut session = crate::manage::api::tests::fixture_session(Instant::now());
            session.administrator.id = source_admin;
            state
                .security()
                .unwrap()
                .insert_session(None, token.clone(), session)
                .unwrap();
            let cookie = format!("{COOKIE_NAME}={token}");
            let stop = CancellationToken::new();
            let mut tasks = OwnedTasks::new();
            tasks.insert(
                "password target",
                stop.clone(),
                tokio::spawn(node::serve(
                    listener,
                    fixture.config(address)?,
                    fixture.server_state.clone(),
                    stop,
                    Some(child.clone()),
                    None,
                    None,
                )),
            );
            let outcome = tokio::time::timeout(Duration::from_secs(15), async {
        let path = format!("/api/v1/targets/{}/proxy/credentials/{}/secret", fixture.server_id, credential.id);
        let body = json!({"expected_node_id":fixture.server_id,"expected_target_revision":"1","user_id":user,"controller_epoch":"2","verifier_revision":"1"});
        let anonymous = call(state.clone(), request(Method::POST, &path, &body.to_string())).await;
        assert_eq!(anonymous.status(), StatusCode::FORBIDDEN);
        assert!(anonymous.headers().get(header::WWW_AUTHENTICATE).is_none());
        let mut no_csrf = request(Method::POST, &path, &body.to_string());
        no_csrf.headers_mut().insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(call(state.clone(), no_csrf).await.status(), StatusCode::FORBIDDEN);
        let mut bearer = request(Method::POST, &path, &body.to_string());
        bearer.headers_mut().insert(header::AUTHORIZATION, "Bearer fixture-no-lookup".parse().unwrap());
        assert_eq!(call(state.clone(), bearer).await.status(), StatusCode::FORBIDDEN);
        for changed in [json!({"user_id":"invalid"}), json!({"expected_target_revision":"01"}), json!({"extra":"forbidden"})] {
            let mut input = body.clone();
            input.as_object_mut().unwrap().extend(changed.as_object().unwrap().clone());
            assert_eq!(invoke(state.clone(), &cookie, Method::POST, &path, input).await.0, StatusCode::BAD_REQUEST);
        }
        assert_eq!(invoke(state.clone(), &cookie, Method::POST, &format!("{path}?secret=forbidden"), body.clone()).await.0, StatusCode::BAD_REQUEST);
        let (status, shown) = invoke(state.clone(), &cookie, Method::POST, &path, body.clone()).await;
        assert_eq!(status, StatusCode::OK, "fixed rejection code: {}", shown["error"]["code"]);
        assert!(shown["secret"].as_str() == Some(secret.as_str()), "current password mismatch");
        assert_eq!(shown["credential_id"], credential.id);
        assert_eq!(shown["user_id"], user);
        assert_eq!(shown.as_object().unwrap().len(), 4);
        let mut changed = body.clone(); changed["verifier_revision"] = "2".into();
        let (status, failure) = invoke(state.clone(), &cookie, Method::POST, &path, changed).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(failure["error"]["code"], "credential_secret_changed");
        child.set_owner(child_admin.clone(), 2, None).await?;
        let (status, denied) = invoke(state.clone(), &cookie, Method::POST, &path, body).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(!denied.to_string().contains(secret.as_str()));
        assert_eq!(invoke(state.clone(), &cookie, Method::GET, "/api/v1/auth/session", Value::Null).await.0, StatusCode::OK);
        assert_eq!(store::ownership(&fixture.server_state)?.last_terminal_command, 0);
        assert_eq!(store::policy_status(&fixture.server_state)?.revision, 3);
        assert!(store::targets::job(&fixture.client_state, &fixture.server_id)?.is_none());
        Ok(())
    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "remote saved password scenario timed out")).and_then(|value| value);
            tasks.finish(outcome).await
        }
    }

    #[tokio::test]
    async fn local_target_filter_keeps_session_and_strict_decoding_without_remote_admission() {
        let (_directory, state, cookie) = managed_state();
        assert_eq!(
            call(
                state.clone(),
                request(Method::GET, "/api/v1/targets?q=west", "")
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        store::register_peer(
            &state.directory,
            &peer(),
            "West %_ 节点",
            b"target filter fixture DER",
            "target.example",
            None,
        )
        .unwrap();
        let (status, _) = invoke(state.clone(), &cookie, Method::POST, "/api/v1/targets",
        json!({"node_id":peer(),"origin":"https://target.example","active":true,"server_ip":"2001:db8::7"})).await;
        assert_eq!(status, StatusCode::CREATED);
        for query in [
            "q=WEST",
            "q=%25_",
            "q=%E8%8A%82%E7%82%B9",
            "q=2001%3A0DB8%3A0%3A0%3A0%3A0%3A0%3A7",
        ] {
            let (status, body) = invoke(
                state.clone(),
                &cookie,
                Method::GET,
                &format!("/api/v1/targets?{query}&limit=1"),
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["items"].as_array().unwrap().len(), 1);
            assert_eq!(body["items"][0]["node_id"], peer());
            assert_eq!(body["controller_available"], false);
        }
        for query in [
            "q=%FF",
            "q=%",
            "q=%0",
            "q=a&%71=b",
            "q=%00",
            "q=%C2%85",
            "q=x&unknown=1",
        ] {
            let (status, body) = invoke(
                state.clone(),
                &cookie,
                Method::GET,
                &format!("/api/v1/targets?{query}"),
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"]["code"], "invalid_pagination");
        }
        let long = format!("/api/v1/targets?q={}", "x".repeat(257));
        assert_eq!(
            invoke(state.clone(), &cookie, Method::GET, &long, Value::Null)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert!(storage::job(&state.directory, &peer()).unwrap().is_none());
        assert_eq!(storage::get(&state.directory, &peer()).unwrap().revision, 1);
    }

    #[test]
    fn first_response_keeps_its_ticket_when_next_command_replaces_the_row() {
        let ticket = |id: &str, number, state| storage::Job {
            peer_id: "same-peer".into(),
            job_id: id.into(),
            epoch: 2,
            command_id: number,
            expected_policy_revision: Some(number),
            expected_metadata_revision: None,
            metadata_revision: None,
            endpoint: None,
            state,
            policy_revision: None,
            outcome_code: None,
            attempts: 0,
            next_attempt: 0,
            user_creation: false,
            routing: None,
            preset: None,
            maintenance: None,
        };
        let first = ticket("first", 1, storage::JobState::Pending);
        let next = ticket("next", 2, storage::JobState::Pending);
        let selected = matching_ticket(first, Some(next));
        assert_eq!(selected.job_id, "first");
        assert_eq!(selected.command_id, 1);
        let applied = ticket("first", 1, storage::JobState::Applied);
        let selected = matching_ticket(selected, Some(applied));
        assert!(selected.state == storage::JobState::Applied);
    }
    use crate::manage::api::tests::{call, managed_state, request};
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};

    #[tokio::test]
    async fn user_result_requires_an_exact_ticket_without_client_identity_or_query_fields() {
        let (_directory, state, cookie) = managed_state();
        let path = format!("/api/v1/targets/{}/command/user-result", peer());
        for body in [
            json!({}),
            json!({"job_id":""}),
            json!({"job_id":"not-an-id"}),
            json!({"job_id":12}),
            json!({"job_id":peer(),"origin":"https://unregistered.example"}),
        ] {
            let (status, _) = invoke(state.clone(), &cookie, Method::POST, &path, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        let (status, _) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("{path}?job_id={}", peer()),
            json!({"job_id":peer()}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, body) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &path,
            json!({"job_id":peer()}),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "node_control_unavailable");
        assert!(storage::job(&state.directory, &peer()).unwrap().is_none());
        assert_eq!(store::policy_status(&state.directory).unwrap().revision, 1);
    }

    #[tokio::test]
    async fn user_search_target_route_requires_session_and_strict_query_before_remote_admission() {
        let (_directory, state, cookie) = managed_state();
        let path = format!("/api/v1/targets/{}/users/search", peer());
        let valid = format!("{path}?mode=name&q=Alice");
        assert_eq!(
            call(state.clone(), request(Method::GET, &valid, ""))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        for query in [
            "mode=name&q=%FF",
            "mode=name&q=a&%71=b",
            "mode=id&q=not-id",
            "mode=name&q=a&limit=51",
            "q=Alice",
            "mode=name&q=",
        ] {
            let (status, body) = invoke(
                state.clone(),
                &cookie,
                Method::GET,
                &format!("{path}?{query}"),
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"]["code"], "invalid_user_search");
        }
        let (status, body) = invoke(state, &cookie, Method::GET, &valid, Value::Null).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "node_control_unavailable");
    }

    #[test]
    fn user_search_target_errors_do_not_reinterpret_authentication_or_unrelated_404s() {
        for (status, code, expected_status, expected_code) in [
            (
                404,
                "node_protocol_unsupported",
                StatusCode::BAD_GATEWAY,
                "user_search_unsupported",
            ),
            (
                404,
                "resource_not_found",
                StatusCode::BAD_GATEWAY,
                "resource_not_found",
            ),
            (
                404,
                "node_request_rejected",
                StatusCode::BAD_GATEWAY,
                "node_request_rejected",
            ),
            (
                403,
                "peer_not_authorized",
                StatusCode::BAD_GATEWAY,
                "peer_not_authorized",
            ),
            (
                409,
                "user_search_changed",
                StatusCode::CONFLICT,
                "user_search_changed",
            ),
            (
                400,
                "invalid_user_search_cursor",
                StatusCode::BAD_REQUEST,
                "invalid_user_search_cursor",
            ),
            (
                400,
                "invalid_user_search",
                StatusCode::BAD_REQUEST,
                "invalid_user_search",
            ),
            (503, "policy_busy", StatusCode::BAD_GATEWAY, "policy_busy"),
        ] {
            let error = search_error(io::Error::other(control::RemoteError { status, code }));
            assert_eq!((error.status, error.code), (expected_status, expected_code));
        }
        let error = search_error(io::Error::new(
            io::ErrorKind::TimedOut,
            "fixed fixture timeout",
        ));
        assert_eq!(
            (error.status, error.code),
            (StatusCode::GATEWAY_TIMEOUT, "node_timeout")
        );
    }

    fn peer() -> String {
        URL_SAFE_NO_PAD.encode([17; 16])
    }

    #[tokio::test]
    async fn server_ip_target_wire_preserves_clears_and_enforces_configuration_cas() {
        let (_directory, state, cookie) = managed_state();
        store::register_peer(
            &state.directory,
            &peer(),
            "target",
            b"public fixture DER",
            "target.example",
            None,
        )
        .unwrap();
        let path = format!("/api/v1/targets/{}", peer());
        let (status, registered) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            "/api/v1/targets",
            json!({"node_id":peer(),"origin":"https://target.example","active":true}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(registered["server_ip"].is_null());
        let body = |revision| json!({"expected_revision":revision,"origin":"https://target.example","active":true});
        let mut input = body("1");
        input["server_ip"] = json!("192.0.2.7");
        let (status, set) = invoke(state.clone(), &cookie, Method::PUT, &path, input).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(set["server_ip"], "192.0.2.7");
        let (status, stale) = invoke(state.clone(), &cookie, Method::PUT, &path, body("1")).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(stale["error"]["code"], "policy_conflict");
        let (status, preserved) =
            invoke(state.clone(), &cookie, Method::PUT, &path, body("2")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(preserved["server_ip"], "192.0.2.7");
        let mut input = body("3");
        input["server_ip"] = Value::Null;
        let (status, cleared) = invoke(state.clone(), &cookie, Method::PUT, &path, input).await;
        assert_eq!(status, StatusCode::OK);
        assert!(cleared["server_ip"].is_null());
        let mut input = body("4");
        input["server_ip"] = json!("FD00:0:0:0:0:0:0:7");
        let (status, set) = invoke(state.clone(), &cookie, Method::PUT, &path, input).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            (set["server_ip"].as_str(), set["origin"].as_str()),
            (Some("fd00::7"), Some("https://target.example"))
        );
        for value in [
            json!("0.0.0.0"),
            json!("ff02::1"),
            json!("example.com"),
            json!("192.0.2.7:80"),
            json!("2001:db8::7/64"),
            json!(12),
        ] {
            let mut input = body("5");
            input["server_ip"] = value;
            let (status, error) = invoke(state.clone(), &cookie, Method::PUT, &path, input).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(error["error"]["code"], "invalid_json");
        }
        let mut input = body("5");
        input["public_ip"] = json!("192.0.2.8");
        assert_eq!(
            invoke(state.clone(), &cookie, Method::PUT, &path, input)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(storage::get(&state.directory, &peer()).unwrap().revision, 5);
        assert_eq!(store::policy_status(&state.directory).unwrap().revision, 1);
    }

    #[tokio::test]
    async fn server_ip_schema_nine_requires_explicit_upgrade_without_disabling_local_policy() {
        let (_directory, mut state, cookie) = managed_state();
        let connection =
            rusqlite::Connection::open(state.directory.join("management.sqlite3")).unwrap();
        store::recovery::remove_schema_for_test(&connection).unwrap();
        connection
            .execute_batch(
                "ALTER TABLE managed_targets DROP COLUMN server_ip; PRAGMA user_version=9;",
            )
            .unwrap();
        Arc::get_mut(&mut state).unwrap().schema_version = 9;
        let (status, error) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/targets",
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error["error"]["code"], "management_upgrade_required");
        let (status, error) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            &format!("/api/v1/targets/{}/policy", peer()),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error["error"]["code"], "management_upgrade_required");
        assert_eq!(
            invoke(
                state.clone(),
                &cookie,
                Method::GET,
                "/api/v1/proxy/policy",
                Value::Null
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(store::inspect(&state.directory).unwrap().schema_version, 9);
    }

    fn command() -> Value {
        json!({"expected_target_revision":"1","controller_epoch":"1","command_id":"1",
        "expected_policy_revision":"1","mutation":{"action":"create_user","name":"Remote user",
        "protocols":["http"],"concurrent_limit":1}})
    }

    async fn invoke(
        state: Arc<AppState>,
        cookie: &str,
        method: Method,
        path: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut request = request(method, path, &body.to_string());
        request
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        request
            .headers_mut()
            .insert("x-csrf-token", "c".repeat(43).parse().unwrap());
        let response = call(state, request).await;
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// Both target configuration and remote commands use the existing browser
    /// identity domain. Supplying a peer ID never bypasses session or CSRF checks.
    #[tokio::test]
    async fn target_routes_require_the_same_session_and_mutation_csrf() {
        let (_directory, state, cookie) = managed_state();
        for path in [
            "/api/v1/targets".into(),
            format!("/api/v1/targets/{}/commands", peer()),
            format!("/api/v1/targets/{}/routing/commands", peer()),
            format!("/api/v1/targets/{}/command/user-result", peer()),
        ] {
            for (with_cookie, csrf, expected) in [
                (false, None, "authentication_required"),
                (true, None, "invalid_csrf"),
                (true, Some("incorrect"), "invalid_csrf"),
            ] {
                let mut req = request(Method::POST, &path, "{}");
                if with_cookie {
                    req.headers_mut()
                        .insert(header::COOKIE, cookie.parse().unwrap());
                }
                if let Some(csrf) = csrf {
                    req.headers_mut()
                        .insert("x-csrf-token", csrf.parse().unwrap());
                }
                let response = call(state.clone(), req).await;
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                let bytes = response.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(
                    serde_json::from_slice::<Value>(&bytes).unwrap()["error"]["code"],
                    expected
                );
            }
        }
        assert!(
            storage::list(&state.directory, None, 25, true)
                .unwrap()
                .items
                .is_empty()
        );
        assert_eq!(store::policy_status(&state.directory).unwrap().revision, 1);
    }

    /// The browser bridge cannot enlarge either node vocabulary or manufacture an
    /// actor. These failures occur before a controller or outbound TLS is needed.
    #[tokio::test]
    async fn routing_commands_keep_v1_actions_and_identity_claims_out() {
        let (_directory, state, cookie) = managed_state();
        let v1 = format!("/api/v1/targets/{}/commands", peer());
        let v2 = format!("/api/v1/targets/{}/routing/commands", peer());
        let mut routing = command();
        routing["mutation"] = json!({"action":"create_pool","name":"Private egress","family":"v4"});
        for (path, body) in [(&v1, routing.clone()), (&v2, command())] {
            let (status, body) = invoke(state.clone(), &cookie, Method::POST, path, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"]["code"], "invalid_json");
        }
        for field in [
            "source_administrator_id",
            "target_node_id",
            "origin",
            "version",
        ] {
            let mut input = routing.clone();
            input[field] = peer().into();
            let (status, body) = invoke(state.clone(), &cookie, Method::POST, &v2, input).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"]["code"], "invalid_json");
        }
        assert!(storage::job(&state.directory, &peer()).unwrap().is_none());
        assert_eq!(store::policy_status(&state.directory).unwrap().revision, 1);
    }

    /// Inventory and monitor pages have separate wire budgets. Registered target
    /// IDs never authorize unbounded pages, arbitrary query keys or probe URLs.
    #[tokio::test]
    async fn remote_inventory_reads_require_session_and_bounded_fixed_inputs() {
        let (_directory, state, cookie) = managed_state();
        let id = peer();
        let base = format!("/api/v1/targets/{id}/proxy");
        for suffix in [
            "prefixes".to_owned(),
            "addresses".to_owned(),
            format!("addresses/{id}"),
            "pools".to_owned(),
            format!("pools/{id}/members"),
            format!("users/{id}/routing"),
            "health".to_owned(),
        ] {
            let path = format!("{base}/{suffix}");
            let response = call(state.clone(), request(Method::GET, &path, "")).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            for query in [
                "limit=0",
                "limit=51",
                "limit=1&limit=2",
                "origin=https://evil.example",
                "after=not-an-id",
            ] {
                let (status, _) = invoke(
                    state.clone(),
                    &cookie,
                    Method::GET,
                    &format!("{path}?{query}"),
                    Value::Null,
                )
                .await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{suffix}: {query}");
            }
        }
        let (status, body) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            &format!("{base}/health?limit=17"),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_pagination");
        for suffix in [
            "pools/not-an-id/members",
            "users/not-an-id/routing",
            "addresses/not-an-id",
        ] {
            let (status, body) = invoke(
                state.clone(),
                &cookie,
                Method::GET,
                &format!("{base}/{suffix}"),
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"]["code"], "invalid_resource_id");
        }
        let (status, body) = invoke(
            state,
            &cookie,
            Method::GET,
            &format!("{base}/prefixes?limit=50"),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "node_control_unavailable");
    }

    /// Actor and destination are chosen from session/path and local configuration,
    /// not JSON. Malformed pagination must fail before any outbound TLS is needed.
    #[tokio::test]
    async fn target_dtos_and_queries_reject_spoofed_identity_and_unbounded_pages() {
        let (_directory, state, cookie) = managed_state();
        for field in ["source_administrator_id", "target_node_id", "origin"] {
            let mut body = command();
            body[field] = peer().into();
            let (status, body) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                &format!("/api/v1/targets/{}/commands", peer()),
                body,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"]["code"], "invalid_json");
        }
        for query in [
            "unknown=true",
            "limit=1&limit=2",
            "limit=0",
            "limit=26",
            "limit=01",
            "include_retired=yes",
            "after=not-an-id",
        ] {
            let (status, body) = invoke(
                state.clone(),
                &cookie,
                Method::GET,
                &format!("/api/v1/targets?{query}"),
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"]["code"], "invalid_pagination");
        }
        for query in ["unknown=true", "limit=1&limit=2", "limit=0"] {
            let (status, body) = invoke(
                state.clone(),
                &cookie,
                Method::GET,
                &format!("/api/v1/targets/{}/users?{query}", peer()),
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"]["code"], "invalid_pagination");
        }
        assert!(storage::job(&state.directory, &peer()).unwrap().is_none());
    }

    /// Node mTLS is optional at startup, not an excuse to invent remote state.
    /// Local configuration remains usable while all network operations say unavailable.
    #[tokio::test]
    async fn local_target_crud_and_cas_remain_available_without_node_tls() {
        let (_directory, state, cookie) = managed_state();
        let peer = peer();
        store::register_peer(
            &state.directory,
            &peer,
            "Hong Kong",
            b"fixture enrolled leaf",
            "node.example",
            None,
        )
        .unwrap();
        let path = format!("/api/v1/targets/{peer}");
        let (status, created) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            "/api/v1/targets",
            json!({"node_id":peer,"origin":"https://node.example:19443","active":true}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["node_id"], peer);
        assert_eq!(created["name"], "Hong Kong");
        assert_eq!(created["revision"], "1");
        assert!(created["observed_epoch"].is_null());
        assert!(created.get("proxy_running").is_none());
        let (status, page) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/targets",
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["controller_available"], false);
        assert_eq!(page["items"].as_array().unwrap().len(), 1);

        for suffix in ["policy", "users", "credentials"] {
            let (status, body) = invoke(
                state.clone(),
                &cookie,
                Method::GET,
                &format!("{path}/{suffix}"),
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body["error"]["code"], "node_control_unavailable");
        }
        let (status, body) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("{path}/commands"),
            command(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "node_control_unavailable");
        assert!(storage::job(&state.directory, &peer).unwrap().is_none());

        let update = |expected| json!({"expected_revision":expected,"origin":"https://node.example:19444","active":true});
        let (status, conflict) =
            invoke(state.clone(), &cookie, Method::PUT, &path, update("2")).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(conflict["error"]["code"], "policy_conflict");
        assert_eq!(storage::get(&state.directory, &peer).unwrap().revision, 1);
        assert_eq!(
            storage::get(&state.directory, &peer).unwrap().origin,
            "https://node.example:19443"
        );
        let (status, updated) =
            invoke(state.clone(), &cookie, Method::PUT, &path, update("1")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(updated["revision"], "2");
        let (status, paused) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("{path}/state"),
            json!({"expected_revision":"2","active":false}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(paused["active"], false);
        assert_eq!(paused["revision"], "3");
        let (status, retired) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("{path}/retire"),
            json!({"expected_revision":"3"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(retired["retired"], true);
        let (_, page) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/targets",
            Value::Null,
        )
        .await;
        assert!(page["items"].as_array().unwrap().is_empty());
        let (_, history) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/targets?include_retired=true&limit=1",
            Value::Null,
        )
        .await;
        assert_eq!(history["items"][0]["node_id"], peer);
        assert_eq!(store::policy_status(&state.directory).unwrap().revision, 1);
    }
}
