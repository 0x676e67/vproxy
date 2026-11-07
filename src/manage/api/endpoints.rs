//! Authenticated endpoint inventory; never a proxy probe or secret exporter.

use super::*;
use crate::manage::views::JobInput as RefreshInput;

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/proxy/endpoints", get(local))
        .route("/api/v1/targets/{id}/proxy/endpoints", get(remote))
        .route("/api/v1/proxy/endpoint-settings", get(settings))
        .route(
            "/api/v1/proxy/endpoint-settings/{id}",
            axum::routing::put(change),
        )
        .route(
            "/api/v1/targets/{id}/proxy/endpoint-settings",
            get(remote_settings),
        )
        .route(
            "/api/v1/targets/{id}/proxy/endpoint-commands",
            axum::routing::post(remote_change),
        )
        .route(
            "/api/v1/targets/{id}/proxy/endpoint-command/refresh",
            axum::routing::post(refresh),
        )
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

fn no_query(uri: &Uri) -> Result<(), ApiError> {
    if uri.query().is_some() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_query"));
    }
    Ok(())
}

async fn local(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let policy = state.policy.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    })?;
    Ok(Json(
        policy
            .effective_endpoints(&state.node.node_id)
            .await
            .map_err(metadata_error)?,
    )
    .into_response())
}

async fn remote(
    State(state): State<Arc<AppState>>,
    path: Result<axum::extract::Path<String>, axum::extract::rejection::PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let operation = super::super::node::control::Request::Endpoints;
    let reply = targets::service(&state)?
        .remote(users::resource_id(path)?, operation)
        .await
        .map_err(remote_error)?;
    match reply {
        super::super::node::control::Reply::Endpoints(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

fn remote_error(error: io::Error) -> ApiError {
    if error
        .get_ref()
        .and_then(|error| error.downcast_ref::<super::super::node::control::RemoteError>())
        .is_some_and(|error| error.code == "node_protocol_unsupported")
    {
        return ApiError::new(StatusCode::BAD_GATEWAY, "remote_endpoints_unsupported");
    }
    targets::remote_error(error)
}

use super::super::{node::control, store};
use serde::{Deserialize, Serialize};

fn coordinator(state: &AppState) -> Result<Arc<super::super::policy::Coordinator>, ApiError> {
    state.policy.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    })
}
fn metadata_error(error: io::Error) -> ApiError {
    control::endpoints::storage_error(error)
}
fn management_remote_error(error: io::Error) -> ApiError {
    if error
        .get_ref()
        .and_then(|e| e.downcast_ref::<control::RemoteError>())
        .is_some_and(|e| e.code == "node_protocol_unsupported")
    {
        return ApiError::new(
            StatusCode::BAD_GATEWAY,
            "remote_endpoint_management_unsupported",
        );
    }
    if error
        .get_ref()
        .is_some_and(|e| e.is::<store::endpoints::Error>())
    {
        return metadata_error(error);
    }
    targets::remote_error(error)
}
async fn settings(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    no_query(&uri)?;
    Ok(Json(
        coordinator(&state)?
            .endpoint_settings(&state.node.node_id)
            .await
            .map_err(metadata_error)?,
    )
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeInput {
    expected_revision: String,
    generation: String,
    selection: store::endpoints::AddressSelection,
}
async fn change(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    path: Result<axum::extract::Path<String>, axum::extract::rejection::PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let listener_id = users::resource_id(path)?;
    let input: ChangeInput = json(request).await?;
    let policy = coordinator(&state)?;
    let inventory = policy.endpoint_inventory().map_err(metadata_error)?;
    let saved = policy
        .endpoint_change(
            actor,
            users::revision(&input.expected_revision)?,
            input.generation,
            store::endpoints::Change {
                listener_id,
                selection: input.selection,
            },
        )
        .await
        .map_err(metadata_error)?;
    let running = policy
        .endpoints(&state.node.node_id)
        .map_err(metadata_error)?
        .proxy_running;
    Ok(Json(
        super::super::proxy::SettingsCatalog::new(&state.node.node_id, running, &inventory, saved)
            .map_err(metadata_error)?,
    )
    .into_response())
}
async fn remote_settings(
    State(state): State<Arc<AppState>>,
    path: Result<axum::extract::Path<String>, axum::extract::rejection::PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    match targets::service(&state)?
        .remote(
            users::resource_id(path)?,
            control::Request::EndpointSettings,
        )
        .await
        .map_err(management_remote_error)?
    {
        control::Reply::EndpointSettings(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteInput {
    expected_target_revision: String,
    controller_epoch: String,
    command_id: String,
    expected_metadata_revision: String,
    mutation: control::endpoints::Mutation,
}
#[derive(Serialize)]
struct Submission {
    job: targets::JobView,
    response: Option<control::endpoints::CommandReply>,
}
async fn remote_change(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    path: Result<axum::extract::Path<String>, axum::extract::rejection::PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let peer = users::resource_id(path)?;
    let input: RemoteInput = json(request).await?;
    let command = store::endpoint_control::Command {
        target_node_id: peer,
        epoch: users::revision(&input.controller_epoch)?,
        command_id: users::revision(&input.command_id)?,
        expected_metadata_revision: users::revision(&input.expected_metadata_revision)?,
        source_administrator_id: actor.clone(),
        generation: input.mutation.generation,
        change: store::endpoints::Change {
            listener_id: input.mutation.listener_id,
            selection: input.mutation.selection,
        },
    };
    store::endpoint_control::validate(&command)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_endpoint"))?;
    let submitted = targets::service(&state)?
        .submit(
            actor,
            users::revision(&input.expected_target_revision)?,
            command,
        )
        .await
        .map_err(management_remote_error)?;
    let response = match timeout(Duration::from_secs(7), submitted.response).await {
        Ok(Ok(Ok(control::DeliveryReply::Endpoint(value)))) => Some(value),
        _ => None,
    };
    let status = if response.is_some() {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    let peer = submitted.job.peer_id.clone();
    let current = coordinator(&state)?
        .read(move |dir| store::targets::job(dir, &peer))
        .await
        .ok()
        .flatten();
    let job = current
        .filter(|job| job.job_id == submitted.job.job_id)
        .unwrap_or(submitted.job);
    let location = format!("/api/v1/targets/{}/command", job.peer_id);
    let mut response = (
        status,
        Json(Submission {
            job: job.into(),
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

async fn refresh(
    State(state): State<Arc<AppState>>,
    path: Result<axum::extract::Path<String>, axum::extract::rejection::PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let input: RefreshInput = json(request).await?;
    users::resource_id(Ok(axum::extract::Path(input.job_id.clone())))?;
    let job = targets::service(&state)?
        .refresh_endpoint(users::resource_id(path)?, input.job_id)
        .await
        .map_err(management_remote_error)?;
    Ok(Json(targets::JobView::from(job)).into_response())
}
