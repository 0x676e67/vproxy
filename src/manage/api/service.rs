//! Local Session/CSRF service control. Desired settings, exact durable receipts
//! and current listener facts are separate projections; a saved flag is never
//! reported as proof that forwarding or an external connection succeeded.

use super::*;
use crate::manage::{proxy, store};
use axum::extract::{
    Path, Query,
    rejection::{PathRejection, QueryRejection},
};

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/proxy/service", get(status).put(change))
        .route(
            "/api/v1/proxy/service/operations/{revision}/{request_id}",
            get(exact),
        )
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Web,
    Startup,
    UpgradeRequired,
}

#[derive(Serialize)]
struct Saved {
    revision: String,
    enabled: bool,
    configuration: Option<proxy::settings::Configuration>,
}
impl From<store::proxy_service::State> for Saved {
    fn from(value: store::proxy_service::State) -> Self {
        Self {
            revision: value.revision.to_string(),
            enabled: value.enabled,
            configuration: value.configuration,
        }
    }
}

#[derive(Serialize)]
struct Runtime {
    generation: Option<String>,
    configuration_revision: Option<String>,
    state: &'static str,
    error: Option<&'static str>,
    listeners: Vec<proxy::ListenerView>,
}
impl From<proxy::service::View> for Runtime {
    fn from(value: proxy::service::View) -> Self {
        use proxy::service::Phase;
        Self {
            generation: Some(value.generation.to_string()),
            configuration_revision: value
                .configuration_revision
                .map(|revision| revision.to_string()),
            state: match value.phase {
                Phase::Stopped => "stopped",
                Phase::Starting => "starting",
                Phase::Running => "running",
                Phase::Stopping => "stopping",
                Phase::Failed => "failed",
            },
            error: value.failure.map(|kind| match kind {
                io::ErrorKind::AddrInUse => "address_in_use",
                io::ErrorKind::AddrNotAvailable => "address_unavailable",
                io::ErrorKind::PermissionDenied => "permission_denied",
                io::ErrorKind::TimedOut => "timed_out",
                io::ErrorKind::WouldBlock => "not_ready",
                _ => "service_failed",
            }),
            listeners: value.endpoints,
        }
    }
}

#[derive(Serialize)]
struct Status {
    node_id: String,
    mode: Mode,
    saved: Option<Saved>,
    runtime: Runtime,
}

#[derive(Serialize)]
struct Receipt {
    node_id: String,
    revision: String,
    request_id: String,
    controller_epoch: String,
    enabled: bool,
    state: &'static str,
}
fn receipt(node_id: &str, value: store::proxy_service::Receipt) -> Receipt {
    use store::proxy_service::Outcome;
    Receipt {
        node_id: node_id.into(),
        revision: value.state.revision.to_string(),
        request_id: value.request_id,
        controller_epoch: value.owner_epoch.to_string(),
        enabled: value.state.enabled,
        state: match value.outcome {
            Outcome::Pending => "pending",
            Outcome::Applied => "applied",
            Outcome::Failed => "failed",
            Outcome::Interrupted => "interrupted",
        },
    }
}

fn policy(state: &AppState) -> Result<Arc<super::super::policy::Coordinator>, ApiError> {
    state.policy.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    })
}
fn control(
    policy: &super::super::policy::Coordinator,
) -> Result<proxy::service::Control, ApiError> {
    policy
        .service()
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "service_startup_managed"))
}
fn no_query(uri: &Uri) -> Result<(), ApiError> {
    if uri.query().is_some() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_query"));
    }
    Ok(())
}
fn storage_error(error: io::Error) -> ApiError {
    if let Some(cause) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<store::proxy_service::Error>())
    {
        use store::proxy_service::Error;
        return match cause {
            Error::UpgradeRequired => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "management_upgrade_required",
            ),
            Error::RevisionConflict => {
                ApiError::new(StatusCode::CONFLICT, "service_configuration_changed")
            }
            Error::OperationConflict => {
                ApiError::new(StatusCode::CONFLICT, "service_operation_changed")
            }
            Error::Pending => ApiError::new(StatusCode::CONFLICT, "service_operation_pending"),
        };
    }
    if let Some(cause) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<proxy::service::Error>())
    {
        use proxy::service::Error;
        return match cause {
            Error::Busy => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "service_busy"),
            Error::GenerationConflict => {
                ApiError::new(StatusCode::CONFLICT, "service_runtime_changed")
            }
            _ => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
        };
    }
    super::runtime::storage_error(error)
}

async fn status(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let policy = policy(&state)?;
    let supported = state.schema_version >= 27;
    let saved = policy
        .read(move |directory| {
            store::admission::local_runtime_snapshot(directory, &actor, None)?;
            if supported {
                store::proxy_service::read(directory).map(Some)
            } else {
                Ok(None)
            }
        })
        .await
        .map_err(storage_error)?;
    let mode = if !supported {
        Mode::UpgradeRequired
    } else if policy.service().is_some() {
        Mode::Web
    } else {
        Mode::Startup
    };
    let runtime = if let Some(control) = policy.service() {
        control
            .snapshot()
            .map(Runtime::from)
            .map_err(storage_error)?
    } else {
        let catalog = policy
            .endpoints(&state.node.node_id)
            .map_err(storage_error)?;
        Runtime {
            generation: None,
            configuration_revision: None,
            state: if catalog.proxy_running {
                "running"
            } else {
                "stopped"
            },
            error: None,
            listeners: catalog.listeners,
        }
    };
    Ok(Json(Status {
        node_id: state.node.node_id.clone(),
        mode,
        saved: saved.map(Saved::from),
        runtime,
    })
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    expected_node_id: String,
    controller_epoch: String,
    expected_revision: String,
    request_id: String,
    enabled: bool,
    configuration: proxy::settings::Configuration,
}
#[derive(Serialize)]
struct Submission {
    operation: Receipt,
    runtime: Runtime,
}

async fn change(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(request.uri())?;
    if state.schema_version < 27 {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        ));
    }
    let input: Change = json_with_limit(request, 10 * 1024).await?;
    if input.expected_node_id != state.node.node_id {
        return Err(ApiError::new(StatusCode::CONFLICT, "target_mismatch"));
    }
    if !store::valid_id(&input.request_id) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_request_id"));
    }
    input
        .configuration
        .encode()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_service_configuration"))?;
    let assertion = store::admission::Assertion {
        node_id: input.expected_node_id,
        epoch: users::revision(&input.controller_epoch)?,
    };
    let expected = users::revision(&input.expected_revision)?;
    let revision = expected
        .checked_add(1)
        .filter(|r| *r <= i64::MAX as u64)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "invalid_revision"))?;
    let request_id = input.request_id;
    let policy = policy(&state)?;
    let runtime = control(&policy)?
        .configure(
            actor.clone(),
            store::proxy_service::Request {
                assertion: assertion.clone(),
                expected_revision: expected,
                request_id: request_id.clone(),
                enabled: input.enabled,
                configuration: input.configuration,
            },
        )
        .await
        .map_err(storage_error)?;
    // This exact query cannot adopt another administrator's/latest operation.
    let original = policy
        .read(move |directory| {
            store::proxy_service::exact(directory, &actor, &assertion, revision, &request_id)
        })
        .await
        .map_err(storage_error)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(Submission {
            operation: receipt(&state.node.node_id, original),
            runtime: runtime.into(),
        }),
    )
        .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactQuery {
    controller_epoch: String,
}
async fn exact(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    path: Result<Path<(String, String)>, PathRejection>,
    query: Result<Query<ExactQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Path((revision, request_id)) =
        path.map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_request"))?;
    let Query(query) =
        query.map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_query"))?;
    if !store::valid_id(&request_id) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_request_id"));
    }
    let revision = users::revision(&revision)?;
    let assertion = store::admission::Assertion {
        node_id: state.node.node_id.clone(),
        epoch: users::revision(&query.controller_epoch)?,
    };
    let original = policy(&state)?
        .read(move |directory| {
            store::proxy_service::exact(directory, &actor, &assertion, revision, &request_id)
        })
        .await
        .map_err(storage_error)?;
    Ok(Json(receipt(&state.node.node_id, original)).into_response())
}
