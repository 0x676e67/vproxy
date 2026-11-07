//! Explicit Session/CSRF-only maintenance. Automation user permissions do not
//! authorize node-wide admission changes, and no endpoint waits for a drain.

use super::*;
use crate::manage::{policy::Coordinator, store};

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/proxy/maintenance", get(status).post(change))
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

fn coordinator(state: &AppState) -> Result<Arc<Coordinator>, ApiError> {
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

fn storage_error(error: io::Error) -> ApiError {
    super::runtime::storage_error(error)
}

async fn status(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let value = coordinator(&state)?
        .maintenance(None)
        .await
        .map_err(storage_error)?;
    value.validate(&state.node.node_id).map_err(storage_error)?;
    Ok(Json(value).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    expected_node_id: String,
    expected_revision: String,
    expected_epoch: String,
    accepting: bool,
}

/// Publication receipt for this mutation, not a new count observation. Runtime
/// data must be requested explicitly after the user receives this answer.
#[derive(Serialize)]
struct Change {
    saved_revision: String,
    applied_revision: Option<String>,
    running: bool,
}

async fn change(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(administrator)): Extension<users::Administrator>,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(request.uri())?;
    let input: Input = json(request).await?;
    if input.expected_node_id != state.node.node_id {
        return Err(ApiError::new(StatusCode::CONFLICT, "target_mismatch"));
    }
    let result = coordinator(&state)?
        .change_admission(
            administrator,
            users::revision(&input.expected_revision)?,
            store::admission::Assertion {
                node_id: input.expected_node_id,
                epoch: users::revision(&input.expected_epoch)?,
            },
            input.accepting,
        )
        .await
        .map_err(storage_error)?;
    Ok(Json(Change {
        saved_revision: result.revision.to_string(),
        applied_revision: result.running.then(|| result.revision.to_string()),
        running: result.running,
    })
    .into_response())
}
