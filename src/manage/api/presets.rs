//! Browser access to finite preset policy. Runtime availability and stored
//! grants are separate facts; saving a grant never loads privileged programs.

use axum::extract::{Path, rejection::PathRejection};

use super::{
    users::{Administrator, resource_id, revision, storage_error},
    *,
};
use crate::{
    access::presets::{PoolPreset, PresetEntity, UserPreset},
    manage::{
        node::control,
        policy::Coordinator,
        store::{self, PolicyChange},
    },
};

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/proxy/presets", get(catalog))
        .route("/api/v1/proxy/users/{id}/presets", get(user).put(set_user))
        .route("/api/v1/proxy/pools/{id}/presets", get(pool).put(set_pool))
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
        Err(bad())
    } else {
        Ok(())
    }
}

async fn catalog(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let config = state
        .policy
        .as_ref()
        .and_then(|policy| policy.preset_config());
    Ok(Json(control::preset_catalog(&state.node.node_id, config)).into_response())
}

async fn user(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let (revision, presets) = coordinator(&state)?
        .read(move |directory| store::presets::user_presets(directory, &id))
        .await
        .map_err(storage_error)?;
    Ok(Json(control::UserPresetsView {
        revision: revision.to_string(),
        presets,
    })
    .into_response())
}

async fn pool(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let (revision, preset) = coordinator(&state)?
        .read(move |directory| store::presets::pool_preset(directory, &id))
        .await
        .map_err(storage_error)?;
    Ok(Json(control::PoolPresetView {
        revision: revision.to_string(),
        preset,
    })
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserInput {
    expected_revision: String,
    presets: UserPreset,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolInput {
    expected_revision: String,
    preset: PoolPreset,
}

async fn set_user(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let input: UserInput = json(request).await?;
    if input.presets.user_id != id {
        return Err(bad());
    }
    let change = coordinator(&state)?
        .change(
            actor,
            revision(&input.expected_revision)?,
            PolicyChange::SetUserPresets {
                presets: input.presets,
            },
        )
        .await
        .map_err(storage_error)?;
    let Some(PresetEntity::User(presets)) = change.presets else {
        return Err(ApiError::internal());
    };
    Ok(Json(control::UserPresetsView {
        revision: change.revision.to_string(),
        presets,
    })
    .into_response())
}

async fn set_pool(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let input: PoolInput = json(request).await?;
    if input.preset.pool_id != id {
        return Err(bad());
    }
    let change = coordinator(&state)?
        .change(
            actor,
            revision(&input.expected_revision)?,
            PolicyChange::SetPoolPreset {
                preset: input.preset,
            },
        )
        .await
        .map_err(storage_error)?;
    let Some(PresetEntity::Pool(preset)) = change.presets else {
        return Err(ApiError::internal());
    };
    Ok(Json(control::PoolPresetView {
        revision: change.revision.to_string(),
        preset,
    })
    .into_response())
}

fn bad() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid_policy")
}
