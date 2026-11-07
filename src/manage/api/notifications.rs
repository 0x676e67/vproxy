//! Node-local browser settings only. No automation scope, peer authorization or
//! remote-control command grants permission to change this outbound authority.

use super::*;
use crate::manage::{
    notifications::{Change, Retry},
    store::notifications as storage,
};

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/notifications/webhook", get(status).post(change))
        .route("/api/v1/notifications/webhook/retry", post(retry))
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

fn coordinator(state: &AppState) -> Result<Arc<super::super::policy::Coordinator>, ApiError> {
    if state.schema_version < 23 {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        ));
    }
    state.policy.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    })
}
fn no_query(uri: &Uri) -> Result<(), ApiError> {
    if uri.query().is_some() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_webhook"));
    }
    Ok(())
}
fn failure(error: io::Error) -> ApiError {
    if let Some(error) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<storage::Error>())
    {
        let (status, code) = match error {
            storage::Error::Invalid => (StatusCode::BAD_REQUEST, "invalid_webhook"),
            storage::Error::Conflict => (StatusCode::CONFLICT, "webhook_changed"),
            storage::Error::Denied => (StatusCode::FORBIDDEN, "webhook_denied"),
            storage::Error::UpgradeRequired => (
                StatusCode::SERVICE_UNAVAILABLE,
                "management_upgrade_required",
            ),
        };
        return ApiError::new(status, code);
    }
    users::storage_error(error)
}
async fn status(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let view = coordinator(&state)?
        .read(move |directory| storage::status(directory, &actor))
        .await
        .map_err(failure)?;
    Ok(Json(view).into_response())
}
async fn change(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(request.uri())?;
    let input: Change = json(request).await?;
    let view = coordinator(&state)?
        .store_write(move |dir, gate| {
            crate::manage::store::notifications::change(dir, gate, &actor, &input)
        })
        .await
        .map_err(failure)?;
    Ok(Json(view).into_response())
}
async fn retry(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(request.uri())?;
    let input: Retry = json(request).await?;
    let view = coordinator(&state)?
        .store_write(move |dir, gate| {
            crate::manage::store::notifications::retry(dir, gate, &actor, &input)
        })
        .await
        .map_err(failure)?;
    Ok(Json(view).into_response())
}
