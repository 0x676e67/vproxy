//! The dedicated witness binding, not proxy-owner authority. Uses the existing
//! mandatory-mTLS router, bounded coordinator and per-transaction peer checks.
//! There is no remote enrollment, retirement or takeover endpoint.

use super::*;
use crate::manage::witness::{Error, Transition};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    routing::{get, post},
};

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/node/v1/witness/bindings/{binding}", get(inspect))
        .route("/node/v1/witness/reserve", post(reserve))
        .route("/node/v1/witness/confirm", post(confirm))
}

fn coordinator(state: &AppState) -> Result<&Arc<Coordinator>, ApiError> {
    state
        .policy
        .as_ref()
        .ok_or_else(|| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "witness_unavailable"))
}
fn no_query(uri: &http::Uri) -> Result<(), ApiError> {
    if uri.query().is_some() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_query"));
    }
    Ok(())
}
fn error(error: io::Error) -> ApiError {
    if let Some(domain) = error.get_ref().and_then(|e| e.downcast_ref::<Error>()) {
        let (status, code) = match domain {
            Error::Invalid => (StatusCode::BAD_REQUEST, "witness_invalid"),
            Error::Conflict => (StatusCode::CONFLICT, "witness_conflict"),
            Error::Denied => (StatusCode::FORBIDDEN, "witness_denied"),
            Error::UpgradeRequired => (StatusCode::SERVICE_UNAVAILABLE, "witness_upgrade_required"),
            Error::Capacity => (StatusCode::CONFLICT, "witness_capacity"),
        };
        return ApiError::new(status, code);
    }
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        if error.kind() == io::ErrorKind::WouldBlock {
            "witness_busy"
        } else {
            "witness_unavailable"
        },
    )
}

async fn inspect(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    path: Result<Path<String>, axum::extract::rejection::PathRejection>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let Path(binding) =
        path.map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "witness_invalid"))?;
    let authorization = peer.authorization();
    let value = coordinator(&state)?
        .witness_inspect(authorization, binding)
        .await
        .map_err(error)?;
    Ok(Json(value).into_response())
}

async fn reserve(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    request: Request,
) -> Result<Response, ApiError> {
    transition(state, peer, request, false).await
}
async fn confirm(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    request: Request,
) -> Result<Response, ApiError> {
    transition(state, peer, request, true).await
}

/// Cancellation before admission submits nothing. After admission the blocking
/// worker owns the directory author, writer slot and update gate through COMMIT;
/// a timeout may therefore have an unknown result, resolved by the exact tuple.
async fn transition(
    state: Arc<AppState>,
    peer: VerifiedPeer,
    request: Request,
    confirm: bool,
) -> Result<Response, ApiError> {
    no_query(request.uri())?;
    let mut types = request.headers().get_all(header::CONTENT_TYPE).iter();
    if !types
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
        || types.next().is_some()
    {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "json_required",
        ));
    }
    let input: Transition = api::json(request).await?;
    input.validate().map_err(error)?;
    let authorization = peer.authorization();
    let value = coordinator(&state)?
        .witness_transition(authorization, input, confirm)
        .await
        .map_err(error)?;
    Ok(Json(value).into_response())
}
