//! Session-only snapshot of this process's browser HTTPS certificate state.
//!
//! Reads never inspect the ACME cache, contact a CA, or trigger an attempt. The
//! supervisor owns the bounded in-memory view; manual TLS exposes only its mode.

use super::*;
use crate::manage::acme::View;

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/tls/acme", get(status))
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

async fn status(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    if uri.query().is_some() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_query"));
    }
    let view = match &state.acme {
        Some(handle) => handle.view().map_err(|_| unavailable())?,
        None => View::manual(),
    };
    Ok(Json(view).into_response())
}

fn unavailable() -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "acme_status_unavailable")
}
