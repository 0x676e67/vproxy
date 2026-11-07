//! Live operations incidents and separate durable event history. Reads perform
//! no collection or remediation; an explicit acknowledgement only records review.

use super::*;
use crate::manage::alerts::{PageError, Query};

mod history;

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .merge(history::routes())
        .route("/api/v1/alerts", get(observations))
        .route("/api/v1/operations-alerts", get(node_observations))
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

/// Only this resource's state and cursor are accepted. A cursor belongs to one
/// boot, filter and evidence revision, not the inventory/search pagination APIs.
fn query(uri: &Uri) -> Result<Query, ApiError> {
    Query::parse(uri.query()).map_err(page_error)
}

async fn observations(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    let query = query(&uri)?;
    let monitor = state.alerts.as_ref().ok_or_else(unavailable)?;
    let page = monitor
        .page(query.filter, query.after.as_deref(), query.limit)
        .map_err(page_error)?;
    Ok(Json(page).into_response())
}

/// The fleet's local card uses the same own-node projection as remote cards;
/// cached observations about managed peers must not inflate its incident count.
async fn node_observations(
    State(state): State<Arc<AppState>>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let query = query(&uri)?;
    let monitor = state.alerts.as_ref().ok_or_else(unavailable)?;
    let page = monitor
        .node_page(query.filter, query.after.as_deref(), query.limit)
        .map_err(page_error)?;
    Ok(Json(page).into_response())
}

fn invalid() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid_alert_query")
}

fn unavailable() -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "alerts_unavailable")
}

pub(super) fn page_error(error: PageError) -> ApiError {
    match error {
        PageError::InvalidQuery => invalid(),
        PageError::Changed => ApiError::new(StatusCode::CONFLICT, "alerts_changed"),
        PageError::Unavailable => unavailable(),
    }
}
