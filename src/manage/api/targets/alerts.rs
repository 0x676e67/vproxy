//! Session-only reads of one configured target, not a global poller. Session
//! lifetime is the browser authority; remote owner/DER and registration checks
//! remain current on either side. No error falls back to local or subset data.

use super::*;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/targets/{id}/egress-alerts", get(observations))
        .route("/api/v1/targets/{id}/operations-alerts", get(operations))
}

async fn operations(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let query = crate::manage::alerts::Query::parse(uri.query())
        .map_err(super::super::alerts::page_error)?;
    let peer = resource_id(path)?;
    match service(&state)?
        .remote(peer, control::Request::OperationsAlerts(query))
        .await
        .map_err(operations_error)?
    {
        control::Reply::OperationsAlerts(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

async fn observations(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let query = crate::manage::alerts::Query::parse(uri.query())
        .map_err(super::super::alerts::page_error)?;
    let peer = resource_id(path)?;
    match service(&state)?
        .remote(peer, control::Request::EgressAlerts(query))
        .await
        .map_err(remote_error)?
    {
        control::Reply::EgressAlerts(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

fn remote_error(error: io::Error) -> ApiError {
    if let Some(remote) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<control::RemoteError>())
    {
        return match (remote.status, remote.code) {
            (404, "node_protocol_unsupported") => {
                ApiError::new(StatusCode::BAD_GATEWAY, "egress_alerts_unsupported")
            }
            (409, "alerts_changed") => ApiError::new(StatusCode::CONFLICT, "alerts_changed"),
            (400, "invalid_alert_query") => {
                ApiError::new(StatusCode::BAD_REQUEST, "invalid_alert_query")
            }
            _ => super::remote_error(error),
        };
    }
    super::remote_error(error)
}

fn operations_error(error: io::Error) -> ApiError {
    if error
        .get_ref()
        .and_then(|e| e.downcast_ref::<control::RemoteError>())
        .is_some_and(|remote| remote.status == 404 && remote.code == "node_protocol_unsupported")
    {
        ApiError::new(StatusCode::BAD_GATEWAY, "operations_alerts_unsupported")
    } else {
        remote_error(error)
    }
}
