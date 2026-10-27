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
        .notifications_write(move |writer| writer.change(&actor, &input))
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
        .notifications_write(move |writer| writer.retry(&actor, &input))
        .await
        .map_err(failure)?;
    Ok(Json(view).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::api::tests::{call, managed_state, request};
    use http_body_util::BodyExt as _;

    #[tokio::test]
    async fn settings_require_session_csrf_and_redact_destination() {
        let (_directory, state, cookie) = managed_state();
        let path = "/api/v1/notifications/webhook";
        assert_eq!(
            call(state.clone(), request(Method::GET, path, ""))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut read = request(Method::GET, path, "");
        read.headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        let response = call(state.clone(), read).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let view: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(view["enabled"], false);
        assert!(view.get("url").is_none());
        let input = serde_json::json!({"expected_node_id":view["node_id"],"expected_revision":"0","operation_id":URL_SAFE_NO_PAD.encode([1u8;16]),"enabled":true,"automatic_retry":false,"url":"https://hooks.example/private?key=secret","bearer":"fake-token","clear_bearer":false,"clear_destination":false,"discard_pending":false}).to_string();
        let mut write = request(Method::POST, path, &input);
        write
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(
            call(state.clone(), write).await.status(),
            StatusCode::FORBIDDEN
        );
        let mut write = request(Method::POST, path, &input);
        write
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        write
            .headers_mut()
            .insert("x-csrf-token", "c".repeat(43).parse().unwrap());
        let response = call(state, write).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        for private in ["hooks.example", "private?key", "fake-token"] {
            assert!(!text.contains(private));
        }
    }
}
