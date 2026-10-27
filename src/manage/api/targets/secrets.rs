//! Session/CSRF-only current password read, never an operation or automation.

use super::*;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new().route(
        "/api/v1/targets/{id}/proxy/credentials/{credential}/secret",
        post(reveal),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    expected_node_id: String,
    expected_target_revision: String,
    user_id: String,
    controller_epoch: String,
    verifier_revision: String,
}

async fn reveal(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<(String, String)>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(request.uri())?;
    let (peer, credential) = routing::resource_pair(path)?;
    let input: Input = json(request).await?;
    if input.expected_node_id != peer {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_proxy_secret",
        ));
    }
    let selected = control::CredentialSecretRead::new(
        peer,
        input.user_id,
        credential,
        input.controller_epoch,
        input.verifier_revision,
    )
    .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_proxy_secret"))?;
    let value = service(&state)?
        .credential_secret(actor, revision(&input.expected_target_revision)?, selected)
        .await
        .map_err(remote_error)?;
    #[derive(Serialize)]
    struct Output<'a> {
        credential_id: &'a str,
        user_id: &'a str,
        verifier_revision: &'a str,
        secret: &'a str,
    }
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(Output {
            credential_id: &value.credential_id,
            user_id: &value.user_id,
            verifier_revision: &value.verifier_revision,
            secret: &value.secret,
        }),
    )
        .into_response())
}
