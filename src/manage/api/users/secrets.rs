//! Explicit current-generation disclosure, never part of credential listings,
//! automation, operation replay or a URL query. Session/CSRF and the durable
//! local-owner check are both required; a read cannot rotate credentials.

use super::*;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/v1/proxy/credentials/{id}/secret", post(reveal))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    expected_node_id: String,
    controller_epoch: String,
    verifier_revision: String,
}

async fn reveal(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    if request.uri().query().is_some() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_proxy_secret",
        ));
    }
    let id = resource_id(path)?;
    let input: Input = json(request).await?;
    if !store::valid_id(&input.expected_node_id) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_proxy_secret",
        ));
    }
    let assertion = store::admission::Assertion {
        node_id: input.expected_node_id,
        epoch: revision(&input.controller_epoch)?,
    };
    let generation = revision(&input.verifier_revision)?;
    let result = coordinator(&state)?
        .read(move |directory| {
            store::secrets::reveal(directory, &actor, &assertion, &id, generation)
        })
        .await
        .map_err(storage_error)?;
    #[derive(Serialize)]
    struct Output<'a> {
        credential_id: &'a str,
        user_id: &'a str,
        verifier_revision: String,
        secret: &'a str,
    }
    // Json serializes synchronously before the zeroizing owner is dropped.
    // The outer request guard also prevents HTTP/Origin/cache misuse.
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(Output {
            credential_id: &result.credential_id,
            user_id: &result.user_id,
            verifier_revision: result.verifier_revision.to_string(),
            secret: &result.value,
        }),
    )
        .into_response())
}
