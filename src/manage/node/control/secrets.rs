//! Current-generation disclosure to the authenticated policy owner. No command,
//! receipt or snapshot stores this response; cancellation discards plaintext.

use super::*;
use axum::extract::{Path, rejection::PathRejection};

const VERSION: u8 = 7;
const RESOURCE: &str = "proxy_credential_secret";
const PREFIX: &str = "/node/v7/proxy/credentials";
pub(super) const RESPONSE_BYTES: usize = 2048;

/// Fixed non-secret selection, constructed only from a source administrator's
/// explicit request. User, credential, epoch and generation cannot be inferred
/// from a recent command or a reusable URL capability.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct CredentialSecretRead {
    pub(in crate::manage) version: u8,
    pub(in crate::manage) resource: String,
    pub(in crate::manage) target_node_id: String,
    pub(in crate::manage) user_id: String,
    pub(in crate::manage) credential_id: String,
    pub(in crate::manage) controller_epoch: String,
    pub(in crate::manage) verifier_revision: String,
}

impl CredentialSecretRead {
    pub(in crate::manage) fn new(
        target_node_id: String,
        user_id: String,
        credential_id: String,
        controller_epoch: String,
        verifier_revision: String,
    ) -> io::Result<Self> {
        let input = Self {
            version: VERSION,
            resource: RESOURCE.into(),
            target_node_id,
            user_id,
            credential_id,
            controller_epoch,
            verifier_revision,
        };
        input.numbers()?;
        Ok(input)
    }

    pub(in crate::manage) fn numbers(&self) -> io::Result<(u64, u64)> {
        if self.version != VERSION
            || self.resource != RESOURCE
            || ![&self.target_node_id, &self.user_id, &self.credential_id]
                .into_iter()
                .all(|id| valid_id(id))
        {
            return Err(invalid("invalid proxy secret selection"));
        }
        Ok((
            client::number(&self.controller_epoch, false)?,
            client::number(&self.verifier_revision, false)?,
        ))
    }
}

/// One transient reply, deliberately without Debug or Clone. The original
/// owned JSON string moves directly into its zeroizing owner on decode.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct CredentialSecret {
    pub(in crate::manage) credential_id: String,
    pub(in crate::manage) user_id: String,
    pub(in crate::manage) controller_epoch: String,
    pub(in crate::manage) verifier_revision: String,
    #[serde(
        serialize_with = "serialize_value",
        deserialize_with = "deserialize_value"
    )]
    pub(in crate::manage) secret: Zeroizing<String>,
}

fn serialize_value<S: serde::Serializer>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value.as_str().serialize(serializer)
}
fn deserialize_value<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/node/v7/proxy/credentials/{id}/secret", post(reveal))
}

async fn reveal(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    path: Result<Path<String>, PathRejection>,
    request: axum::extract::Request,
) -> Result<Response, ApiError> {
    no_query(request.uri())?;
    let Path(id) = path.map_err(|_| bad("invalid_proxy_secret"))?;
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
    let input: CredentialSecretRead = api::json(request).await?;
    let (epoch, generation) = input.numbers().map_err(|_| bad("invalid_proxy_secret"))?;
    if input.target_node_id != state.node_id || input.credential_id != id {
        return Err(ApiError::new(StatusCode::CONFLICT, "target_mismatch"));
    }
    let authorization = peer.authorization();
    let assertion = store::admission::Assertion {
        node_id: input.target_node_id,
        epoch,
    };
    let value = coordinator(&state)?
        .read(move |directory| {
            store::secrets::reveal_remote(
                directory,
                &authorization,
                &assertion,
                &input.user_id,
                &id,
                generation,
            )
        })
        .await
        .map_err(storage_error)?;
    let mut response = respond_resource_limited(
        VERSION,
        RESOURCE,
        &state.node_id,
        StatusCode::OK,
        CredentialSecret {
            credential_id: value.credential_id,
            user_id: value.user_id,
            controller_epoch: epoch.to_string(),
            verifier_revision: value.verifier_revision.to_string(),
            secret: value.value,
        },
        RESPONSE_BYTES,
    )?;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub(super) fn encode(input: &CredentialSecretRead) -> io::Result<(Method, String, Vec<u8>)> {
    input.numbers()?;
    let body =
        serde_json::to_vec(input).map_err(|_| invalid("cannot encode proxy secret selection"))?;
    if body.len() > RESPONSE_BYTES {
        return Err(invalid("proxy secret selection exceeds its limit"));
    }
    Ok((
        Method::POST,
        format!("{PREFIX}/{}/secret", input.credential_id),
        body,
    ))
}

pub(super) fn decode(
    input: &CredentialSecretRead,
    bytes: &[u8],
    expected: &str,
) -> io::Result<Reply> {
    input.numbers()?;
    let value: Envelope<CredentialSecret> =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid proxy secret response"))?;
    let mut decoded = Zeroizing::new([0u8; 32]);
    if value.version != VERSION
        || value.resource != RESOURCE
        || value.node_id != expected
        || expected != input.target_node_id
        || value.data.credential_id != input.credential_id
        || value.data.user_id != input.user_id
        || value.data.controller_epoch != input.controller_epoch
        || value.data.verifier_revision != input.verifier_revision
        || value.data.secret.len() != 43
        || !matches!(
            URL_SAFE_NO_PAD.decode_slice(value.data.secret.as_bytes(), &mut *decoded),
            Ok(32)
        )
    {
        return Err(invalid(
            "proxy secret response changed its selected identity",
        ));
    }
    Ok(Reply::CredentialSecret(value.data))
}

/// Only fixed status/code pairs escape a peer's untrusted error body.
pub(super) fn rejection_code(status: StatusCode, bytes: &[u8]) -> Option<&'static str> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Detail {
        code: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ErrorBody {
        error: Detail,
    }
    let value: ErrorBody = serde_json::from_slice(bytes).ok()?;
    match (status, value.error.code.as_str()) {
        (StatusCode::CONFLICT, "credential_secret_not_saved") => {
            Some("credential_secret_not_saved")
        }
        (StatusCode::CONFLICT, "credential_secret_changed") => Some("credential_secret_changed"),
        (StatusCode::SERVICE_UNAVAILABLE, "credential_secret_key_unavailable") => {
            Some("credential_secret_key_unavailable")
        }
        (StatusCode::SERVICE_UNAVAILABLE, "credential_secret_invalid") => {
            Some("credential_secret_invalid")
        }
        (StatusCode::SERVICE_UNAVAILABLE, "management_upgrade_required") => {
            Some("management_upgrade_required")
        }
        _ => None,
    }
}

fn storage_error(error: io::Error) -> ApiError {
    if let Some(cause) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<store::secrets::Error>())
    {
        use store::secrets::Error;
        let (status, code) = match cause {
            Error::UpgradeRequired => (
                StatusCode::SERVICE_UNAVAILABLE,
                "management_upgrade_required",
            ),
            Error::NotSaved => (StatusCode::CONFLICT, "credential_secret_not_saved"),
            Error::Changed => (StatusCode::CONFLICT, "credential_secret_changed"),
            Error::KeyUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "credential_secret_key_unavailable",
            ),
            Error::Invalid => (StatusCode::SERVICE_UNAVAILABLE, "credential_secret_invalid"),
        };
        return ApiError::new(status, code);
    }
    super::storage_error(error)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_reply_is_bound_to_every_selection_and_has_no_generic_fallback() {
        let id = |byte| URL_SAFE_NO_PAD.encode([byte; 16]);
        let input = CredentialSecretRead::new(id(1), id(2), id(3), "2".into(), "4".into()).unwrap();
        let (method, path, body) = encode(&input).unwrap();
        assert_eq!(method, Method::POST);
        assert_eq!(path, format!("{PREFIX}/{}/secret", id(3)));
        assert!(!String::from_utf8(body).unwrap().contains("secret\":"));
        let valid = serde_json::json!({
            "version":7,"resource":RESOURCE,"node_id":id(1),"data":{
                "credential_id":id(3),"user_id":id(2),"controller_epoch":"2",
                "verifier_revision":"4","secret":URL_SAFE_NO_PAD.encode([0u8;32])
            }
        });
        let decode_value =
            |value: &serde_json::Value| decode(&input, &serde_json::to_vec(value).unwrap(), &id(1));
        assert!(matches!(
            decode_value(&valid).unwrap(),
            Reply::CredentialSecret(_)
        ));
        for (field, replacement) in [
            ("credential_id", id(4)),
            ("user_id", id(4)),
            ("controller_epoch", "3".into()),
            ("verifier_revision", "5".into()),
            ("secret", "A".repeat(42) + "B"),
            ("secret", "short".into()),
            ("extra", "forbidden".into()),
        ] {
            let mut changed = valid.clone();
            changed["data"][field] = replacement.into();
            assert!(
                decode_value(&changed).is_err(),
                "accepted substituted {field}"
            );
        }
        for (field, value) in [
            ("version", serde_json::json!(6)),
            ("resource", "proxy_policy".into()),
            ("node_id", id(4).into()),
        ] {
            let mut changed = valid.clone();
            changed[field] = value;
            assert!(decode_value(&changed).is_err());
        }
        assert!(CredentialSecretRead::new(id(1), id(2), id(3), "02".into(), "4".into()).is_err());
        assert!(CredentialSecretRead::new(id(1), id(2), id(3), "2".into(), "0".into()).is_err());
        let mut selection = serde_json::to_value(&input).unwrap();
        selection["source_administrator_id"] = id(4).into();
        assert!(serde_json::from_value::<CredentialSecretRead>(selection).is_err());
    }

    #[test]
    fn secret_error_codes_never_echo_peer_diagnostics_or_mismatched_status() {
        for (status, code) in [
            (StatusCode::CONFLICT, "credential_secret_not_saved"),
            (StatusCode::CONFLICT, "credential_secret_changed"),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "credential_secret_key_unavailable",
            ),
            (StatusCode::SERVICE_UNAVAILABLE, "credential_secret_invalid"),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "management_upgrade_required",
            ),
        ] {
            let bytes = serde_json::to_vec(&serde_json::json!({"error":{"code":code}})).unwrap();
            assert_eq!(rejection_code(status, &bytes), Some(code));
            assert_eq!(rejection_code(StatusCode::UNAUTHORIZED, &bytes), None);
            let error = client::remote_error(status, &bytes, VERSION);
            assert_eq!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<client::RemoteError>()
                    .unwrap()
                    .code,
                code
            );
        }
        assert_eq!(
            rejection_code(
                StatusCode::SERVICE_UNAVAILABLE,
                br#"{"error":{"code":"credential_secret_invalid","secret":"private"}}"#
            ),
            None
        );
        let unsupported = client::remote_error(
            StatusCode::NOT_FOUND,
            br#"{"error":{"code":"not_found"}}"#,
            VERSION,
        );
        assert_eq!(
            unsupported
                .get_ref()
                .unwrap()
                .downcast_ref::<client::RemoteError>()
                .unwrap()
                .code,
            "node_protocol_unsupported"
        );
    }
}
