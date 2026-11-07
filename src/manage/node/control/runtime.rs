//! Version-six process-local listener control. No policy command sequence or
//! durable receipt is consumed; recovery reads the original runtime/request.

use super::*;
use crate::manage::{drain as model, proxy};

const VERSION: u8 = 6;
const RESOURCE: &str = "proxy_runtime";
const PREFIX: &str = "/node/v6/proxy/runtime";

/// An authenticated controller's administrator claim accompanies one exact
/// target/runtime request. It never authenticates a target-local administrator.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct RuntimeDrain {
    pub(in crate::manage) version: u8,
    pub(in crate::manage) resource: String,
    pub(in crate::manage) source_administrator_id: String,
    pub(in crate::manage) request: model::Request,
}

impl RuntimeDrain {
    fn validate(&self) -> io::Result<()> {
        if self.version != VERSION
            || self.resource != RESOURCE
            || !valid_id(&self.source_administrator_id)
        {
            return Err(invalid("invalid runtime drain command"));
        }
        self.request.numbers()?;
        Ok(())
    }
}

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/node/v6/proxy/runtime", get(status))
        .route("/node/v6/proxy/runtime/drain", post(start))
        .route(
            "/node/v6/proxy/runtime/drains/{runtime_id}/{request_id}",
            get(original),
        )
}

async fn status(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let value = coordinator(&state)?
        .remote_runtime_status(peer.authorization(), None)
        .await
        .map_err(storage_error)?;
    value.validate(&state.node_id).map_err(storage_error)?;
    respond_resource(VERSION, RESOURCE, &state.node_id, StatusCode::OK, value)
}

async fn original(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    path: Result<Path<(String, String)>, axum::extract::rejection::PathRejection>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let Path((runtime_id, request_id)) = path.map_err(|_| bad("invalid_request"))?;
    if !valid_id(&runtime_id) || !valid_id(&request_id) {
        return Err(bad("invalid_request"));
    }
    let value = coordinator(&state)?
        .remote_runtime_status(peer.authorization(), Some((runtime_id, request_id)))
        .await
        .map_err(storage_error)?;
    value.validate(&state.node_id).map_err(storage_error)?;
    respond_resource(VERSION, RESOURCE, &state.node_id, StatusCode::OK, value)
}

async fn start(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    request: axum::extract::Request,
) -> Result<Response, ApiError> {
    no_query(request.uri())?;
    let mut types = request.headers().get_all(header::CONTENT_TYPE).iter();
    if !types
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
        || types.next().is_some()
    {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "json_required",
        ));
    }
    let input: RuntimeDrain = api::json(request).await?;
    input.validate().map_err(|_| bad("invalid_request"))?;
    if input.request.expected_node_id != state.node_id {
        return Err(ApiError::new(StatusCode::CONFLICT, "target_mismatch"));
    }
    // The coordinator rechecks this peer's current owner/DER, asserted epoch,
    // paused revision and actual runtime before the process-local transition.
    let value = coordinator(&state)?
        .request_remote_drain(
            peer.authorization(),
            input.source_administrator_id,
            input.request,
        )
        .await
        .map_err(storage_error)?;
    value.validate(&state.node_id).map_err(storage_error)?;
    respond_resource(
        VERSION,
        RESOURCE,
        &state.node_id,
        StatusCode::ACCEPTED,
        value,
    )
}

pub(super) fn encode(operation: &Request) -> io::Result<(Method, String, Vec<u8>)> {
    match operation {
        Request::Runtime => Ok((Method::GET, PREFIX.into(), Vec::new())),
        Request::RuntimeDrainStatus {
            runtime_id,
            request_id,
        } => {
            if !valid_id(runtime_id) || !valid_id(request_id) {
                return Err(invalid("invalid original runtime request"));
            }
            Ok((
                Method::GET,
                format!("{PREFIX}/drains/{runtime_id}/{request_id}"),
                Vec::new(),
            ))
        }
        Request::RuntimeDrain(command) => {
            command.validate()?;
            let body = serde_json::to_vec(command)
                .map_err(|_| invalid("cannot encode runtime drain command"))?;
            if body.len() > 4096 {
                return Err(invalid("runtime drain command exceeds input limit"));
            }
            Ok((Method::POST, format!("{PREFIX}/drain"), body))
        }
        _ => Err(invalid("invalid runtime operation")),
    }
}

pub(super) fn decode(
    operation: &Request,
    bytes: &[u8],
    peer: &str,
    status: StatusCode,
) -> io::Result<Reply> {
    let expected_status = match operation {
        Request::RuntimeDrain(_) => StatusCode::ACCEPTED,
        Request::Runtime | Request::RuntimeDrainStatus { .. } => StatusCode::OK,
        _ => return Err(invalid("invalid runtime response operation")),
    };
    if status != expected_status {
        return Err(invalid("invalid runtime response status"));
    }
    let envelope: Envelope<model::Status> =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid runtime response"))?;
    if envelope.version != VERSION || envelope.resource != RESOURCE || envelope.node_id != peer {
        return Err(invalid("runtime response changed protocol or target"));
    }
    let value = envelope.data;
    value.validate(peer)?;
    match operation {
        Request::Runtime => {}
        Request::RuntimeDrain(command) => {
            command.validate()?;
            if command.request.expected_node_id != peer
                || value
                    .runtime
                    .as_ref()
                    .and_then(|runtime| runtime.request.as_ref())
                    != Some(&command.request)
            {
                return Err(invalid(
                    "runtime response differs from original drain intent",
                ));
            }
        }
        Request::RuntimeDrainStatus {
            runtime_id,
            request_id,
        } => {
            if !valid_id(runtime_id)
                || !valid_id(request_id)
                || value.runtime.as_ref().is_none_or(|runtime| {
                    runtime.runtime_id != *runtime_id
                        || runtime
                            .request
                            .as_ref()
                            .is_none_or(|request| request.request_id != *request_id)
                })
            {
                return Err(invalid("runtime response differs from original request"));
            }
        }
        _ => return Err(invalid("unsupported runtime response")),
    }
    Ok(Reply::Runtime(Box::new(value)))
}

fn storage_error(error: io::Error) -> ApiError {
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<model::Error>())
    {
        return ApiError::new(StatusCode::CONFLICT, error.code());
    }
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<proxy::Error>())
    {
        return ApiError::new(
            StatusCode::CONFLICT,
            match error {
                proxy::Error::RuntimeChanged => "proxy_runtime_changed",
                proxy::Error::AlreadyDraining => "proxy_already_draining",
                proxy::Error::Stopping => "proxy_runtime_stopping",
            },
        );
    }
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<store::admission::Error>())
    {
        return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error.code());
    }
    super::storage_error(error)
}

/// Only v6 interprets these fixed pre-transition refusals. An old protocol or a
/// different HTTP status must not acquire new diagnostic semantics implicitly.
pub(super) fn rejection_code(status: StatusCode, bytes: &[u8]) -> Option<&'static str> {
    if status != StatusCode::CONFLICT {
        return None;
    }
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
    let body: ErrorBody = serde_json::from_slice(bytes).ok()?;
    match body.error.code.as_str() {
        "proxy_runtime_changed" => Some("proxy_runtime_changed"),
        "proxy_already_draining" => Some("proxy_already_draining"),
        "proxy_runtime_stopping" => Some("proxy_runtime_stopping"),
        "proxy_runtime_unavailable" => Some("proxy_runtime_unavailable"),
        "proxy_admission_not_paused" => Some("proxy_admission_not_paused"),
        "proxy_policy_unavailable" => Some("proxy_policy_unavailable"),
        "proxy_restart_required" => Some("proxy_restart_required"),
        _ => None,
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
