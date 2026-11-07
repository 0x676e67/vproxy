//! Version-five admission mode and managed operation observations. These reads
//! and commands retain the policy owner's exact mTLS authorization and shared
//! command sequence; neither active-operation zero nor a saved receipt means
//! that protocol drivers or transport buffers have drained.

use super::*;
use crate::manage::maintenance as model;

const VERSION: u8 = 5;
const PREFIX: &str = "/node/v5/proxy";

pub(in crate::manage) use crate::manage::store::MaintenanceMutation;

/// Fixed policy-domain command. Epoch, sequence and full-policy CAS are the
/// same durable namespace used by v1-v3; this is not a second runtime switch.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct MaintenanceCommand {
    pub(in crate::manage) version: u8,
    pub(in crate::manage) target_node_id: String,
    pub(in crate::manage) resource: String,
    pub(in crate::manage) controller_epoch: String,
    pub(in crate::manage) command_id: String,
    pub(in crate::manage) expected_policy_revision: String,
    pub(in crate::manage) source_administrator_id: String,
    pub(in crate::manage) mutation: MaintenanceMutation,
}

impl MaintenanceCommand {
    fn into_store(self) -> Result<store::Command, ApiError> {
        if self.version != VERSION
            || self.resource != RESOURCE
            || !valid_id(&self.target_node_id)
            || !valid_id(&self.source_administrator_id)
        {
            return Err(bad("invalid_command"));
        }
        Ok(store::Command {
            target_node_id: self.target_node_id,
            epoch: decimal(&self.controller_epoch, false)?,
            command_id: decimal(&self.command_id, false)?,
            expected_policy_revision: decimal(&self.expected_policy_revision, false)?,
            source_administrator_id: self.source_administrator_id,
            change: self.mutation.into(),
        })
    }
}

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/node/v5/proxy/maintenance", get(status))
        .route("/node/v5/proxy/commands", post(command))
        .route("/node/v5/proxy/receipts/{epoch}/{command_id}", get(receipt))
}

async fn status(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let status = coordinator(&state)?
        .maintenance(Some(peer.authorization()))
        .await
        .map_err(storage_error)?;
    status.validate(&state.node_id).map_err(storage_error)?;
    respond_version(VERSION, &state.node_id, StatusCode::OK, status)
}

async fn receipt(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    path: Result<Path<(String, String)>, axum::extract::rejection::PathRejection>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let Path((epoch, id)) = path.map_err(|_| bad("invalid_command"))?;
    let (epoch, id) = (decimal(&epoch, false)?, decimal(&id, false)?);
    let authorization = peer.authorization();
    let value = coordinator(&state)?
        .read(move |directory| store::receipt(directory, &authorization, epoch, id))
        .await
        .map_err(storage_error)?;
    if value.version != VERSION {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "resource_not_found"));
    }
    respond_version(
        VERSION,
        &state.node_id,
        StatusCode::OK,
        Receipt::from(value),
    )
}

async fn command(
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
    let input: MaintenanceCommand = api::json(request).await?;
    let result = coordinator(&state)?
        .command(peer.authorization(), input.into_store()?)
        .await
        .map_err(storage_error)?;
    let saved = result.receipt.status == store::ReceiptStatus::Saved;
    let location = format!(
        "{PREFIX}/receipts/{}/{}",
        result.receipt.epoch, result.receipt.command_id
    );
    let data = CommandReply {
        receipt: result.receipt.into(),
        replayed: result.replayed,
        user: None,
        credential: None,
        secret: None,
        secret_available: false,
        routing: None,
        presets: None,
    };
    let mut response = respond_version(
        VERSION,
        &state.node_id,
        if saved {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        },
        data,
    )?;
    if saved {
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&location).map_err(|_| ApiError::internal())?,
        );
    }
    Ok(response)
}

pub(super) fn encode(operation: &Request) -> io::Result<(Method, String, Vec<u8>)> {
    match operation {
        Request::Maintenance => Ok((Method::GET, format!("{PREFIX}/maintenance"), Vec::new())),
        Request::MaintenanceCommand(command) => {
            command
                .clone()
                .into_store()
                .map_err(|_| invalid("invalid maintenance command"))?;
            let body = serde_json::to_vec(command)
                .map_err(|_| invalid("cannot encode maintenance command"))?;
            if body.len() > 4096 {
                return Err(invalid("maintenance command exceeds input limit"));
            }
            Ok((Method::POST, format!("{PREFIX}/commands"), body))
        }
        _ => Err(invalid("invalid maintenance operation")),
    }
}

pub(super) fn decode(
    operation: &Request,
    bytes: &[u8],
    peer: &str,
    status: StatusCode,
) -> io::Result<Reply> {
    match operation {
        Request::Maintenance => {
            if status != StatusCode::OK {
                return Err(invalid("invalid maintenance status response"));
            }
            let value: model::Status = client::envelope(bytes, peer, VERSION)?;
            value.validate(peer)?;
            Ok(Reply::Maintenance(Box::new(value)))
        }
        Request::MaintenanceCommand(command) => {
            let mut value: CommandReply = client::envelope(bytes, peer, VERSION)?;
            value.receipt.version = VERSION;
            client::validate_receipt(&value.receipt)?;
            if value.receipt.controller_epoch != command.controller_epoch
                || value.receipt.command_id != command.command_id
                || status
                    != if value.receipt.status == ReceiptStatus::Saved {
                        StatusCode::ACCEPTED
                    } else {
                        StatusCode::OK
                    }
                || value.user.is_some()
                || value.credential.is_some()
                || value.secret.is_some()
                || value.secret_available
                || value.routing.is_some()
                || value.presets.is_some()
            {
                return Err(invalid("invalid maintenance command result"));
            }
            if value.receipt.status != ReceiptStatus::Rejected {
                let revision = client::number(&command.expected_policy_revision, false)?
                    .checked_add(1)
                    .filter(|value| *value <= i64::MAX as u64)
                    .ok_or_else(|| invalid("maintenance policy revision exhausted"))?;
                if value
                    .receipt
                    .policy_revision
                    .as_deref()
                    .map(|value| client::number(value, false))
                    .transpose()?
                    != Some(revision)
                {
                    return Err(invalid("maintenance receipt differs from policy CAS"));
                }
            }
            Ok(Reply::Command(Box::new(value)))
        }
        _ => Err(invalid("unsupported maintenance response")),
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn storage_error(error: io::Error) -> ApiError {
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<store::admission::Error>())
    {
        return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error.code());
    }
    super::storage_error(error)
}
