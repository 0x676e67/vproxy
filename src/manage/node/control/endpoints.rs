//! Version-four public endpoint metadata; authority remains the node's existing
//! exact-DER owner domain, while metadata revisions never activate the proxy.

use super::*;
use crate::manage::{
    proxy::SettingsCatalog,
    store::{
        endpoint_control as durable,
        endpoints::{AddressSelection, Change},
    },
};

const VERSION: u8 = 4;
const RESOURCE: &str = "proxy_endpoints";
pub(in crate::manage) const SETTINGS_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Mutation {
    pub(in crate::manage) listener_id: String,
    pub(in crate::manage) generation: String,
    pub(in crate::manage) selection: AddressSelection,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Command {
    pub(in crate::manage) version: u8,
    pub(in crate::manage) target_node_id: String,
    pub(in crate::manage) resource: String,
    pub(in crate::manage) controller_epoch: String,
    pub(in crate::manage) command_id: String,
    pub(in crate::manage) expected_metadata_revision: String,
    pub(in crate::manage) source_administrator_id: String,
    pub(in crate::manage) mutation: Mutation,
}
impl From<durable::Command> for Command {
    fn from(value: durable::Command) -> Self {
        Self {
            version: VERSION,
            resource: RESOURCE.into(),
            target_node_id: value.target_node_id,
            controller_epoch: value.epoch.to_string(),
            command_id: value.command_id.to_string(),
            expected_metadata_revision: value.expected_metadata_revision.to_string(),
            source_administrator_id: value.source_administrator_id,
            mutation: Mutation {
                listener_id: value.change.listener_id,
                generation: value.generation,
                selection: value.change.selection,
            },
        }
    }
}
impl Command {
    pub(super) fn into_store(self) -> Result<durable::Command, ApiError> {
        if self.version != VERSION || self.resource != RESOURCE {
            return Err(bad("invalid_endpoint"));
        }
        let value = durable::Command {
            target_node_id: self.target_node_id,
            epoch: decimal(&self.controller_epoch, false)?,
            command_id: decimal(&self.command_id, false)?,
            expected_metadata_revision: decimal(&self.expected_metadata_revision, false)?,
            source_administrator_id: self.source_administrator_id,
            generation: self.mutation.generation,
            change: Change {
                listener_id: self.mutation.listener_id,
                selection: self.mutation.selection,
            },
        };
        durable::validate(&value).map_err(|_| bad("invalid_endpoint"))?;
        Ok(value)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Receipt {
    pub(in crate::manage) controller_epoch: String,
    pub(in crate::manage) command_id: String,
    pub(in crate::manage) status: String,
    pub(in crate::manage) metadata_revision: Option<String>,
    pub(in crate::manage) rejection: Option<String>,
    pub(in crate::manage) listener_id: Option<String>,
    pub(in crate::manage) generation: Option<String>,
}
impl From<durable::Receipt> for Receipt {
    fn from(value: durable::Receipt) -> Self {
        Self {
            controller_epoch: value.epoch.to_string(),
            command_id: value.command_id.to_string(),
            status: if value.rejection.is_some() {
                "rejected"
            } else {
                "saved"
            }
            .into(),
            metadata_revision: value.metadata_revision.map(|n| n.to_string()),
            rejection: value.rejection.map(str::to_owned),
            listener_id: value.listener_id,
            generation: value.generation,
        }
    }
}
impl Receipt {
    pub(in crate::manage) fn into_store(self) -> io::Result<durable::Receipt> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid endpoint metadata receipt",
            )
        };
        let parse = |value: &str| super::client::number(value, false);
        let epoch = parse(&self.controller_epoch)?;
        let command_id = parse(&self.command_id)?;
        let revision = self.metadata_revision.as_deref().map(parse).transpose()?;
        let rejected = self.status == "rejected";
        if (!rejected && self.status != "saved")
            || rejected != self.rejection.is_some()
            || rejected == revision.is_some()
            || rejected == self.listener_id.is_some()
            || rejected == self.generation.is_some()
            || self.listener_id.as_deref().is_some_and(|id| !valid_id(id))
            || self.generation.as_deref().is_some_and(|hash| {
                hash.len() != 64
                    || !hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(invalid());
        }
        let rejection = match self.rejection.as_deref() {
            None => None,
            Some("invalid_endpoint") => Some("invalid_endpoint"),
            Some("endpoint_revision_changed") => Some("endpoint_revision_changed"),
            Some("endpoint_configuration_changed") => Some("endpoint_configuration_changed"),
            Some("endpoint_capacity") => Some("endpoint_capacity"),
            _ => return Err(invalid()),
        };
        Ok(durable::Receipt {
            epoch,
            command_id,
            metadata_revision: revision,
            rejection,
            listener_id: self.listener_id,
            generation: self.generation,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct CommandReply {
    pub(in crate::manage) receipt: Receipt,
    pub(in crate::manage) replayed: bool,
}

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/node/v4/proxy/endpoints", get(settings))
        .route("/node/v4/proxy/commands", post(command))
        .route("/node/v4/proxy/receipts/{epoch}/{command_id}", get(receipt))
}

pub(in crate::manage) fn storage_error(error: io::Error) -> ApiError {
    if let Some(kind) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<store::endpoints::Error>())
    {
        let status = match kind {
            store::endpoints::Error::InvalidEndpoint => StatusCode::BAD_REQUEST,
            store::endpoints::Error::UpgradeRequired => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::CONFLICT,
        };
        return ApiError::new(status, kind.code());
    }
    super::storage_error(error)
}

async fn settings(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let policy = coordinator(&state)?;
    let inventory = policy.endpoint_inventory().map_err(storage_error)?;
    let authorization = peer.authorization();
    let observed = policy
        .observe(move |directory| durable::state(directory, &authorization))
        .await
        .map_err(storage_error)?;
    let catalog =
        SettingsCatalog::new(&state.node_id, observed.running, &inventory, observed.value)
            .map_err(storage_error)?;
    respond(&state.node_id, catalog, SETTINGS_RESPONSE_BYTES)
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
    let input: Command = api::json(request).await?;
    let outcome = coordinator(&state)?
        .endpoint_command(peer.authorization(), input.into_store()?)
        .await
        .map_err(storage_error)?;
    respond(
        &state.node_id,
        CommandReply {
            receipt: outcome.receipt.into(),
            replayed: outcome.replayed,
        },
        MAX_RESPONSE_BYTES,
    )
}
async fn receipt(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    path: Result<Path<(String, String)>, axum::extract::rejection::PathRejection>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let Path((epoch, id)) = path.map_err(|_| bad("invalid_command"))?;
    let epoch = decimal(&epoch, false)?;
    let id = decimal(&id, false)?;
    let authorization = peer.authorization();
    let value = coordinator(&state)?
        .read(move |directory| durable::receipt(directory, &authorization, epoch, id))
        .await
        .map_err(storage_error)?;
    respond(&state.node_id, Receipt::from(value), MAX_RESPONSE_BYTES)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    version: u8,
    node_id: String,
    resource: String,
    data: T,
}
fn respond<T: Serialize>(node_id: &str, data: T, limit: usize) -> Result<Response, ApiError> {
    // All values are bounded metadata models; no verifier/secret can enter this
    // versioned response. The larger cap is only for the finite settings list.
    let bytes = serde_json::to_vec(&Envelope {
        version: VERSION,
        node_id: node_id.into(),
        resource: RESOURCE.into(),
        data,
    })
    .map_err(|_| ApiError::internal())?;
    if bytes.len() > limit {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "response_too_large",
        ));
    }
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response())
}
fn envelope<T: serde::de::DeserializeOwned>(bytes: &[u8], expected: &str) -> io::Result<T> {
    let value: Envelope<T> = serde_json::from_slice(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid endpoint management response",
        )
    })?;
    if value.version != VERSION || value.node_id != expected || value.resource != RESOURCE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "endpoint response identity/resource mismatch",
        ));
    }
    Ok(value.data)
}
pub(super) fn decode(operation: &Request, bytes: &[u8], expected: &str) -> io::Result<Reply> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "endpoint response does not match its command",
        )
    };
    match operation {
        Request::EndpointSettings => {
            let value: SettingsCatalog = envelope(bytes, expected)?;
            value.validate(expected)?;
            Ok(Reply::EndpointSettings(value))
        }
        Request::EndpointReceipt {
            controller_epoch,
            command_id,
        } => {
            let value: Receipt = envelope(bytes, expected)?;
            let receipt = value.clone().into_store()?;
            if receipt.epoch != *controller_epoch || receipt.command_id != *command_id {
                return Err(invalid());
            }
            Ok(Reply::EndpointReceipt(value))
        }
        Request::EndpointCommand(command) => {
            let value: CommandReply = envelope(bytes, expected)?;
            let receipt = value.receipt.clone().into_store()?;
            if value.receipt.controller_epoch != command.controller_epoch
                || value.receipt.command_id != command.command_id
            {
                return Err(invalid());
            }
            if receipt.rejection.is_none()
                && (receipt.metadata_revision
                    != super::client::number(&command.expected_metadata_revision, false)?
                        .checked_add(1)
                    || receipt.listener_id.as_deref()
                        != Some(command.mutation.listener_id.as_str())
                    || receipt.generation.as_deref() != Some(command.mutation.generation.as_str()))
            {
                return Err(invalid());
            }
            Ok(Reply::EndpointCommand(value))
        }
        _ => Err(invalid()),
    }
}
