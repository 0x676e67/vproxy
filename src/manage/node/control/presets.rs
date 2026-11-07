//! Version-three finite preset configuration and actual backend observations.
//! A catalog is informational, not a permission grant: every read repeats the
//! mTLS owner's current authorization, and every mutation is authorized again
//! inside the policy commit transaction. No template or arbitrary command is
//! accepted and older command vocabularies remain separate serde types.

use super::*;
use crate::{access::presets as model, ebpf};

const VERSION: u8 = 3;
const PREFIX: &str = "/node/v3/proxy";

pub(in crate::manage) use crate::manage::store::PresetMutation;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct PresetCommand {
    pub(in crate::manage) version: u8,
    pub(in crate::manage) target_node_id: String,
    pub(in crate::manage) resource: String,
    pub(in crate::manage) controller_epoch: String,
    pub(in crate::manage) command_id: String,
    pub(in crate::manage) expected_policy_revision: String,
    pub(in crate::manage) source_administrator_id: String,
    pub(in crate::manage) mutation: PresetMutation,
}
impl PresetCommand {
    fn into_store(self) -> Result<store::Command, ApiError> {
        if self.version != VERSION
            || self.resource != RESOURCE
            || !valid_id(&self.target_node_id)
            || !valid_id(&self.source_administrator_id)
        {
            return Err(bad("invalid_command"));
        }
        // Policy-domain validation occurs inside the durable command handling
        // so an otherwise well-formed rejected command still has a receipt.
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

pub(in crate::manage) use model::PresetEntity;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct UserPresetsView {
    pub(in crate::manage) revision: String,
    pub(in crate::manage) presets: model::UserPreset,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct PoolPresetView {
    pub(in crate::manage) revision: String,
    pub(in crate::manage) preset: model::PoolPreset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum PresetBackendState {
    Ready,
    Disabled,
    Unsupported,
    Unavailable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum PresetReason {
    NotConfigured,
    FeatureDisabled,
    PlatformUnsupported,
    ProxyUnavailable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum PresetOperation {
    HttpForward,
    HttpConnect,
    Socks5Connect,
}

/// Shared browser/node capability DTO. It describes this process's actual
/// startup engine, never the identity-v1 capability string or an OS heuristic.
/// Ready does not imply that a particular route's MSS/receive-buffer limits can
/// realize every preset; connect must still validate and fail closed.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct PresetCatalog {
    pub(in crate::manage) node_id: String,
    pub(in crate::manage) capability_version: u8,
    pub(in crate::manage) backend_state: PresetBackendState,
    pub(in crate::manage) reason_code: Option<PresetReason>,
    pub(in crate::manage) preset_revision: String,
    pub(in crate::manage) abi_version: Option<u8>,
    pub(in crate::manage) available_presets: Vec<ebpf::Profile>,
    pub(in crate::manage) operations: Vec<PresetOperation>,
    pub(in crate::manage) observed_at_unix_ms: Option<u64>,
}

/// Pure bounded projection of the one startup configuration. Missing setup is
/// explicitly unavailable, never inferred to be the native disabled state.
pub(in crate::manage) fn preset_catalog(
    node_id: &str,
    config: Option<&ebpf::Config>,
) -> PresetCatalog {
    let catalog = config.map(ebpf::Config::catalog);
    let (backend_state, reason_code) = match catalog.as_ref().map(|value| value.state) {
        Some(ebpf::BackendState::Ready) => (PresetBackendState::Ready, None),
        Some(ebpf::BackendState::NotConfigured) => (
            PresetBackendState::Disabled,
            Some(PresetReason::NotConfigured),
        ),
        Some(ebpf::BackendState::FeatureDisabled) => (
            PresetBackendState::Disabled,
            Some(PresetReason::FeatureDisabled),
        ),
        Some(ebpf::BackendState::PlatformUnsupported) => (
            PresetBackendState::Unsupported,
            Some(PresetReason::PlatformUnsupported),
        ),
        None => (
            PresetBackendState::Unavailable,
            Some(PresetReason::ProxyUnavailable),
        ),
    };
    let ready = backend_state == PresetBackendState::Ready;
    PresetCatalog {
        node_id: node_id.to_owned(),
        capability_version: 1,
        backend_state,
        reason_code,
        preset_revision: "1".into(),
        abi_version: ready.then_some(1),
        available_presets: catalog
            .map(|value| value.available_presets.to_vec())
            .unwrap_or_default(),
        operations: if ready {
            vec![
                PresetOperation::HttpForward,
                PresetOperation::HttpConnect,
                PresetOperation::Socks5Connect,
            ]
        } else {
            Vec::new()
        },
        observed_at_unix_ms: crate::manage::traffic::now(),
    }
}

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/node/v3/proxy/commands", post(command))
        .route("/node/v3/proxy/receipts/{epoch}/{command_id}", get(receipt))
        .route("/node/v3/proxy/users/{id}/presets", get(user))
        .route("/node/v3/proxy/pools/{id}/preset", get(pool))
        .route("/node/v3/proxy/presets/catalog", get(catalog))
}
async fn data(state: &AppState, peer: VerifiedPeer) -> Result<(u64, model::PresetData), ApiError> {
    let authorization = peer.authorization();
    coordinator(state)?
        .read(move |directory| store::remote_presets_data(directory, &authorization))
        .await
        .map_err(storage_error)
}
fn path_id(
    path: Result<Path<String>, axum::extract::rejection::PathRejection>,
) -> Result<String, ApiError> {
    let Path(id) = path.map_err(|_| bad("invalid_resource"))?;
    if !valid_id(&id) {
        return Err(bad("invalid_resource"));
    }
    Ok(id)
}
async fn user(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    path: Result<Path<String>, axum::extract::rejection::PathRejection>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = path_id(path)?;
    let (revision, data) = data(&state, peer).await?;
    let presets = data
        .users
        .into_iter()
        .find(|value| value.user_id == id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "resource_not_found"))?;
    respond_version(
        VERSION,
        &state.node_id,
        StatusCode::OK,
        UserPresetsView {
            revision: revision.to_string(),
            presets,
        },
    )
}
async fn pool(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    path: Result<Path<String>, axum::extract::rejection::PathRejection>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = path_id(path)?;
    let (revision, data) = data(&state, peer).await?;
    let preset = data
        .pools
        .into_iter()
        .find(|value| value.pool_id == id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "resource_not_found"))?;
    respond_version(
        VERSION,
        &state.node_id,
        StatusCode::OK,
        PoolPresetView {
            revision: revision.to_string(),
            preset,
        },
    )
}
async fn catalog(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let authorization = peer.authorization();
    let policy = coordinator(&state)?;
    let observed = policy.clone();
    let id = state.node_id.clone();
    let data = policy
        .read(move |directory| {
            store::remote_authorized(directory, &authorization, || {
                Ok(preset_catalog(&id, observed.preset_config()))
            })
        })
        .await
        .map_err(storage_error)?;
    respond_version(VERSION, &state.node_id, StatusCode::OK, data)
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
    let input: PresetCommand = api::json(request).await?;
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
        presets: result.presets,
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
    let path = match operation {
        Request::PresetCommand(command) => {
            command
                .clone()
                .into_store()
                .map_err(|_| invalid("invalid preset command"))?;
            let body =
                serde_json::to_vec(command).map_err(|_| invalid("cannot encode preset command"))?;
            if body.len() > 4096 {
                return Err(invalid("preset command exceeds input limit"));
            }
            return Ok((Method::POST, format!("{PREFIX}/commands"), body));
        }
        Request::UserPresets { user_id } if valid_id(user_id) => {
            format!("{PREFIX}/users/{user_id}/presets")
        }
        Request::PoolPreset { pool_id } if valid_id(pool_id) => {
            format!("{PREFIX}/pools/{pool_id}/preset")
        }
        Request::PresetCatalog => format!("{PREFIX}/presets/catalog"),
        _ => return Err(invalid("invalid preset operation")),
    };
    Ok((Method::GET, path, Vec::new()))
}
fn validate_user(value: &model::UserPreset) -> io::Result<()> {
    if !valid_id(&value.user_id) {
        return Err(invalid("invalid preset user identity"));
    }
    model::allowed_mask(value).map_err(|_| invalid("invalid preset grants"))?;
    Ok(())
}
fn validate_pool(value: &model::PoolPreset) -> io::Result<()> {
    if !valid_id(&value.pool_id) {
        return Err(invalid("invalid preset pool identity"));
    }
    Ok(())
}
fn validate_catalog(value: &PresetCatalog, peer: &str) -> io::Result<()> {
    if value.node_id != peer
        || value.capability_version != 1
        || value.preset_revision != "1"
        || value
            .observed_at_unix_ms
            .is_some_and(|value| value > 9_007_199_254_740_991)
    {
        return Err(invalid("invalid preset catalog identity or version"));
    }
    let ready = value.backend_state == PresetBackendState::Ready;
    let shape = match value.backend_state {
        PresetBackendState::Ready => value.reason_code.is_none() && value.abi_version == Some(1),
        PresetBackendState::Disabled => {
            matches!(
                value.reason_code,
                Some(PresetReason::NotConfigured | PresetReason::FeatureDisabled)
            ) && value.abi_version.is_none()
        }
        PresetBackendState::Unsupported => {
            value.reason_code == Some(PresetReason::PlatformUnsupported)
                && value.abi_version.is_none()
        }
        PresetBackendState::Unavailable => {
            value.reason_code == Some(PresetReason::ProxyUnavailable) && value.abi_version.is_none()
        }
    };
    let mut presets = 0_u8;
    for &profile in &value.available_presets {
        let bit = model::bit(profile);
        if presets & bit != 0 {
            return Err(invalid("duplicate available preset"));
        }
        presets |= bit;
    }
    let mut operations = 0_u8;
    for operation in &value.operations {
        let bit = match operation {
            PresetOperation::HttpForward => 1,
            PresetOperation::HttpConnect => 2,
            PresetOperation::Socks5Connect => 4,
        };
        if operations & bit != 0 {
            return Err(invalid("duplicate preset operation"));
        }
        operations |= bit;
    }
    if !shape
        || (ready && (presets != 31 || operations != 7))
        || (!ready && (presets != 0 || operations != 0))
    {
        return Err(invalid("inconsistent preset catalog availability"));
    }
    Ok(())
}
pub(super) fn decode(
    operation: &Request,
    bytes: &[u8],
    peer: &str,
    status: StatusCode,
) -> io::Result<Reply> {
    match operation {
        Request::UserPresets { user_id } => {
            let value: UserPresetsView = client::envelope(bytes, peer, VERSION)?;
            client::number(&value.revision, false)?;
            validate_user(&value.presets)?;
            if &value.presets.user_id != user_id {
                return Err(invalid("preset configuration belongs to another user"));
            }
            Ok(Reply::UserPresets(value))
        }
        Request::PoolPreset { pool_id } => {
            let value: PoolPresetView = client::envelope(bytes, peer, VERSION)?;
            client::number(&value.revision, false)?;
            validate_pool(&value.preset)?;
            if &value.preset.pool_id != pool_id {
                return Err(invalid("preset configuration belongs to another pool"));
            }
            Ok(Reply::PoolPreset(value))
        }
        Request::PresetCatalog => {
            let value: PresetCatalog = client::envelope(bytes, peer, VERSION)?;
            validate_catalog(&value, peer)?;
            Ok(Reply::PresetCatalog(value))
        }
        Request::PresetCommand(command) => {
            let mut value: CommandReply = client::envelope(bytes, peer, VERSION)?;
            value.receipt.version = VERSION;
            client::validate_receipt(&value.receipt)?;
            validate_command(command, &value, status)?;
            Ok(Reply::Command(Box::new(value)))
        }
        _ => Err(invalid("unsupported preset response")),
    }
}
fn validate_command(
    command: &PresetCommand,
    value: &CommandReply,
    status: StatusCode,
) -> io::Result<()> {
    if value.receipt.controller_epoch != command.controller_epoch
        || value.receipt.command_id != command.command_id
        || (status == StatusCode::ACCEPTED) != (value.receipt.status == ReceiptStatus::Saved)
        || value.user.is_some()
        || value.credential.is_some()
        || value.secret.is_some()
        || value.secret_available
        || value.routing.is_some()
        || ((value.replayed || value.receipt.status == ReceiptStatus::Rejected)
            && value.presets.is_some())
    {
        return Err(invalid("invalid preset command result shape"));
    }
    if value.receipt.status == ReceiptStatus::Rejected {
        return Ok(());
    }
    let revision = client::number(&command.expected_policy_revision, false)?
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| invalid("preset policy revision exhausted"))?;
    if value
        .receipt
        .policy_revision
        .as_deref()
        .map(|value| client::number(value, false))
        .transpose()?
        != Some(revision)
    {
        return Err(invalid("preset receipt differs from policy CAS"));
    }
    let reference = value
        .receipt
        .preset
        .as_ref()
        .ok_or_else(|| invalid("missing preset receipt reference"))?;
    let (kind, id) = match &command.mutation {
        PresetMutation::SetUserPresets { presets } => (store::PresetKind::User, &presets.user_id),
        PresetMutation::SetPoolPreset { preset } => (store::PresetKind::Pool, &preset.pool_id),
    };
    if reference.kind != kind || &reference.id != id {
        return Err(invalid("preset receipt names another resource"));
    }
    if !value.replayed {
        let matches = match (&command.mutation, value.presets.as_ref()) {
            (PresetMutation::SetUserPresets { presets }, Some(PresetEntity::User(value))) => {
                validate_user(value)?;
                // Grants are a finite set. A peer may return their canonical
                // order; correlate permissions, not JSON array presentation.
                value.user_id == presets.user_id
                    && value.default_preset == presets.default_preset
                    && model::allowed_mask(value)? == model::allowed_mask(presets)?
            }
            (PresetMutation::SetPoolPreset { preset }, Some(PresetEntity::Pool(value))) => {
                validate_pool(value)?;
                value == preset
            }
            _ => false,
        };
        if !matches {
            return Err(invalid("preset entity differs from accepted command"));
        }
    }
    Ok(())
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
