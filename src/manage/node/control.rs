//! Version-one control of the existing proxy policy, not a generic RPC tunnel.
//!
//! TLS supplies the private connection identity. Every store operation repeats
//! that identity's current ownership/DER authorization in its own transaction;
//! parsing an actor or revision from JSON never grants authority.

mod alerts;
mod client;
pub(in crate::manage) mod endpoints;
mod maintenance;
mod presets;
mod routing;
mod runtime;
pub(in crate::manage) mod search;
mod secrets;
pub(in crate::manage) mod traffic;
pub(in crate::manage) mod witness;
pub(in crate::manage) use crate::manage::views::{Page, User};
pub(in crate::manage) use client::{
    Offline, RemoteError, TransportError, request, request_with_admission,
};
pub(in crate::manage) use maintenance::{MaintenanceCommand, MaintenanceMutation};
pub(in crate::manage) use presets::{
    PoolPresetView, PresetCatalog, PresetCommand, PresetMutation, UserPresetsView, preset_catalog,
};
pub(in crate::manage) use routing::{RoutingCommand, RoutingMutation};
pub(in crate::manage) use runtime::RuntimeDrain;
pub(in crate::manage) use secrets::{CredentialSecret, CredentialSecretRead};

use axum::{
    Extension, Router,
    extract::{Path, State},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::*;
use crate::{
    access::Protocol,
    manage::{policy, store},
};

const VERSION: u8 = 1;
const RESOURCE: &str = "proxy_policy";
const PREFIX: &str = "/node/v1/proxy";
const MAX_RESPONSE_BYTES: usize = 32 * 1024;

/// Fixed command vocabulary. New variants require an explicit protocol review;
/// arbitrary JSON, URLs, credentials and executable instructions are excluded.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::manage) enum Mutation {
    CreateUser {
        name: String,
        protocols: Vec<Protocol>,
        concurrent_limit: u32,
    },
    UpdateUser {
        id: String,
        name: String,
        protocols: Vec<Protocol>,
        concurrent_limit: u32,
    },
    SetUserActive {
        id: String,
        active: bool,
    },
    DeleteUser {
        id: String,
    },
    CreateCredential {
        user_id: String,
    },
    SetCredentialActive {
        id: String,
        active: bool,
    },
    RotateCredential {
        id: String,
    },
    RevokeCredential {
        id: String,
    },
}

impl From<Mutation> for store::PolicyChange {
    fn from(value: Mutation) -> Self {
        match value {
            Mutation::CreateUser {
                name,
                protocols,
                concurrent_limit,
            } => Self::CreateUser {
                name,
                protocols,
                concurrent_limit,
            },
            Mutation::UpdateUser {
                id,
                name,
                protocols,
                concurrent_limit,
            } => Self::UpdateUser {
                id,
                name,
                protocols,
                concurrent_limit,
            },
            Mutation::SetUserActive { id, active } => Self::SetUserActive { id, active },
            Mutation::DeleteUser { id } => Self::DeleteUser { id },
            Mutation::CreateCredential { user_id } => Self::CreateCredential { user_id },
            Mutation::SetCredentialActive { id, active } => {
                Self::SetCredentialActive { id, active }
            }
            Mutation::RotateCredential { id } => Self::RotateCredential { id },
            Mutation::RevokeCredential { id } => Self::RevokeCredential { id },
        }
    }
}

impl TryFrom<store::PolicyChange> for Mutation {
    type Error = io::Error;

    fn try_from(value: store::PolicyChange) -> io::Result<Self> {
        Ok(match value {
            store::PolicyChange::CreateUser {
                name,
                protocols,
                concurrent_limit,
            } => Self::CreateUser {
                name,
                protocols,
                concurrent_limit,
            },
            store::PolicyChange::UpdateUser {
                id,
                name,
                protocols,
                concurrent_limit,
            } => Self::UpdateUser {
                id,
                name,
                protocols,
                concurrent_limit,
            },
            store::PolicyChange::SetUserActive { id, active } => Self::SetUserActive { id, active },
            store::PolicyChange::DeleteUser { id } => Self::DeleteUser { id },
            store::PolicyChange::CreateCredential { user_id } => Self::CreateCredential { user_id },
            store::PolicyChange::SetCredentialActive { id, active } => {
                Self::SetCredentialActive { id, active }
            }
            store::PolicyChange::RotateCredential { id } => Self::RotateCredential { id },
            store::PolicyChange::RevokeCredential { id } => Self::RevokeCredential { id },
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "version-one node control does not support routing mutations",
                ));
            }
        })
    }
}

/// Decimal strings preserve SQLite's whole positive i64 range in browsers.
/// The source administrator is an audit claim by the authenticated controller,
/// not an administrator identity on this target.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Command {
    pub(in crate::manage) version: u8,
    pub(in crate::manage) target_node_id: String,
    pub(in crate::manage) resource: String,
    pub(in crate::manage) controller_epoch: String,
    pub(in crate::manage) command_id: String,
    pub(in crate::manage) expected_policy_revision: String,
    pub(in crate::manage) source_administrator_id: String,
    pub(in crate::manage) mutation: Mutation,
}

impl Command {
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

/// Allowlisted outbound operations; callers cannot select an arbitrary method,
/// path, header or URL. The endpoint is a separate locally registered origin.
pub(in crate::manage) enum Request {
    Witness(witness::Operation),
    Policy,
    Maintenance,
    MaintenanceCommand(MaintenanceCommand),
    Runtime,
    RuntimeDrain(RuntimeDrain),
    RuntimeDrainStatus {
        runtime_id: String,
        request_id: String,
    },
    Endpoints,
    EndpointSettings,
    EndpointCommand(endpoints::Command),
    EndpointReceipt {
        controller_epoch: u64,
        command_id: u64,
    },
    UsersPage {
        after: Option<String>,
        limit: u32,
        include_deleted: bool,
    },
    UsersSearch(crate::manage::user_search::Query),
    CredentialsPage {
        after: Option<String>,
        limit: u32,
        user_id: Option<String>,
    },
    CredentialSecret(CredentialSecretRead),
    Receipt {
        version: u8,
        controller_epoch: u64,
        command_id: u64,
    },
    Command(Command),
    RoutingCommand(RoutingCommand),
    PresetCommand(PresetCommand),
    UserPresets {
        user_id: String,
    },
    PoolPreset {
        pool_id: String,
    },
    PresetCatalog,
    PrefixesPage {
        after: Option<String>,
        limit: u32,
    },
    AddressesPage {
        after: Option<String>,
        limit: u32,
    },
    Address {
        address_id: String,
    },
    PoolsPage {
        after: Option<String>,
        limit: u32,
    },
    PoolMembersPage {
        pool_id: String,
        after: Option<String>,
        limit: u32,
    },
    UserRouting {
        user_id: String,
    },
    HealthPage {
        after: Option<String>,
        limit: u32,
    },
    EgressAlerts(crate::manage::alerts::Query),
    OperationsAlerts(crate::manage::alerts::Query),
    OperationsSnapshot,
    TrafficSnapshot,
    TrafficSnapshotV2,
    TrafficTotalsV2 {
        scope: store::traffic::Scope,
    },
    TrafficBucketsV2 {
        scope: store::traffic::Scope,
        resolution: store::traffic::Resolution,
        after: Option<u64>,
        limit: u32,
    },
    TrafficTotals {
        scope: store::traffic::Scope,
    },
    TrafficBuckets {
        scope: store::traffic::Scope,
        resolution: store::traffic::Resolution,
        after: Option<u64>,
        limit: u32,
    },
}

/// Control envelopes and witness records are checked against the locally
/// selected target before escaping. No remote name or JSON ID selects trust.
pub(in crate::manage) enum Reply {
    Witness(Box<Fetched<crate::manage::witness::Record>>),
    Policy(Policy),
    Maintenance(Box<crate::manage::maintenance::Status>),
    Runtime(Box<crate::manage::drain::Status>),
    Endpoints(crate::manage::proxy::EndpointCatalog),
    EndpointSettings(crate::manage::proxy::SettingsCatalog),
    EndpointCommand(endpoints::CommandReply),
    EndpointReceipt(endpoints::Receipt),
    UsersPage(Page<User>),
    UsersSearch(Page<User>),
    CredentialsPage(Page<Credential>),
    CredentialSecret(CredentialSecret),
    Receipt(Receipt),
    Command(Box<CommandReply>),
    PrefixesPage(crate::manage::views::Page<crate::manage::views::Prefix>),
    AddressesPage(crate::manage::views::Page<crate::manage::views::Address>),
    Address(crate::manage::views::AddressView),
    PoolsPage(crate::manage::views::Page<crate::manage::views::Pool>),
    PoolMembersPage(crate::manage::views::Page<String>),
    UserRouting(crate::manage::views::PermissionView),
    HealthPage(Box<crate::manage::views::HealthPage>),
    EgressAlerts(crate::manage::alerts::EgressPage),
    OperationsAlerts(crate::manage::alerts::NodePage),
    OperationsSnapshot(Box<Fetched<crate::manage::alerts::NodeSnapshot>>),
    UserPresets(UserPresetsView),
    PoolPreset(PoolPresetView),
    PresetCatalog(PresetCatalog),
    TrafficSnapshot(Box<Fetched<store::traffic::NodeSnapshot>>),
    TrafficTotals(Box<Fetched<store::traffic::Totals>>),
    TrafficBuckets(Box<Fetched<store::traffic::BucketPage>>),
}

/// Actual, twice-checked TLS identity evidence, never accepted from wire JSON.
/// Importers must repeat authorization and target-generation checks in the
/// transaction publishing a fetch; success here is not commit-time authority.
pub(in crate::manage) struct Fetched<T> {
    pub(in crate::manage) authorization: store::RemoteAuthorization,
    pub(in crate::manage) value: T,
}

pub(in crate::manage) enum DeliveryReply {
    Policy(Box<CommandReply>),
    Endpoint(endpoints::CommandReply),
}

/// Every control reply identifies the actual target and fixed vocabulary.
/// Clients verify this only after TLS/local registration, never as identity.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    version: u8,
    node_id: String,
    resource: String,
    data: T,
}

/// Saved is the durable candidate; applied is this process's live Reader.
/// Durable applied is historical and cannot establish current availability.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Policy {
    pub(in crate::manage) controller_node_id: Option<String>,
    pub(in crate::manage) controller_epoch: String,
    pub(in crate::manage) last_terminal_command: String,
    pub(in crate::manage) saved_revision: String,
    pub(in crate::manage) applied_revision: Option<String>,
    pub(in crate::manage) durable_applied_revision: Option<String>,
    pub(in crate::manage) proxy_running: bool,
    pub(in crate::manage) user_count: u32,
    pub(in crate::manage) credential_count: u32,
}

/// Public login and lifecycle metadata only. Credential identity is stable
/// across rotations, while verifier_revision advances with the secret.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Credential {
    pub(in crate::manage) id: String,
    pub(in crate::manage) user_id: String,
    pub(in crate::manage) login: String,
    pub(in crate::manage) syntax_version: u8,
    pub(in crate::manage) active: bool,
    pub(in crate::manage) revoked: bool,
    pub(in crate::manage) verifier_revision: String,
}
impl From<store::CredentialView> for Credential {
    fn from(value: store::CredentialView) -> Self {
        Self {
            id: value.id,
            user_id: value.user_id,
            login: value.login,
            syntax_version: value.syntax_version,
            active: value.active,
            revoked: value.revoked,
            verifier_revision: value.verifier_revision.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(in crate::manage) enum ReceiptStatus {
    Saved,
    Applied,
    Rejected,
}

/// Replayable terminal metadata. Applied is historical publication of this
/// exact command; no stored receipt permits recovering its one-time secret.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Receipt {
    /// The verified envelope/route supplies this value; old wire bytes omit it.
    #[serde(skip)]
    pub(in crate::manage) version: u8,
    pub(in crate::manage) controller_epoch: String,
    pub(in crate::manage) command_id: String,
    pub(in crate::manage) status: ReceiptStatus,
    pub(in crate::manage) policy_revision: Option<String>,
    pub(in crate::manage) rejection: Option<String>,
    pub(in crate::manage) user_id: Option<String>,
    pub(in crate::manage) credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::manage) routing: Option<store::RoutingReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::manage) preset: Option<store::PresetReceipt>,
}
impl From<store::Receipt> for Receipt {
    fn from(value: store::Receipt) -> Self {
        Self {
            version: value.version,
            controller_epoch: value.epoch.to_string(),
            command_id: value.command_id.to_string(),
            status: match value.status {
                store::ReceiptStatus::Saved => ReceiptStatus::Saved,
                store::ReceiptStatus::Applied => ReceiptStatus::Applied,
                store::ReceiptStatus::Rejected => ReceiptStatus::Rejected,
            },
            policy_revision: value.policy_revision.map(|value| value.to_string()),
            rejection: value.rejection.map(str::to_owned),
            user_id: value.user_id,
            credential_id: value.credential_id,
            routing: value.routing,
            preset: value.preset,
        }
    }
}

/// Only the first successful delivery owns a one-time secret. Neither Debug
/// nor Clone exists: receipts/retries must not reconstruct or copy that value.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct CommandReply {
    pub(in crate::manage) receipt: Receipt,
    pub(in crate::manage) replayed: bool,
    pub(in crate::manage) user: Option<User>,
    pub(in crate::manage) credential: Option<Credential>,
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub(in crate::manage) secret: Option<Zeroizing<String>>,
    pub(in crate::manage) secret_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::manage) routing: Option<crate::manage::views::Entity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::manage) presets: Option<presets::PresetEntity>,
}

fn serialize_secret<S: serde::Serializer>(
    secret: &Option<Zeroizing<String>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    secret.as_deref().map(String::as_str).serialize(serializer)
}
fn deserialize_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(|value| value.map(Zeroizing::new))
}

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/node/v1/proxy/policy", get(policy))
        .route("/node/v1/proxy/endpoints", get(endpoints))
        .route("/node/v1/proxy/users", get(users))
        .route("/node/v1/proxy/credentials", get(credentials))
        .route("/node/v1/proxy/receipts/{epoch}/{command_id}", get(receipt))
        .route("/node/v1/proxy/commands", post(command))
        .merge(routing::routes())
        .merge(presets::routes())
        .merge(traffic::routes())
        .merge(endpoints::routes())
        .merge(search::routes())
        .merge(alerts::routes())
        .merge(maintenance::routes())
        .merge(runtime::routes())
        .merge(secrets::routes())
}

fn coordinator(state: &AppState) -> Result<Arc<policy::Coordinator>, ApiError> {
    state.policy.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    })
}

async fn policy(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let authorization = peer.authorization();
    let observed = coordinator(&state)?
        .observe(move |directory| store::remote_policy_status(directory, &authorization))
        .await
        .map_err(storage_error)?;
    let status = observed.value;
    if status.node_id != state.node_id {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "policy_unavailable",
        ));
    }
    let data = Policy {
        controller_node_id: status.ownership.controller_node_id,
        controller_epoch: status.ownership.epoch.to_string(),
        last_terminal_command: status.ownership.last_terminal_command.to_string(),
        saved_revision: status.policy.revision.to_string(),
        applied_revision: observed.applied_revision.map(|value| value.to_string()),
        durable_applied_revision: status
            .policy
            .applied_revision
            .map(|value| value.to_string()),
        proxy_running: observed.running,
        user_count: status.policy.user_count,
        credential_count: status.policy.credential_count,
    };
    respond(&state.node_id, StatusCode::OK, data)
}

/// Immutable endpoint metadata is still owner-scoped: the outer node guard
/// alone grants identity access, not permission to inspect this proxy policy.
async fn endpoints(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let authorization = peer.authorization();
    let coordinator = coordinator(&state)?;
    let observed = coordinator
        .observe(move |directory| store::remote_policy_status(directory, &authorization))
        .await
        .map_err(storage_error)?;
    if observed.value.node_id != state.node_id {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "policy_unavailable",
        ));
    }
    let mut catalog = if let Ok(inventory) = coordinator.endpoint_inventory() {
        let authorization = peer.authorization();
        match coordinator
            .read(move |directory| store::endpoint_control::state(directory, &authorization))
            .await
        {
            Ok(saved) => crate::manage::proxy::SettingsCatalog::new(
                &state.node_id,
                observed.running,
                &inventory,
                saved,
            )
            .map_err(storage_error)?
            .legacy(),
            Err(error)
                if error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<store::endpoints::Error>())
                    .is_some_and(|e| matches!(e, store::endpoints::Error::UpgradeRequired)) =>
            {
                coordinator
                    .endpoints(&state.node_id)
                    .map_err(storage_error)?
            }
            Err(error) => return Err(storage_error(error)),
        }
    } else {
        coordinator
            .endpoints(&state.node_id)
            .map_err(storage_error)?
    };
    catalog.proxy_running = observed.running;
    respond(&state.node_id, StatusCode::OK, catalog)
}

async fn users(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    let page = pagination(&uri, false)?;
    let authorization = peer.authorization();
    let page = coordinator(&state)?
        .read(move |directory| {
            store::remote_list_users(
                directory,
                &authorization,
                page.include_deleted,
                page.after.as_deref(),
                page.limit,
            )
        })
        .await
        .map_err(storage_error)?;
    respond(
        &state.node_id,
        StatusCode::OK,
        Page {
            revision: page.revision.to_string(),
            items: page.items.into_iter().map(User::from).collect::<Vec<_>>(),
            next_cursor: page.next_cursor,
        },
    )
}

async fn credentials(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    let page = pagination(&uri, true)?;
    let authorization = peer.authorization();
    let page = coordinator(&state)?
        .read(move |directory| {
            store::remote_list_credentials(
                directory,
                &authorization,
                page.user_id.as_deref(),
                page.after.as_deref(),
                page.limit,
            )
        })
        .await
        .map_err(storage_error)?;
    respond(
        &state.node_id,
        StatusCode::OK,
        Page {
            revision: page.revision.to_string(),
            items: page
                .items
                .into_iter()
                .map(Credential::from)
                .collect::<Vec<_>>(),
            next_cursor: page.next_cursor,
        },
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
    let receipt = coordinator(&state)?
        .read(move |directory| store::receipt(directory, &authorization, epoch, id))
        .await
        .map_err(storage_error)?;
    if receipt.version != VERSION {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "resource_not_found"));
    }
    respond(&state.node_id, StatusCode::OK, Receipt::from(receipt))
}

async fn command(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    request: axum::extract::Request,
) -> Result<Response, ApiError> {
    no_query(request.uri())?;
    // JSON belongs to this command route, not the C2 identity contract's
    // method dispatch. Browser Origin, Cookie and CSRF grant no node identity.
    let mut types = request.headers().get_all(header::CONTENT_TYPE).iter();
    let content_type = types.next().and_then(|value| value.to_str().ok());
    if types.next().is_some()
        || !content_type
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "json_required",
        ));
    }
    let input: Command = api::json(request).await?;
    let command = input.into_store()?;
    let result = coordinator(&state)?
        .command(peer.authorization(), command)
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
        user: result.user.map(User::from),
        credential: result.credential.map(Credential::from),
        secret_available: result.secret.is_some(),
        secret: result.secret,
        routing: None,
        presets: None,
    };
    // A saved receipt does not imply application. Its monitor address lets an
    // uncertain caller recover without executing a second command (9110 §15.3.3).
    // https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.3
    let mut response = respond(
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

/// Serialize before returning so even a worst-case metadata page cannot evade
/// the wire cap. A partial serialization error zeroizes its buffer; success
/// moves its sole plaintext allocation into the HTTPS response body.
fn respond<T: Serialize>(node_id: &str, status: StatusCode, data: T) -> Result<Response, ApiError> {
    respond_version(VERSION, node_id, status, data)
}

fn respond_version<T: Serialize>(
    version: u8,
    node_id: &str,
    status: StatusCode,
    data: T,
) -> Result<Response, ApiError> {
    respond_resource(version, RESOURCE, node_id, status, data)
}

/// The bounded representation is shared, but each independent protocol keeps
/// its fixed resource namespace. Runtime requests never become policy commands.
fn respond_resource<T: Serialize>(
    version: u8,
    resource: &str,
    node_id: &str,
    status: StatusCode,
    data: T,
) -> Result<Response, ApiError> {
    respond_resource_limited(version, resource, node_id, status, data, MAX_RESPONSE_BYTES)
}

/// Only the fixed operations snapshot has a larger, independently reviewed cap.
/// Other existing resources continue through the original 32 KiB wrapper.
fn respond_resource_limited<T: Serialize>(
    version: u8,
    resource: &str,
    node_id: &str,
    status: StatusCode,
    data: T,
    limit: usize,
) -> Result<Response, ApiError> {
    struct Bounded<'a>(&'a mut Vec<u8>, usize);
    impl io::Write for Bounded<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .len()
                .checked_add(bytes.len())
                .filter(|length| *length <= self.1)
                .ok_or_else(|| io::Error::other("node response cap reached"))?;
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit));
    serde_json::to_writer(
        Bounded(&mut bytes, limit),
        &Envelope {
            version,
            node_id: node_id.to_owned(),
            resource: resource.to_owned(),
            data,
        },
    )
    .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "response_too_large"))?;
    // Transfer the single plaintext buffer to the HTTP stack. No extra secret
    // copy is retained by the serializer; on any error its owner zeroizes it.
    let mut response = (status, Body::from(std::mem::take(&mut *bytes))).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(response)
}

fn bad(code: &'static str) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, code)
}
fn no_query(uri: &http::Uri) -> Result<(), ApiError> {
    if uri.query().is_some() {
        Err(bad("invalid_query"))
    } else {
        Ok(())
    }
}

fn decimal(value: &str, zero: bool) -> Result<u64, ApiError> {
    if zero && value == "0" {
        return Ok(0);
    }
    if value.is_empty()
        || value.len() > 19
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(bad("invalid_revision"));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| bad("invalid_revision"))
}

fn valid_id(value: &str) -> bool {
    let mut bytes = [0; 16];
    value.len() == 22 && matches!(URL_SAFE_NO_PAD.decode_slice(value, &mut bytes), Ok(16))
}

fn storage_error(error: io::Error) -> ApiError {
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<store::ControlError>())
    {
        return ApiError::new(
            if *error == store::ControlError::PeerNotAuthorized {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::CONFLICT
            },
            error.code(),
        );
    }
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<policy::Error>())
    {
        return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error.code());
    }
    match error.kind() {
        io::ErrorKind::InvalidInput => bad("invalid_policy"),
        io::ErrorKind::PermissionDenied => {
            ApiError::new(StatusCode::FORBIDDEN, "peer_not_authorized")
        }
        io::ErrorKind::NotFound => ApiError::new(StatusCode::NOT_FOUND, "resource_not_found"),
        io::ErrorKind::AlreadyExists => ApiError::new(StatusCode::CONFLICT, "policy_conflict"),
        io::ErrorKind::WouldBlock => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "policy_busy"),
        _ => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable"),
    }
}

struct Pagination {
    after: Option<String>,
    limit: u32,
    include_deleted: bool,
    user_id: Option<String>,
}
fn pagination(uri: &http::Uri, credentials: bool) -> Result<Pagination, ApiError> {
    let query = uri.query().unwrap_or_default();
    if query.len() > 1024 {
        return Err(bad("invalid_pagination"));
    }
    let mut result = Pagination {
        after: None,
        limit: 25,
        include_deleted: false,
        user_id: None,
    };
    let mut seen = [false; 4];
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let index = match key.as_ref() {
            "after" => 0,
            "limit" => 1,
            "include_deleted" if !credentials => 2,
            "user_id" if credentials => 3,
            _ => return Err(bad("invalid_pagination")),
        };
        if seen[index] {
            return Err(bad("invalid_pagination"));
        }
        seen[index] = true;
        match index {
            0 | 3 => {
                if !valid_id(&value) {
                    return Err(bad("invalid_pagination"));
                }
                if index == 0 {
                    result.after = Some(value.into_owned())
                } else {
                    result.user_id = Some(value.into_owned())
                }
            }
            1 => {
                result.limit = u32::try_from(decimal(&value, false)?)
                    .ok()
                    .filter(|value| (1..=50).contains(value))
                    .ok_or_else(|| bad("invalid_pagination"))?;
            }
            2 => {
                result.include_deleted = match value.as_ref() {
                    "true" => true,
                    "false" => false,
                    _ => return Err(bad("invalid_pagination")),
                }
            }
            _ => return Err(bad("invalid_pagination")),
        }
    }
    Ok(result)
}

#[cfg(test)]
pub(in crate::manage) fn decode_egress_alerts_for_test(
    query: &crate::manage::alerts::Query,
    bytes: &[u8],
    expected: &str,
) -> std::io::Result<Reply> {
    alerts::decode(query, bytes, expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn command() -> serde_json::Value {
        serde_json::json!({"version":1,"target_node_id":"AAAAAAAAAAAAAAAAAAAAAA","resource":"proxy_policy","controller_epoch":"2","command_id":"1","expected_policy_revision":"1","source_administrator_id":"AQEBAQEBAQEBAQEBAQEBAQ","mutation":{"action":"create_user","name":"remote user","protocols":["http"],"concurrent_limit":2}})
    }

    #[test]
    fn command_vocabulary_is_strict_and_all_revisions_are_canonical_decimal_strings() {
        let input: Command = serde_json::from_value(command()).unwrap();
        assert!(input.into_store().is_ok());
        for field in ["controller_epoch", "command_id", "expected_policy_revision"] {
            for invalid in ["", "0", "01", "+1", "1 ", "9223372036854775808"] {
                let mut body = command();
                body[field] = invalid.into();
                let input: Command = serde_json::from_value(body).unwrap();
                assert!(input.into_store().is_err());
            }
            let mut body = command();
            body[field] = 1.into();
            assert!(serde_json::from_value::<Command>(body).is_err());
        }
        for (field, value) in [
            ("version", serde_json::json!(2)),
            ("target_node_id", serde_json::json!("attacker")),
            ("resource", serde_json::json!("shell")),
            ("source_administrator_id", serde_json::json!("not-an-id")),
        ] {
            let mut body = command();
            body[field] = value;
            assert!(
                serde_json::from_value::<Command>(body)
                    .unwrap()
                    .into_store()
                    .is_err()
            );
        }
        let mut body = command();
        body["actor"] = serde_json::json!({"node_id":"forged"});
        assert!(serde_json::from_value::<Command>(body).is_err());
        let mut body = command();
        body["mutation"]["password"] = serde_json::json!("chosen-secret");
        assert!(serde_json::from_value::<Command>(body).is_err());
        let mut body = command();
        body["mutation"]["action"] = serde_json::json!("exec");
        assert!(serde_json::from_value::<Command>(body).is_err());
    }

    #[test]
    fn node_queries_reject_unknown_duplicate_or_oversized_filters() {
        for query in [
            "limit=0",
            "limit=51",
            "limit=01",
            "limit=2&limit=3",
            "after=not-an-id",
            "include_deleted=1",
            "user_id=AAAAAAAAAAAAAAAAAAAAAA",
            "url=https://other.test",
        ] {
            let uri = format!("/node/v1/proxy/users?{query}").parse().unwrap();
            assert!(pagination(&uri, false).is_err(), "accepted {query}");
        }
        let uri = "/node/v1/proxy/credentials?limit=50&user_id=AAAAAAAAAAAAAAAAAAAAAA"
            .parse()
            .unwrap();
        let page = pagination(&uri, true).unwrap();
        assert_eq!(page.limit, 50);
        assert!(no_query(&"/node/v1/proxy/policy?".parse().unwrap()).is_err());
    }

    #[test]
    fn oversized_metadata_is_rejected_before_returning_a_response() {
        assert!(
            respond(
                "AAAAAAAAAAAAAAAAAAAAAA",
                StatusCode::OK,
                "x".repeat(MAX_RESPONSE_BYTES)
            )
            .is_err()
        );
    }
}
