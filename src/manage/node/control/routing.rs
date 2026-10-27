//! Version-two finite routing control and bounded node-local observations.
//! The old command vocabulary remains a different serde type and route.

use super::*;
use crate::{
    access::routing::{self as model, AddressFamily, ResourceState, RoutePermission},
    manage::{health, views},
};
use std::{collections::HashSet, net::IpAddr};

const VERSION: u8 = 2;
const PREFIX: &str = "/node/v2/proxy";

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::manage) enum RoutingMutation {
    CreatePrefix {
        name: String,
        #[serde(
            serialize_with = "serialize_cidr",
            deserialize_with = "deserialize_cidr"
        )]
        cidr: cidr::IpCidr,
    },
    RetirePrefix {
        id: String,
    },
    CreateAddress {
        name: String,
        ip: IpAddr,
        prefix_id: Option<String>,
    },
    SetAddressState {
        id: String,
        state: ResourceState,
    },
    CreatePool {
        name: String,
        family: AddressFamily,
    },
    SetPoolState {
        id: String,
        state: ResourceState,
    },
    AddPoolMember {
        pool_id: String,
        address_id: String,
    },
    RemovePoolMember {
        pool_id: String,
        address_id: String,
    },
    SetRoutePermission {
        permission: views::Permission,
    },
}
fn serialize_cidr<S: serde::Serializer>(
    value: &cidr::IpCidr,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}
fn deserialize_cidr<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<cidr::IpCidr, D::Error> {
    let text = String::deserialize(deserializer)?;
    text.parse::<cidr::IpCidr>()
        .ok()
        // Accept explicit host masks, but retain Display for outgoing commands:
        // older peers, durable outboxes and receipt digests use the bare host.
        .filter(|value| value.to_string() == text || format!("{value:#}") == text)
        .ok_or_else(|| serde::de::Error::custom("canonical IP prefix required"))
}
impl From<RoutingMutation> for store::PolicyChange {
    fn from(value: RoutingMutation) -> Self {
        match value {
            RoutingMutation::CreatePrefix { name, cidr } => Self::CreatePrefix { name, cidr },
            RoutingMutation::RetirePrefix { id } => Self::RetirePrefix { id },
            RoutingMutation::CreateAddress {
                name,
                ip,
                prefix_id,
            } => Self::CreateAddress {
                name,
                ip,
                prefix_id,
            },
            RoutingMutation::SetAddressState { id, state } => Self::SetAddressState { id, state },
            RoutingMutation::CreatePool { name, family } => Self::CreatePool { name, family },
            RoutingMutation::SetPoolState { id, state } => Self::SetPoolState { id, state },
            RoutingMutation::AddPoolMember {
                pool_id,
                address_id,
            } => Self::AddPoolMember {
                pool_id,
                address_id,
            },
            RoutingMutation::RemovePoolMember {
                pool_id,
                address_id,
            } => Self::RemovePoolMember {
                pool_id,
                address_id,
            },
            RoutingMutation::SetRoutePermission { permission } => Self::SetRoutePermission {
                permission: RoutePermission {
                    user_id: permission.user_id,
                    legacy_allowed: permission.legacy_allowed,
                    exits: permission.exits,
                    pools: permission.pools,
                },
            },
        }
    }
}
impl TryFrom<store::PolicyChange> for RoutingMutation {
    type Error = io::Error;
    fn try_from(value: store::PolicyChange) -> io::Result<Self> {
        Ok(match value {
            store::PolicyChange::CreatePrefix { name, cidr } => Self::CreatePrefix { name, cidr },
            store::PolicyChange::RetirePrefix { id } => Self::RetirePrefix { id },
            store::PolicyChange::CreateAddress {
                name,
                ip,
                prefix_id,
            } => Self::CreateAddress {
                name,
                ip,
                prefix_id,
            },
            store::PolicyChange::SetAddressState { id, state } => {
                Self::SetAddressState { id, state }
            }
            store::PolicyChange::CreatePool { name, family } => Self::CreatePool { name, family },
            store::PolicyChange::SetPoolState { id, state } => Self::SetPoolState { id, state },
            store::PolicyChange::AddPoolMember {
                pool_id,
                address_id,
            } => Self::AddPoolMember {
                pool_id,
                address_id,
            },
            store::PolicyChange::RemovePoolMember {
                pool_id,
                address_id,
            } => Self::RemovePoolMember {
                pool_id,
                address_id,
            },
            store::PolicyChange::SetRoutePermission { permission } => Self::SetRoutePermission {
                permission: permission.into(),
            },
            _ => return Err(invalid("version-two routing action required")),
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct RoutingCommand {
    pub(in crate::manage) version: u8,
    pub(in crate::manage) target_node_id: String,
    pub(in crate::manage) resource: String,
    pub(in crate::manage) controller_epoch: String,
    pub(in crate::manage) command_id: String,
    pub(in crate::manage) expected_policy_revision: String,
    pub(in crate::manage) source_administrator_id: String,
    pub(in crate::manage) mutation: RoutingMutation,
}
impl RoutingCommand {
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
        .route("/node/v2/proxy/commands", post(command))
        .route("/node/v2/proxy/receipts/{epoch}/{command_id}", get(receipt))
        .route("/node/v2/proxy/prefixes", get(prefixes))
        .route("/node/v2/proxy/addresses", get(addresses))
        .route("/node/v2/proxy/addresses/{id}", get(address))
        .route("/node/v2/proxy/pools", get(pools))
        .route("/node/v2/proxy/pools/{id}/members", get(members))
        .route("/node/v2/proxy/users/{id}/routing", get(permission))
        .route("/node/v2/proxy/health", get(observations))
}
async fn catalog(
    state: &AppState,
    peer: VerifiedPeer,
) -> Result<(u64, model::RoutingData), ApiError> {
    let authorization = peer.authorization();
    coordinator(state)?
        .read(move |directory| store::remote_routing_data(directory, &authorization))
        .await
        .map_err(storage_error)
}
struct Pagination {
    after: Option<String>,
    limit: u32,
}
fn pagination(uri: &http::Uri, health: bool) -> Result<Pagination, ApiError> {
    let query = uri.query().unwrap_or_default();
    if query.len() > 1024 {
        return Err(bad("invalid_pagination"));
    }
    let mut value = Pagination {
        after: None,
        limit: if health { 10 } else { 25 },
    };
    let mut seen = [false; 2];
    for (key, text) in url::form_urlencoded::parse(query.as_bytes()) {
        let index = match key.as_ref() {
            "after" => 0,
            "limit" => 1,
            _ => return Err(bad("invalid_pagination")),
        };
        if seen[index] {
            return Err(bad("invalid_pagination"));
        }
        seen[index] = true;
        if index == 0 {
            if !valid_id(&text) {
                return Err(bad("invalid_pagination"));
            }
            value.after = Some(text.into_owned());
        } else {
            let limit = decimal(&text, false).map_err(|_| bad("invalid_pagination"))?;
            if limit > if health { 16 } else { 50 } {
                return Err(bad("invalid_pagination"));
            }
            value.limit = limit as u32;
        }
    }
    Ok(value)
}
fn path_id(
    path: Result<Path<String>, axum::extract::rejection::PathRejection>,
) -> Result<String, ApiError> {
    let Path(id) = path.map_err(|_| bad("invalid_query"))?;
    if !valid_id(&id) {
        return Err(bad("invalid_query"));
    }
    Ok(id)
}
fn page<T>(mut items: Vec<(String, T)>, revision: u64, input: Pagination) -> views::Page<T> {
    items.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let mut rows = items
        .into_iter()
        .filter(|(id, _)| input.after.as_ref().is_none_or(|after| id > after));
    let mut items = Vec::new();
    let mut last = None;
    for _ in 0..input.limit {
        let Some((id, value)) = rows.next() else {
            break;
        };
        last = Some(id);
        items.push(value);
    }
    views::Page {
        revision: revision.to_string(),
        items,
        next_cursor: if rows.next().is_some() { last } else { None },
    }
}
async fn prefixes(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    let input = pagination(&uri, false)?;
    let (revision, data) = catalog(&state, peer).await?;
    respond_version(
        VERSION,
        &state.node_id,
        StatusCode::OK,
        page(
            data.prefixes
                .into_iter()
                .map(|v| (v.id.clone(), views::Prefix::from(v)))
                .collect(),
            revision,
            input,
        ),
    )
}
async fn addresses(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    let input = pagination(&uri, false)?;
    let (revision, data) = catalog(&state, peer).await?;
    respond_version(
        VERSION,
        &state.node_id,
        StatusCode::OK,
        page(
            data.addresses
                .into_iter()
                .map(|v| (v.id.clone(), views::Address::from(v)))
                .collect(),
            revision,
            input,
        ),
    )
}
async fn address(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    path: Result<Path<String>, axum::extract::rejection::PathRejection>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = path_id(path)?;
    let (revision, data) = catalog(&state, peer).await?;
    let address = data
        .addresses
        .into_iter()
        .find(|value| value.id == id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "resource_not_found"))?;
    respond_version(
        VERSION,
        &state.node_id,
        StatusCode::OK,
        views::AddressView {
            revision: revision.to_string(),
            address: address.into(),
        },
    )
}

async fn pools(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    let input = pagination(&uri, false)?;
    let (revision, data) = catalog(&state, peer).await?;
    respond_version(
        VERSION,
        &state.node_id,
        StatusCode::OK,
        page(
            data.pools
                .into_iter()
                .map(|v| (v.id.clone(), views::Pool::from(v)))
                .collect(),
            revision,
            input,
        ),
    )
}
async fn members(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    path: Result<Path<String>, axum::extract::rejection::PathRejection>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    let id = path_id(path)?;
    let input = pagination(&uri, false)?;
    let (revision, data) = catalog(&state, peer).await?;
    let pool = data
        .pools
        .into_iter()
        .find(|v| v.id == id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "resource_not_found"))?;
    respond_version(
        VERSION,
        &state.node_id,
        StatusCode::OK,
        page(
            pool.members
                .into_iter()
                .map(|id| (id.clone(), id))
                .collect(),
            revision,
            input,
        ),
    )
}
async fn permission(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    path: Result<Path<String>, axum::extract::rejection::PathRejection>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = path_id(path)?;
    let (revision, data) = catalog(&state, peer).await?;
    let permission = data
        .permissions
        .into_iter()
        .find(|v| v.user_id == id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "resource_not_found"))?;
    respond_version(
        VERSION,
        &state.node_id,
        StatusCode::OK,
        views::PermissionView {
            revision: revision.to_string(),
            permission: permission.into(),
        },
    )
}
async fn observations(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    let input = pagination(&uri, true)?;
    let authorization = peer.authorization();
    let handle = state.health.clone();
    let mut snapshot = coordinator(&state)?
        .read(move |directory| {
            store::remote_authorized(directory, &authorization, || {
                handle
                    .as_ref()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::Unsupported, "health observer not configured")
                    })?
                    .snapshot()
            })
        })
        .await
        .map_err(|e| {
            if e.kind() == io::ErrorKind::Unsupported {
                ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "health_unavailable")
            } else {
                storage_error(e)
            }
        })?;
    snapshot
        .entries
        .sort_unstable_by(|a, b| a.address_id.cmp(&b.address_id));
    snapshot.entries.retain(|v| {
        input
            .after
            .as_ref()
            .is_none_or(|after| &v.address_id > after)
    });
    let limit = input.limit as usize;
    let cursor = if snapshot.entries.len() > limit {
        snapshot
            .entries
            .get(limit - 1)
            .map(|v| v.address_id.clone())
    } else {
        None
    };
    snapshot.entries.truncate(limit);
    respond_version(
        VERSION,
        &state.node_id,
        StatusCode::OK,
        views::HealthPage::new(snapshot, cursor),
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
    let mut values = request.headers().get_all(header::CONTENT_TYPE).iter();
    if !values
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
        || values.next().is_some()
    {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "json_required",
        ));
    }
    let input: RoutingCommand = api::json(request).await?;
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
        routing: result.routing.map(Into::into),
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
    let (path, after, limit) = match operation {
        Request::RoutingCommand(command) => {
            command
                .clone()
                .into_store()
                .map_err(|_| invalid("invalid routing command"))?;
            let body = serde_json::to_vec(command)
                .map_err(|_| invalid("cannot encode routing command"))?;
            if body.len() > 4096 {
                return Err(invalid("routing command exceeds input limit"));
            }
            return Ok((Method::POST, format!("{PREFIX}/commands"), body));
        }
        Request::PrefixesPage { after, limit } => (format!("{PREFIX}/prefixes"), after, *limit),
        Request::AddressesPage { after, limit } => (format!("{PREFIX}/addresses"), after, *limit),
        Request::Address { address_id } => {
            if !valid_id(address_id) {
                return Err(invalid("invalid routing address"));
            }
            return Ok((
                Method::GET,
                format!("{PREFIX}/addresses/{address_id}"),
                Vec::new(),
            ));
        }
        Request::PoolsPage { after, limit } => (format!("{PREFIX}/pools"), after, *limit),
        Request::PoolMembersPage {
            pool_id,
            after,
            limit,
        } => {
            if !valid_id(pool_id) {
                return Err(invalid("invalid routing resource"));
            }
            (format!("{PREFIX}/pools/{pool_id}/members"), after, *limit)
        }
        Request::UserRouting { user_id } => {
            if !valid_id(user_id) {
                return Err(invalid("invalid routing user"));
            }
            return Ok((
                Method::GET,
                format!("{PREFIX}/users/{user_id}/routing"),
                Vec::new(),
            ));
        }
        Request::HealthPage { after, limit } => (format!("{PREFIX}/health"), after, *limit),
        _ => return Err(invalid("unsupported routing operation")),
    };
    if !(1..=if matches!(operation, Request::HealthPage { .. }) {
        16
    } else {
        50
    })
        .contains(&limit)
        || after.as_deref().is_some_and(|id| !valid_id(id))
    {
        return Err(invalid("invalid routing pagination"));
    }
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("limit", &limit.to_string());
    if let Some(after) = after {
        query.append_pair("after", after);
    }
    Ok((
        Method::GET,
        format!("{path}?{}", query.finish()),
        Vec::new(),
    ))
}

pub(super) fn decode(
    operation: &Request,
    bytes: &[u8],
    peer: &str,
    status: StatusCode,
) -> io::Result<Reply> {
    match operation {
        Request::RoutingCommand(command) => {
            let mut value: CommandReply = client::envelope(bytes, peer, VERSION)?;
            value.receipt.version = VERSION;
            client::validate_receipt(&value.receipt)?;
            validate_command(command, &value, status)?;
            Ok(Reply::Command(Box::new(value)))
        }
        Request::PrefixesPage { after, limit } => {
            let value: views::Page<views::Prefix> = client::envelope(bytes, peer, VERSION)?;
            validate_page(&value, after, *limit, |v| {
                (&v.id, Some(v.revision.as_str()), validate_prefix(v))
            })?;
            Ok(Reply::PrefixesPage(value))
        }
        Request::AddressesPage { after, limit } => {
            let value: views::Page<views::Address> = client::envelope(bytes, peer, VERSION)?;
            validate_page(&value, after, *limit, |v| {
                (&v.id, Some(v.revision.as_str()), validate_address(v))
            })?;
            Ok(Reply::AddressesPage(value))
        }
        Request::Address { address_id } => {
            let value: views::AddressView = client::envelope(bytes, peer, VERSION)?;
            let revision = client::number(&value.revision, false)?;
            validate_address(&value.address)?;
            if !valid_id(address_id)
                || value.address.id != *address_id
                || client::number(&value.address.revision, false)? > revision
            {
                return Err(invalid(
                    "address does not match the requested catalog identity",
                ));
            }
            Ok(Reply::Address(value))
        }
        Request::PoolsPage { after, limit } => {
            let value: views::Page<views::Pool> = client::envelope(bytes, peer, VERSION)?;
            validate_page(&value, after, *limit, |v| {
                (&v.id, Some(v.revision.as_str()), validate_pool(v))
            })?;
            Ok(Reply::PoolsPage(value))
        }
        Request::PoolMembersPage { after, limit, .. } => {
            let value: views::Page<String> = client::envelope(bytes, peer, VERSION)?;
            validate_page(&value, after, *limit, |v| (v, None, Ok(())))?;
            Ok(Reply::PoolMembersPage(value))
        }
        Request::UserRouting { user_id } => {
            let value: views::PermissionView = client::envelope(bytes, peer, VERSION)?;
            client::number(&value.revision, false)?;
            validate_permission(&value.permission)?;
            if &value.permission.user_id != user_id {
                return Err(invalid("routing permission belongs to another user"));
            }
            Ok(Reply::UserRouting(value))
        }
        Request::HealthPage { after, limit } => {
            let value: views::HealthPage = client::envelope(bytes, peer, VERSION)?;
            validate_health(&value, after, *limit)?;
            Ok(Reply::HealthPage(Box::new(value)))
        }
        _ => Err(invalid("unsupported routing reply")),
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn validate_prefix(value: &views::Prefix) -> io::Result<()> {
    client::number(&value.revision, false)?;
    if !valid_name(&value.name)
        || value
            .cidr
            .parse::<cidr::IpCidr>()
            .ok()
            .is_none_or(|v| v.to_string() != value.cidr)
    {
        return Err(invalid("invalid prefix metadata"));
    }
    Ok(())
}
fn validate_address(value: &views::Address) -> io::Result<()> {
    client::number(&value.revision, false)?;
    if !valid_name(&value.name)
        || !model::valid_ip(value.ip)
        || value.prefix_id.as_deref().is_some_and(|v| !valid_id(v))
    {
        return Err(invalid("invalid address metadata"));
    }
    Ok(())
}
fn validate_pool(value: &views::Pool) -> io::Result<()> {
    client::number(&value.revision, false)?;
    if !valid_name(&value.name) || value.member_count > model::MAX_ADDRESSES {
        return Err(invalid("invalid pool metadata"));
    }
    Ok(())
}
fn validate_permission(value: &views::Permission) -> io::Result<()> {
    if !valid_id(&value.user_id) {
        return Err(invalid("invalid permission identity"));
    }
    for ids in [&value.exits, &value.pools] {
        let mut unique = HashSet::new();
        if ids.len() > model::MAX_GRANTS || ids.iter().any(|v| !valid_id(v) || !unique.insert(v)) {
            return Err(invalid("invalid permission grants"));
        }
    }
    Ok(())
}
fn validate_page<T>(
    value: &views::Page<T>,
    after: &Option<String>,
    limit: u32,
    project: impl for<'a> Fn(&'a T) -> (&'a str, Option<&'a str>, io::Result<()>),
) -> io::Result<()> {
    let revision = client::number(&value.revision, false)?;
    if value.items.len() > limit as usize {
        return Err(invalid("routing page exceeds input limit"));
    }
    let mut previous = after.as_deref();
    for item in &value.items {
        let (id, item_revision, valid) = project(item);
        valid?;
        if item_revision
            .map(|v| client::number(v, false))
            .transpose()?
            .is_some_and(|v| v > revision)
        {
            return Err(invalid("routing entity exceeds catalog revision"));
        }
        if !valid_id(id) || previous.is_some_and(|last| id <= last) {
            return Err(invalid("invalid routing page ordering"));
        }
        previous = Some(id);
    }
    if value
        .next_cursor
        .as_deref()
        .is_some_and(|v| !valid_id(v) || Some(v) != previous)
        || value.items.is_empty() && value.next_cursor.is_some()
    {
        return Err(invalid("invalid routing page cursor"));
    }
    Ok(())
}

fn validate_command(
    command: &RoutingCommand,
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
        || value.presets.is_some()
        || ((value.replayed || value.receipt.status == ReceiptStatus::Rejected)
            && value.routing.is_some())
    {
        return Err(invalid("invalid routing command result shape"));
    }
    if value.receipt.status == ReceiptStatus::Rejected {
        return Ok(());
    }
    let revision = client::number(&command.expected_policy_revision, false)?
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or_else(|| invalid("routing policy revision exhausted"))?;
    if value
        .receipt
        .policy_revision
        .as_deref()
        .map(|v| client::number(v, false))
        .transpose()?
        != Some(revision)
    {
        return Err(invalid("routing receipt differs from policy CAS"));
    }
    let reference = value
        .receipt
        .routing
        .as_ref()
        .ok_or_else(|| invalid("missing routing receipt reference"))?;
    let (kind, id) = match &command.mutation {
        RoutingMutation::CreatePrefix { .. } => (store::RoutingKind::Prefix, None),
        RoutingMutation::RetirePrefix { id } => (store::RoutingKind::Prefix, Some(id.as_str())),
        RoutingMutation::CreateAddress { .. } => (store::RoutingKind::Address, None),
        RoutingMutation::SetAddressState { id, .. } => {
            (store::RoutingKind::Address, Some(id.as_str()))
        }
        RoutingMutation::CreatePool { .. } => (store::RoutingKind::Pool, None),
        RoutingMutation::SetPoolState { id, .. } => (store::RoutingKind::Pool, Some(id.as_str())),
        RoutingMutation::AddPoolMember { pool_id, .. }
        | RoutingMutation::RemovePoolMember { pool_id, .. } => {
            (store::RoutingKind::Pool, Some(pool_id.as_str()))
        }
        RoutingMutation::SetRoutePermission { permission } => (
            store::RoutingKind::Permission,
            Some(permission.user_id.as_str()),
        ),
    };
    if reference.kind != kind || id.is_some_and(|id| id != reference.id) {
        return Err(invalid("routing receipt names another resource"));
    }
    if !value.replayed {
        let entity = value
            .routing
            .as_ref()
            .ok_or_else(|| invalid("first routing reply omitted entity"))?;
        let (entity_kind, entity_id, entity_revision) = match entity {
            views::Entity::Prefix(v) => {
                validate_prefix(v)?;
                (store::RoutingKind::Prefix, &v.id, Some(&v.revision))
            }
            views::Entity::Address(v) => {
                validate_address(v)?;
                (store::RoutingKind::Address, &v.id, Some(&v.revision))
            }
            views::Entity::Pool(v) => {
                validate_pool(v)?;
                (store::RoutingKind::Pool, &v.id, Some(&v.revision))
            }
            views::Entity::Permission(v) => {
                validate_permission(v)?;
                (store::RoutingKind::Permission, &v.user_id, None)
            }
        };
        if entity_kind != reference.kind
            || entity_id != &reference.id
            || entity_revision.is_some_and(|v| v != &revision.to_string())
        {
            return Err(invalid("routing entity differs from receipt"));
        }
        let matches = match (&command.mutation, entity) {
            (RoutingMutation::CreatePrefix { name, cidr }, views::Entity::Prefix(v)) => {
                v.name == *name && v.cidr == cidr.to_string() && !v.retired
            }
            (RoutingMutation::RetirePrefix { .. }, views::Entity::Prefix(v)) => v.retired,
            (
                RoutingMutation::CreateAddress {
                    name,
                    ip,
                    prefix_id,
                },
                views::Entity::Address(v),
            ) => {
                v.name == *name
                    && v.ip == *ip
                    && v.prefix_id == *prefix_id
                    && v.state == ResourceState::Active
            }
            (RoutingMutation::SetAddressState { state, .. }, views::Entity::Address(v)) => {
                v.state == *state
            }
            (RoutingMutation::CreatePool { name, family }, views::Entity::Pool(v)) => {
                v.name == *name
                    && v.family == *family
                    && v.state == ResourceState::Active
                    && v.member_count == 0
            }
            (RoutingMutation::SetPoolState { state, .. }, views::Entity::Pool(v)) => {
                v.state == *state
            }
            (
                RoutingMutation::AddPoolMember { .. } | RoutingMutation::RemovePoolMember { .. },
                views::Entity::Pool(_),
            ) => true,
            (RoutingMutation::SetRoutePermission { permission }, views::Entity::Permission(v)) => {
                v.user_id == permission.user_id
                    && v.legacy_allowed == permission.legacy_allowed
                    && same_set(&v.exits, &permission.exits)
                    && same_set(&v.pools, &permission.pools)
            }
            _ => false,
        };
        if !matches {
            return Err(invalid("routing entity differs from requested mutation"));
        }
    }
    Ok(())
}
fn same_set(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().collect::<HashSet<_>>() == b.iter().collect::<HashSet<_>>()
}
fn counter(value: &str) -> io::Result<u64> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|v| v.is_ascii_digit())
    {
        return Err(invalid("invalid health counter"));
    }
    value.parse().map_err(|_| invalid("invalid health counter"))
}
fn validate_health(
    value: &views::HealthPage,
    after: &Option<String>,
    limit: u32,
) -> io::Result<()> {
    let sequence = counter(&value.sequence)?;
    let catalog = value
        .catalog_revision
        .as_deref()
        .map(|v| client::number(v, false))
        .transpose()?;
    if !valid_id(&value.boot_id)
        || value.in_flight > 4
        || value.entries.len() > limit as usize
        || limit > 16
        || value
            .catalog_error
            .as_deref()
            .is_some_and(|v| v != "catalog_unavailable")
        || (value.catalog_loaded && (catalog.is_none() || value.catalog_age_millis.is_none()))
        || (!value.catalog_loaded
            && (catalog.is_some()
                || value.catalog_observed_at_unix_ms.is_some()
                || value.catalog_age_millis.is_some()
                || !value.entries.is_empty()))
    {
        return Err(invalid("invalid health catalog"));
    }
    let safe = |v: Option<u64>| v.is_none_or(|v| v <= 9_007_199_254_740_991);
    if !safe(value.catalog_observed_at_unix_ms) || !safe(value.catalog_age_millis) {
        return Err(invalid("invalid health timestamp"));
    }
    let mut previous = after.as_deref();
    for entry in &value.entries {
        let revision = client::number(&entry.address_revision, false)?;
        if !valid_id(&entry.address_id)
            || previous.is_some_and(|v| v >= entry.address_id.as_str())
            || !model::valid_ip(entry.ip)
            || catalog.is_none_or(|v| revision > v)
            || entry.checks.is_empty()
            || entry.checks.len() > 5
        {
            return Err(invalid("invalid health address metadata"));
        }
        previous = Some(&entry.address_id);
        let mut bind = 0;
        let mut targets = HashSet::new();
        for check in &entry.checks {
            match (check.kind, check.target) {
                (health::CheckKind::Bind, None) => bind += 1,
                (health::CheckKind::Tcp, Some(target))
                    if target.port() != 0
                        && model::valid_ip(target.ip())
                        && match target {
                            std::net::SocketAddr::V6(v) => v.scope_id() == 0 && v.flowinfo() == 0,
                            _ => true,
                        }
                        && targets.insert(target) => {}
                _ => return Err(invalid("invalid health target")),
            }
            let check_seq = check.sequence.as_deref().map(counter).transpose()?;
            if check_seq.is_some_and(|v| v == 0 || v > sequence)
                || !safe(check.observed_at_unix_ms)
                || !safe(check.age_millis)
                || !safe(check.latency_millis)
                || (check_seq.is_none()
                    && (check.outcome != health::FixedOutcome::Unknown
                        || check.observed_at_unix_ms.is_some()
                        || check.age_millis.is_some()
                        || check.latency_millis.is_some()))
                || (check_seq.is_some()
                    && (check.age_millis.is_none() || check.latency_millis.is_none()))
            {
                return Err(invalid("invalid health observation"));
            }
        }
        if bind != 1 {
            return Err(invalid("health address requires one bind observation"));
        }
    }
    if value
        .next_cursor
        .as_deref()
        .is_some_and(|v| !valid_id(v) || Some(v) != previous)
        || value.entries.is_empty() && value.next_cursor.is_some()
    {
        return Err(invalid("invalid health cursor"));
    }
    Ok(())
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn id(value: u8) -> String {
        URL_SAFE_NO_PAD.encode([value; 16])
    }
    fn command() -> RoutingCommand {
        RoutingCommand {
            version: 2,
            target_node_id: id(1),
            resource: RESOURCE.into(),
            controller_epoch: "2".into(),
            command_id: "3".into(),
            expected_policy_revision: "10".into(),
            source_administrator_id: id(2),
            mutation: RoutingMutation::CreatePool {
                name: "finite pool".into(),
                family: AddressFamily::V4,
            },
        }
    }
    fn body() -> Value {
        json!({"receipt":{"controller_epoch":"2","command_id":"3","status":"applied","policy_revision":"11","rejection":null,"user_id":null,"credential_id":null,"routing":{"kind":"pool","id":id(3)}},"replayed":false,"user":null,"credential":null,"secret":null,"secret_available":false,"routing":{"kind":"pool","data":{"id":id(3),"name":"finite pool","family":"v4","state":"active","member_count":0,"revision":"11"}}})
    }
    fn wire(data: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"version":2,"node_id":id(1),"resource":RESOURCE,"data":data}))
            .unwrap()
    }

    #[test]
    fn exact_address_lookup_encoding_and_decoder_bind_identity_and_snapshot() {
        let operation = Request::Address { address_id: id(3) };
        let (method, path, body) = encode(&operation).unwrap();
        assert_eq!(method, Method::GET);
        assert_eq!(path, format!("/node/v2/proxy/addresses/{}", id(3)));
        assert!(body.is_empty());
        assert!(
            encode(&Request::Address {
                address_id: "../policy".into()
            })
            .is_err()
        );
        let good = json!({"revision":"11","address":{"id":id(3),"name":"Retired metadata","ip":"127.0.0.1","prefix_id":null,"state":"retired","revision":"9"}});
        assert!(matches!(
            decode(&operation, &wire(good.clone()), &id(1), StatusCode::OK),
            Ok(Reply::Address(_))
        ));
        for (field, value) in [
            ("id", json!(id(4))),
            ("id", json!("not-an-id")),
            ("name", json!(" wrong name ")),
            ("ip", json!("0.0.0.0")),
            ("prefix_id", json!("not-an-id")),
            ("state", json!("invented")),
            ("revision", json!("12")),
            ("revision", json!("09")),
            ("revision", json!("0")),
            ("revision", json!("9223372036854775808")),
            ("unexpected", json!(true)),
        ] {
            let mut wrong = good.clone();
            wrong["address"][field] = value;
            assert!(
                decode(&operation, &wire(wrong), &id(1), StatusCode::OK).is_err(),
                "field: {field}"
            );
        }
        for revision in ["0", "011", "-1", "9223372036854775808"] {
            let mut wrong = good.clone();
            wrong["revision"] = json!(revision);
            assert!(decode(&operation, &wire(wrong), &id(1), StatusCode::OK).is_err());
        }
        let mut wrong = good.clone();
        wrong["unexpected"] = json!(true);
        assert!(decode(&operation, &wire(wrong), &id(1), StatusCode::OK).is_err());
        assert!(decode(&operation, &wire(good), &id(2), StatusCode::OK).is_err());
    }

    #[test]
    fn host_prefix_inputs_keep_the_legacy_wire_encoding() {
        for (explicit, legacy) in [
            ("127.0.0.1/32", "127.0.0.1"),
            ("2001:db8::1/128", "2001:db8::1"),
        ] {
            let old = json!({"action":"create_prefix","name":"host","cidr":legacy});
            for cidr in [explicit, legacy] {
                let parsed: RoutingMutation = serde_json::from_value(
                    json!({"action":"create_prefix","name":"host","cidr":cidr}),
                )
                .unwrap();
                assert_eq!(serde_json::to_value(parsed).unwrap(), old);
            }
        }
        for cidr in [
            "127.0.0.1/032",
            "127.0.0.1/24",
            "::1/129",
            "2001:DB8::1/128",
            "2001:0db8::1/128",
            " ::1/128",
        ] {
            assert!(
                serde_json::from_value::<RoutingMutation>(
                    json!({"action":"create_prefix","name":"host","cidr":cidr}),
                )
                .is_err(),
                "{cidr}"
            );
        }
    }

    #[test]
    fn host_prefix_first_reply_keeps_legacy_shape_and_exact_correlation() {
        for (explicit, legacy) in [
            ("127.0.0.1/32", "127.0.0.1"),
            ("2001:db8::1/128", "2001:db8::1"),
        ] {
            let mut command = command();
            command.mutation = RoutingMutation::CreatePrefix {
                name: "host".into(),
                cidr: explicit.parse().unwrap(),
            };
            let request = Request::RoutingCommand(command);
            let mut data = body();
            data["receipt"]["routing"]["kind"] = json!("prefix");
            data["routing"] = json!({"kind":"prefix","data":{"id":id(3),"name":"host","cidr":legacy,"retired":false,"revision":"11"}});
            assert!(decode(&request, &wire(data.clone()), &id(1), StatusCode::OK).is_ok());
            for (field, value) in [
                ("cidr", json!(explicit)),
                ("cidr", json!("192.0.2.1")),
                ("name", json!("other")),
                ("retired", json!(true)),
            ] {
                let mut wrong = data.clone();
                wrong["routing"]["data"][field] = value;
                assert!(decode(&request, &wire(wrong), &id(1), StatusCode::OK).is_err());
            }
        }
    }

    #[test]
    fn vocabularies_and_nested_permissions_do_not_cross_versions() {
        let value = serde_json::to_value(command()).unwrap();
        assert!(serde_json::from_value::<Command>(value.clone()).is_err());
        let mut wrong = value.clone();
        wrong["version"] = json!(1);
        assert!(
            serde_json::from_value::<RoutingCommand>(wrong)
                .unwrap()
                .into_store()
                .is_err()
        );
        let mut wrong = value.clone();
        wrong["mutation"] =
            json!({"action":"create_user","name":"no","protocols":["http"],"concurrent_limit":1});
        assert!(serde_json::from_value::<RoutingCommand>(wrong).is_err());
        let permission = json!({"action":"set_route_permission","permission":{"user_id":id(4),"legacy_allowed":false,"exits":[id(5)],"pools":[id(6)]}});
        let mutation: RoutingMutation = serde_json::from_value(permission.clone()).unwrap();
        assert_eq!(serde_json::to_value(mutation).unwrap(), permission);
        assert!(serde_json::from_value::<RoutingMutation>(json!({"action":"set_route_permission","user_id":id(4),"legacy_allowed":false,"exits":[],"pools":[]})).is_err());
        assert!(
            serde_json::from_value::<RoutingMutation>(
                json!({"action":"create_prefix","name":"canonical","cidr":"2001:0db8::/32"})
            )
            .is_err()
        );
        let prefix: RoutingMutation = serde_json::from_value(
            json!({"action":"create_prefix","name":"canonical","cidr":"2001:db8::/32"}),
        )
        .unwrap();
        let change: store::PolicyChange = prefix.into();
        assert_eq!(change.control_version(), 2);
        let encoded = encode(&Request::RoutingCommand(command())).unwrap();
        assert_eq!(encoded.0, Method::POST);
        assert_eq!(encoded.1, "/node/v2/proxy/commands");
        assert!(
            encode(&Request::HealthPage {
                after: None,
                limit: 17
            })
            .is_err()
        );
        assert!(
            encode(&Request::PoolMembersPage {
                pool_id: "../policy".into(),
                after: None,
                limit: 1
            })
            .is_err()
        );
    }

    #[test]
    fn v1_reply_serialization_has_identical_fields_order_and_nulls() {
        let value = CommandReply {
            receipt: Receipt {
                version: 1,
                controller_epoch: "2".into(),
                command_id: "3".into(),
                status: ReceiptStatus::Applied,
                policy_revision: Some("11".into()),
                rejection: None,
                user_id: Some(id(3)),
                credential_id: None,
                routing: None,
                preset: None,
            },
            replayed: true,
            user: None,
            credential: None,
            secret: None,
            secret_available: false,
            routing: None,
            presets: None,
        };
        let expected = format!(
            r#"{{"receipt":{{"controller_epoch":"2","command_id":"3","status":"applied","policy_revision":"11","rejection":null,"user_id":"{}","credential_id":null}},"replayed":true,"user":null,"credential":null,"secret":null,"secret_available":false}}"#,
            id(3)
        );
        assert_eq!(serde_json::to_vec(&value).unwrap(), expected.as_bytes());
        let old: CommandReply = serde_json::from_slice(expected.as_bytes()).unwrap();
        assert!(old.routing.is_none());
        assert!(old.receipt.routing.is_none());
    }

    #[test]
    fn routing_reply_correlates_cas_reference_shape_and_empty_new_pool() {
        let request = Request::RoutingCommand(command());
        assert!(matches!(
            decode(&request, &wire(body()), &id(1), StatusCode::OK),
            Ok(Reply::Command(_))
        ));
        let mut invalids = Vec::new();
        let mut wrong = body();
        wrong["routing"]["data"]["member_count"] = json!(1);
        invalids.push(wrong);
        let mut wrong = body();
        wrong["receipt"]["routing"]["kind"] = json!("address");
        invalids.push(wrong);
        let mut wrong = body();
        wrong["routing"]["data"]["id"] = json!(id(8));
        invalids.push(wrong);
        let mut wrong = body();
        wrong["receipt"]["policy_revision"] = json!("10");
        invalids.push(wrong);
        let mut wrong = body();
        wrong["routing"]["data"]["revision"] = json!("12");
        invalids.push(wrong);
        let mut wrong = body();
        wrong["routing"] = Value::Null;
        invalids.push(wrong);
        let mut wrong = body();
        wrong["secret"] = json!(URL_SAFE_NO_PAD.encode([7; 32]));
        wrong["secret_available"] = json!(true);
        invalids.push(wrong);
        let mut wrong = body();
        wrong["replayed"] = json!(true);
        invalids.push(wrong);
        for wrong in invalids {
            assert!(decode(&request, &wire(wrong), &id(1), StatusCode::OK).is_err());
        }
        let mut replay = body();
        replay["replayed"] = json!(true);
        replay["routing"] = Value::Null;
        let Ok(Reply::Command(replayed)) = decode(&request, &wire(replay), &id(1), StatusCode::OK)
        else {
            panic!("matching replay should succeed")
        };
        assert!(replayed.replayed && replayed.routing.is_none() && replayed.secret.is_none());
        let mut rejected = body();
        rejected["receipt"]["status"] = json!("rejected");
        rejected["receipt"]["policy_revision"] = Value::Null;
        rejected["receipt"]["routing"] = Value::Null;
        rejected["receipt"]["rejection"] = json!("invalid_policy");
        rejected["routing"] = Value::Null;
        assert!(decode(&request, &wire(rejected), &id(1), StatusCode::OK).is_ok());
        let mut wrong_version: Value = serde_json::from_slice(&wire(body())).unwrap();
        wrong_version["version"] = json!(1);
        assert!(
            decode(
                &request,
                &serde_json::to_vec(&wrong_version).unwrap(),
                &id(1),
                StatusCode::OK
            )
            .is_err()
        );
    }

    #[test]
    fn inventory_pages_validate_global_revision_and_order_not_just_json_types() {
        let request = Request::AddressesPage {
            after: None,
            limit: 2,
        };
        let entry = json!({"id":id(2),"name":"owned","ip":"127.0.0.2","prefix_id":null,"state":"active","revision":"10"});
        let data = json!({"revision":"10","items":[entry.clone()],"next_cursor":null});
        assert!(decode(&request, &wire(data.clone()), &id(1), StatusCode::OK).is_ok());
        let mut wrong = data.clone();
        wrong["items"][0]["revision"] = json!("11");
        assert!(decode(&request, &wire(wrong), &id(1), StatusCode::OK).is_err());
        let mut wrong = data.clone();
        wrong["items"] = json!([entry.clone(), entry]);
        assert!(decode(&request, &wire(wrong), &id(1), StatusCode::OK).is_err());
        let mut wrong = data;
        wrong["items"][0]["ip"] = json!("0.0.0.0");
        assert!(decode(&request, &wire(wrong), &id(1), StatusCode::OK).is_err());
    }

    fn health_page() -> views::HealthPage {
        views::HealthPage {
            boot_id: id(8),
            sequence: u64::MAX.to_string(),
            catalog_revision: Some(i64::MAX.to_string()),
            catalog_loaded: true,
            catalog_error: Some("catalog_unavailable".into()),
            catalog_observed_at_unix_ms: Some(9_007_199_254_740_991),
            catalog_age_millis: Some(9_007_199_254_740_991),
            in_flight: 4,
            entries: (0..16)
                .map(|index| views::HealthEntry {
                    address_id: id(index),
                    address_revision: i64::MAX.to_string(),
                    ip: "2001:db8f:ffff:ffff:ffff:ffff:ffff:fffe".parse().unwrap(),
                    checks: (0..5)
                        .map(|target| views::HealthCheck {
                            kind: if target == 0 {
                                health::CheckKind::Bind
                            } else {
                                health::CheckKind::Tcp
                            },
                            target: if target == 0 {
                                None
                            } else {
                                Some(
                                    format!(
                                        "[2001:db8f:ffff:ffff:ffff:ffff:ffff:fffe]:{}",
                                        65535 - target
                                    )
                                    .parse()
                                    .unwrap(),
                                )
                            },
                            outcome: health::FixedOutcome::NetworkUnreachable,
                            sequence: Some(u64::MAX.to_string()),
                            observed_at_unix_ms: Some(9_007_199_254_740_991),
                            age_millis: Some(9_007_199_254_740_991),
                            latency_millis: Some(9_007_199_254_740_991),
                        })
                        .collect(),
                })
                .collect(),
            next_cursor: Some(id(15)),
        }
    }

    #[test]
    fn health_full_envelope_fits_cap_and_validates_stale_sequence_and_targets() {
        let mut maximum = health_page();
        maximum
            .entries
            .sort_by(|a, b| a.address_id.cmp(&b.address_id));
        maximum.next_cursor = maximum.entries.last().map(|v| v.address_id.clone());
        assert!(respond_version(2, &id(1), StatusCode::OK, maximum).is_ok());
        let request = Request::HealthPage {
            after: None,
            limit: 16,
        };
        let mut value = health_page();
        value
            .entries
            .sort_by(|a, b| a.address_id.cmp(&b.address_id));
        value.next_cursor = value.entries.last().map(|v| v.address_id.clone());
        let mut data = serde_json::to_value(value).unwrap();
        assert!(decode(&request, &wire(data.clone()), &id(1), StatusCode::OK).is_ok());
        let mut multicast = data.clone();
        multicast["entries"][0]["ip"] = json!("ff02::1");
        assert!(decode(&request, &wire(multicast), &id(1), StatusCode::OK).is_err());
        data["entries"][0]["checks"][0]["outcome"] = json!("unknown");
        assert!(decode(&request, &wire(data.clone()), &id(1), StatusCode::OK).is_ok());
        let mut wrong = data.clone();
        wrong["entries"][0]["checks"][1]["target"] = json!("[::1%1]:80");
        assert!(decode(&request, &wire(wrong), &id(1), StatusCode::OK).is_err());
        let mut wrong = data.clone();
        wrong["entries"][0]["checks"][0]["sequence"] = Value::Null;
        assert!(decode(&request, &wire(wrong), &id(1), StatusCode::OK).is_err());
        let mut wrong = data;
        wrong["catalog_age_millis"] = json!(9_007_199_254_740_992u64);
        assert!(decode(&request, &wire(wrong), &id(1), StatusCode::OK).is_err());
    }
}
