//! Explicit reads of this node's existing incidents. The original egress route
//! keeps its narrow projection; operations reads add local operational sources
//! without exporting downstream observations or starting a second monitor.

use std::collections::HashSet;

use super::*;
use crate::manage::alerts::{
    EgressPage, Filter, Kind, NodePage, NodeSnapshot, PageError, Query, SnapshotError, Status,
};

// 512 finite-vocabulary ASCII incidents fit below 400 KiB, including metadata.
// Only this fixed snapshot may exceed the original paged RPC's 32 KiB cap.
pub(super) const SNAPSHOT_RESPONSE_BYTES: usize = 512 * 1024;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/node/v1/proxy/egress-alerts", get(observations))
        .route("/node/v1/proxy/operations-alerts", get(operations))
        .route("/node/v1/proxy/operations-snapshot", get(snapshot))
}

async fn snapshot(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let authorization = peer.authorization();
    let monitor = state.alerts.clone();
    let snapshot = coordinator(&state)?
        .read(move |directory| {
            store::remote_authorized(directory, &authorization, || {
                Ok(monitor
                    .as_ref()
                    .ok_or(SnapshotError::Unavailable)
                    .and_then(crate::manage::alerts::Handle::node_snapshot))
            })
        })
        .await
        .map_err(storage_error)?
        .map_err(|error| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                match error {
                    SnapshotError::Unavailable => "alerts_unavailable",
                    SnapshotError::Capacity => "operations_alerts_capacity",
                },
            )
        })?;
    respond_resource_limited(
        VERSION,
        RESOURCE,
        &state.node_id,
        StatusCode::OK,
        snapshot,
        SNAPSHOT_RESPONSE_BYTES,
    )
}

async fn operations(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    let query = Query::parse(uri.query()).map_err(page_error)?;
    let authorization = peer.authorization();
    let monitor = state.alerts.clone();
    let page = coordinator(&state)?
        .read(move |directory| {
            store::remote_authorized(directory, &authorization, || {
                Ok(monitor
                    .as_ref()
                    .ok_or(PageError::Unavailable)
                    .and_then(|handle| {
                        handle.node_page(query.filter, query.after.as_deref(), query.limit)
                    }))
            })
        })
        .await
        .map_err(storage_error)?
        .map_err(page_error)?;
    respond(&state.node_id, StatusCode::OK, page)
}

async fn observations(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    let query = Query::parse(uri.query()).map_err(page_error)?;
    let authorization = peer.authorization();
    let monitor = state.alerts.clone();
    let page = coordinator(&state)?
        .read(move |directory| {
            // Authorization and the RAM read share the current owner/leaf
            // transaction, just like the existing health route. A registered
            // identity alone has no permission to inspect egress resources.
            store::remote_authorized(directory, &authorization, || {
                Ok(monitor
                    .as_ref()
                    .ok_or(PageError::Unavailable)
                    .and_then(|handle| {
                        handle.egress_page(query.filter, query.after.as_deref(), query.limit)
                    }))
            })
        })
        .await
        .map_err(storage_error)?
        .map_err(page_error)?;
    respond(&state.node_id, StatusCode::OK, page)
}

fn page_error(error: PageError) -> ApiError {
    match error {
        PageError::InvalidQuery => bad("invalid_alert_query"),
        PageError::Changed => ApiError::new(StatusCode::CONFLICT, "alerts_changed"),
        PageError::Unavailable => {
            ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "alerts_unavailable")
        }
    }
}

pub(super) fn encode(query: &Query) -> io::Result<(Method, String, Vec<u8>)> {
    encode_path(query, "egress-alerts")
}

pub(super) fn encode_operations(query: &Query) -> io::Result<(Method, String, Vec<u8>)> {
    encode_path(query, "operations-alerts")
}

fn encode_path(query: &Query, route: &str) -> io::Result<(Method, String, Vec<u8>)> {
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    encoded.append_pair(
        "state",
        match query.filter {
            Filter::Active => "active",
            Filter::Recent => "recent",
        },
    );
    encoded.append_pair("limit", &query.limit.to_string());
    if let Some(after) = &query.after {
        encoded.append_pair("after", after);
    }
    let raw = encoded.finish();
    Query::parse(Some(&raw)).map_err(|_| invalid())?;
    Ok((Method::GET, format!("{PREFIX}/{route}?{raw}"), Vec::new()))
}

/// A trusted peer still has to return the selected scope and exact page.
/// Validate before browser JSON escapes the controller: no arbitrary public
/// code, other-node origin or local-alert cursor is accepted as an egress fact.
pub(super) fn decode(query: &Query, bytes: &[u8], expected: &str) -> io::Result<Reply> {
    let page: EgressPage = client::envelope(bytes, expected, VERSION)?;
    let revision = integer(&page.revision, false)?;
    let offset = query
        .egress_offset(&page.boot_id, revision)
        .map_err(|_| invalid())?;
    if page.node_id != expected
        || !valid_id(&page.boot_id)
        || !(1..=16).contains(&query.limit)
        || page.active_count > 6144
        || page.recent_count > 256
        || page.items.len() > query.limit as usize
        || page.observed_at_unix_ms.is_some() && page.age_millis.is_none()
        || !page.monitored
            && (page.active_count != 0
                || page.recent_count != 0
                || page.age_millis.is_some()
                || page.dropped != "0")
    {
        return Err(invalid());
    }
    integer(&page.dropped, true)?;
    optional_integer(page.observed_at_unix_ms.as_deref())?;
    optional_integer(page.age_millis.as_deref())?;
    let total = match query.filter {
        Filter::Active => page.active_count,
        Filter::Recent => page.recent_count,
    } as usize;
    let next = offset
        .checked_add(page.items.len())
        .filter(|next| *next <= total)
        .ok_or_else(invalid)?;
    if offset > total
        || page.items.len() != (total - offset).min(query.limit as usize)
        || page.next_cursor
            != (next < total).then(|| {
                format!(
                    "{}:{}:{}:{next}",
                    page.boot_id,
                    page.revision,
                    query.filter.egress_code()
                )
            })
    {
        return Err(invalid());
    }
    let mut ids = HashSet::with_capacity(page.items.len());
    for item in &page.items {
        integer(&item.id, false)?;
        integer(&item.age_millis, true)?;
        for value in [
            item.first_observed_at_unix_ms.as_deref(),
            item.last_observed_at_unix_ms.as_deref(),
            item.ended_at_unix_ms.as_deref(),
            item.evidence_sequence.as_deref(),
        ] {
            optional_integer(value)?;
        }
        let kind_valid = match item.kind {
            Kind::EgressCheck => {
                item.resource_id.as_deref().is_some_and(valid_id)
                    && match item.check {
                        Some(crate::manage::health::CheckKind::Bind) => item.target.is_none(),
                        Some(crate::manage::health::CheckKind::Tcp) => {
                            item.target.is_some_and(|target| {
                                target.port() != 0
                                    && crate::access::routing::valid_ip(target.ip())
                                    && !matches!(target, std::net::SocketAddr::V6(address)
                                        if address.scope_id() != 0 || address.flowinfo() != 0)
                            })
                        }
                        None => false,
                    }
                    && matches!(
                        item.code.as_str(),
                        "egress_address_unavailable"
                            | "egress_connection_refused"
                            | "egress_timed_out"
                            | "egress_permission_denied"
                            | "egress_network_unreachable"
                            | "egress_failed"
                            | "egress_family_mismatch"
                    )
            }
            Kind::HealthCatalog => {
                item.resource_id.is_none()
                    && item.check.is_none()
                    && item.target.is_none()
                    && matches!(
                        item.code.as_str(),
                        "health_catalog_unavailable" | "health_catalog_stale"
                    )
            }
            _ => false,
        };
        if !kind_valid
            || item.origin_node_id != expected
            || !ids.insert(&item.id)
            || (query.filter == Filter::Active) != (item.status == Status::Active)
            || item.status == Status::Active && item.ended_at_unix_ms.is_some()
            || item.status == Status::Unmonitored && item.evidence_fresh
            || item.status == Status::Recovered && !item.evidence_fresh
        {
            return Err(invalid());
        }
    }
    Ok(Reply::EgressAlerts(page))
}

/// Full local operations use their own cursor domain. An owner is not thereby
/// authorised to read another node's identity, cached traffic or command jobs.
pub(super) fn decode_operations(query: &Query, bytes: &[u8], expected: &str) -> io::Result<Reply> {
    required_operations_fields(bytes, &["items"], true)?;
    let page: NodePage = client::envelope(bytes, expected, VERSION)?;
    let revision = integer(&page.revision, false)?;
    let offset = query
        .node_offset(&page.boot_id, revision)
        .map_err(|_| invalid_operations())?;
    if page.node_id != expected
        || !valid_id(&page.boot_id)
        || !(1..=16).contains(&query.limit)
        || page.active_count > 6144
        || page.recent_count > 256
        || page.observed_at_unix_ms.is_some() && page.age_millis.is_none()
    {
        return Err(invalid_operations());
    }
    integer(&page.dropped, true)?;
    optional_integer(page.observed_at_unix_ms.as_deref())?;
    optional_integer(page.age_millis.as_deref())?;
    let total = match query.filter {
        Filter::Active => page.active_count,
        Filter::Recent => page.recent_count,
    } as usize;
    let next = offset
        .checked_add(page.items.len())
        .filter(|next| *next <= total)
        .ok_or_else(invalid_operations)?;
    if offset > total
        || page.items.len() != (total - offset).min(query.limit as usize)
        || page.next_cursor
            != (next < total).then(|| {
                format!(
                    "{}:{}:{}:{next}",
                    page.boot_id,
                    page.revision,
                    query.filter.node_code()
                )
            })
    {
        return Err(invalid_operations());
    }
    let mut ids = HashSet::with_capacity(page.items.len());
    for item in &page.items {
        operations_item(item, expected, query.filter, &mut ids)?;
    }
    Ok(Reply::OperationsAlerts(page))
}

/// Decode one complete inventory with actual caller-supplied TLS evidence.
/// The existing page and this atomic snapshot share item/nullable validation.
pub(super) fn decode_snapshot(
    bytes: &[u8],
    expected: &str,
    authorization: store::RemoteAuthorization,
) -> io::Result<Reply> {
    if bytes.len() > SNAPSHOT_RESPONSE_BYTES
        || !valid_id(expected)
        || authorization.node_id != expected
        || authorization.authorization_revision == 0
        || authorization.authorization_revision > i64::MAX as u64
        || authorization.leaf.is_empty()
        || authorization.leaf.len() > 16 * 1024
    {
        return Err(invalid_operations());
    }
    required_operations_fields(bytes, &["active", "recent"], false)?;
    let snapshot: NodeSnapshot = client::envelope(bytes, expected, VERSION)?;
    if snapshot.node_id != expected
        || !valid_id(&snapshot.boot_id)
        || snapshot.active.len() > 256
        || snapshot.recent.len() > 256
        || snapshot.active.len() != snapshot.active_count as usize
        || snapshot.recent.len() != snapshot.recent_count as usize
        || snapshot.observed_at_unix_ms.is_some() && snapshot.age_millis.is_none()
    {
        return Err(invalid_operations());
    }
    integer(&snapshot.revision, false)?;
    integer(&snapshot.dropped, true)?;
    optional_integer(snapshot.observed_at_unix_ms.as_deref())?;
    optional_integer(snapshot.age_millis.as_deref())?;
    let mut ids = HashSet::with_capacity(snapshot.active.len() + snapshot.recent.len());
    for item in &snapshot.active {
        operations_item(item, expected, Filter::Active, &mut ids)?;
    }
    for item in &snapshot.recent {
        operations_item(item, expected, Filter::Recent, &mut ids)?;
    }
    Ok(Reply::OperationsSnapshot(Box::new(Fetched {
        authorization,
        value: snapshot,
    })))
}

fn required_operations_fields(bytes: &[u8], lists: &[&str], paged: bool) -> io::Result<()> {
    // Serde Option alone accepts omitted keys. Nullable fields are mandatory in
    // both additive contracts; a missing field cannot silently become unknown.
    let raw: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| invalid_operations())?;
    let data = raw
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid_operations)?;
    if ["observed_at_unix_ms", "age_millis"]
        .iter()
        .any(|key| !data.contains_key(*key))
        || paged && !data.contains_key("next_cursor")
        || lists.iter().any(|list| {
            data.get(*list)
                .and_then(serde_json::Value::as_array)
                .is_none_or(|items| {
                    items.iter().any(|item| {
                        item.as_object().is_none_or(|item| {
                            [
                                "resource_id",
                                "check",
                                "target",
                                "first_observed_at_unix_ms",
                                "last_observed_at_unix_ms",
                                "ended_at_unix_ms",
                                "evidence_sequence",
                            ]
                            .iter()
                            .any(|key| !item.contains_key(*key))
                        })
                    })
                })
        })
    {
        return Err(invalid_operations());
    }
    Ok(())
}

fn operations_item<'a>(
    item: &'a crate::manage::alerts::Alert,
    expected: &str,
    filter: Filter,
    ids: &mut HashSet<&'a str>,
) -> io::Result<()> {
    integer(&item.id, false)?;
    integer(&item.age_millis, true)?;
    for value in [
        item.first_observed_at_unix_ms.as_deref(),
        item.last_observed_at_unix_ms.as_deref(),
        item.ended_at_unix_ms.as_deref(),
        item.evidence_sequence.as_deref(),
    ] {
        optional_integer(value)?;
    }
    if item.origin_node_id != expected
        || !ids.insert(item.id.as_str())
        || !local_kind(item)
        || (filter == Filter::Active) != (item.status == Status::Active)
        || item.status == Status::Active && item.ended_at_unix_ms.is_some()
        || item.status == Status::Unmonitored && item.evidence_fresh
        || item.status == Status::Recovered && !item.evidence_fresh
    {
        return Err(invalid_operations());
    }
    Ok(())
}

/// Keep the wire's public vocabulary independent of the history storage format.
fn local_kind(item: &crate::manage::alerts::Alert) -> bool {
    if item.kind != Kind::EgressCheck && (item.check.is_some() || item.target.is_some()) {
        return false;
    }
    let code = item.code.as_str();
    match item.kind {
        Kind::EgressCheck => {
            item.resource_id.as_deref().is_some_and(valid_id)
                && match item.check {
                    Some(crate::manage::health::CheckKind::Bind) => item.target.is_none(),
                    Some(crate::manage::health::CheckKind::Tcp) => {
                        item.target.is_some_and(|target| {
                            target.port() != 0
                                && crate::access::routing::valid_ip(target.ip())
                                && !matches!(target, std::net::SocketAddr::V6(address)
                                if address.scope_id() != 0 || address.flowinfo() != 0)
                        })
                    }
                    None => false,
                }
                && matches!(
                    code,
                    "egress_address_unavailable"
                        | "egress_connection_refused"
                        | "egress_timed_out"
                        | "egress_permission_denied"
                        | "egress_network_unreachable"
                        | "egress_failed"
                        | "egress_family_mismatch"
                )
        }
        Kind::HealthCatalog => {
            item.resource_id.is_none()
                && matches!(code, "health_catalog_unavailable" | "health_catalog_stale")
        }
        Kind::ManagementHttps => {
            item.resource_id.is_none()
                && matches!(
                    code,
                    "https_identity_unavailable"
                        | "https_identity_expiring"
                        | "https_identity_expired"
                        | "https_identity_not_yet_valid"
                        | "https_identity_metadata_unavailable"
                        | "acme_attempt_unavailable"
                        | "acme_review_required"
                        | "acme_worker_stopped"
                )
        }
        Kind::NodeTls => {
            item.resource_id.is_none()
                && matches!(
                    code,
                    "node_tls_identity_unavailable"
                        | "node_tls_identity_expiring"
                        | "node_tls_identity_expired"
                        | "node_tls_identity_not_yet_valid"
                        | "node_tls_identity_metadata_unavailable"
                )
        }
        Kind::ProxyTls => {
            item.resource_id.as_deref().is_some_and(valid_id)
                && matches!(
                    code,
                    "proxy_tls_identity_unavailable"
                        | "proxy_tls_identity_expiring"
                        | "proxy_tls_identity_expired"
                        | "proxy_tls_identity_not_yet_valid"
                        | "proxy_tls_identity_metadata_unavailable"
                )
        }
        Kind::Policy => {
            item.resource_id.is_none()
                && matches!(
                    code,
                    "proxy_not_running"
                        | "policy_publication_unavailable"
                        | "policy_not_applied"
                        | "proxy_drain_failed"
                        | "proxy_drain_interrupted"
                )
        }
        Kind::TrafficCheckpoint => {
            item.resource_id.is_none()
                && matches!(
                    code,
                    "traffic_checkpoint_failed" | "traffic_checkpoint_stale"
                )
        }
        Kind::TrafficContinuity => {
            item.resource_id.is_none()
                && matches!(
                    code,
                    "traffic_loss_possible" | "traffic_history_gap" | "traffic_time_uncertain"
                )
        }
        Kind::RemoteTraffic | Kind::RemoteJob | Kind::RemoteObservation => false,
    }
}

fn invalid_operations() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid node operations alert page",
    )
}

fn integer(value: &str, zero: bool) -> io::Result<u64> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
        || !zero && value == "0"
    {
        return Err(invalid());
    }
    value.parse().map_err(|_| invalid())
}

fn optional_integer(value: Option<&str>) -> io::Result<()> {
    value
        .map(|value| integer(value, true))
        .transpose()
        .map(|_| ())
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid node egress alert page")
}
