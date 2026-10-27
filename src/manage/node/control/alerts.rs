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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const NODE: &str = "AAAAAAAAAAAAAAAAAAAAAA";
    const ADDRESS: &str = "AQEBAQEBAQEBAQEBAQEBAQ";

    fn item(id: &str) -> Value {
        json!({"id":id,"kind":"egress_check","origin_node_id":NODE,"resource_id":ADDRESS,
        "check":"bind","target":null,"status":"active","code":"egress_address_unavailable",
        "first_observed_at_unix_ms":null,"last_observed_at_unix_ms":null,"ended_at_unix_ms":null,
        "age_millis":"0","evidence_sequence":"18446744073709551615","evidence_fresh":true})
    }

    fn page() -> Value {
        json!({"node_id":NODE,"boot_id":NODE,"revision":"7","observed_at_unix_ms":null,
        "age_millis":"0","collection_error":false,"monitored":true,
        "active_count":2,"recent_count":0,"dropped":"0","items":[item("1")],
        "next_cursor":format!("{NODE}:7:egress-active:1")})
    }

    fn wire(page: Value) -> Vec<u8> {
        serde_json::to_vec(
            &json!({"version":1,"node_id":NODE,"resource":"proxy_policy","data":page}),
        )
        .unwrap()
    }

    #[test]
    fn egress_alert_wire_checks_scope_reasons_exact_counts_and_cursor_bindings() {
        let query = Query::parse(Some("limit=1")).unwrap();
        let valid = page();
        assert!(matches!(
            decode(&query, &wire(valid.clone()), NODE),
            Ok(Reply::EgressAlerts(_))
        ));
        let mut invalid = Vec::new();
        for (field, value) in [
            ("node_id", json!(ADDRESS)),
            ("boot_id", json!("bad")),
            ("revision", json!("07")),
            ("active_count", json!(1)),
            ("items", json!([])),
            ("next_cursor", json!(format!("{NODE}:7:active:1"))),
            ("next_cursor", json!(format!("{NODE}:7:egress-active:2"))),
            ("next_cursor", Value::Null),
            ("arbitrary", json!("not allowed")),
        ] {
            let mut value_page = valid.clone();
            value_page[field] = value;
            invalid.push(value_page);
        }
        for (field, value) in [
            ("origin_node_id", json!(ADDRESS)),
            ("kind", json!("remote_job")),
            ("code", json!("raw_remote_error")),
            ("code", json!("health_catalog_stale")),
            ("resource_id", Value::Null),
            ("target", json!("127.0.0.1:80")),
            ("status", json!("recovered")),
            ("age_millis", json!("18446744073709551616")),
            ("evidence_sequence", json!("01")),
            ("secret", json!("not allowed")),
        ] {
            let mut value_page = valid.clone();
            value_page["items"][0][field] = value;
            invalid.push(value_page);
        }
        for value in invalid {
            assert!(decode(&query, &wire(value), NODE).is_err());
        }
        for cursor in [
            format!("{NODE}:7:active:0"),
            format!("{NODE}:8:egress-active:0"),
            format!("{ADDRESS}:7:egress-active:0"),
            format!("{NODE}:7:egress-recent:0"),
        ] {
            let query = Query::parse(Some(&format!("limit=1&after={cursor}"))).unwrap();
            assert!(decode(&query, &wire(valid.clone()), NODE).is_err());
        }
        assert!(decode(&query, &wire(valid), ADDRESS).is_err());
    }

    #[test]
    fn egress_alert_wire_accepts_final_and_terminal_pages_without_claiming_new_health() {
        let query = Query::parse(Some(&format!("limit=1&after={NODE}:7:egress-active:1"))).unwrap();
        let mut last = page();
        last["items"][0] = item("2");
        last["next_cursor"] = Value::Null;
        last["collection_error"] = json!(true);
        last["items"][0]["evidence_fresh"] = json!(false);
        assert!(decode(&query, &wire(last.clone()), NODE).is_ok());
        let recent = Query::parse(Some("state=recent&limit=1")).unwrap();
        last["active_count"] = json!(0);
        last["recent_count"] = json!(1);
        last["items"][0]["status"] = json!("unmonitored");
        assert!(decode(&recent, &wire(last.clone()), NODE).is_ok());
        last["items"][0]["status"] = json!("recovered");
        assert!(decode(&recent, &wire(last.clone()), NODE).is_err());
        last["items"][0]["evidence_fresh"] = json!(true);
        assert!(decode(&recent, &wire(last), NODE).is_ok());
    }

    #[test]
    fn missing_egress_route_negotiates_only_the_fixed_not_found_response() {
        for (status, code, expected) in [
            (
                StatusCode::NOT_FOUND,
                "not_found",
                "node_protocol_unsupported",
            ),
            (
                StatusCode::NOT_FOUND,
                "resource_not_found",
                "resource_not_found",
            ),
            (StatusCode::FORBIDDEN, "not_found", "node_request_rejected"),
            (StatusCode::CONFLICT, "alerts_changed", "alerts_changed"),
            (
                StatusCode::BAD_REQUEST,
                "alerts_changed",
                "node_request_rejected",
            ),
        ] {
            let bytes = serde_json::to_vec(&json!({"error":{"code":code}})).unwrap();
            let error = client::remote_error(status, &bytes, 2);
            assert_eq!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<RemoteError>()
                    .unwrap()
                    .code,
                expected
            );
        }
    }

    fn operations_item(id: &str, kind: &str, code: &str) -> Value {
        let mut value = item(id);
        value["kind"] = json!(kind);
        value["code"] = json!(code);
        if kind != "egress_check" {
            value["check"] = Value::Null;
            value["resource_id"] = if kind == "proxy_tls" {
                json!(ADDRESS)
            } else {
                Value::Null
            };
        }
        value
    }

    fn operations_page() -> Value {
        json!({"node_id":NODE,"boot_id":NODE,"revision":"7","observed_at_unix_ms":null,
        "age_millis":"0","collection_error":false,
        "coverage":{"local_egress":true,"local_traffic":true,"local_proxy_expected":true,
            "local_management_https":true,"local_node_tls":true,"local_proxy_tls":true},
        "active_count":8,"recent_count":0,"dropped":"0","items":[
            operations_item("1","egress_check","egress_address_unavailable"),
            operations_item("2","health_catalog","health_catalog_stale"),
            operations_item("3","management_https","acme_worker_stopped"),
            operations_item("4","node_tls","node_tls_identity_expiring"),
            operations_item("5","proxy_tls","proxy_tls_identity_metadata_unavailable"),
            operations_item("6","policy","proxy_drain_interrupted"),
            operations_item("7","traffic_checkpoint","traffic_checkpoint_failed"),
            operations_item("8","traffic_continuity","traffic_history_gap")
        ],"next_cursor":null})
    }

    #[test]
    fn operations_wire_accepts_all_eight_local_kinds_and_keeps_the_read_path_additive() {
        let query = Query::parse(Some("limit=16")).unwrap();
        let valid = operations_page();
        assert!(matches!(
            decode_operations(&query, &wire(valid.clone()), NODE),
            Ok(Reply::OperationsAlerts(_))
        ));
        assert!(
            decode(&query, &wire(valid), NODE).is_err(),
            "not an egress page"
        );
        let (method, path, bytes) = client::encode(&Request::OperationsAlerts(query)).unwrap();
        assert_eq!(method, Method::GET);
        assert_eq!(
            path,
            "/node/v1/proxy/operations-alerts?state=active&limit=16"
        );
        assert!(bytes.is_empty());
    }

    #[test]
    fn operations_wire_rejects_other_subjects_missing_nullables_and_inconsistent_pages() {
        let query = Query::parse(Some("limit=16")).unwrap();
        let valid = operations_page();
        let mut invalid = Vec::new();
        for (field, value) in [
            ("node_id", json!(ADDRESS)),
            ("revision", json!("07")),
            ("active_count", json!(6145)),
            ("recent_count", json!(257)),
            ("active_count", json!(7)),
            ("dropped", json!("18446744073709551616")),
            ("next_cursor", json!(format!("{NODE}:7:node-active:8"))),
            ("observed_at_unix_ms", json!("1")),
            ("monitored", json!(true)),
        ] {
            let mut value_page = valid.clone();
            value_page[field] = value;
            if field == "observed_at_unix_ms" {
                value_page["age_millis"] = Value::Null;
            }
            invalid.push(value_page);
        }
        for field in ["observed_at_unix_ms", "age_millis", "next_cursor"] {
            let mut value_page = valid.clone();
            value_page.as_object_mut().unwrap().remove(field);
            invalid.push(value_page);
        }
        for (field, value) in [
            ("id", json!("0")),
            ("id", json!("2")),
            ("origin_node_id", json!(ADDRESS)),
            ("kind", json!("remote_traffic")),
            ("kind", json!("remote_job")),
            ("code", json!("raw_remote_error")),
            ("code", json!("health_catalog_stale")),
            ("evidence_sequence", json!("18446744073709551616")),
            ("resource_id", Value::Null),
            ("target", json!("127.0.0.1:443")),
            ("status", json!("recovered")),
            ("ended_at_unix_ms", json!("1")),
            ("secret", json!("not allowed")),
        ] {
            let mut value_page = valid.clone();
            value_page["items"][0][field] = value;
            invalid.push(value_page);
        }
        for field in [
            "resource_id",
            "check",
            "target",
            "first_observed_at_unix_ms",
            "last_observed_at_unix_ms",
            "ended_at_unix_ms",
            "evidence_sequence",
        ] {
            let mut value_page = valid.clone();
            value_page["items"][0]
                .as_object_mut()
                .unwrap()
                .remove(field);
            invalid.push(value_page);
        }
        for (kind, code) in [
            ("policy", "traffic_checkpoint_failed"),
            ("management_https", "node_tls_identity_expired"),
            ("traffic_continuity", "proxy_not_running"),
        ] {
            let mut value_page = valid.clone();
            value_page["items"][1] = operations_item("2", kind, code);
            invalid.push(value_page);
        }
        for key in ["remote_cached", "remote_egress"] {
            let mut value_page = valid.clone();
            value_page["coverage"][key] = json!(false);
            invalid.push(value_page);
        }
        let mut missing_coverage = valid.clone();
        missing_coverage["coverage"]
            .as_object_mut()
            .unwrap()
            .remove("local_node_tls");
        invalid.push(missing_coverage);
        for value in invalid {
            assert!(decode_operations(&query, &wire(value), NODE).is_err());
        }
        for cursor in [
            format!("{NODE}:7:active:0"),
            format!("{NODE}:7:egress-active:0"),
            format!("{NODE}:7:node-recent:0"),
            format!("{NODE}:8:node-active:0"),
            format!("{ADDRESS}:7:node-active:0"),
        ] {
            let query = Query::parse(Some(&format!("limit=16&after={cursor}"))).unwrap();
            assert!(decode_operations(&query, &wire(valid.clone()), NODE).is_err());
        }
        assert!(decode_operations(&query, &wire(valid), ADDRESS).is_err());
    }

    #[test]
    fn operations_wire_checks_exact_final_pages_and_terminal_freshness() {
        let mut valid = operations_page();
        valid["items"] = json!([operations_item(
            "8",
            "traffic_continuity",
            "traffic_history_gap"
        )]);
        valid["collection_error"] = json!(true);
        valid["items"][0]["evidence_fresh"] = json!(false);
        let query = Query::parse(Some(&format!("limit=1&after={NODE}:7:node-active:7"))).unwrap();
        assert!(decode_operations(&query, &wire(valid.clone()), NODE).is_ok());
        let recent = Query::parse(Some("state=recent&limit=1")).unwrap();
        valid["active_count"] = json!(0);
        valid["recent_count"] = json!(1);
        valid["items"][0]["status"] = json!("unmonitored");
        assert!(decode_operations(&recent, &wire(valid.clone()), NODE).is_ok());
        valid["items"][0]["evidence_fresh"] = json!(true);
        assert!(decode_operations(&recent, &wire(valid.clone()), NODE).is_err());
        valid["items"][0]["status"] = json!("recovered");
        assert!(decode_operations(&recent, &wire(valid.clone()), NODE).is_ok());
        valid["items"][0]["evidence_fresh"] = json!(false);
        assert!(decode_operations(&recent, &wire(valid.clone()), NODE).is_err());
        valid["recent_count"] = json!(0);
        valid["items"] = json!([]);
        assert!(decode_operations(&recent, &wire(valid), NODE).is_ok());
    }

    fn operations_snapshot() -> Value {
        let mut value = operations_page();
        let active = value.as_object_mut().unwrap().remove("items").unwrap();
        value.as_object_mut().unwrap().remove("next_cursor");
        value["active"] = active;
        value["recent"] = json!([]);
        value
    }

    fn proof() -> store::RemoteAuthorization {
        store::RemoteAuthorization {
            node_id: NODE.to_owned(),
            authorization_revision: 1,
            leaf: std::sync::Arc::from(b"synthetic-leaf".as_slice()),
        }
    }

    #[test]
    fn atomic_operations_snapshot_shares_strict_items_and_never_accepts_wire_authority() {
        let valid = operations_snapshot();
        let Reply::OperationsSnapshot(snapshot) =
            decode_snapshot(&wire(valid.clone()), NODE, proof()).unwrap()
        else {
            panic!("snapshot reply");
        };
        assert_eq!(snapshot.value.active.len(), 8);
        assert_eq!(&*snapshot.authorization.leaf, b"synthetic-leaf");
        let (method, path, body) = client::encode(&Request::OperationsSnapshot).unwrap();
        assert_eq!(method, Method::GET);
        assert_eq!(path, "/node/v1/proxy/operations-snapshot");
        assert!(body.is_empty());
        assert!(
            client::decode(
                &Request::OperationsSnapshot,
                &wire(valid.clone()),
                NODE,
                StatusCode::OK
            )
            .is_err()
        );
        let mut invalid = Vec::new();
        for (field, value) in [
            ("node_id", json!(ADDRESS)),
            ("boot_id", json!("bad")),
            ("revision", json!("07")),
            ("active_count", json!(7)),
            ("recent_count", json!(1)),
            ("authorization", json!({"node_id":NODE})),
            ("items", json!([])),
            ("dropped", json!("18446744073709551616")),
        ] {
            let mut value_page = valid.clone();
            value_page[field] = value;
            invalid.push(value_page);
        }
        for field in ["observed_at_unix_ms", "age_millis"] {
            let mut value = valid.clone();
            value.as_object_mut().unwrap().remove(field);
            invalid.push(value);
        }
        for (field, value) in [
            ("origin_node_id", json!(ADDRESS)),
            ("kind", json!("remote_observation")),
            ("kind", json!("remote_traffic")),
            ("kind", json!("remote_job")),
            ("code", json!("arbitrary_remote_text")),
            ("status", json!("recovered")),
            ("evidence_sequence", json!("01")),
            ("ended_at_unix_ms", json!("1")),
        ] {
            let mut value_page = valid.clone();
            value_page["active"][0][field] = value;
            invalid.push(value_page);
        }
        for field in [
            "resource_id",
            "check",
            "target",
            "first_observed_at_unix_ms",
            "last_observed_at_unix_ms",
            "ended_at_unix_ms",
            "evidence_sequence",
        ] {
            let mut value = valid.clone();
            value["active"][0].as_object_mut().unwrap().remove(field);
            invalid.push(value);
        }
        let mut duplicate = valid.clone();
        let mut recent = duplicate["active"][0].clone();
        recent["status"] = json!("recovered");
        duplicate["recent"] = json!([recent]);
        duplicate["recent_count"] = json!(1);
        invalid.push(duplicate);
        for value in invalid {
            assert!(decode_snapshot(&wire(value), NODE, proof()).is_err());
        }
        for revision in [0, i64::MAX as u64 + 1] {
            let mut invalid_proof = proof();
            invalid_proof.authorization_revision = revision;
            assert!(decode_snapshot(&wire(valid.clone()), NODE, invalid_proof).is_err());
        }
        let mut invalid_proof = proof();
        invalid_proof.node_id = ADDRESS.into();
        assert!(decode_snapshot(&wire(valid.clone()), NODE, invalid_proof).is_err());
        let mut invalid_proof = proof();
        invalid_proof.leaf = std::sync::Arc::from([]);
        assert!(decode_snapshot(&wire(valid), NODE, invalid_proof).is_err());
    }

    #[tokio::test]
    async fn maximum_atomic_inventory_fits_only_its_fixed_snapshot_cap() {
        let mut value = operations_snapshot();
        let mut active = Vec::new();
        let mut recent = Vec::new();
        for index in 0..512_u64 {
            let mut item = operations_item(
                &(u64::MAX - index).to_string(),
                "egress_check",
                "egress_network_unreachable",
            );
            item["check"] = json!("tcp");
            item["target"] = json!("[2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535");
            for field in [
                "first_observed_at_unix_ms",
                "last_observed_at_unix_ms",
                "age_millis",
                "evidence_sequence",
            ] {
                item[field] = json!(u64::MAX.to_string());
            }
            if index < 256 {
                active.push(item);
            } else {
                item["status"] = json!("recovered");
                item["ended_at_unix_ms"] = json!(u64::MAX.to_string());
                recent.push(item);
            }
        }
        value["active"] = json!(active);
        value["recent"] = json!(recent);
        value["active_count"] = json!(256);
        value["recent_count"] = json!(256);
        let bytes = wire(value.clone());
        assert!(bytes.len() > MAX_RESPONSE_BYTES && bytes.len() < SNAPSHOT_RESPONSE_BYTES);
        assert!(decode_snapshot(&bytes, NODE, proof()).is_ok());
        let typed: NodeSnapshot = serde_json::from_value(value.clone()).unwrap();
        assert!(respond(NODE, StatusCode::OK, typed.clone()).is_err());
        let response = respond_resource_limited(
            VERSION,
            RESOURCE,
            NODE,
            StatusCode::OK,
            typed,
            SNAPSHOT_RESPONSE_BYTES,
        )
        .unwrap();
        let serialized = axum::body::to_bytes(response.into_body(), SNAPSHOT_RESPONSE_BYTES)
            .await
            .unwrap();
        assert!(decode_snapshot(&serialized, NODE, proof()).is_ok());
        value["active"].as_array_mut().unwrap().push(item("1"));
        value["active_count"] = json!(257);
        assert!(decode_snapshot(&wire(value), NODE, proof()).is_err());
        assert!(decode_snapshot(&vec![b' '; SNAPSHOT_RESPONSE_BYTES + 1], NODE, proof()).is_err());
    }
}
