//! Read-only, durable traffic facts in a separate fixed protocol vocabulary.
//!
//! The response is not a command receipt, live meter or billing guarantee. The
//! TLS client attaches its actual, twice-checked peer authorization only after
//! reading the complete bounded body. Importers must recheck that proof together
//! with their registered target generation in the committing transaction.

use std::collections::HashSet;

use super::*;
use crate::access::traffic::{
    PROTOCOL_COUNT, PROTOCOLS, legacy_values, legacy_window, protocol_index,
};
use crate::{
    manage::store::{traffic as durable, valid_id as canonical_id},
    traffic::Snapshot,
};

const PREFIX: &str = "/node/v1/traffic";
const SPLIT_PREFIX: &str = "/node/v2/traffic";
pub(super) const SPLIT_RESPONSE_BYTES: usize = 64 * 1024;
const RESOURCE: &str = "proxy_traffic";
const DEFINITION: &str = "accepted_effective_payload_v1";
const MAX_TIME: u64 = 9_007_199_254_740_991;
const ZERO: Snapshot = Snapshot {
    upload: 0,
    download: 0,
    saturated: false,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    version: u8,
    node_id: String,
    resource: String,
    definition: String,
    data: T,
}

/// Stored facts only. No current-process loss overlay or request clock enters
/// the same-cursor snapshot; otherwise a retry could produce conflicting bytes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    meter_epoch: String,
    run_id: Option<String>,
    cursor: String,
    clean: bool,
    loss_possible: bool,
    history_gap: bool,
    time_uncertain: bool,
    last_checkpoint_at: Option<u64>,
    meter_started_at: Option<u64>,
}

impl From<durable::Status> for Metadata {
    fn from(value: durable::Status) -> Self {
        Self {
            meter_epoch: value.meter_epoch,
            run_id: value.run_id,
            cursor: value.cursor.to_string(),
            clean: value.clean,
            loss_possible: value.loss_possible,
            history_gap: value.history_gap,
            time_uncertain: value.time_uncertain,
            last_checkpoint_at: value.last_checkpoint_at,
            meter_started_at: value.meter_started_at,
        }
    }
}

impl Metadata {
    fn into_status(self, expected: &str, split: bool) -> io::Result<durable::Status> {
        if !canonical_id(&self.meter_epoch)
            || self
                .run_id
                .as_deref()
                .is_some_and(|value| !canonical_id(value))
            || (!self.clean && self.run_id.is_none())
            || self
                .last_checkpoint_at
                .is_some_and(|value| value > MAX_TIME)
            || self.meter_started_at.is_some_and(|value| value > MAX_TIME)
        {
            return Err(invalid("invalid durable traffic metadata"));
        }
        Ok(durable::Status {
            http_split: split,
            node_id: expected.to_owned(),
            meter_epoch: self.meter_epoch,
            run_id: self.run_id,
            cursor: integer(&self.cursor, i64::MAX as u64)?,
            clean: self.clean,
            loss_possible: self.loss_possible,
            history_gap: self.history_gap,
            time_uncertain: self.time_uncertain,
            last_checkpoint_at: self.last_checkpoint_at,
            meter_started_at: self.meter_started_at,
        })
    }
}

/// Fixed [upload, download, saturated] tuples keep all retained node windows
/// inside 32 KiB without lossy numbers or compression. Protocol positions are
/// always HTTP, SOCKS5, MASQUE, not a source-selected label vocabulary.
#[derive(Serialize, Deserialize)]
struct Counter(String, String, bool);

impl From<Snapshot> for Counter {
    fn from(value: Snapshot) -> Self {
        Self(
            value.upload.to_string(),
            value.download.to_string(),
            value.saturated,
        )
    }
}

impl Counter {
    fn into_value(self) -> io::Result<Snapshot> {
        Ok(Snapshot {
            upload: integer(&self.0, u64::MAX)?,
            download: integer(&self.1, u64::MAX)?,
            saturated: self.2,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Window {
    window_id: String,
    values: Vec<Option<Counter>>,
}

impl From<durable::Window> for Window {
    fn from(value: durable::Window) -> Self {
        window_view(value, false)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeSnapshot {
    metadata: Metadata,
    totals: Vec<Counter>,
    floors: [Option<String>; 3],
    minute: Vec<Window>,
    hour: Vec<Window>,
    day: Vec<Window>,
}

impl From<durable::NodeSnapshot> for NodeSnapshot {
    fn from(value: durable::NodeSnapshot) -> Self {
        snapshot_view(value, false)
    }
}

fn wire_values(values: [Snapshot; PROTOCOL_COUNT], split: bool) -> Vec<Counter> {
    if split {
        values.into_iter().map(Counter::from).collect()
    } else {
        legacy_values(values)
            .into_iter()
            .map(Counter::from)
            .collect()
    }
}

fn window_view(value: durable::Window, split: bool) -> Window {
    Window {
        window_id: value.window_id.to_string(),
        values: if split {
            value
                .values
                .into_iter()
                .map(|value| value.map(Counter::from))
                .collect()
        } else {
            legacy_window(value.values)
                .into_iter()
                .map(|value| value.map(Counter::from))
                .collect()
        },
    }
}

fn snapshot_view(value: durable::NodeSnapshot, split: bool) -> NodeSnapshot {
    NodeSnapshot {
        metadata: value.status.into(),
        totals: wire_values(value.totals, split),
        floors: value
            .floors
            .map(|value| value.map(|value| value.to_string())),
        minute: value
            .minute
            .into_iter()
            .map(|value| window_view(value, split))
            .collect(),
        hour: value
            .hour
            .into_iter()
            .map(|value| window_view(value, split))
            .collect(),
        day: value
            .day
            .into_iter()
            .map(|value| window_view(value, split))
            .collect(),
    }
}

#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    kind: String,
    id: Option<String>,
}

impl From<&durable::Scope> for Scope {
    fn from(value: &durable::Scope) -> Self {
        let (kind, id) = match value {
            durable::Scope::Node => ("node", None),
            durable::Scope::User(id) => ("user", Some(id.clone())),
            durable::Scope::Credential(id) => ("credential", Some(id.clone())),
            durable::Scope::Pool(id) => ("pool", Some(id.clone())),
        };
        Self {
            kind: kind.into(),
            id,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Totals {
    metadata: Metadata,
    scope: Scope,
    values: Vec<Counter>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Buckets {
    metadata: Metadata,
    scope: Scope,
    resolution: String,
    items: Vec<Window>,
    next_cursor: Option<String>,
    floor: Option<String>,
}

pub(super) fn is_request(operation: &Request) -> bool {
    matches!(
        operation,
        Request::TrafficSnapshot
            | Request::TrafficTotals { .. }
            | Request::TrafficBuckets { .. }
            | Request::TrafficSnapshotV2
            | Request::TrafficTotalsV2 { .. }
            | Request::TrafficBucketsV2 { .. }
    )
}

pub(super) fn is_split(operation: &Request) -> bool {
    matches!(
        operation,
        Request::TrafficSnapshotV2
            | Request::TrafficTotalsV2 { .. }
            | Request::TrafficBucketsV2 { .. }
    )
}

impl Request {
    /// A bounded read-only fallback. It is never constructed for mutations,
    /// transport failures, changed authorization or malformed reply bodies.
    pub(in crate::manage) fn legacy_traffic(&self) -> Option<Self> {
        match self {
            Self::TrafficSnapshotV2 => Some(Self::TrafficSnapshot),
            Self::TrafficTotalsV2 { scope } => Some(Self::TrafficTotals {
                scope: scope.clone(),
            }),
            Self::TrafficBucketsV2 {
                scope,
                resolution,
                after,
                limit,
            } => Some(Self::TrafficBuckets {
                scope: scope.clone(),
                resolution: *resolution,
                after: *after,
                limit: *limit,
            }),
            _ => None,
        }
    }
}

pub(super) fn encode(operation: &Request) -> io::Result<(Method, String, Vec<u8>)> {
    let prefix = if is_split(operation) {
        SPLIT_PREFIX
    } else {
        PREFIX
    };
    let path = match operation {
        Request::TrafficSnapshot | Request::TrafficSnapshotV2 => format!("{prefix}/snapshot"),
        Request::TrafficTotals { scope } | Request::TrafficTotalsV2 { scope } => {
            validate_scope(scope, false)?;
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            scope_query(&mut query, scope);
            format!("{prefix}?{}", query.finish())
        }
        Request::TrafficBuckets {
            scope,
            resolution,
            after,
            limit,
        }
        | Request::TrafficBucketsV2 {
            scope,
            resolution,
            after,
            limit,
        } => {
            validate_scope(scope, true)?;
            if !(1..=50).contains(limit) || after.is_some_and(|value| value > MAX_TIME) {
                return Err(invalid("invalid traffic history page input"));
            }
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            scope_query(&mut query, scope);
            query.append_pair("resolution", resolution_name(*resolution));
            query.append_pair("limit", &limit.to_string());
            if let Some(after) = after {
                query.append_pair("after", &after.to_string());
            }
            format!("{prefix}/buckets?{}", query.finish())
        }
        _ => return Err(invalid("fixed traffic request required")),
    };
    Ok((Method::GET, path, Vec::new()))
}

fn scope_query(query: &mut url::form_urlencoded::Serializer<'_, String>, scope: &durable::Scope) {
    let view = Scope::from(scope);
    query.append_pair("scope", &view.kind);
    if let Some(id) = view.id {
        query.append_pair("id", &id);
    }
}

fn validate_scope(scope: &durable::Scope, history: bool) -> io::Result<()> {
    match scope {
        durable::Scope::Node => Ok(()),
        durable::Scope::Credential(_) if history => {
            Err(invalid("credential history is unavailable"))
        }
        durable::Scope::User(id) | durable::Scope::Credential(id) | durable::Scope::Pool(id)
            if canonical_id(id) =>
        {
            Ok(())
        }
        _ => Err(invalid("invalid traffic scope identity")),
    }
}

pub(super) fn decode(
    operation: &Request,
    bytes: &[u8],
    expected: &str,
    authorization: store::RemoteAuthorization,
) -> io::Result<Reply> {
    let split = is_split(operation);
    if authorization.node_id != expected
        || !canonical_id(expected)
        || authorization.authorization_revision == 0
        || authorization.leaf.is_empty()
        || authorization.leaf.len() > 16 * 1024
    {
        return Err(invalid("traffic proof does not match the selected target"));
    }
    match operation {
        Request::TrafficSnapshot | Request::TrafficSnapshotV2 => {
            let value: NodeSnapshot = envelope(bytes, expected, split)?;
            let floors = snapshot_floors(value.floors)?;
            let snapshot = durable::NodeSnapshot {
                status: value.metadata.into_status(expected, split)?,
                totals: counters(value.totals, split)?,
                floors,
                minute: windows(value.minute, 60_000, 60, None, split)?,
                hour: windows(value.hour, 3_600_000, 48, None, split)?,
                day: windows(value.day, 86_400_000, 30, None, split)?,
            };
            // Import and the wire client share domain bounds, including the
            // relationship between retained windows and cumulative totals.
            store::remote_traffic::validate_snapshot(&snapshot)?;
            Ok(Reply::TrafficSnapshot(Box::new(Fetched {
                authorization,
                value: snapshot,
            })))
        }
        Request::TrafficTotals { scope } | Request::TrafficTotalsV2 { scope } => {
            validate_scope(scope, false)?;
            let value: Totals = envelope(bytes, expected, split)?;
            if value.scope != Scope::from(scope) {
                return Err(invalid("traffic totals changed their selected scope"));
            }
            Ok(Reply::TrafficTotals(Box::new(Fetched {
                authorization,
                value: durable::Totals {
                    status: value.metadata.into_status(expected, split)?,
                    items: protocol_values(counters(value.values, split)?),
                },
            })))
        }
        Request::TrafficBuckets {
            scope,
            resolution,
            after,
            limit,
        }
        | Request::TrafficBucketsV2 {
            scope,
            resolution,
            after,
            limit,
        } => {
            validate_scope(scope, true)?;
            let value: Buckets = envelope(bytes, expected, split)?;
            if value.scope != Scope::from(scope)
                || value.resolution != resolution_name(*resolution)
                || !(1..=50).contains(limit)
            {
                return Err(invalid(
                    "traffic history changed its selected scope or resolution",
                ));
            }
            let items = windows(
                value.items,
                resolution_width(*resolution),
                *limit as usize,
                *after,
                split,
            )?;
            let next_cursor = value
                .next_cursor
                .map(|value| integer(&value, MAX_TIME))
                .transpose()?;
            let floor = value
                .floor
                .map(|value| integer(&value, MAX_TIME))
                .transpose()?;
            if next_cursor.is_some_and(|next| {
                items.len() != *limit as usize
                    || items.last().is_none_or(|last| last.window_id != next)
            }) || floor.is_some_and(|floor| !floor.is_multiple_of(resolution_width(*resolution)))
                || items
                    .first()
                    .is_some_and(|first| floor.is_none_or(|floor| floor > first.window_id))
            {
                return Err(invalid("invalid traffic history cursor or retention floor"));
            }
            Ok(Reply::TrafficBuckets(Box::new(Fetched {
                authorization,
                value: durable::BucketPage {
                    status: value.metadata.into_status(expected, split)?,
                    items: items
                        .into_iter()
                        .map(|window| durable::Bucket {
                            window_id: window.window_id,
                            items: window
                                .values
                                .into_iter()
                                .zip(PROTOCOLS)
                                .filter_map(|(value, protocol)| {
                                    value.map(|value| durable::ProtocolTotal { protocol, value })
                                })
                                .collect(),
                        })
                        .collect(),
                    next_cursor,
                    floor,
                },
            })))
        }
        _ => Err(invalid("fixed traffic request required")),
    }
}

fn envelope<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    expected: &str,
    split: bool,
) -> io::Result<T> {
    if bytes.len()
        > if split {
            SPLIT_RESPONSE_BYTES
        } else {
            MAX_RESPONSE_BYTES
        }
    {
        return Err(invalid("traffic response exceeds its size limit"));
    }
    let envelope: Envelope<T> =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid traffic response JSON"))?;
    if envelope.version != if split { 2 } else { 1 }
        || envelope.node_id != expected
        || envelope.resource != RESOURCE
        || envelope.definition != DEFINITION
    {
        return Err(invalid(
            "traffic response changed its identity or definition",
        ));
    }
    Ok(envelope.data)
}

fn counters(values: Vec<Counter>, split: bool) -> io::Result<[Snapshot; PROTOCOL_COUNT]> {
    if values.len() != if split { PROTOCOL_COUNT } else { 3 } {
        return Err(invalid("invalid traffic total positions"));
    }
    let mut restored = [ZERO; PROTOCOL_COUNT];
    for (slot, value) in restored.iter_mut().zip(values) {
        *slot = value.into_value()?;
    }
    Ok(restored)
}

fn snapshot_floors(values: [Option<String>; 3]) -> io::Result<[Option<u64>; 3]> {
    let [minute, hour, day] = values;
    let floors = [
        minute.map(|value| integer(&value, MAX_TIME)).transpose()?,
        hour.map(|value| integer(&value, MAX_TIME)).transpose()?,
        day.map(|value| integer(&value, MAX_TIME)).transpose()?,
    ];
    for (floor, width) in floors.into_iter().zip([60_000, 3_600_000, 86_400_000]) {
        if floor.is_some_and(|value| !value.is_multiple_of(width)) {
            return Err(invalid("unaligned traffic retention floor"));
        }
    }
    Ok(floors)
}

fn windows(
    values: Vec<Window>,
    width: u64,
    limit: usize,
    after: Option<u64>,
    split: bool,
) -> io::Result<Vec<durable::Window>> {
    if values.len() > limit {
        return Err(invalid("traffic window count exceeds its limit"));
    }
    let mut previous = after;
    let mut windows = Vec::with_capacity(values.len());
    for value in values {
        let window_id = integer(&value.window_id, MAX_TIME)?;
        if !window_id.is_multiple_of(width)
            || previous.is_some_and(|previous| window_id <= previous)
            || value.values.iter().all(Option::is_none)
        {
            return Err(invalid("invalid traffic window order or contents"));
        }
        if value.values.len() != if split { PROTOCOL_COUNT } else { 3 } {
            return Err(invalid("invalid traffic window positions"));
        }
        let mut restored = [None; PROTOCOL_COUNT];
        for (slot, value) in restored.iter_mut().zip(value.values) {
            *slot = value.map(Counter::into_value).transpose()?;
        }
        windows.push(durable::Window {
            window_id,
            values: restored,
        });
        previous = Some(window_id);
    }
    Ok(windows)
}

fn integer(value: &str, maximum: u64) -> io::Result<u64> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid("noncanonical traffic integer"));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value <= maximum)
        .ok_or_else(|| invalid("traffic integer exceeds its limit"))
}

fn protocol_values(values: [Snapshot; PROTOCOL_COUNT]) -> Vec<durable::ProtocolTotal> {
    values
        .into_iter()
        .zip(PROTOCOLS)
        .map(|(value, protocol)| durable::ProtocolTotal { protocol, value })
        .collect()
}

fn resolution_name(value: durable::Resolution) -> &'static str {
    match value {
        durable::Resolution::Minute => "minute",
        durable::Resolution::Hour => "hour",
        durable::Resolution::Day => "day",
    }
}

fn resolution_width(value: durable::Resolution) -> u64 {
    match value {
        durable::Resolution::Minute => 60_000,
        durable::Resolution::Hour => 3_600_000,
        durable::Resolution::Day => 86_400_000,
    }
}

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(PREFIX, get(totals))
        .route("/node/v1/traffic/buckets", get(buckets))
        .route("/node/v1/traffic/snapshot", get(snapshot))
        .route(SPLIT_PREFIX, get(totals))
        .route("/node/v2/traffic/buckets", get(buckets))
        .route("/node/v2/traffic/snapshot", get(snapshot))
}

async fn snapshot(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let authorization = peer.authorization();
    let value = coordinator(&state)?
        .read(move |directory| store::remote_traffic::export_snapshot(directory, &authorization))
        .await
        .map_err(storage_error)?;
    checked_node(&value.status, &state.node_id)?;
    store::remote_traffic::validate_snapshot(&value).map_err(storage_error)?;
    let split = uri.path().starts_with(SPLIT_PREFIX);
    if split && !value.status.http_split {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "traffic_protocols_unsupported",
        ));
    }
    respond(&state.node_id, snapshot_view(value, split), split)
}

async fn totals(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    let Request::TrafficTotals { scope } = parse(&uri, false)? else {
        return Err(ApiError::internal());
    };
    let wire_scope = Scope::from(&scope);
    let authorization = peer.authorization();
    let value = coordinator(&state)?
        .read(move |directory| {
            store::remote_traffic::export_totals(directory, &authorization, scope)
        })
        .await
        .map_err(storage_error)?;
    checked_node(&value.status, &state.node_id)?;
    let split = uri.path().starts_with(SPLIT_PREFIX);
    if split && !value.status.http_split {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "traffic_protocols_unsupported",
        ));
    }
    respond(
        &state.node_id,
        Totals {
            metadata: value.status.into(),
            scope: wire_scope,
            values: wire_values(total_values(value.items).map_err(storage_error)?, split),
        },
        split,
    )
}

async fn buckets(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    let Request::TrafficBuckets {
        scope,
        resolution,
        after,
        limit,
    } = parse(&uri, true)?
    else {
        return Err(ApiError::internal());
    };
    let wire_scope = Scope::from(&scope);
    let authorization = peer.authorization();
    let value = coordinator(&state)?
        .read(move |directory| {
            store::remote_traffic::export_buckets(
                directory,
                &authorization,
                scope,
                resolution,
                after,
                limit,
            )
        })
        .await
        .map_err(storage_error)?;
    checked_node(&value.status, &state.node_id)?;
    let split = uri.path().starts_with(SPLIT_PREFIX);
    if split && !value.status.http_split {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "traffic_protocols_unsupported",
        ));
    }
    let items = value
        .items
        .into_iter()
        .map(|bucket| {
            let mut values = [None; PROTOCOL_COUNT];
            for item in bucket.items {
                let index = protocol_index(item.protocol);
                if values[index].replace(item.value).is_some() {
                    return Err(invalid("duplicate durable traffic protocol"));
                }
            }
            Ok(window_view(
                durable::Window {
                    window_id: bucket.window_id,
                    values,
                },
                split,
            ))
        })
        .collect::<io::Result<Vec<_>>>()
        .map_err(storage_error)?;
    respond(
        &state.node_id,
        Buckets {
            metadata: value.status.into(),
            scope: wire_scope,
            resolution: resolution_name(resolution).into(),
            items,
            next_cursor: value.next_cursor.map(|value| value.to_string()),
            floor: value.floor.map(|value| value.to_string()),
        },
        split,
    )
}

fn total_values(items: Vec<durable::ProtocolTotal>) -> io::Result<[Snapshot; PROTOCOL_COUNT]> {
    let mut values = [ZERO; PROTOCOL_COUNT];
    let mut seen = [false; PROTOCOL_COUNT];
    for item in items {
        let index = protocol_index(item.protocol);
        if std::mem::replace(&mut seen[index], true) {
            return Err(invalid("duplicate durable traffic protocol"));
        }
        values[index] = item.value;
    }
    if !seen.into_iter().all(|value| value) {
        return Err(invalid("missing durable traffic protocol"));
    }
    Ok(values)
}

fn checked_node(status: &durable::Status, expected: &str) -> Result<(), ApiError> {
    if status.node_id != expected {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "traffic_unavailable",
        ));
    }
    Ok(())
}

fn parse(uri: &http::Uri, history: bool) -> Result<Request, ApiError> {
    let raw = uri.query().unwrap_or_default();
    if raw.len() > 1024 {
        return Err(bad("invalid_traffic_query"));
    }
    let mut seen = HashSet::new();
    let (mut scope, mut id, mut resolution, mut after, mut limit) =
        (None, None, durable::Resolution::Hour, None, 25);
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if !seen.insert(key.clone()) {
            return Err(bad("invalid_traffic_query"));
        }
        match key.as_ref() {
            "scope" => scope = Some(value.into_owned()),
            "id" if canonical_id(&value) => id = Some(value.into_owned()),
            "resolution" if history => {
                resolution = match value.as_ref() {
                    "minute" => durable::Resolution::Minute,
                    "hour" => durable::Resolution::Hour,
                    "day" => durable::Resolution::Day,
                    _ => return Err(bad("invalid_traffic_query")),
                }
            }
            "after" if history => {
                after = Some(integer(&value, MAX_TIME).map_err(|_| bad("invalid_traffic_query"))?)
            }
            "limit" if history => {
                limit =
                    u32::try_from(integer(&value, 50).map_err(|_| bad("invalid_traffic_query"))?)
                        .map_err(|_| bad("invalid_traffic_query"))?
            }
            _ => return Err(bad("invalid_traffic_query")),
        }
    }
    let scope = match (scope.as_deref().unwrap_or("node"), id) {
        ("node", None) => durable::Scope::Node,
        ("user", Some(id)) => durable::Scope::User(id),
        ("credential", Some(id)) if !history => durable::Scope::Credential(id),
        ("pool", Some(id)) => durable::Scope::Pool(id),
        _ => return Err(bad("invalid_traffic_query")),
    };
    if history {
        if limit == 0 {
            return Err(bad("invalid_traffic_query"));
        }
        Ok(Request::TrafficBuckets {
            scope,
            resolution,
            after,
            limit,
        })
    } else {
        Ok(Request::TrafficTotals { scope })
    }
}

fn respond<T: Serialize>(node_id: &str, data: T, split: bool) -> Result<Response, ApiError> {
    struct Bounded<'a>(&'a mut Vec<u8>, usize);
    impl io::Write for Bounded<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .len()
                .checked_add(bytes.len())
                .filter(|length| *length <= self.1)
                .ok_or_else(|| invalid("traffic response cap reached"))?;
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let limit = if split {
        SPLIT_RESPONSE_BYTES
    } else {
        MAX_RESPONSE_BYTES
    };
    let mut bytes = Vec::with_capacity(limit);
    serde_json::to_writer(
        Bounded(&mut bytes, limit),
        &Envelope {
            version: if split { 2 } else { 1 },
            node_id: node_id.to_owned(),
            resource: RESOURCE.to_owned(),
            definition: DEFINITION.to_owned(),
            data,
        },
    )
    .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "response_too_large"))?;
    let mut response = Body::from(bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(response)
}

fn storage_error(error: io::Error) -> ApiError {
    match error.kind() {
        io::ErrorKind::Unsupported => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        ),
        io::ErrorKind::WouldBlock => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "traffic_busy"),
        io::ErrorKind::InvalidData => {
            ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "traffic_unavailable")
        }
        _ => super::storage_error(error),
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
