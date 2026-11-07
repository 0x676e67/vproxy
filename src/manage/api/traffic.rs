//! Fixed-scope traffic reads. A page observes one node/entity, not an arbitrary
//! aggregation expression or a browser-selected source URL.

use super::*;
use crate::{
    access::traffic::{PROTOCOL_COUNT, PoolSnapshot, Protocol, SeriesSnapshot, protocol_index},
    manage::{
        store::traffic::{self as durable, Resolution, Scope},
        traffic as collector,
    },
    traffic::Snapshot,
};

const DEFINITION: &str = "accepted_effective_payload_v1";

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/proxy/traffic", get(totals))
        .route("/api/v1/proxy/traffic/buckets", get(buckets))
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

pub(super) struct Query {
    /// Explicit opt-in; existing v1 callers retain the HTTP-family projection.
    pub(super) split: bool,
    pub(super) scope: Scope,
    pub(super) protocol: Option<Protocol>,
    pub(super) resolution: Resolution,
    pub(super) after: Option<u64>,
    pub(super) limit: u32,
}

pub(super) fn query(uri: &Uri, history: bool) -> Result<Query, ApiError> {
    let raw = uri.query().unwrap_or_default();
    if raw.len() > 1024 {
        return Err(invalid());
    }
    let mut seen = std::collections::HashSet::new();
    let (mut scope, mut id, mut protocol, mut resolution, mut after, mut limit) =
        (None, None, None, None, None, None);
    let mut split = false;
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if !seen.insert(key.clone()) {
            return Err(invalid());
        }
        match key.as_ref() {
            "scope" => scope = Some(value.into_owned()),
            "id" => {
                let mut decoded = [0; 16];
                if value.len() != 22
                    || !matches!(
                        URL_SAFE_NO_PAD.decode_slice(value.as_bytes(), &mut decoded),
                        Ok(16)
                    )
                    || URL_SAFE_NO_PAD.encode(decoded) != value
                {
                    return Err(invalid());
                }
                id = Some(value.into_owned());
            }
            "protocol" => {
                protocol = Some(match value.as_ref() {
                    "http" => Protocol::Http,
                    "https" => Protocol::Https,
                    "http_legacy" => Protocol::HttpLegacy,
                    "socks5" => Protocol::Socks5,
                    "masque" => Protocol::Masque,
                    _ => return Err(invalid()),
                })
            }
            "protocol_format" if value == "split" => split = true,
            "resolution" if history => {
                resolution = Some(match value.as_ref() {
                    "minute" => Resolution::Minute,
                    "hour" => Resolution::Hour,
                    "day" => Resolution::Day,
                    _ => return Err(invalid()),
                })
            }
            "after" if history => after = Some(decimal(&value)?),
            "limit" if history => {
                let size = decimal(&value)?;
                if !(1..=50).contains(&size) {
                    return Err(invalid());
                }
                limit = Some(u32::try_from(size).map_err(|_| invalid())?);
            }
            _ => return Err(invalid()),
        }
    }
    let scope = match (scope.as_deref().unwrap_or("node"), id) {
        ("node", None) => Scope::Node,
        ("user", Some(id)) => Scope::User(id),
        ("credential", Some(id)) if !history => Scope::Credential(id),
        ("pool", Some(id)) => Scope::Pool(id),
        _ => return Err(invalid()),
    };
    if !split && matches!(protocol, Some(Protocol::Https | Protocol::HttpLegacy)) {
        return Err(invalid());
    }
    Ok(Query {
        split,
        scope,
        protocol,
        resolution: resolution.unwrap_or(Resolution::Hour),
        after,
        limit: limit.unwrap_or(25),
    })
}

fn decimal(value: &str) -> Result<u64, ApiError> {
    crate::manage::views::number(value)
        .filter(|value| *value <= 9_007_199_254_740_991)
        .ok_or_else(invalid)
}

fn invalid() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid_traffic_query")
}

fn storage(error: io::Error) -> ApiError {
    match error.kind() {
        io::ErrorKind::WouldBlock => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "traffic_busy"),
        io::ErrorKind::NotFound if error.raw_os_error().is_none() => {
            ApiError::new(StatusCode::NOT_FOUND, "resource_not_found")
        }
        _ => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "traffic_unavailable"),
    }
}

fn handle(state: &AppState) -> Result<&collector::Handle, ApiError> {
    state
        .traffic
        .as_ref()
        .ok_or_else(|| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "traffic_unavailable"))
}

#[derive(Serialize)]
struct ScopeView<'a> {
    kind: &'static str,
    id: Option<&'a str>,
}

fn scope_view(scope: &Scope) -> ScopeView<'_> {
    match scope {
        Scope::Node => ScopeView {
            kind: "node",
            id: None,
        },
        Scope::User(id) => ScopeView {
            kind: "user",
            id: Some(id),
        },
        Scope::Credential(id) => ScopeView {
            kind: "credential",
            id: Some(id),
        },
        Scope::Pool(id) => ScopeView {
            kind: "pool",
            id: Some(id),
        },
    }
}

#[derive(Serialize)]
struct Metadata<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    http_split: Option<bool>,
    definition: &'static str,
    origin_node_id: &'a str,
    meter_epoch: &'a str,
    meter_started_at_unix_ms: Option<u64>,
    checkpoint_cursor: String,
    last_checkpoint_at_unix_ms: Option<u64>,
    last_run_clean: bool,
    loss_possible: bool,
    history_gap: bool,
    time_uncertain: bool,
    observed_at_unix_ms: Option<u64>,
}

fn metadata(status: &durable::Status, split: bool) -> Metadata<'_> {
    Metadata {
        http_split: split.then_some(status.http_split),
        definition: DEFINITION,
        origin_node_id: &status.node_id,
        meter_epoch: &status.meter_epoch,
        meter_started_at_unix_ms: status.meter_started_at,
        checkpoint_cursor: status.cursor.to_string(),
        last_checkpoint_at_unix_ms: status.last_checkpoint_at,
        last_run_clean: status.clean,
        loss_possible: status.loss_possible,
        history_gap: status.history_gap,
        time_uncertain: status.time_uncertain,
        observed_at_unix_ms: collector::now(),
    }
}

#[derive(Serialize)]
struct TotalView {
    protocol: Protocol,
    durable_upload_bytes: String,
    durable_download_bytes: String,
    durable_saturated: bool,
    live_upload_bytes: Option<String>,
    live_download_bytes: Option<String>,
    live_saturated: Option<bool>,
}

fn index(protocol: Protocol) -> usize {
    protocol_index(protocol)
}

fn sum(total: &mut Snapshot, value: Snapshot) {
    *total = total.sum(value);
}

/// Preserve old API shapes without treating a family total as plain HTTP in the
/// new format. Older remote sources omit unknown split rows instead of zeros.
fn project(
    items: Vec<durable::ProtocolTotal>,
    split: bool,
    supported: bool,
) -> Vec<durable::ProtocolTotal> {
    if split {
        return items
            .into_iter()
            .filter(|row| supported || !matches!(row.protocol, Protocol::Http | Protocol::Https))
            .collect();
    }
    let mut values = [None; PROTOCOL_COUNT];
    for row in items {
        let protocol = if matches!(
            row.protocol,
            Protocol::HttpLegacy | Protocol::Http | Protocol::Https
        ) {
            Protocol::Http
        } else {
            row.protocol
        };
        let value = &mut values[index(protocol)];
        *value = Some(value.map_or(row.value, |old: Snapshot| old.sum(row.value)));
    }
    [Protocol::Http, Protocol::Socks5, Protocol::Masque]
        .into_iter()
        .filter_map(|protocol| {
            values[index(protocol)].map(|value| durable::ProtocolTotal { protocol, value })
        })
        .collect()
}

fn live(
    scope: &Scope,
    series: Vec<SeriesSnapshot>,
    pools: Vec<PoolSnapshot>,
) -> [Snapshot; PROTOCOL_COUNT] {
    let mut totals = [Snapshot {
        upload: 0,
        download: 0,
        saturated: false,
    }; PROTOCOL_COUNT];
    if let Scope::Pool(id) = scope {
        for row in pools.into_iter().filter(|row| row.pool_id.as_ref() == id) {
            sum(&mut totals[index(row.protocol)], row.value);
        }
    } else {
        for row in series.into_iter().filter(|row| match scope {
            Scope::Node => true,
            Scope::User(id) => row.user_id.as_ref() == id,
            Scope::Credential(id) => row.credential_id.as_ref() == id,
            Scope::Pool(_) => false,
        }) {
            sum(&mut totals[index(row.protocol)], row.value);
        }
    }
    totals
}

async fn totals(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    let query = query(&uri, false)?;
    let observer = handle(&state)?;
    let policy = state
        .policy
        .as_ref()
        .ok_or_else(|| storage(io::ErrorKind::Unsupported.into()))?;
    let scope = query.scope.clone();
    let mut durable = policy
        .read(move |directory| durable::totals(directory, scope))
        .await
        .map_err(storage)?;
    // Read durable first, then monotonically growing live counters. Reversing
    // this order can display a checkpoint newer/larger than the live sample.
    let (series, pools) = observer.sample().await.map_err(storage)?;
    let observation = observer.observation().map_err(storage)?;
    durable.status.loss_possible =
        collector::observed_loss(&durable.status, observation.active_run.as_deref());
    if observation.durable.meter_epoch != durable.status.meter_epoch {
        return Err(storage(io::ErrorKind::InvalidData.into()));
    }
    let active = observation.active_run.is_some();
    let mut live = live(&query.scope, series, pools);
    if !query.split {
        live[3] = live[0].sum(live[3]).sum(live[4]);
    }
    let items: Vec<_> = project(durable.items, query.split, durable.status.http_split)
        .into_iter()
        .filter(|row| {
            query
                .protocol
                .is_none_or(|protocol| row.protocol == protocol)
        })
        .map(|row| {
            let current = live[index(row.protocol)];
            TotalView {
                protocol: row.protocol,
                durable_upload_bytes: row.value.upload.to_string(),
                durable_download_bytes: row.value.download.to_string(),
                durable_saturated: row.value.saturated,
                live_upload_bytes: active.then(|| current.upload.to_string()),
                live_download_bytes: active.then(|| current.download.to_string()),
                live_saturated: active.then_some(current.saturated),
            }
        })
        .collect();
    Ok(Json(TotalsView {
        metadata: metadata(&durable.status, query.split),
        scope: scope_view(&query.scope),
        active_run_id: observation.active_run,
        checkpoint_error: observation.checkpoint_error,
        checkpoint_failure_stage: observation.checkpoint_failure_stage,
        last_completed_cycle_at_unix_ms: observation.last_completed_at,
        last_completed_cycle_age_millis: observation.age_millis,
        items,
    })
    .into_response())
}

#[derive(Serialize)]
struct TotalsView<'a> {
    #[serde(flatten)]
    metadata: Metadata<'a>,
    scope: ScopeView<'a>,
    active_run_id: Option<String>,
    checkpoint_error: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint_failure_stage: Option<collector::CheckpointStage>,
    last_completed_cycle_at_unix_ms: Option<u64>,
    last_completed_cycle_age_millis: Option<u64>,
    items: Vec<TotalView>,
}

/// Project confirmed remote facts through the same browser DTO. A remote run
/// marker is not proof of a live process, and no live/checkpoint health is
/// inferred from it. Current remote contact/cache health is a separate source.
pub(super) fn durable_totals_response(query: &Query, totals: durable::Totals) -> Response {
    let items = project(totals.items, query.split, totals.status.http_split)
        .into_iter()
        .filter(|row| {
            query
                .protocol
                .is_none_or(|protocol| row.protocol == protocol)
        })
        .map(|row| TotalView {
            protocol: row.protocol,
            durable_upload_bytes: row.value.upload.to_string(),
            durable_download_bytes: row.value.download.to_string(),
            durable_saturated: row.value.saturated,
            live_upload_bytes: None,
            live_download_bytes: None,
            live_saturated: None,
        })
        .collect();
    Json(TotalsView {
        metadata: metadata(&totals.status, query.split),
        scope: scope_view(&query.scope),
        active_run_id: None,
        checkpoint_error: false,
        checkpoint_failure_stage: None,
        last_completed_cycle_at_unix_ms: None,
        last_completed_cycle_age_millis: None,
        items,
    })
    .into_response()
}

async fn buckets(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    let query = query(&uri, true)?;
    let policy = state
        .policy
        .as_ref()
        .ok_or_else(|| storage(io::ErrorKind::Unsupported.into()))?;
    let scope = query.scope.clone();
    let mut page = policy
        .read(move |directory| {
            durable::buckets(directory, scope, query.resolution, query.after, query.limit)
        })
        .await
        .map_err(storage)?;
    let observation = handle(&state)?.observation().map_err(storage)?;
    page.status.loss_possible =
        collector::observed_loss(&page.status, observation.active_run.as_deref());
    Ok(bucket_response(&query, page))
}

/// Keep the actual compact wire projection separately testable: the maximum
/// 50-window/three-protocol response must fit the shared 32 KiB client budget.
pub(super) fn bucket_response(query: &Query, page: durable::BucketPage) -> Response {
    #[derive(Serialize)]
    struct BucketTotal {
        protocol: Protocol,
        upload_bytes: String,
        download_bytes: String,
        saturated: bool,
    }
    #[derive(Serialize)]
    struct Bucket {
        window_id: String,
        items: Vec<BucketTotal>,
    }
    let items = page
        .items
        .into_iter()
        .map(|bucket| Bucket {
            window_id: bucket.window_id.to_string(),
            items: project(bucket.items, query.split, page.status.http_split)
                .into_iter()
                .filter(|row| {
                    query
                        .protocol
                        .is_none_or(|protocol| row.protocol == protocol)
                })
                .map(|row| BucketTotal {
                    protocol: row.protocol,
                    upload_bytes: row.value.upload.to_string(),
                    download_bytes: row.value.download.to_string(),
                    saturated: row.value.saturated,
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    #[derive(Serialize)]
    struct View<'a> {
        #[serde(flatten)]
        metadata: Metadata<'a>,
        scope: ScopeView<'a>,
        resolution: &'static str,
        next_cursor: Option<String>,
        retention_floor: Option<String>,
        retention_gap: bool,
        items: Vec<Bucket>,
    }
    Json(View {
        metadata: metadata(&page.status, query.split), scope: scope_view(&query.scope),
        resolution: match query.resolution { Resolution::Minute => "minute", Resolution::Hour => "hour", Resolution::Day => "day" },
        retention_gap: matches!((query.after, page.floor), (Some(after), Some(floor)) if after < floor),
        next_cursor: page.next_cursor.map(|cursor| cursor.to_string()),
        retention_floor: page.floor.map(|floor| floor.to_string()), items,
    }).into_response()
}
