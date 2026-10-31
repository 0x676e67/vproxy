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
    if value.is_empty()
        || value.len() > 16
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|value| value.is_ascii_digit())
    {
        return Err(invalid());
    }
    value
        .parse::<u64>()
        .ok()
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

#[cfg(test)]
mod tests {
    //! Pure query/DTO boundaries plus the real session-protected management router.

    use http_body_util::BodyExt as _;
    use serde_json::Value;

    use super::*;

    const MAX_SAFE_TIME: u64 = 9_007_199_254_740_991;

    fn id(byte: u8) -> String {
        URL_SAFE_NO_PAD.encode([byte; 16])
    }

    fn parse(raw: &str, history: bool) -> Result<Query, ApiError> {
        let path = if history {
            "/api/v1/proxy/traffic/buckets"
        } else {
            "/api/v1/proxy/traffic"
        };
        query(&format!("{path}?{raw}").parse().unwrap(), history)
    }

    fn assert_invalid(raw: &str, history: bool) {
        let Err(error) = parse(raw, history) else {
            panic!("unsupported traffic query was accepted: {raw}");
        };
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "invalid_traffic_query");
    }

    #[test]
    fn fixed_scopes_protocols_and_history_resolutions_have_explicit_combinations() {
        let default = parse("", false).unwrap();
        assert!(matches!(default.scope, Scope::Node));
        assert!(default.protocol.is_none());
        assert!(matches!(default.resolution, Resolution::Hour));
        assert_eq!(default.after, None);
        assert_eq!(default.limit, 25);

        for kind in ["user", "credential", "pool"] {
            for protocol in ["http", "socks5", "masque"] {
                let parsed = parse(
                    &format!("scope={kind}&id={}&protocol={protocol}", id(1)),
                    false,
                )
                .unwrap();
                let scope = serde_json::to_value(scope_view(&parsed.scope)).unwrap();
                assert_eq!(scope["kind"], kind);
                assert_eq!(scope["id"], id(1));
                assert_eq!(
                    index(parsed.protocol.unwrap()),
                    match protocol {
                        "http" => 3,
                        "socks5" => 1,
                        _ => 2,
                    }
                );
            }
        }
        for (resolution, expected) in [("minute", 0), ("hour", 1), ("day", 2)] {
            let parsed = parse(
                &format!(
                    "scope=user&id={}&resolution={resolution}&after=0&limit=50",
                    id(2)
                ),
                true,
            )
            .unwrap();
            assert_eq!(
                match parsed.resolution {
                    Resolution::Minute => 0,
                    Resolution::Hour => 1,
                    Resolution::Day => 2,
                },
                expected
            );
            // Unix window zero is valid. `after=0` excludes it in storage, whereas
            // no cursor can include it; neither value means an unknown timestamp.
            assert_eq!(parsed.after, Some(0));
            assert_eq!(parsed.limit, 50);
        }
        assert_invalid(&format!("scope=credential&id={}", id(3)), true);
    }

    #[test]
    fn traffic_query_rejects_unknown_duplicate_and_noncanonical_inputs() {
        let subject = id(1);
        for raw in [
            "scope=unknown".to_owned(),
            "scope=NODE".to_owned(),
            "scope=user".to_owned(),
            "scope=pool".to_owned(),
            format!("scope=node&id={subject}"),
            format!("id={subject}"),
            "scope=user&id=not-an-id".to_owned(),
            "scope=user&id=AAAAAAAAAAAAAAAAAAAAAB".to_owned(),
            "scope=user&id=AQEBAQEBAQEBAQEBAQEBAQ%3D%3D".to_owned(),
            "scope=user&id=!!!!!!!!!!!!!!!!!!!!!!".to_owned(),
            "scope=node&scope=node".to_owned(),
            "scope=node&%73cope=node".to_owned(),
            format!("scope=user&id={subject}&id={subject}"),
            "protocol=http&protocol=http".to_owned(),
            "protocol=HTTP".to_owned(),
            "protocol=udp".to_owned(),
            "dimension=node".to_owned(),
            "window=0".to_owned(),
            "__proto__=node".to_owned(),
            "origin=https%3A%2F%2Fexample.invalid".to_owned(),
            "after=0".to_owned(),
            "limit=25".to_owned(),
            "resolution=minute".to_owned(),
        ] {
            assert_invalid(&raw, false);
        }
        for raw in [
            "resolution=minute&resolution=minute",
            "after=0&after=0",
            "limit=1&limit=1",
            "resolution=week",
            "scope=credential",
            "scope=node&id=AAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert_invalid(raw, true);
        }
        assert_invalid(&format!("x={}", "a".repeat(1023)), true);
    }

    #[test]
    fn history_numbers_distinguish_zero_cursor_from_invalid_zero_limit() {
        assert_eq!(decimal("0").unwrap(), 0);
        assert_eq!(decimal(&MAX_SAFE_TIME.to_string()).unwrap(), MAX_SAFE_TIME);
        let parsed = parse(&format!("after={MAX_SAFE_TIME}&limit=1"), true).unwrap();
        assert_eq!(parsed.after, Some(MAX_SAFE_TIME));
        assert_eq!(parsed.limit, 1);
        assert!(parse("after=0&limit=50", true).is_ok());
        assert!(parse("", true).unwrap().after.is_none());
        for value in [
            "",
            "-1",
            "+1",
            "01",
            "1.0",
            "1e3",
            "9007199254740992",
            "18446744073709551615",
        ] {
            assert!(decimal(value).is_err(), "noncanonical decimal {value}");
        }
        for raw in [
            "after=00",
            "after=-1",
            "after=9007199254740992",
            "limit=0",
            "limit=51",
            "limit=01",
            "limit=+1",
        ] {
            assert_invalid(raw, true);
        }
    }

    fn value(upload: u64, download: u64) -> Snapshot {
        Snapshot {
            upload,
            download,
            saturated: false,
        }
    }

    fn samples() -> (Vec<SeriesSnapshot>, Vec<PoolSnapshot>) {
        (
            vec![
                SeriesSnapshot {
                    user_id: Arc::from(id(1)),
                    credential_id: Arc::from(id(2)),
                    protocol: Protocol::Http,
                    value: value(5, 7),
                },
                SeriesSnapshot {
                    user_id: Arc::from(id(1)),
                    credential_id: Arc::from(id(3)),
                    protocol: Protocol::Http,
                    value: value(11, 13),
                },
                SeriesSnapshot {
                    user_id: Arc::from(id(4)),
                    credential_id: Arc::from(id(5)),
                    protocol: Protocol::Socks5,
                    value: value(3, 4),
                },
            ],
            vec![
                PoolSnapshot {
                    pool_id: Arc::from(id(6)),
                    protocol: Protocol::Http,
                    value: value(16, 20),
                },
                PoolSnapshot {
                    pool_id: Arc::from(id(7)),
                    protocol: Protocol::Http,
                    value: value(u64::MAX, u64::MAX),
                },
            ],
        )
    }

    #[test]
    fn live_scopes_use_primary_series_and_never_add_pool_aliases_to_node() {
        let (series, pools) = samples();
        let node = live(&Scope::Node, series, pools);
        assert_eq!(
            node,
            [
                value(0, 0),
                value(3, 4),
                value(0, 0),
                value(16, 20),
                value(0, 0)
            ]
        );
        let (series, pools) = samples();
        assert_eq!(
            live(&Scope::User(id(1)), series, pools),
            [
                value(0, 0),
                value(0, 0),
                value(0, 0),
                value(16, 20),
                value(0, 0)
            ]
        );
        let (series, pools) = samples();
        assert_eq!(
            live(&Scope::Credential(id(3)), series, pools),
            [
                value(0, 0),
                value(0, 0),
                value(0, 0),
                value(11, 13),
                value(0, 0)
            ]
        );
        let (series, pools) = samples();
        assert_eq!(
            live(&Scope::Pool(id(6)), series, pools),
            [
                value(0, 0),
                value(0, 0),
                value(0, 0),
                value(16, 20),
                value(0, 0)
            ]
        );
    }

    #[test]
    fn aggregation_saturates_each_direction_without_losing_the_uncertainty_flag() {
        let mut totals = value(u64::MAX - 1, 4);
        sum(&mut totals, value(2, 7));
        assert_eq!(
            totals,
            Snapshot {
                upload: u64::MAX,
                download: 11,
                saturated: true
            }
        );
        sum(&mut totals, value(0, u64::MAX));
        assert_eq!(
            totals,
            Snapshot {
                upload: u64::MAX,
                download: u64::MAX,
                saturated: true
            }
        );
        let mut totals = value(2, 3);
        sum(
            &mut totals,
            Snapshot {
                upload: 0,
                download: 0,
                saturated: true,
            },
        );
        assert_eq!(
            totals,
            Snapshot {
                upload: 2,
                download: 3,
                saturated: true
            }
        );
        sum(&mut totals, value(0, 0));
        assert!(totals.saturated);
    }

    #[tokio::test]
    async fn split_reads_distinguish_both_transports_and_leave_v1_family_totals_compatible() {
        let rows = || {
            vec![
                durable::ProtocolTotal {
                    protocol: Protocol::HttpLegacy,
                    value: value(37, 19),
                },
                durable::ProtocolTotal {
                    protocol: Protocol::Socks5,
                    value: value(2, 3),
                },
                durable::ProtocolTotal {
                    protocol: Protocol::Masque,
                    value: value(0, 0),
                },
                durable::ProtocolTotal {
                    protocol: Protocol::Http,
                    value: value(11, 5),
                },
                durable::ProtocolTotal {
                    protocol: Protocol::Https,
                    value: value(17, 7),
                },
            ]
        };
        let (_, old) = json(durable_totals_response(
            &parse("protocol=http", false).unwrap(),
            durable::Totals {
                status: status(),
                items: rows(),
            },
        ))
        .await;
        assert_eq!(old["items"][0]["durable_upload_bytes"], "65");
        assert_eq!(old["items"][0]["protocol"], "http");
        assert!(old.get("http_split").is_none());
        for (protocol, bytes) in [("http", "11"), ("https", "17"), ("http_legacy", "37")] {
            let query =
                parse(&format!("protocol_format=split&protocol={protocol}"), false).unwrap();
            let (_, data) = json(durable_totals_response(
                &query,
                durable::Totals {
                    status: status(),
                    items: rows(),
                },
            ))
            .await;
            assert_eq!(data["http_split"], true);
            assert_eq!(data["items"].as_array().unwrap().len(), 1);
            assert_eq!(data["items"][0]["protocol"], protocol);
            assert_eq!(data["items"][0]["durable_upload_bytes"], bytes);
        }
        for invalid in [
            "protocol=https",
            "protocol=http_legacy",
            "protocol_format=v2",
            "protocol_format=split&protocol_format=split",
        ] {
            assert_invalid(invalid, false);
        }
        let mut legacy = status();
        legacy.http_split = false;
        let (_, data) = json(durable_totals_response(
            &parse("protocol_format=split&protocol=https", false).unwrap(),
            durable::Totals {
                status: legacy,
                items: rows().into_iter().take(3).collect(),
            },
        ))
        .await;
        assert_eq!(data["http_split"], false);
        assert!(data["items"].as_array().unwrap().is_empty());
    }

    fn status() -> durable::Status {
        durable::Status {
            http_split: true,
            node_id: id(1),
            meter_epoch: id(2),
            run_id: Some(id(3)),
            cursor: u64::MAX,
            clean: false,
            loss_possible: true,
            history_gap: true,
            time_uncertain: true,
            last_checkpoint_at: Some(MAX_SAFE_TIME),
            meter_started_at: Some(0),
        }
    }

    async fn json(response: Response) -> (usize, Value) {
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (body.len(), serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn failed_local_totals_expose_only_the_stage_and_remote_totals_omit_it() {
        let status = status();
        let local = TotalsView {
            metadata: metadata(&status, false),
            scope: scope_view(&Scope::Node),
            active_run_id: status.run_id.clone(),
            checkpoint_error: true,
            checkpoint_failure_stage: Some(collector::CheckpointStage::Store),
            last_completed_cycle_at_unix_ms: None,
            last_completed_cycle_age_millis: None,
            items: Vec::new(),
        };
        let (_, body) = json(Json(local).into_response()).await;
        assert_eq!(body["checkpoint_failure_stage"], "store");
        assert_eq!(body["checkpoint_error"], true);
        let (_, body) = json(durable_totals_response(
            &parse("", false).unwrap(),
            durable::Totals {
                status,
                items: Vec::new(),
            },
        ))
        .await;
        assert!(
            !body
                .as_object()
                .unwrap()
                .contains_key("checkpoint_failure_stage")
        );
        assert_eq!(body["checkpoint_error"], false);
    }

    #[tokio::test]
    async fn maximum_actual_history_projection_fits_the_browser_budget_with_exact_strings() {
        let query = parse(
            &format!("scope=pool&id={}&resolution=day&after=0&limit=50", id(6)),
            true,
        )
        .unwrap();
        let width = 86_400_000;
        let maximum = MAX_SAFE_TIME / width * width;
        let first = maximum - 50 * width;
        let items = (0..50)
            .map(|position| durable::Bucket {
                window_id: first + position * width,
                items: [Protocol::Http, Protocol::Socks5, Protocol::Masque]
                    .into_iter()
                    .map(|protocol| durable::ProtocolTotal {
                        protocol,
                        value: value(u64::MAX, u64::MAX),
                    })
                    .collect(),
            })
            .collect();
        let response = bucket_response(
            &query,
            durable::BucketPage {
                status: status(),
                items,
                next_cursor: Some(maximum - width),
                floor: Some(0),
            },
        );
        let (length, body) = json(response).await;
        assert!(
            length < 32 * 1024,
            "maximum history response is {length} bytes"
        );
        assert_eq!(body["checkpoint_cursor"], u64::MAX.to_string());
        assert_eq!(body["meter_started_at_unix_ms"], 0);
        assert_eq!(body["next_cursor"], (maximum - width).to_string());
        assert_eq!(body["retention_floor"], "0");
        assert_eq!(body["scope"]["kind"], "pool");
        assert_eq!(body["items"].as_array().unwrap().len(), 50);
        for bucket in body["items"].as_array().unwrap() {
            assert!(bucket["window_id"].is_string());
            let rows = bucket["items"].as_array().unwrap();
            assert_eq!(rows.len(), 3);
            for row in rows {
                assert_eq!(row.as_object().unwrap().len(), 4);
                assert_eq!(row["upload_bytes"], u64::MAX.to_string());
                assert_eq!(row["download_bytes"], u64::MAX.to_string());
            }
        }
    }

    #[tokio::test]
    async fn history_keeps_missing_windows_and_protocols_absent_and_preserves_gap_metadata() {
        let query = parse("after=0&resolution=minute", true).unwrap();
        let (_, empty) = json(bucket_response(
            &query,
            durable::BucketPage {
                status: status(),
                items: vec![],
                next_cursor: None,
                floor: Some(60_000),
            },
        ))
        .await;
        assert!(empty["items"].as_array().unwrap().is_empty());
        assert!(empty["next_cursor"].is_null());
        assert_eq!(empty["retention_gap"], true);
        assert_eq!(empty["last_run_clean"], false);
        assert_eq!(empty["loss_possible"], true);
        assert_eq!(empty["history_gap"], true);
        assert_eq!(empty["time_uncertain"], true);
        // A persisted run marker is not evidence this API process has a live run.
        assert!(empty.get("run_id").is_none());
        assert!(empty.get("active_run_id").is_none());

        for protocol in [None, Some("socks5")] {
            let query = parse(
                &format!(
                    "resolution=minute{}",
                    protocol
                        .map(|protocol| format!("&protocol={protocol}"))
                        .unwrap_or_default()
                ),
                true,
            )
            .unwrap();
            let page = durable::BucketPage {
                status: status(),
                items: [0, 120_000]
                    .into_iter()
                    .map(|window_id| durable::Bucket {
                        window_id,
                        items: vec![durable::ProtocolTotal {
                            protocol: Protocol::Http,
                            value: value(0, 0),
                        }],
                    })
                    .collect(),
                next_cursor: None,
                floor: Some(0),
            };
            let (_, body) = json(bucket_response(&query, page)).await;
            let buckets = body["items"].as_array().unwrap();
            assert_eq!(buckets.len(), 2);
            assert_eq!(buckets[0]["window_id"], "0");
            assert_eq!(buckets[1]["window_id"], "120000");
            assert_eq!(body["retention_gap"], false);
            for bucket in buckets {
                let rows = bucket["items"].as_array().unwrap();
                if protocol.is_some() {
                    assert!(rows.is_empty());
                } else {
                    assert_eq!(rows.len(), 1);
                    assert_eq!(rows[0]["upload_bytes"], "0");
                }
            }
        }
    }

    #[tokio::test]
    async fn storage_failures_keep_busy_missing_and_internal_results_distinct_without_details() {
        // Missing database/file is an OS failure, not a missing entity result.
        assert_eq!(
            storage(io::Error::from_raw_os_error(2)).status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        for (kind, status, code) in [
            (
                io::ErrorKind::WouldBlock,
                StatusCode::SERVICE_UNAVAILABLE,
                "traffic_busy",
            ),
            (
                io::ErrorKind::NotFound,
                StatusCode::NOT_FOUND,
                "resource_not_found",
            ),
            (
                io::ErrorKind::InvalidData,
                StatusCode::SERVICE_UNAVAILABLE,
                "traffic_unavailable",
            ),
            (
                io::ErrorKind::PermissionDenied,
                StatusCode::SERVICE_UNAVAILABLE,
                "traffic_unavailable",
            ),
        ] {
            let response =
                storage(io::Error::new(kind, "internal storage diagnostic")).into_response();
            assert_eq!(response.status(), status);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["error"]["code"], code);
            assert!(!String::from_utf8_lossy(&bytes).contains("internal storage diagnostic"));
        }
    }

    async fn router_fixture() -> (
        crate::manage::api::tests::TestDirectory,
        Arc<AppState>,
        String,
    ) {
        let (directory, mut state, cookie) = crate::manage::api::tests::managed_state();
        let (handle, _runner) = collector::new(state.policy.as_ref().unwrap().clone())
            .await
            .unwrap();
        Arc::get_mut(&mut state).unwrap().traffic = Some(handle);
        (directory, state, cookie)
    }

    fn router_request(method: Method, path: &str, cookie: Option<&str>) -> Request {
        let mut request = crate::manage::api::tests::request(method, path, "");
        if let Some(cookie) = cookie {
            request
                .headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
        }
        request
    }

    async fn router_json(response: Response, expected: StatusCode) -> Value {
        assert_eq!(response.status(), expected);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.len() <= 32 * 1024);
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn router_requires_cookie_guards_unsafe_origin_and_rejects_duplicate_queries() {
        use crate::manage::api::tests::call;

        let (_directory, state, cookie) = router_fixture().await;
        for path in ["/api/v1/proxy/traffic", "/api/v1/proxy/traffic/buckets"] {
            // This application's Cookie domain uses 403 without a Basic/Bearer
            // challenge. Do not accidentally introduce a traffic-only 401 contract.
            let body = router_json(
                call(state.clone(), router_request(Method::GET, path, None)).await,
                StatusCode::FORBIDDEN,
            )
            .await;
            assert_eq!(body["error"]["code"], "authentication_required");

            let mut request = router_request(Method::GET, path, Some(&cookie));
            request.headers_mut().remove(header::ORIGIN);
            let body = router_json(call(state.clone(), request).await, StatusCode::OK).await;
            assert_eq!(body["last_run_clean"], true);
            assert_eq!(body["loss_possible"], false);
            assert_eq!(body["checkpoint_cursor"], "0");
            if path.ends_with("/buckets") {
                assert!(body["items"].as_array().unwrap().is_empty());
            } else {
                assert!(body["active_run_id"].is_null());
                assert!(
                    !body
                        .as_object()
                        .unwrap()
                        .contains_key("checkpoint_failure_stage")
                );
                for row in body["items"].as_array().unwrap() {
                    assert_eq!(row["durable_upload_bytes"], "0");
                    assert_eq!(row["durable_download_bytes"], "0");
                    assert!(row["live_upload_bytes"].is_null());
                    assert!(row["live_download_bytes"].is_null());
                    assert!(row["live_saturated"].is_null());
                }
            }

            // GET intentionally accepts a missing Origin. An unsafe method with a
            // hostile Origin is rejected by the common guard before route/method
            // dispatch; a legitimate Origin still cannot turn this read into POST.
            let mut wrong_origin = router_request(Method::POST, path, Some(&cookie));
            wrong_origin
                .headers_mut()
                .insert(header::ORIGIN, "https://attacker.invalid".parse().unwrap());
            let body = router_json(
                call(state.clone(), wrong_origin).await,
                StatusCode::FORBIDDEN,
            )
            .await;
            assert_eq!(body["error"]["code"], "invalid_origin");
            let body = router_json(
                call(
                    state.clone(),
                    router_request(Method::POST, path, Some(&cookie)),
                )
                .await,
                StatusCode::METHOD_NOT_ALLOWED,
            )
            .await;
            assert_eq!(body["error"]["code"], "method_not_allowed");
        }
        for path in [
            "/api/v1/proxy/traffic?scope=node&%73cope=node",
            "/api/v1/proxy/traffic/buckets?limit=1&limit=1",
        ] {
            let body = router_json(
                call(
                    state.clone(),
                    router_request(Method::GET, path, Some(&cookie)),
                )
                .await,
                StatusCode::BAD_REQUEST,
            )
            .await;
            assert_eq!(body["error"]["code"], "invalid_traffic_query");
        }
    }

    #[tokio::test]
    async fn router_projects_persisted_old_open_as_loss_without_mislabeling_a_current_run() {
        use crate::manage::{api::tests::call, policy::Coordinator, store};

        let (_directory, mut state, cookie) = router_fixture().await;
        let observer = state.traffic.as_ref().unwrap().clone();
        observer.begin().await.unwrap();
        let active = observer.observation().unwrap().active_run.unwrap();
        for path in ["/api/v1/proxy/traffic", "/api/v1/proxy/traffic/buckets"] {
            let body = router_json(
                call(
                    state.clone(),
                    router_request(Method::GET, path, Some(&cookie)),
                )
                .await,
                StatusCode::OK,
            )
            .await;
            assert_eq!(body["last_run_clean"], false);
            assert_eq!(body["loss_possible"], false);
            if !path.ends_with("/buckets") {
                assert_eq!(body["active_run_id"], active);
                assert!(body["items"].as_array().unwrap().iter().all(|row| {
                    row["live_upload_bytes"] == "0" && row["live_download_bytes"] == "0"
                }));
            }
        }
        observer.finish(false).await.unwrap();
        let open = store::traffic::status(&state.directory).unwrap();
        assert!(!open.clean && !open.loss_possible);
        drop(observer);

        // Reconstruct the production Coordinator/collector from the real durable
        // old marker, without opening another proxy run. Keep the existing author
        // and fixture login to isolate recovery projection from lock/login tests.
        let policy = Coordinator::new(
            state.directory.clone(),
            store::load_policy(&state.directory).unwrap(),
            state._author.as_ref().unwrap().clone(),
        )
        .unwrap();
        let (observer, _runner) = collector::new(policy.clone()).await.unwrap();
        let mutable = Arc::get_mut(&mut state).unwrap();
        mutable.policy = Some(policy);
        mutable.traffic = Some(observer);
        for path in ["/api/v1/proxy/traffic", "/api/v1/proxy/traffic/buckets"] {
            let body = router_json(
                call(
                    state.clone(),
                    router_request(Method::GET, path, Some(&cookie)),
                )
                .await,
                StatusCode::OK,
            )
            .await;
            assert_eq!(body["last_run_clean"], false);
            assert_eq!(body["loss_possible"], true);
            assert_eq!(body["meter_epoch"], open.meter_epoch);
            assert_eq!(body["checkpoint_cursor"], open.cursor.to_string());
            if !path.ends_with("/buckets") {
                assert!(body["active_run_id"].is_null());
                assert!(body["items"].as_array().unwrap().iter().all(|row| {
                    row["live_upload_bytes"].is_null() && row["live_download_bytes"].is_null()
                }));
            }
        }
        let unchanged = store::traffic::status(&state.directory).unwrap();
        assert_eq!(unchanged.cursor, open.cursor);
        assert!(!unchanged.clean && !unchanged.loss_possible);
    }
}
