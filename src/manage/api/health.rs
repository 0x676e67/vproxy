//! Administrative health configuration and bounded observation projection. Probe
//! endpoints are startup-only operator inputs, not arbitrary URLs from a page.

use super::*;
use crate::manage::health::Config;
use std::{fs::OpenOptions, io::Read as _, path::Path};

// A record can contain five checks; using inventory's 50-row page would exceed
// the browser's 32 KiB response cap. Keep the complete worst-case page below it.
const MAX_PAGE_SIZE: u32 = 16;

use crate::manage::views::HealthPage as PageView;

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/proxy/health", get(observations))
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

async fn observations(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    let mut pagination = super::routing::pagination(&uri)?;
    if !url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
        .any(|(key, _)| key == "limit")
    {
        pagination.limit = 10;
    }
    if pagination.limit > MAX_PAGE_SIZE {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_pagination"));
    }
    let observer = state
        .health
        .as_ref()
        .ok_or_else(|| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "health_unavailable"))?;
    let mut snapshot = observer
        .snapshot()
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "health_unavailable"))?;
    snapshot
        .entries
        .sort_unstable_by(|a, b| a.address_id.cmp(&b.address_id));
    snapshot.entries.retain(|entry| {
        pagination
            .after
            .as_ref()
            .is_none_or(|after| &entry.address_id > after)
    });
    let limit = pagination.limit as usize;
    let next_cursor = if snapshot.entries.len() > limit {
        snapshot
            .entries
            .get(limit.saturating_sub(1))
            .map(|entry| entry.address_id.clone())
    } else {
        None
    };
    snapshot.entries.truncate(limit);
    Ok(Json(PageView::new(snapshot, next_cursor)).into_response())
}

/// Read a regular, bounded JSON configuration (Unix refuses leaf symlinks).
/// Missing input uses bind-only defaults and sends no network probes. All
/// endpoints are numeric socket addresses, and unknown fields are rejected.
/// Ancestors must be trusted; Windows inherits the operator's filesystem ACLs.
pub(super) fn load(path: Option<&Path>) -> io::Result<Config> {
    let Some(path) = path else {
        return Ok(Config::default());
    };
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_JSON_BYTES as u64 {
        return Err(invalid());
    }
    let mut bytes = Vec::with_capacity(MAX_JSON_BYTES + 1);
    file.take((MAX_JSON_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    from_bytes(&bytes)
}

/// Parse an already captured bounded buffer with the ordinary startup rules;
/// no file, observer, probe or network operation is created by validation.
pub(super) fn from_bytes(bytes: &[u8]) -> io::Result<Config> {
    if bytes.len() > MAX_JSON_BYTES {
        return Err(invalid());
    }
    #[derive(Deserialize)]
    #[serde(default, deny_unknown_fields)]
    struct Input {
        interval_secs: u64,
        timeout_secs: u64,
        concurrency: usize,
        probes_per_second: u32,
        targets: Vec<SocketAddr>,
    }
    impl Default for Input {
        fn default() -> Self {
            let config = Config::default();
            Self {
                interval_secs: config.interval_secs,
                timeout_secs: config.timeout_secs,
                concurrency: config.concurrency,
                probes_per_second: config.probes_per_second,
                targets: config.targets,
            }
        }
    }
    let input: Input = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let config = Config {
        interval_secs: input.interval_secs,
        timeout_secs: input.timeout_secs,
        concurrency: input.concurrency,
        probes_per_second: input.probes_per_second,
        targets: input.targets,
    };
    config.validate()?;
    Ok(config)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "health configuration requires at most 4 KiB of valid bounded JSON",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::{
        api::tests::{call, managed_state, request},
        health::{self, CheckKind, CheckView, Entry, FixedOutcome, Snapshot},
    };
    use http_body_util::BodyExt as _;

    #[test]
    fn startup_probe_config_is_bounded_regular_numeric_and_opt_in() {
        let (_directory, state, _cookie) = managed_state();
        let config = load(None).unwrap();
        assert!(config.targets.is_empty());
        assert_eq!(config.interval_secs, 60);
        let path = state.directory.join("health.json");
        std::fs::write(&path, r#"{"targets":["127.0.0.1:443"],"interval_secs":30}"#).unwrap();
        let config = load(Some(&path)).unwrap();
        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.interval_secs, 30);
        for input in [
            r#"{"targets":["localhost:443"]}"#,
            r#"{"targets":["127.0.0.1:0"]}"#,
            r#"{"targets":["[::1%1]:443"]}"#,
            r#"{"timeout_secs":0}"#,
            r#"{"concurrency":5}"#,
            r#"{"interval_secs":9}"#,
            r#"{"targets":["127.0.0.1:443","127.0.0.1:443"]}"#,
            r#"{"password":"not-supported"}"#,
        ] {
            std::fs::write(&path, input).unwrap();
            assert!(load(Some(&path)).is_err());
        }
        std::fs::write(&path, " ".repeat(MAX_JSON_BYTES + 1)).unwrap();
        assert!(load(Some(&path)).is_err());
        assert!(load(Some(&state.directory)).is_err());
        #[cfg(unix)]
        {
            let link = state.directory.join("health-link.json");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(load(Some(&link)).is_err());
        }
    }

    #[test]
    fn largest_health_page_fits_the_browser_response_budget() {
        let mut entries = Vec::new();
        for index in 0..MAX_PAGE_SIZE {
            let mut checks = Vec::new();
            for target in 0..5 {
                checks.push(CheckView {
                    kind: if target == 0 {
                        CheckKind::Bind
                    } else {
                        CheckKind::Tcp
                    },
                    target: if target == 0 {
                        None
                    } else {
                        Some(
                            format!(
                                "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe]:{}",
                                65535 - target
                            )
                            .parse()
                            .unwrap(),
                        )
                    },
                    outcome: FixedOutcome::NetworkUnreachable,
                    sequence: Some(u64::MAX),
                    observed_at_unix_ms: Some(9_007_199_254_740_991),
                    age_millis: Some(9_007_199_254_740_991),
                    latency_millis: Some(9_007_199_254_740_991),
                });
            }
            entries.push(Entry {
                address_id: URL_SAFE_NO_PAD.encode([u8::try_from(index).unwrap(); 16]),
                address_revision: i64::MAX as u64,
                ip: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe".parse().unwrap(),
                checks,
            });
        }
        let view = PageView::new(
            Snapshot {
                boot_id: URL_SAFE_NO_PAD.encode([1; 16]),
                sequence: u64::MAX,
                catalog_revision: Some(i64::MAX as u64),
                catalog_loaded: true,
                catalog_error: Some("catalog_unavailable"),
                catalog_observed_at_unix_ms: Some(9_007_199_254_740_991),
                catalog_age_millis: Some(9_007_199_254_740_991),
                in_flight: 4,
                entries,
            },
            Some(URL_SAFE_NO_PAD.encode([2; 16])),
        );
        assert!(serde_json::to_vec(&view).unwrap().len() <= 32 * 1024);
    }

    #[tokio::test]
    async fn health_read_requires_session_and_never_claims_unobserved_addresses_are_healthy() {
        let (_directory, mut state, cookie) = managed_state();
        let config = crate::connect::Connector::new(
            None,
            None,
            None,
            3,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            None,
            None,
        );
        let (handle, _runner) = health::new(
            state.policy.as_ref().unwrap().clone(),
            config,
            Config::default(),
        )
        .unwrap();
        Arc::get_mut(&mut state).unwrap().health = Some(handle);
        assert_eq!(
            call(
                state.clone(),
                request(Method::GET, "/api/v1/proxy/health", "")
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let mut read = request(Method::GET, "/api/v1/proxy/health", "");
        read.headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        let response = call(state.clone(), read).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["catalog_loaded"], false);
        assert_eq!(value["sequence"], "0");
        assert!(value["entries"].as_array().unwrap().is_empty());
        assert!(value["catalog_revision"].is_null());
        for query in ["limit=17", "limit=50", "limit=10&limit=16", "unknown=true"] {
            let mut read = request(Method::GET, &format!("/api/v1/proxy/health?{query}"), "");
            read.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            assert_eq!(
                call(state.clone(), read).await.status(),
                StatusCode::BAD_REQUEST
            );
        }
    }
}
