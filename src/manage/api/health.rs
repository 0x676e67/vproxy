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
