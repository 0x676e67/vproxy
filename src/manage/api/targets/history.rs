//! Controller-local, non-secret command history. Reading a record neither
//! contacts its target nor authorizes delivery, retry, ownership or secret recovery.

use super::*;
use crate::manage::store::targets::history as storage_history;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/targets/{id}/commands/history", get(list))
        .route("/api/v1/targets/{id}/commands/history/{job_id}", get(find))
}

/// Historical facts use lossless decimals. A missing timestamp is unknown,
/// and a saved/applied receipt does not describe today's policy or runtime.
#[derive(Serialize)]
struct Entry {
    sequence: String,
    controller_node_id: String,
    administrator_id: String,
    protocol_version: u8,
    action: String,
    job: JobView,
    user_id: Option<String>,
    credential_id: Option<String>,
    imported: bool,
    recorded_at_unix_s: Option<String>,
    updated_at_unix_s: Option<String>,
}

impl From<storage_history::StoredEntry> for Entry {
    fn from(value: storage_history::StoredEntry) -> Self {
        Self {
            sequence: value.sequence.to_string(),
            controller_node_id: value.controller_node_id,
            administrator_id: value.administrator_id,
            protocol_version: value.protocol_version,
            action: value.action,
            job: value.job.into(),
            user_id: value.user_id,
            credential_id: value.credential_id,
            imported: value.imported,
            recorded_at_unix_s: value.recorded_at_unix_s.map(|value| value.to_string()),
            updated_at_unix_s: value.updated_at_unix_s.map(|value| value.to_string()),
        }
    }
}

#[derive(Serialize)]
struct Page {
    items: Vec<Entry>,
    next_cursor: Option<String>,
    oldest_sequence: Option<String>,
    trimmed: bool,
}

/// Read one bounded local SQL snapshot using the existing blocking admission.
/// Retired or no-longer-authorized peers remain auditable by local admins;
/// this read does not restore their authority or create a controller service.
async fn list(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let peer = resource_id(path)?;
    if !store::valid_id(&peer) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_resource_id",
        ));
    }
    let (before, limit) = pagination(&uri)?;
    let page = coordinator(&state)?
        .read(move |directory| storage_history::list(directory, &actor, &peer, before, limit))
        .await
        .map_err(storage_error)?;
    Ok(Json(Page {
        items: page.items.into_iter().map(Entry::from).collect(),
        next_cursor: page.next_cursor.map(|value| value.to_string()),
        oldest_sequence: page.oldest_sequence.map(|value| value.to_string()),
        trimmed: page.trimmed > 0,
    })
    .into_response())
}

/// Look up only this peer's original job ID. Absence means unavailable locally,
/// not never executed, safely retryable, or a reason to inspect another job.
async fn find(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let Path((peer, job)) =
        path.map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_resource_id"))?;
    if !store::valid_id(&peer) || !store::valid_id(&job) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_resource_id",
        ));
    }
    let entry = coordinator(&state)?
        .read(move |directory| storage_history::get(directory, &actor, &peer, &job))
        .await
        .map_err(storage_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "resource_not_found"))?;
    Ok(Json(Entry::from(entry)).into_response())
}

/// Exclusive positive sequence cursor, at most 50 records. Decode names before
/// rejecting duplicates so escaped spellings cannot override another bound.
fn pagination(uri: &Uri) -> Result<(Option<u64>, u32), ApiError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Parameters {
        before: Option<String>,
        limit: Option<String>,
    }
    let invalid = || ApiError::new(StatusCode::BAD_REQUEST, "invalid_pagination");
    let raw = uri.query().unwrap_or_default();
    if raw.len() > 1024 {
        return Err(invalid());
    }
    let query: Parameters = serde_urlencoded::from_str(raw).map_err(|_| invalid())?;
    let before = query
        .before
        .as_deref()
        .map(revision)
        .transpose()
        .map_err(|_| invalid())?;
    let limit = query
        .limit
        .as_deref()
        .map(|text| {
            let value = revision(text).map_err(|_| invalid())?;
            u32::try_from(value)
                .ok()
                .filter(|value| *value <= 50)
                .ok_or_else(invalid)
        })
        .transpose()?
        .unwrap_or(25);
    Ok((before, limit))
}
