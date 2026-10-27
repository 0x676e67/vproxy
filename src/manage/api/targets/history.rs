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
    let invalid = || ApiError::new(StatusCode::BAD_REQUEST, "invalid_pagination");
    let query = uri.query().unwrap_or_default();
    if query.len() > 1024 {
        return Err(invalid());
    }
    let mut before = None;
    let mut limit = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let parsed = revision(&value).map_err(|_| invalid())?;
        match key.as_ref() {
            "before" if before.is_none() => before = Some(parsed),
            "limit" if limit.is_none() => {
                limit = Some(
                    u32::try_from(parsed)
                        .ok()
                        .filter(|value| *value <= 50)
                        .ok_or_else(invalid)?,
                );
            }
            _ => return Err(invalid()),
        }
    }
    Ok((before, limit.unwrap_or(25)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::api::tests::{call, managed_state, request};
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};

    fn id(value: u8) -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            [value; 16],
        )
    }

    fn actor(state: &AppState) -> String {
        rusqlite::Connection::open(state.directory.join("management.sqlite3"))
            .unwrap()
            .query_row("SELECT id FROM administrators", [], |row| row.get(0))
            .unwrap()
    }

    fn register(state: &AppState, peer: &str) {
        store::register_peer(
            &state.directory,
            peer,
            "History target",
            format!("fixture public DER for {peer}").as_bytes(),
            "target.example",
            None,
        )
        .unwrap();
        storage::configure(
            &state.directory,
            &actor(state),
            peer,
            None,
            "https://target.example:9443",
            true,
            None,
        )
        .unwrap();
    }

    async fn get(state: Arc<AppState>, cookie: &str, path: &str) -> (StatusCode, Value) {
        let mut request = request(Method::GET, path, "");
        request
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        let response = call(state, request).await;
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn command_history_is_session_only_strict_and_does_not_need_a_remote_service() {
        let (_directory, state, cookie) = managed_state();
        let peer = id(43);
        register(&state, &peer);
        assert!(state.controller.is_none());
        let list = format!("/api/v1/targets/{peer}/commands/history");
        let exact = format!("{list}/{}", id(44));
        for path in [&list, &exact] {
            assert_eq!(
                call(state.clone(), request(Method::GET, path, ""))
                    .await
                    .status(),
                StatusCode::FORBIDDEN
            );
            let mut machine = request(Method::GET, path, "");
            machine.headers_mut().insert(
                header::AUTHORIZATION,
                "Bearer deliberately-not-loaded".parse().unwrap(),
            );
            let response = call(state.clone(), machine).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap()["error"]["code"],
                "automation_route_denied"
            );
        }
        let (status, page) = get(state.clone(), &cookie, &list).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            page,
            json!({"items":[],"next_cursor":null,"oldest_sequence":null,"trimmed":false})
        );
        for query in [
            "before=0",
            "before=01",
            "before=9223372036854775808",
            "before=%FF",
            "limit=0",
            "limit=51",
            "limit=%2B1",
            "limit=1&%6cimit=2",
            "before=1&before=2",
            "after=1",
        ] {
            let (status, body) = get(state.clone(), &cookie, &format!("{list}?{query}")).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "accepted invalid history pagination"
            );
            assert_eq!(body["error"]["code"], "invalid_pagination");
        }
        assert_eq!(
            get(state.clone(), &cookie, &exact).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get(state.clone(), &cookie, &format!("{exact}?")).await.0,
            StatusCode::BAD_REQUEST
        );
        let mut head = request(Method::HEAD, &list, "");
        head.headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        let response = call(state.clone(), head).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        assert!(storage::job(&state.directory, &peer).unwrap().is_none());
    }

    #[tokio::test]
    async fn original_command_result_survives_slot_replacement_and_revoked_peer_without_replay() {
        let (_directory, state, cookie) = managed_state();
        let peer = id(45);
        let other = id(46);
        register(&state, &peer);
        register(&state, &other);
        let actor = actor(&state);
        storage::observe(&state.directory, &peer, 1, 2, 0, 1).unwrap();
        let command = |number, revision| store::Command {
            target_node_id: peer.clone(),
            epoch: 2,
            command_id: number,
            expected_policy_revision: revision,
            source_administrator_id: actor.clone(),
            change: store::PolicyChange::CreateUser {
                name: "must-not-appear-in-history".into(),
                protocols: vec![crate::access::Protocol::Http],
                concurrent_limit: 1,
            },
        };
        let first = storage::enqueue(&state.directory, &actor, 1, command(1, 1)).unwrap();
        let user = id(47);
        storage::complete(
            &state.directory,
            &peer,
            &first.job_id,
            &store::Receipt {
                version: 1,
                epoch: 2,
                command_id: 1,
                status: store::ReceiptStatus::Saved,
                policy_revision: Some(2),
                rejection: None,
                user_id: Some(user.clone()),
                credential_id: None,
                routing: None,
                preset: None,
            },
        )
        .unwrap();
        let next = storage::enqueue(&state.directory, &actor, 1, command(2, 2)).unwrap();
        let list = format!("/api/v1/targets/{peer}/commands/history");
        let exact = format!("{list}/{}", first.job_id);
        let (status, entry) = get(state.clone(), &cookie, &exact).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(entry["job"]["job_id"], first.job_id);
        assert_eq!(entry["job"]["state"], "saved");
        assert_eq!(entry["user_id"], user);
        assert_eq!(entry["administrator_id"], actor);
        assert_eq!(entry["imported"], false);
        assert!(!entry.to_string().contains("must-not-appear-in-history"));
        assert!(entry.get("secret").is_none() && entry.get("command").is_none());
        let (status, first_page) = get(state.clone(), &cookie, &format!("{list}?limit=1")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first_page["items"][0]["job"]["job_id"], next.job_id);
        let before = first_page["next_cursor"].as_str().unwrap();
        let (_, second_page) = get(
            state.clone(),
            &cookie,
            &format!("{list}?before={before}&limit=1"),
        )
        .await;
        assert_eq!(second_page["items"][0]["job"]["job_id"], first.job_id);
        assert!(second_page["next_cursor"].is_null());
        assert_eq!(
            get(
                state.clone(),
                &cookie,
                &format!("/api/v1/targets/{other}/commands/history/{}", first.job_id)
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        let connection =
            rusqlite::Connection::open(state.directory.join("management.sqlite3")).unwrap();
        connection
            .execute(
                "UPDATE managed_targets SET active=0,retired=1 WHERE peer_id=?1",
                [&peer],
            )
            .unwrap();
        connection
            .execute("UPDATE peers SET active=0 WHERE node_id=?1", [&peer])
            .unwrap();
        assert_eq!(get(state.clone(), &cookie, &exact).await.0, StatusCode::OK);
        let current = storage::job(&state.directory, &peer).unwrap().unwrap();
        assert_eq!(current.job_id, next.job_id);
        assert_eq!(current.attempts, 0);
        assert!(current.state == storage::JobState::Pending);
    }
}
