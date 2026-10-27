//! Caller-bound local user operations. IDs identify records, not capabilities;
//! every store snapshot rechecks the administrator or current machine key.

use super::*;
use crate::manage::store::operations::{
    self, Caller, Operation, State as OperationState, UserChange,
};

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/proxy/user-operations", get(list).post(reserve))
        .route("/api/v1/proxy/user-operations/context", get(context))
        .route("/api/v1/proxy/user-operations/{id}", get(find))
        .route("/api/v1/proxy/user-operations/{id}/execute", post(execute))
}

/// Revisions stay lossless decimal strings, with the actual actor supplied only
/// by authentication middleware. No credential mutation or client-selected ID can
/// enter a reservation through this vocabulary.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    #[serde(default, deserialize_with = "node_binding")]
    expected_node_id: Option<String>,
    expected_revision: String,
    expected_epoch: String,
    change: UserChange,
}

impl Input {
    fn into_store(self) -> Result<operations::Input, ApiError> {
        if self
            .expected_node_id
            .as_deref()
            .is_some_and(|id| !store::valid_id(id))
        {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_operation"));
        }
        Ok(operations::Input {
            expected_node_id: self.expected_node_id,
            expected_revision: revision(&self.expected_revision)?,
            expected_epoch: revision(&self.expected_epoch)?,
            change: self.change,
        })
    }
}

/// Missing keeps legacy clients compatible; a present null is not a binding.
fn node_binding<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

/// A historical, non-secret result; Saved deliberately says nothing about the
/// current running proxy or later edits. Input names and secrets are not stored
/// in, or reconstructed by, these responses.
#[derive(Serialize)]
struct View {
    id: String,
    node_id: String,
    sequence: String,
    expected_revision: String,
    expected_epoch: String,
    action: String,
    user_id: Option<String>,
    state: &'static str,
    saved_revision: Option<String>,
    rejection: Option<String>,
}

impl From<Operation> for View {
    fn from(operation: Operation) -> Self {
        Self {
            id: operation.id,
            node_id: operation.node_id,
            sequence: operation.sequence.to_string(),
            expected_revision: operation.expected_revision.to_string(),
            expected_epoch: operation.expected_epoch.to_string(),
            action: operation.action.to_string(),
            user_id: operation.user_id,
            state: match operation.state {
                OperationState::Reserved => "reserved",
                OperationState::Saved => "saved",
                OperationState::Rejected => "rejected",
            },
            saved_revision: operation.saved_revision.map(|value| value.to_string()),
            rejection: operation.rejection.map(|value| value.to_string()),
        }
    }
}

fn storage(error: io::Error) -> ApiError {
    if let Some(known) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<operations::Error>())
    {
        let status = match known {
            operations::Error::UpgradeRequired => StatusCode::SERVICE_UNAVAILABLE,
            operations::Error::InvalidOperation => StatusCode::BAD_REQUEST,
            operations::Error::NotQueryable => StatusCode::NOT_FOUND,
            operations::Error::Conflict | operations::Error::Capacity => StatusCode::CONFLICT,
            operations::Error::Denied => StatusCode::FORBIDDEN,
        };
        return ApiError::new(status, known.code());
    }
    automation::storage_error(error)
}

fn caller(
    administrator: Option<Extension<Administrator>>,
    key: Option<Extension<automation::Key>>,
) -> Result<Caller, ApiError> {
    match (administrator, key) {
        (Some(Extension(Administrator(id))), None) => Ok(Caller::Administrator(id)),
        (None, Some(Extension(key))) => Ok(Caller::Automation(key)),
        _ => Err(ApiError::authentication_required()),
    }
}

/// One authenticated snapshot for preparing a reservation, not a reusable
/// authorization. Reserve and execute recheck caller, ownership and revision.
async fn context(
    State(state): State<Arc<AppState>>,
    administrator: Option<Extension<Administrator>>,
    key: Option<Extension<automation::Key>>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let caller = caller(administrator, key)?;
    if uri.query().is_some_and(|query| !query.is_empty()) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_query"));
    }
    let context = coordinator(&state)?
        .read(move |directory| operations::context(directory, &caller))
        .await
        .map_err(storage)?;
    #[derive(Serialize)]
    struct Context {
        node_id: String,
        policy_revision: String,
        expected_epoch: String,
        local: bool,
    }
    Ok(Json(Context {
        node_id: context.node_id,
        policy_revision: context.policy_revision.to_string(),
        expected_epoch: context.expected_epoch.to_string(),
        local: context.local,
    })
    .into_response())
}

async fn reserve(
    State(state): State<Arc<AppState>>,
    administrator: Option<Extension<Administrator>>,
    key: Option<Extension<automation::Key>>,
    request: Request,
) -> Result<Response, ApiError> {
    let actor = caller(administrator, key)?;
    let input = json::<Input>(request).await?.into_store()?;
    let operation = coordinator(&state)?
        .reserve_user_operation(actor, input)
        .await
        .map_err(storage)?;
    Ok((StatusCode::CREATED, Json(View::from(operation))).into_response())
}

async fn execute(
    State(state): State<Arc<AppState>>,
    administrator: Option<Extension<Administrator>>,
    key: Option<Extension<automation::Key>>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let actor = caller(administrator, key)?;
    let id = resource_id(path)?;
    let input = json::<Input>(request).await?.into_store()?;
    let operation = coordinator(&state)?
        .execute_user_operation(actor, id, input)
        .await
        .map_err(storage)?;
    Ok(Json(View::from(operation)).into_response())
}

async fn find(
    State(state): State<Arc<AppState>>,
    administrator: Option<Extension<Administrator>>,
    key: Option<Extension<automation::Key>>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Response, ApiError> {
    let actor = caller(administrator, key)?;
    let id = resource_id(path)?;
    let operation = coordinator(&state)?
        .read(move |directory| match &actor {
            Caller::Administrator(administrator) => operations::get(directory, administrator, &id),
            Caller::Automation(_) => operations::get_as(directory, &actor, &id),
        })
        .await
        .map_err(storage)?;
    Ok(Json(View::from(operation)).into_response())
}

/// List only the authenticated caller's bounded records in descending durable
/// sequence order. The cursor is an exclusive sequence bound, never a claim
/// that the newest record belongs to a previously lost browser request.
async fn list(
    State(state): State<Arc<AppState>>,
    administrator: Option<Extension<Administrator>>,
    key: Option<Extension<automation::Key>>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let actor = caller(administrator, key)?;
    let (before, limit) = pagination(&uri)?;
    let page = coordinator(&state)?
        .read(move |directory| match &actor {
            Caller::Administrator(administrator) => {
                operations::list(directory, administrator, before, limit)
            }
            Caller::Automation(_) => operations::list_as(directory, &actor, before, limit),
        })
        .await
        .map_err(storage)?;
    #[derive(Serialize)]
    struct Page {
        items: Vec<View>,
        next_cursor: Option<String>,
    }
    Ok(Json(Page {
        items: page.items.into_iter().map(View::from).collect(),
        next_cursor: page.next_cursor.map(|value| value.to_string()),
    })
    .into_response())
}

fn pagination(uri: &Uri) -> Result<(Option<u64>, u32), ApiError> {
    let invalid = || ApiError::new(StatusCode::BAD_REQUEST, "invalid_pagination");
    let query = uri.query().unwrap_or_default();
    if query.len() > 1024 {
        return Err(invalid());
    }
    let mut before = None;
    let mut limit = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "before" if before.is_none() => before = Some(revision(&value)?),
            "limit" if limit.is_none() => {
                let parsed = revision(&value)?;
                limit = Some(
                    u32::try_from(parsed)
                        .ok()
                        .filter(|n| *n <= 50)
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

    const BASE: &str = "/api/v1/proxy/user-operations";

    async fn invoke(
        state: Arc<AppState>,
        cookie: &str,
        method: Method,
        path: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut input = request(method, path, &body.to_string());
        input
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        input
            .headers_mut()
            .insert("x-csrf-token", "c".repeat(43).parse().unwrap());
        let response = call(state, input).await;
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    fn create(revision: &str) -> Value {
        json!({"expected_revision":revision,"expected_epoch":"1","change":{
            "action":"create_user","name":"Reserved user","protocols":["http"],"concurrent_limit":2
        }})
    }

    #[tokio::test]
    async fn expected_node_binding_conflicts_before_publication_and_keeps_legacy_requests_compatible()
     {
        let (_directory, state, cookie) = managed_state();
        let service = coordinator(&state).unwrap();
        service.activate().await.unwrap();
        let mut wrong = create("1");
        let node = store::inspect(&state.directory).unwrap().node_id;
        wrong["expected_node_id"] = json!(if node == "AAAAAAAAAAAAAAAAAAAAAA" {
            "AQEBAQEBAQEBAQEBAQEBAQ"
        } else {
            "AAAAAAAAAAAAAAAAAAAAAA"
        });
        let (status, error) =
            invoke(state.clone(), &cookie, Method::POST, BASE, wrong.clone()).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(error["error"]["code"], "operation_conflict");
        let (_, page) = invoke(state.clone(), &cookie, Method::GET, BASE, Value::Null).await;
        assert_eq!(page["items"], json!([]));
        assert_eq!(service.reader().revision().unwrap(), 1);

        let legacy = create("1");
        let (status, reserved) =
            invoke(state.clone(), &cookie, Method::POST, BASE, legacy.clone()).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(reserved["sequence"], "1");
        let id = reserved["id"].as_str().unwrap();
        let exact = format!("{BASE}/{id}");
        let execute = format!("{exact}/execute");
        let (status, error) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &execute,
            wrong.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(error["error"]["code"], "operation_conflict");
        let (_, unchanged) = invoke(state.clone(), &cookie, Method::GET, &exact, Value::Null).await;
        assert_eq!(unchanged, reserved);
        assert_eq!(service.reader().revision().unwrap(), 1);
        assert_eq!(service.status().await.unwrap().user_count, 0);

        let mut bound = legacy.clone();
        bound["expected_node_id"] = json!(reserved["node_id"]);
        let (status, saved) = invoke(state.clone(), &cookie, Method::POST, &execute, bound).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(saved["state"], "saved");
        assert_eq!(service.reader().revision().unwrap(), 2);
        let (status, error) = invoke(state.clone(), &cookie, Method::POST, &execute, wrong).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(error["error"]["code"], "operation_conflict");
        let (status, replay) = invoke(state.clone(), &cookie, Method::POST, &execute, legacy).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replay, saved);
        assert_eq!(service.reader().revision().unwrap(), 2);
        assert_eq!(service.status().await.unwrap().user_count, 1);
    }

    #[tokio::test]
    async fn exact_records_survive_lost_replies_without_republishing_an_old_policy() {
        let (_directory, state, cookie) = managed_state();
        let service = coordinator(&state).unwrap();
        service.activate().await.unwrap();
        let input = create("1");
        let (status, reserved) =
            invoke(state.clone(), &cookie, Method::POST, BASE, input.clone()).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(reserved["state"], "reserved");
        assert_eq!(reserved.as_object().unwrap().len(), 10);
        assert!(reserved["user_id"].is_null());
        assert_eq!(service.status().await.unwrap().saved_revision, 1);
        let id = reserved["id"].as_str().unwrap();
        let path = format!("{BASE}/{id}");
        let execute = format!("{path}/execute");
        let (status, saved) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &execute,
            input.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(saved["state"], "saved");
        assert_eq!(saved["saved_revision"], "2");
        assert!(saved["user_id"].is_string());
        let (status, recovered) =
            invoke(state.clone(), &cookie, Method::GET, &path, Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(recovered, saved);
        let (_, page) = invoke(state.clone(), &cookie, Method::GET, BASE, Value::Null).await;
        assert_eq!(page["items"], json!([saved]));
        assert!(page["next_cursor"].is_null());
        let encoded = page.to_string();
        for hidden in ["Reserved user", "password", "secret", "digest", "applied"] {
            assert!(!encoded.contains(hidden));
        }

        // A terminal replay recovers its saved result, without replacing a later
        // live policy or requiring the old CAS to match the current revision.
        let (status, _) = invoke(
        state.clone(),
        &cookie,
        Method::POST,
        "/api/v1/proxy/users",
        json!({"expected_revision":"2","name":"Later edit","protocols":[],"concurrent_limit":1}),
    )
    .await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, replay) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &execute,
            input.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replay, recovered);
        assert_eq!(service.reader().revision().unwrap(), 3);
        assert_eq!(service.status().await.unwrap().user_count, 2);
        let mut changed = input;
        changed["change"]["name"] = json!("Different request");
        let (status, rejected) = invoke(state, &cookie, Method::POST, &execute, changed).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(rejected["error"]["code"], "operation_conflict");
        assert_eq!(service.reader().revision().unwrap(), 3);
    }

    #[tokio::test]
    async fn missing_identity_and_stale_cas_never_create_or_repeat_an_edit() {
        let (_directory, state, cookie) = managed_state();
        let missing = format!("{BASE}/AAECAwQFBgcICQoLDA0ODw/execute");
        let (status, error) =
            invoke(state.clone(), &cookie, Method::POST, &missing, create("1")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(error["error"]["code"], "operation_not_queryable");
        let (_, reserved) = invoke(state.clone(), &cookie, Method::POST, BASE, create("1")).await;
        let id = reserved["id"].as_str().unwrap();
        let (status, _) = invoke(
        state.clone(),
        &cookie,
        Method::POST,
        "/api/v1/proxy/users",
        json!({"expected_revision":"1","name":"Other request","protocols":[],"concurrent_limit":1}),
    )
    .await;
        assert_eq!(status, StatusCode::CREATED);
        let path = format!("{BASE}/{id}/execute");
        let (status, rejected) =
            invoke(state.clone(), &cookie, Method::POST, &path, create("1")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rejected["state"], "rejected");
        assert_eq!(rejected["rejection"], "policy_conflict");
        assert!(rejected["saved_revision"].is_null());
        let (_, again) = invoke(state.clone(), &cookie, Method::POST, &path, create("1")).await;
        assert_eq!(again, rejected);
        let status = coordinator(&state).unwrap().status().await.unwrap();
        assert_eq!(status.saved_revision, 2);
        assert_eq!(status.user_count, 1);
    }

    #[tokio::test]
    async fn new_operation_routes_keep_session_csrf_and_strict_input_boundaries() {
        let (_directory, state, cookie) = managed_state();
        let anonymous = call(state.clone(), request(Method::GET, BASE, "null")).await;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        let mut no_csrf = request(Method::POST, BASE, &create("1").to_string());
        no_csrf
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(
            call(state.clone(), no_csrf).await.status(),
            StatusCode::FORBIDDEN
        );
        for input in [
            json!({"expected_revision":1,"expected_epoch":"1","change":{"action":"delete_user","id":"AAECAwQFBgcICQoLDA0ODw"}}),
            json!({"expected_revision":"1","expected_epoch":"1","change":{"action":"create_credential","user_id":"AAECAwQFBgcICQoLDA0ODw"}}),
            json!({"expected_revision":"1","expected_epoch":"1","change":{"action":"delete_user","id":"AAECAwQFBgcICQoLDA0ODw","secret":"never accepted"}}),
        ] {
            let (status, _) = invoke(state.clone(), &cookie, Method::POST, BASE, input).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        for node in [
            Value::Null,
            json!(false),
            json!(1),
            json!(""),
            json!("not-an-id"),
            json!("A".repeat(21)),
        ] {
            let mut input = create("1");
            input["expected_node_id"] = node;
            let (status, _) = invoke(state.clone(), &cookie, Method::POST, BASE, input).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        for query in [
            "limit=0",
            "limit=51",
            "before=01",
            "before=1&before=2",
            "limit=1&limit=2",
            "actor=other",
            "before=9223372036854775808",
        ] {
            let (status, _) = invoke(
                state.clone(),
                &cookie,
                Method::GET,
                &format!("{BASE}?{query}"),
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "accepted {query}");
        }
        assert_eq!(
            coordinator(&state)
                .unwrap()
                .status()
                .await
                .unwrap()
                .saved_revision,
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_the_coordinator_future_keeps_its_writer_until_the_sql_worker_finishes() {
        let (_directory, state, cookie) = managed_state();
        let service = coordinator(&state).unwrap();
        let (_, reserved) = invoke(state.clone(), &cookie, Method::POST, BASE, create("1")).await;
        let id = reserved["id"].as_str().unwrap().to_owned();
        let connection =
            rusqlite::Connection::open(state.directory.join("management.sqlite3")).unwrap();
        let actor: String = connection
            .query_row("SELECT id FROM administrators", [], |row| row.get(0))
            .unwrap();
        let input = serde_json::from_value::<Input>(create("1"))
            .unwrap()
            .into_store()
            .unwrap();
        connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut execution = Box::pin(service.execute_user_operation(
            Caller::Administrator(actor.clone()),
            id.clone(),
            input.clone(),
        ));
        // One poll acquires the writer and enqueues the blocking worker. The SQL
        // lock prevents that worker from committing before its future is dropped.
        assert!(futures_util::poll!(&mut execution).is_pending());
        drop(execution);
        assert_eq!(
            service
                .reserve_user_operation(Caller::Administrator(actor.clone()), input)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        connection.execute_batch("ROLLBACK").unwrap();
        let saved = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let actor = actor.clone();
                let id = id.clone();
                let operation = service
                    .read(move |directory| operations::get(directory, &actor, &id))
                    .await
                    .unwrap();
                if operation.state == OperationState::Saved {
                    break operation;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(saved.saved_revision, Some(2));
        assert_eq!(service.status().await.unwrap().user_count, 1);
    }

    #[tokio::test]
    async fn a_post_commit_receipt_error_leaves_saved_queryable_without_repairing_the_runtime_on_replay()
     {
        let (_directory, state, cookie) = managed_state();
        let service = coordinator(&state).unwrap();
        service.activate().await.unwrap();
        let input = create("1");
        let (_, reserved) = invoke(state.clone(), &cookie, Method::POST, BASE, input.clone()).await;
        let id = reserved["id"].as_str().unwrap();
        let path = format!("{BASE}/{id}");
        let execute = format!("{path}/execute");
        let connection =
            rusqlite::Connection::open(state.directory.join("management.sqlite3")).unwrap();
        connection.execute_batch("CREATE TRIGGER fail_applied_receipt BEFORE UPDATE OF applied_revision ON proxy_policy_state BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        let (status, _) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &execute,
            input.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(service.reader().revision().is_err());
        let (status, saved) = invoke(state.clone(), &cookie, Method::GET, &path, Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(saved["state"], "saved");
        assert_eq!(saved["saved_revision"], "2");
        connection
            .execute_batch("DROP TRIGGER fail_applied_receipt")
            .unwrap();
        let (status, replay) = invoke(state, &cookie, Method::POST, &execute, input).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replay, saved);
        assert!(service.reader().revision().is_err());
    }
}
