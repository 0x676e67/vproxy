//! Explicit Session/CSRF-only maintenance. Automation user permissions do not
//! authorize node-wide admission changes, and no endpoint waits for a drain.

use super::*;
use crate::manage::{policy::Coordinator, store};

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/proxy/maintenance", get(status).post(change))
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

fn coordinator(state: &AppState) -> Result<Arc<Coordinator>, ApiError> {
    state.policy.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    })
}

fn no_query(uri: &Uri) -> Result<(), ApiError> {
    if uri.query().is_some() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_query"));
    }
    Ok(())
}

fn storage_error(error: io::Error) -> ApiError {
    super::runtime::storage_error(error)
}

async fn status(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let value = coordinator(&state)?
        .maintenance(None)
        .await
        .map_err(storage_error)?;
    value.validate(&state.node.node_id).map_err(storage_error)?;
    Ok(Json(value).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    expected_node_id: String,
    expected_revision: String,
    expected_epoch: String,
    accepting: bool,
}

/// Publication receipt for this mutation, not a new count observation. Runtime
/// data must be requested explicitly after the user receives this answer.
#[derive(Serialize)]
struct Change {
    saved_revision: String,
    applied_revision: Option<String>,
    running: bool,
}

async fn change(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(administrator)): Extension<users::Administrator>,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(request.uri())?;
    let input: Input = json(request).await?;
    if input.expected_node_id != state.node.node_id {
        return Err(ApiError::new(StatusCode::CONFLICT, "target_mismatch"));
    }
    let result = coordinator(&state)?
        .change_admission(
            administrator,
            users::revision(&input.expected_revision)?,
            store::admission::Assertion {
                node_id: input.expected_node_id,
                epoch: users::revision(&input.expected_epoch)?,
            },
            input.accepting,
        )
        .await
        .map_err(storage_error)?;
    Ok(Json(Change {
        saved_revision: result.revision.to_string(),
        applied_revision: result.running.then(|| result.revision.to_string()),
        running: result.running,
    })
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        access::{Error as AccessError, Protocol},
        manage::{
            api::tests::{TestDirectory, call, managed_state, request},
            store::automation::Scope,
        },
    };
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};

    const PATH: &str = "/api/v1/proxy/maintenance";

    fn fixture() -> (TestDirectory, Arc<AppState>, String) {
        let (directory, mut state, cookie) = managed_state();
        let node_id = store::inspect(&state.directory).unwrap().node_id;
        Arc::get_mut(&mut state).unwrap().node.node_id = node_id;
        (directory, state, cookie)
    }

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
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn input(state: &AppState, revision: &str, accepting: bool) -> Value {
        json!({"expected_node_id":state.node.node_id,"expected_revision":revision,"expected_epoch":"1","accepting":accepting})
    }

    #[tokio::test]
    async fn saved_gate_and_current_operation_observation_are_separate_from_transport_drain() {
        let (_directory, state, cookie) = fixture();
        let policy = coordinator(&state).unwrap();
        let (status, before) = invoke(state.clone(), &cookie, Method::GET, PATH, Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(before["saved_accepting"], true);
        assert_eq!(before["running"], false);
        for field in ["applied_revision", "runtime_accepting", "active_operations"] {
            assert!(before[field].is_null());
        }
        let (_, user) = invoke(state.clone(), &cookie, Method::POST, "/api/v1/proxy/users",
        json!({"expected_revision":"1","name":"Maintenance","protocols":["http"],"concurrent_limit":2})).await;
        let user = user["user"]["id"].as_str().unwrap();
        let (_, credential) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("/api/v1/proxy/users/{user}/credentials"),
            json!({"expected_revision":"2"}),
        )
        .await;
        let login = credential["credential"]["login"].as_str().unwrap();
        let secret = credential["secret"].as_str().unwrap();
        let flow = policy
            .reader()
            .authenticate(login, secret.as_bytes(), Protocol::Http)
            .unwrap();

        let (status, saved) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            PATH,
            input(&state, "3", false),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            saved,
            json!({"saved_revision":"4","applied_revision":null,"running":false})
        );
        assert_eq!(
            policy
                .reader()
                .authenticate(login, secret.as_bytes(), Protocol::Http)
                .err(),
            Some(AccessError::Unavailable)
        );
        // A real Reader publication is exercised here; this fixture's runner flag
        // is not evidence of a bound network listener or protocol-level flush.
        policy.activate().await.unwrap();
        let (_, observed) = invoke(state.clone(), &cookie, Method::GET, PATH, Value::Null).await;
        assert_eq!(observed["saved_accepting"], false);
        assert_eq!(observed["runtime_accepting"], false);
        assert_eq!(observed["applied_revision"], "4");
        assert_eq!(observed["active_operations"], "1");
        drop(flow);
        let (_, observed) = invoke(state.clone(), &cookie, Method::GET, PATH, Value::Null).await;
        assert_eq!(observed["active_operations"], "0");
        assert!(observed.get("drained").is_none());
        assert!(!observed.to_string().contains(secret));

        let (status, resumed) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            PATH,
            input(&state, "4", true),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            resumed,
            json!({"saved_revision":"5","applied_revision":"5","running":true})
        );
        assert!(
            policy
                .reader()
                .authenticate(login, secret.as_bytes(), Protocol::Http)
                .is_ok()
        );
        policy.reader().fail_closed();
        let (_, unknown) = invoke(state.clone(), &cookie, Method::GET, PATH, Value::Null).await;
        assert_eq!(unknown["saved_accepting"], true);
        assert_eq!(unknown["running"], true);
        assert!(unknown["runtime_accepting"].is_null());
        assert!(unknown["active_operations"].is_null());
        assert!(unknown["applied_revision"].is_null());
        policy.deactivate();
        let (_, stopped) = invoke(state, &cookie, Method::GET, PATH, Value::Null).await;
        assert_eq!(stopped["running"], false);
        assert_eq!(stopped["durable_applied_revision"], "5");
        assert!(stopped["active_operations"].is_null());
    }

    #[tokio::test]
    async fn session_csrf_identity_epoch_and_policy_cas_fail_before_any_gate_change() {
        let (_directory, state, cookie) = fixture();
        assert_eq!(
            call(state.clone(), request(Method::GET, PATH, ""))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut no_csrf = request(Method::POST, PATH, &input(&state, "1", false).to_string());
        no_csrf
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(
            call(state.clone(), no_csrf).await.status(),
            StatusCode::FORBIDDEN
        );
        for (field, value, expected) in [
            (
                "expected_node_id",
                Value::String(URL_SAFE_NO_PAD.encode([7; 16])),
                "target_mismatch",
            ),
            (
                "expected_epoch",
                Value::String("2".into()),
                "controller_epoch_changed",
            ),
            (
                "expected_revision",
                Value::String("2".into()),
                "policy_conflict",
            ),
        ] {
            let mut body = input(&state, "1", false);
            body[field] = value;
            let (status, rejected) = invoke(state.clone(), &cookie, Method::POST, PATH, body).await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(rejected["error"]["code"], expected);
        }
        for suffix in ["?", "?retry=1"] {
            assert_eq!(
                invoke(
                    state.clone(),
                    &cookie,
                    Method::GET,
                    &format!("{PATH}{suffix}"),
                    Value::Null
                )
                .await
                .0,
                StatusCode::BAD_REQUEST
            );
        }
        let mut malformed = input(&state, "1", false);
        malformed["accepting"] = Value::String("false".into());
        assert_eq!(
            invoke(state.clone(), &cookie, Method::POST, PATH, malformed)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let mut extra = input(&state, "1", false);
        extra["force"] = Value::Bool(true);
        assert_eq!(
            invoke(state.clone(), &cookie, Method::POST, PATH, extra)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let mut head = request(Method::HEAD, PATH, "");
        head.headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        let head = call(state.clone(), head).await;
        assert_eq!(head.status(), StatusCode::OK);
        assert!(
            head.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        let saved = store::admission::snapshot(&state.directory).unwrap();
        assert!(saved.accepting);
        assert_eq!(saved.saved_revision, 1);
    }

    #[tokio::test]
    async fn remote_maintenance_refuses_unbound_receipt_reads_before_contact() {
        let (_directory, state, cookie) = fixture();
        let peer = URL_SAFE_NO_PAD.encode([6; 16]);
        let path = format!("/api/v1/targets/{peer}/maintenance/commands/refresh");
        for body in [
            json!({}),
            json!({"job_id":""}),
            json!({"job_id":7}),
            json!({"job_id":peer,"accepting":false}),
        ] {
            assert_eq!(
                invoke(state.clone(), &cookie, Method::POST, &path, body)
                    .await
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        for suffix in ["?", "?job_id=other"] {
            assert_eq!(
                invoke(
                    state.clone(),
                    &cookie,
                    Method::POST,
                    &format!("{path}{suffix}"),
                    json!({"job_id":peer})
                )
                .await
                .0,
                StatusCode::BAD_REQUEST
            );
        }
        let mut no_csrf = request(Method::POST, &path, &json!({"job_id":peer}).to_string());
        no_csrf
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(
            call(state.clone(), no_csrf).await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            store::admission::snapshot(&state.directory)
                .unwrap()
                .saved_revision,
            1
        );
    }

    #[tokio::test]
    async fn an_issued_user_write_key_cannot_read_or_change_maintenance_even_with_a_session() {
        let (_directory, state, cookie) = fixture();
        let mut token = Zeroizing::new(String::new());
        store::automation::create(
            &state.directory,
            "Maintenance denial",
            Scope::UsersWrite,
            3600,
            |value| {
                token.push_str(value);
                Ok(())
            },
        )
        .unwrap();
        for method in [Method::GET, Method::POST] {
            let mut request = request(method, PATH, &input(&state, "1", false).to_string());
            request.headers_mut().insert(
                header::AUTHORIZATION,
                format!("Bearer {}", token.as_str()).parse().unwrap(),
            );
            request
                .headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            request
                .headers_mut()
                .insert("x-csrf-token", "c".repeat(43).parse().unwrap());
            let response = call(state.clone(), request).await;
            assert!(!response.status().is_success());
        }
        assert!(
            store::admission::snapshot(&state.directory)
                .unwrap()
                .accepting
        );
    }
}
