//! Version-six process-local listener control. No policy command sequence or
//! durable receipt is consumed; recovery reads the original runtime/request.

use super::*;
use crate::manage::{drain as model, proxy};

const VERSION: u8 = 6;
const RESOURCE: &str = "proxy_runtime";
const PREFIX: &str = "/node/v6/proxy/runtime";

/// An authenticated controller's administrator claim accompanies one exact
/// target/runtime request. It never authenticates a target-local administrator.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct RuntimeDrain {
    pub(in crate::manage) version: u8,
    pub(in crate::manage) resource: String,
    pub(in crate::manage) source_administrator_id: String,
    pub(in crate::manage) request: model::Request,
}

impl RuntimeDrain {
    fn validate(&self) -> io::Result<()> {
        if self.version != VERSION
            || self.resource != RESOURCE
            || !valid_id(&self.source_administrator_id)
        {
            return Err(invalid("invalid runtime drain command"));
        }
        self.request.numbers()?;
        Ok(())
    }
}

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/node/v6/proxy/runtime", get(status))
        .route("/node/v6/proxy/runtime/drain", post(start))
        .route(
            "/node/v6/proxy/runtime/drains/{runtime_id}/{request_id}",
            get(original),
        )
}

async fn status(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let value = coordinator(&state)?
        .remote_runtime_status(peer.authorization(), None)
        .await
        .map_err(storage_error)?;
    value.validate(&state.node_id).map_err(storage_error)?;
    respond_resource(VERSION, RESOURCE, &state.node_id, StatusCode::OK, value)
}

async fn original(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    path: Result<Path<(String, String)>, axum::extract::rejection::PathRejection>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let Path((runtime_id, request_id)) = path.map_err(|_| bad("invalid_request"))?;
    if !valid_id(&runtime_id) || !valid_id(&request_id) {
        return Err(bad("invalid_request"));
    }
    let value = coordinator(&state)?
        .remote_runtime_status(peer.authorization(), Some((runtime_id, request_id)))
        .await
        .map_err(storage_error)?;
    value.validate(&state.node_id).map_err(storage_error)?;
    respond_resource(VERSION, RESOURCE, &state.node_id, StatusCode::OK, value)
}

async fn start(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    request: axum::extract::Request,
) -> Result<Response, ApiError> {
    no_query(request.uri())?;
    let mut types = request.headers().get_all(header::CONTENT_TYPE).iter();
    if !types
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
        || types.next().is_some()
    {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "json_required",
        ));
    }
    let input: RuntimeDrain = api::json(request).await?;
    input.validate().map_err(|_| bad("invalid_request"))?;
    if input.request.expected_node_id != state.node_id {
        return Err(ApiError::new(StatusCode::CONFLICT, "target_mismatch"));
    }
    // The coordinator rechecks this peer's current owner/DER, asserted epoch,
    // paused revision and actual runtime before the process-local transition.
    let value = coordinator(&state)?
        .request_remote_drain(
            peer.authorization(),
            input.source_administrator_id,
            input.request,
        )
        .await
        .map_err(storage_error)?;
    value.validate(&state.node_id).map_err(storage_error)?;
    respond_resource(
        VERSION,
        RESOURCE,
        &state.node_id,
        StatusCode::ACCEPTED,
        value,
    )
}

pub(super) fn encode(operation: &Request) -> io::Result<(Method, String, Vec<u8>)> {
    match operation {
        Request::Runtime => Ok((Method::GET, PREFIX.into(), Vec::new())),
        Request::RuntimeDrainStatus {
            runtime_id,
            request_id,
        } => {
            if !valid_id(runtime_id) || !valid_id(request_id) {
                return Err(invalid("invalid original runtime request"));
            }
            Ok((
                Method::GET,
                format!("{PREFIX}/drains/{runtime_id}/{request_id}"),
                Vec::new(),
            ))
        }
        Request::RuntimeDrain(command) => {
            command.validate()?;
            let body = serde_json::to_vec(command)
                .map_err(|_| invalid("cannot encode runtime drain command"))?;
            if body.len() > 4096 {
                return Err(invalid("runtime drain command exceeds input limit"));
            }
            Ok((Method::POST, format!("{PREFIX}/drain"), body))
        }
        _ => Err(invalid("invalid runtime operation")),
    }
}

pub(super) fn decode(
    operation: &Request,
    bytes: &[u8],
    peer: &str,
    status: StatusCode,
) -> io::Result<Reply> {
    let expected_status = match operation {
        Request::RuntimeDrain(_) => StatusCode::ACCEPTED,
        Request::Runtime | Request::RuntimeDrainStatus { .. } => StatusCode::OK,
        _ => return Err(invalid("invalid runtime response operation")),
    };
    if status != expected_status {
        return Err(invalid("invalid runtime response status"));
    }
    let envelope: Envelope<model::Status> =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid runtime response"))?;
    if envelope.version != VERSION || envelope.resource != RESOURCE || envelope.node_id != peer {
        return Err(invalid("runtime response changed protocol or target"));
    }
    let value = envelope.data;
    value.validate(peer)?;
    match operation {
        Request::Runtime => {}
        Request::RuntimeDrain(command) => {
            command.validate()?;
            if command.request.expected_node_id != peer
                || value
                    .runtime
                    .as_ref()
                    .and_then(|runtime| runtime.request.as_ref())
                    != Some(&command.request)
            {
                return Err(invalid(
                    "runtime response differs from original drain intent",
                ));
            }
        }
        Request::RuntimeDrainStatus {
            runtime_id,
            request_id,
        } => {
            if !valid_id(runtime_id)
                || !valid_id(request_id)
                || value.runtime.as_ref().is_none_or(|runtime| {
                    runtime.runtime_id != *runtime_id
                        || runtime
                            .request
                            .as_ref()
                            .is_none_or(|request| request.request_id != *request_id)
                })
            {
                return Err(invalid("runtime response differs from original request"));
            }
        }
        _ => return Err(invalid("unsupported runtime response")),
    }
    Ok(Reply::Runtime(Box::new(value)))
}

fn storage_error(error: io::Error) -> ApiError {
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<model::Error>())
    {
        return ApiError::new(StatusCode::CONFLICT, error.code());
    }
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<proxy::Error>())
    {
        return ApiError::new(
            StatusCode::CONFLICT,
            match error {
                proxy::Error::RuntimeChanged => "proxy_runtime_changed",
                proxy::Error::AlreadyDraining => "proxy_already_draining",
                proxy::Error::Stopping => "proxy_runtime_stopping",
            },
        );
    }
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<store::admission::Error>())
    {
        return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error.code());
    }
    super::storage_error(error)
}

/// Only v6 interprets these fixed pre-transition refusals. An old protocol or a
/// different HTTP status must not acquire new diagnostic semantics implicitly.
pub(super) fn rejection_code(status: StatusCode, bytes: &[u8]) -> Option<&'static str> {
    if status != StatusCode::CONFLICT {
        return None;
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Detail {
        code: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ErrorBody {
        error: Detail,
    }
    let body: ErrorBody = serde_json::from_slice(bytes).ok()?;
    match body.error.code.as_str() {
        "proxy_runtime_changed" => Some("proxy_runtime_changed"),
        "proxy_already_draining" => Some("proxy_already_draining"),
        "proxy_runtime_stopping" => Some("proxy_runtime_stopping"),
        "proxy_runtime_unavailable" => Some("proxy_runtime_unavailable"),
        "proxy_admission_not_paused" => Some("proxy_admission_not_paused"),
        "proxy_policy_unavailable" => Some("proxy_policy_unavailable"),
        "proxy_restart_required" => Some("proxy_restart_required"),
        _ => None,
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn id(value: u8) -> String {
        URL_SAFE_NO_PAD.encode([value; 16])
    }

    fn command() -> RuntimeDrain {
        RuntimeDrain {
            version: VERSION,
            resource: RESOURCE.into(),
            source_administrator_id: id(2),
            request: model::Request {
                expected_node_id: id(1),
                expected_epoch: "2".into(),
                expected_revision: "10".into(),
                runtime_id: id(3),
                request_id: id(4),
            },
        }
    }

    fn status_body(phase: &str) -> Value {
        json!({
            "node_id":id(1), "ownership":{"controller_node_id":id(2),"epoch":"2","last_terminal_command":"3"},
            "saved_revision":"10", "saved_accepting":false,
            "runtime":{"runtime_id":id(3),"phase":phase,"request":command().request,"active_operations":"0"}
        })
    }

    fn wire(data: Value) -> Vec<u8> {
        serde_json::to_vec(
            &json!({"version":VERSION,"node_id":id(1),"resource":RESOURCE,"data":data}),
        )
        .unwrap()
    }

    #[test]
    fn v6_has_fixed_routes_and_a_separate_nonsequence_request_vocabulary() {
        let original = serde_json::to_value(command()).unwrap();
        for value in [
            serde_json::from_value::<Command>(original.clone()).is_err(),
            serde_json::from_value::<MaintenanceCommand>(original.clone()).is_err(),
            serde_json::from_value::<RoutingCommand>(original.clone()).is_err(),
            serde_json::from_value::<PresetCommand>(original.clone()).is_err(),
        ] {
            assert!(value);
        }
        for (pointer, replacement) in [
            ("/version", json!(5)),
            ("/resource", json!("proxy_policy")),
            ("/source_administrator_id", json!("unverified")),
            ("/request/expected_node_id", json!("../node")),
            ("/request/expected_epoch", json!("0")),
            ("/request/expected_revision", json!("9223372036854775808")),
            ("/request/runtime_id", json!("../runtime")),
            ("/request/request_id", json!("../request")),
        ] {
            let mut wrong = original.clone();
            *wrong.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                client::encode(&Request::RuntimeDrain(
                    serde_json::from_value(wrong).unwrap()
                ))
                .is_err(),
                "{pointer}"
            );
        }
        for field in [
            "command_id",
            "controller_epoch",
            "target_node_id",
            "mutation",
            "password",
        ] {
            let mut wrong = original.clone();
            wrong[field] = json!("forbidden");
            assert!(serde_json::from_value::<RuntimeDrain>(wrong).is_err());
        }
        let (method, path, bytes) = client::encode(&Request::RuntimeDrain(command())).unwrap();
        assert_eq!(method, Method::POST);
        assert_eq!(path, "/node/v6/proxy/runtime/drain");
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), original);
        let (method, path, body) = client::encode(&Request::Runtime).unwrap();
        assert_eq!(
            (method, path.as_str(), body.len()),
            (Method::GET, "/node/v6/proxy/runtime", 0)
        );
        let (method, path, body) = client::encode(&Request::RuntimeDrainStatus {
            runtime_id: id(3),
            request_id: id(4),
        })
        .unwrap();
        assert_eq!(method, Method::GET);
        assert_eq!(
            path,
            format!("/node/v6/proxy/runtime/drains/{}/{}", id(3), id(4))
        );
        assert!(body.is_empty());
        for (runtime_id, request_id) in [("../id".into(), id(4)), (id(3), "wrong".into())] {
            assert!(
                client::encode(&Request::RuntimeDrainStatus {
                    runtime_id,
                    request_id
                })
                .is_err()
            );
        }
    }

    #[test]
    fn runtime_replies_bind_the_full_post_intent_and_original_get_namespace() {
        let operation = Request::RuntimeDrain(command());
        let original = status_body("draining");
        for phase in ["draining", "drained", "interrupted", "failed"] {
            let bytes = wire(status_body(phase));
            assert!(matches!(
                client::decode(&operation, &bytes, &id(1), StatusCode::ACCEPTED),
                Ok(Reply::Runtime(_))
            ));
            assert!(
                client::decode(
                    &Request::RuntimeDrainStatus {
                        runtime_id: id(3),
                        request_id: id(4)
                    },
                    &bytes,
                    &id(1),
                    StatusCode::OK
                )
                .is_ok()
            );
        }
        for status in [StatusCode::OK, StatusCode::CREATED, StatusCode::NO_CONTENT] {
            assert!(client::decode(&operation, &wire(original.clone()), &id(1), status).is_err());
        }
        for (pointer, replacement) in [
            ("/node_id", json!(id(8))),
            ("/saved_revision", json!("09")),
            ("/ownership/controller_node_id", json!(id(1))),
            ("/runtime/runtime_id", json!(id(8))),
            ("/runtime/phase", json!("serving")),
            ("/runtime/request/expected_node_id", json!(id(8))),
            ("/runtime/request/expected_epoch", json!("1")),
            ("/runtime/request/expected_revision", json!("9")),
            ("/runtime/request/runtime_id", json!(id(8))),
            ("/runtime/request/request_id", json!(id(8))),
            ("/runtime/active_operations", json!("18446744073709551616")),
        ] {
            let mut wrong = original.clone();
            *wrong.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                client::decode(&operation, &wire(wrong), &id(1), StatusCode::ACCEPTED).is_err(),
                "{pointer}"
            );
        }
        let mut maximum = original.clone();
        maximum["runtime"]["active_operations"] = json!(u64::MAX.to_string());
        assert!(client::decode(&operation, &wire(maximum), &id(1), StatusCode::ACCEPTED).is_ok());
        let mut unknown = original.clone();
        unknown["runtime"] = Value::Null;
        assert!(
            client::decode(
                &Request::Runtime,
                &wire(unknown.clone()),
                &id(1),
                StatusCode::OK
            )
            .is_ok()
        );
        assert!(
            client::decode(
                &operation,
                &wire(unknown.clone()),
                &id(1),
                StatusCode::ACCEPTED
            )
            .is_err()
        );
        assert!(
            client::decode(
                &Request::RuntimeDrainStatus {
                    runtime_id: id(3),
                    request_id: id(4)
                },
                &wire(unknown),
                &id(1),
                StatusCode::OK
            )
            .is_err()
        );
        let bytes = wire(original.clone());
        for (runtime_id, request_id) in [(id(8), id(4)), (id(3), id(8))] {
            assert!(
                client::decode(
                    &Request::RuntimeDrainStatus {
                        runtime_id,
                        request_id
                    },
                    &bytes,
                    &id(1),
                    StatusCode::OK
                )
                .is_err()
            );
        }
        for field in ["request", "active_operations"] {
            let mut wrong = original.clone();
            wrong["runtime"].as_object_mut().unwrap().remove(field);
            assert!(
                client::decode(&Request::Runtime, &wire(wrong), &id(1), StatusCode::OK).is_err()
            );
        }
        for (field, value) in [
            ("version", json!(5)),
            ("resource", json!("proxy_policy")),
            ("node_id", json!(id(8))),
        ] {
            let mut wrong: Value = serde_json::from_slice(&bytes).unwrap();
            wrong[field] = value;
            assert!(
                client::decode(
                    &operation,
                    &serde_json::to_vec(&wrong).unwrap(),
                    &id(1),
                    StatusCode::ACCEPTED
                )
                .is_err()
            );
        }
        let mut wrong = original;
        wrong["runtime"]["runtime_stopped"] = json!(true);
        assert!(client::decode(&Request::Runtime, &wire(wrong), &id(1), StatusCode::OK).is_err());
    }

    #[test]
    fn new_refusals_are_v6_and_status_specific_without_old_protocol_fallback() {
        for code in [
            "proxy_runtime_changed",
            "proxy_already_draining",
            "proxy_runtime_stopping",
            "proxy_runtime_unavailable",
            "proxy_admission_not_paused",
            "proxy_policy_unavailable",
            "proxy_restart_required",
        ] {
            let body = serde_json::to_vec(&json!({"error":{"code":code}})).unwrap();
            for version in 1..=6 {
                for status in [
                    StatusCode::CONFLICT,
                    StatusCode::BAD_REQUEST,
                    StatusCode::FORBIDDEN,
                    StatusCode::SERVICE_UNAVAILABLE,
                ] {
                    let error = client::remote_error(status, &body, version);
                    let error = error
                        .get_ref()
                        .unwrap()
                        .downcast_ref::<RemoteError>()
                        .unwrap();
                    assert_eq!(
                        error.code,
                        if version == VERSION && status == StatusCode::CONFLICT {
                            code
                        } else {
                            "node_request_rejected"
                        }
                    );
                }
            }
        }
        for (body, expected) in [
            (
                json!({"error":{"code":"not_found"}}),
                "node_protocol_unsupported",
            ),
            (
                json!({"error":{"code":"resource_not_found"}}),
                "resource_not_found",
            ),
            (
                json!({"error":{"code":"proxy_runtime_changed","private":"not copied"}}),
                "node_request_rejected",
            ),
        ] {
            let error = client::remote_error(
                StatusCode::NOT_FOUND,
                &serde_json::to_vec(&body).unwrap(),
                VERSION,
            );
            assert_eq!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<RemoteError>()
                    .unwrap()
                    .code,
                expected
            );
            assert!(!error.to_string().contains("not copied"));
        }
    }

    #[test]
    fn actual_mtls_runtime_drain_keeps_node_online_and_rechecks_ownership() -> io::Result<()> {
        use std::{fs::OpenOptions, io::Write as _};

        use crate::manage::{
            controller::tests::tasks::OwnedTasks,
            node::{self, tests::Fixture},
            proxy,
        };

        fn administrator(path: &std::path::Path) -> io::Result<String> {
            rusqlite::Connection::open(path.join("management.sqlite3"))
                .map_err(io::Error::other)?
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)
        }

        let fixture = Fixture::new(true, true)?;
        let author = Arc::new(store::lock(&fixture.server_state)?);
        let server = policy::Coordinator::new(
            fixture.server_state.clone(),
            store::load_policy(&fixture.server_state)?,
            author.clone(),
        )?;
        let caller = policy::Coordinator::new(
            fixture.client_state.clone(),
            store::load_policy(&fixture.client_state)?,
            Arc::new(store::lock(&fixture.client_state)?),
        )?;
        let source = administrator(&fixture.client_state)?;
        let local = administrator(&fixture.server_state)?;
        let path = fixture.server_state.join("runtime-proxy.json");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        options.open(&path)?.write_all(
            br#"{"listeners":[{"protocol":"http","bind":"127.0.0.1:8080"}],"workers":1}"#,
        )?;
        let prepared = proxy::tests::ephemeral(proxy::load(&path)?);
        let control = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mut running = None;
        let result = control.block_on(async {
            running = Some(proxy::start(prepared, server.reader(), author)?);
            let forwarding = running.as_mut().unwrap();
            forwarding.ready().await?;
            let lifecycle = forwarding.lifecycle();
            server.configure_runtime(lifecycle.clone())?;
            server.activate().await?;
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let origin = format!("https://localhost:{}", address.port());
            let config = fixture.config(address)?;
            let shutdown = CancellationToken::new();
            let mut tasks = OwnedTasks::new();
            tasks.insert(
                "runtime_node",
                shutdown.clone(),
                tokio::spawn(node::serve(
                    listener,
                    config,
                    fixture.server_state.clone(),
                    shutdown,
                    Some(server.clone()),
                    None,
                    None,
                )),
            );
            let scenario = timeout(Duration::from_secs(30), async {
                let call = |operation| {
                    client::request(
                        &caller,
                        fixture.client_tls.clone(),
                        &origin,
                        &fixture.server_id,
                        operation,
                    )
                };
                assert_eq!(
                    call(Request::Runtime).await.err().unwrap().kind(),
                    io::ErrorKind::PermissionDenied
                );
                server
                    .set_owner(local.clone(), 1, Some(fixture.client_id.clone()))
                    .await?;
                let Reply::Runtime(status) = call(Request::Runtime).await? else {
                    return Err(invalid("expected runtime status"));
                };
                let actual = status.runtime.as_ref().unwrap();
                assert!(matches!(actual.phase, model::Phase::Serving));
                let request = model::Request {
                    expected_node_id: fixture.server_id.clone(),
                    expected_epoch: "2".into(),
                    expected_revision: "1".into(),
                    runtime_id: actual.runtime_id.clone(),
                    request_id: id(4),
                };
                let input = |request| RuntimeDrain {
                    version: VERSION,
                    resource: RESOURCE.into(),
                    source_administrator_id: source.clone(),
                    request,
                };
                let error = call(Request::RuntimeDrain(input(request.clone())))
                    .await
                    .err()
                    .unwrap();
                assert_eq!(
                    error
                        .get_ref()
                        .unwrap()
                        .downcast_ref::<RemoteError>()
                        .unwrap()
                        .code,
                    "proxy_admission_not_paused"
                );
                assert!(!forwarding.handle().is_graceful_shutdown_requested());
                call(Request::MaintenanceCommand(MaintenanceCommand {
                    version: 5,
                    target_node_id: fixture.server_id.clone(),
                    resource: "proxy_policy".into(),
                    controller_epoch: "2".into(),
                    command_id: "1".into(),
                    expected_policy_revision: "1".into(),
                    source_administrator_id: source.clone(),
                    mutation: MaintenanceMutation::SetAdmission { accepting: false },
                }))
                .await?;
                let request = model::Request {
                    expected_revision: "2".into(),
                    ..request
                };
                let Reply::Runtime(accepted) =
                    call(Request::RuntimeDrain(input(request.clone()))).await?
                else {
                    return Err(invalid("expected runtime acceptance"));
                };
                assert_eq!(
                    accepted.runtime.as_ref().unwrap().request.as_ref(),
                    Some(&request)
                );
                assert!(forwarding.handle().is_quiescing());
                let completion = forwarding.finished().await;
                assert!(lifecycle.complete(&completion)?);
                completion?;
                let exact = || Request::RuntimeDrainStatus {
                    runtime_id: request.runtime_id.clone(),
                    request_id: request.request_id.clone(),
                };
                let Reply::Runtime(observed) = call(exact()).await? else {
                    return Err(invalid("expected original runtime status"));
                };
                assert!(matches!(
                    observed.runtime.as_ref().unwrap().phase,
                    model::Phase::Drained
                ));
                assert_eq!(observed.saved_revision, "2");
                assert_eq!(observed.ownership.last_terminal_command, "1");
                let error = call(Request::RuntimeDrainStatus {
                    runtime_id: request.runtime_id.clone(),
                    request_id: id(8),
                })
                .await
                .err()
                .unwrap();
                assert_eq!(
                    error
                        .get_ref()
                        .unwrap()
                        .downcast_ref::<RemoteError>()
                        .unwrap()
                        .code,
                    "resource_not_found"
                );
                server.set_owner(local, 2, None).await?;
                assert_eq!(
                    call(exact()).await.err().unwrap().kind(),
                    io::ErrorKind::PermissionDenied
                );
                Ok(())
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "runtime node scenario timed out"))
            .and_then(|result| result);
            tasks.finish(scenario).await
        });
        // Real forwarding runtime destruction belongs outside every async executor.
        let cleanup = running.map(|running| running.finish());
        control.shutdown_timeout(Duration::from_secs(5));
        let cleanup = cleanup.map_or(Ok(()), |cleanup| {
            assert!(cleanup.runtime_stopped);
            cleanup.result
        });
        result.and(cleanup)
    }
}
