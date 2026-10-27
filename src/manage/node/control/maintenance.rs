//! Version-five admission mode and managed operation observations. These reads
//! and commands retain the policy owner's exact mTLS authorization and shared
//! command sequence; neither active-operation zero nor a saved receipt means
//! that protocol drivers or transport buffers have drained.

use super::*;
use crate::manage::maintenance as model;

const VERSION: u8 = 5;
const PREFIX: &str = "/node/v5/proxy";

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::manage) enum MaintenanceMutation {
    SetAdmission { accepting: bool },
}

impl From<MaintenanceMutation> for store::PolicyChange {
    fn from(value: MaintenanceMutation) -> Self {
        match value {
            MaintenanceMutation::SetAdmission { accepting } => Self::SetAdmission { accepting },
        }
    }
}

impl TryFrom<store::PolicyChange> for MaintenanceMutation {
    type Error = io::Error;

    fn try_from(value: store::PolicyChange) -> io::Result<Self> {
        match value {
            store::PolicyChange::SetAdmission { accepting } => Ok(Self::SetAdmission { accepting }),
            _ => Err(invalid("version-five admission action required")),
        }
    }
}

/// Fixed policy-domain command. Epoch, sequence and full-policy CAS are the
/// same durable namespace used by v1-v3; this is not a second runtime switch.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct MaintenanceCommand {
    pub(in crate::manage) version: u8,
    pub(in crate::manage) target_node_id: String,
    pub(in crate::manage) resource: String,
    pub(in crate::manage) controller_epoch: String,
    pub(in crate::manage) command_id: String,
    pub(in crate::manage) expected_policy_revision: String,
    pub(in crate::manage) source_administrator_id: String,
    pub(in crate::manage) mutation: MaintenanceMutation,
}

impl MaintenanceCommand {
    fn into_store(self) -> Result<store::Command, ApiError> {
        if self.version != VERSION
            || self.resource != RESOURCE
            || !valid_id(&self.target_node_id)
            || !valid_id(&self.source_administrator_id)
        {
            return Err(bad("invalid_command"));
        }
        Ok(store::Command {
            target_node_id: self.target_node_id,
            epoch: decimal(&self.controller_epoch, false)?,
            command_id: decimal(&self.command_id, false)?,
            expected_policy_revision: decimal(&self.expected_policy_revision, false)?,
            source_administrator_id: self.source_administrator_id,
            change: self.mutation.into(),
        })
    }
}

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/node/v5/proxy/maintenance", get(status))
        .route("/node/v5/proxy/commands", post(command))
        .route("/node/v5/proxy/receipts/{epoch}/{command_id}", get(receipt))
}

async fn status(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let status = coordinator(&state)?
        .maintenance(Some(peer.authorization()))
        .await
        .map_err(storage_error)?;
    status.validate(&state.node_id).map_err(storage_error)?;
    respond_version(VERSION, &state.node_id, StatusCode::OK, status)
}

async fn receipt(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    path: Result<Path<(String, String)>, axum::extract::rejection::PathRejection>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let Path((epoch, id)) = path.map_err(|_| bad("invalid_command"))?;
    let (epoch, id) = (decimal(&epoch, false)?, decimal(&id, false)?);
    let authorization = peer.authorization();
    let value = coordinator(&state)?
        .read(move |directory| store::receipt(directory, &authorization, epoch, id))
        .await
        .map_err(storage_error)?;
    if value.version != VERSION {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "resource_not_found"));
    }
    respond_version(
        VERSION,
        &state.node_id,
        StatusCode::OK,
        Receipt::from(value),
    )
}

async fn command(
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
    let input: MaintenanceCommand = api::json(request).await?;
    let result = coordinator(&state)?
        .command(peer.authorization(), input.into_store()?)
        .await
        .map_err(storage_error)?;
    let saved = result.receipt.status == store::ReceiptStatus::Saved;
    let location = format!(
        "{PREFIX}/receipts/{}/{}",
        result.receipt.epoch, result.receipt.command_id
    );
    let data = CommandReply {
        receipt: result.receipt.into(),
        replayed: result.replayed,
        user: None,
        credential: None,
        secret: None,
        secret_available: false,
        routing: None,
        presets: None,
    };
    let mut response = respond_version(
        VERSION,
        &state.node_id,
        if saved {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        },
        data,
    )?;
    if saved {
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&location).map_err(|_| ApiError::internal())?,
        );
    }
    Ok(response)
}

pub(super) fn encode(operation: &Request) -> io::Result<(Method, String, Vec<u8>)> {
    match operation {
        Request::Maintenance => Ok((Method::GET, format!("{PREFIX}/maintenance"), Vec::new())),
        Request::MaintenanceCommand(command) => {
            command
                .clone()
                .into_store()
                .map_err(|_| invalid("invalid maintenance command"))?;
            let body = serde_json::to_vec(command)
                .map_err(|_| invalid("cannot encode maintenance command"))?;
            if body.len() > 4096 {
                return Err(invalid("maintenance command exceeds input limit"));
            }
            Ok((Method::POST, format!("{PREFIX}/commands"), body))
        }
        _ => Err(invalid("invalid maintenance operation")),
    }
}

pub(super) fn decode(
    operation: &Request,
    bytes: &[u8],
    peer: &str,
    status: StatusCode,
) -> io::Result<Reply> {
    match operation {
        Request::Maintenance => {
            if status != StatusCode::OK {
                return Err(invalid("invalid maintenance status response"));
            }
            let value: model::Status = client::envelope(bytes, peer, VERSION)?;
            value.validate(peer)?;
            Ok(Reply::Maintenance(Box::new(value)))
        }
        Request::MaintenanceCommand(command) => {
            let mut value: CommandReply = client::envelope(bytes, peer, VERSION)?;
            value.receipt.version = VERSION;
            client::validate_receipt(&value.receipt)?;
            if value.receipt.controller_epoch != command.controller_epoch
                || value.receipt.command_id != command.command_id
                || status
                    != if value.receipt.status == ReceiptStatus::Saved {
                        StatusCode::ACCEPTED
                    } else {
                        StatusCode::OK
                    }
                || value.user.is_some()
                || value.credential.is_some()
                || value.secret.is_some()
                || value.secret_available
                || value.routing.is_some()
                || value.presets.is_some()
            {
                return Err(invalid("invalid maintenance command result"));
            }
            if value.receipt.status != ReceiptStatus::Rejected {
                let revision = client::number(&command.expected_policy_revision, false)?
                    .checked_add(1)
                    .filter(|value| *value <= i64::MAX as u64)
                    .ok_or_else(|| invalid("maintenance policy revision exhausted"))?;
                if value
                    .receipt
                    .policy_revision
                    .as_deref()
                    .map(|value| client::number(value, false))
                    .transpose()?
                    != Some(revision)
                {
                    return Err(invalid("maintenance receipt differs from policy CAS"));
                }
            }
            Ok(Reply::Command(Box::new(value)))
        }
        _ => Err(invalid("unsupported maintenance response")),
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn storage_error(error: io::Error) -> ApiError {
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<store::admission::Error>())
    {
        return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error.code());
    }
    super::storage_error(error)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn id(value: u8) -> String {
        URL_SAFE_NO_PAD.encode([value; 16])
    }

    fn command() -> MaintenanceCommand {
        MaintenanceCommand {
            version: VERSION,
            target_node_id: id(1),
            resource: RESOURCE.into(),
            controller_epoch: "2".into(),
            command_id: "3".into(),
            expected_policy_revision: "10".into(),
            source_administrator_id: id(2),
            mutation: MaintenanceMutation::SetAdmission { accepting: false },
        }
    }

    fn wire(version: u8, data: Value) -> Vec<u8> {
        serde_json::to_vec(
            &json!({"version":version,"node_id":id(1),"resource":RESOURCE,"data":data}),
        )
        .unwrap()
    }

    fn status_body() -> Value {
        json!({
            "node_id":id(1),"ownership":{"controller_node_id":id(2),"epoch":"2","last_terminal_command":"3"},
            "saved_revision":"10","durable_applied_revision":"9","running":true,"saved_accepting":false,
            "applied_revision":"10","runtime_accepting":false,"active_operations":"0"
        })
    }

    fn reply_body() -> Value {
        json!({
            "receipt":{"controller_epoch":"2","command_id":"3","status":"applied","policy_revision":"11",
                       "rejection":null,"user_id":null,"credential_id":null},
            "replayed":false,"user":null,"credential":null,"secret":null,"secret_available":false
        })
    }

    #[test]
    fn v5_is_a_fixed_policy_command_not_an_old_action_or_arbitrary_endpoint() {
        let value = serde_json::to_value(command()).unwrap();
        assert!(serde_json::from_value::<Command>(value.clone()).is_err());
        assert!(serde_json::from_value::<RoutingCommand>(value.clone()).is_err());
        assert!(serde_json::from_value::<PresetCommand>(value.clone()).is_err());
        let stored = command().into_store().unwrap();
        assert_eq!(stored.change.control_version(), VERSION);
        assert!(matches!(
            stored.change,
            store::PolicyChange::SetAdmission { accepting: false }
        ));
        for (field, replacement) in [
            ("version", json!(1)),
            ("target_node_id", json!("../peer")),
            ("resource", json!("proxy_admission")),
            ("controller_epoch", json!("01")),
            ("command_id", json!("0")),
            ("expected_policy_revision", json!("9223372036854775808")),
            ("source_administrator_id", json!("unknown")),
        ] {
            let mut wrong = value.clone();
            wrong[field] = replacement;
            assert!(
                serde_json::from_value::<MaintenanceCommand>(wrong)
                    .unwrap()
                    .into_store()
                    .is_err()
            );
        }
        for mutation in [
            json!({"action":"set_admission","accepting":"false"}),
            json!({"action":"set_admission","accepting":false,"force":true}),
            json!({"action":"create_user","name":"not v5","protocols":["http"],"concurrent_limit":1}),
        ] {
            assert!(serde_json::from_value::<MaintenanceMutation>(mutation).is_err());
        }
        let (method, path, body) = client::encode(&Request::Maintenance).unwrap();
        assert_eq!(method, Method::GET);
        assert_eq!(path, "/node/v5/proxy/maintenance");
        assert!(body.is_empty());
        let (method, path, bytes) =
            client::encode(&Request::MaintenanceCommand(command())).unwrap();
        assert_eq!(method, Method::POST);
        assert_eq!(path, "/node/v5/proxy/commands");
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), value);
        assert_eq!(
            client::encode(&Request::Receipt {
                version: 5,
                controller_epoch: 2,
                command_id: 3
            })
            .unwrap()
            .1,
            "/node/v5/proxy/receipts/2/3"
        );
        let error = client::remote_error(
            StatusCode::NOT_FOUND,
            br#"{"error":{"code":"not_found"}}"#,
            VERSION,
        );
        assert_eq!(
            error
                .get_ref()
                .unwrap()
                .downcast_ref::<RemoteError>()
                .unwrap()
                .code,
            "node_protocol_unsupported"
        );
        assert_eq!(
            storage_error(io::Error::new(
                io::ErrorKind::Unsupported,
                store::admission::Error::UpgradeRequired
            ))
            .into_response()
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn status_requires_exact_node_decimals_and_joint_runtime_facts_without_a_drained_claim() {
        let original = status_body();
        assert!(matches!(
            decode(
                &Request::Maintenance,
                &wire(VERSION, original.clone()),
                &id(1),
                StatusCode::OK
            ),
            Ok(Reply::Maintenance(_))
        ));
        let mut maximum = original.clone();
        maximum["active_operations"] = json!(u64::MAX.to_string());
        assert!(
            decode(
                &Request::Maintenance,
                &wire(VERSION, maximum),
                &id(1),
                StatusCode::OK
            )
            .is_ok()
        );
        let mut unknown = original.clone();
        for field in ["applied_revision", "runtime_accepting", "active_operations"] {
            unknown[field] = Value::Null;
        }
        // Running does not turn unavailable runtime facts into an invented zero.
        assert!(
            decode(
                &Request::Maintenance,
                &wire(VERSION, unknown.clone()),
                &id(1),
                StatusCode::OK
            )
            .is_ok()
        );
        unknown["running"] = json!(false);
        assert!(
            decode(
                &Request::Maintenance,
                &wire(VERSION, unknown.clone()),
                &id(1),
                StatusCode::OK
            )
            .is_ok()
        );
        for (pointer, replacement) in [
            ("/node_id", json!(id(3))),
            ("/ownership/controller_node_id", json!(id(1))),
            ("/ownership/epoch", json!("0")),
            ("/ownership/last_terminal_command", json!("01")),
            ("/saved_revision", json!("9223372036854775808")),
            ("/durable_applied_revision", json!("11")),
            ("/running", json!(false)),
            ("/applied_revision", json!("9")),
            ("/runtime_accepting", json!(true)),
            ("/active_operations", json!("01")),
            ("/active_operations", json!("18446744073709551616")),
            ("/active_operations", Value::Null),
        ] {
            let mut wrong = original.clone();
            *wrong.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                decode(
                    &Request::Maintenance,
                    &wire(VERSION, wrong),
                    &id(1),
                    StatusCode::OK
                )
                .is_err(),
                "{pointer}"
            );
        }
        for field in [
            "applied_revision",
            "runtime_accepting",
            "active_operations",
            "durable_applied_revision",
        ] {
            let mut wrong = unknown.clone();
            wrong.as_object_mut().unwrap().remove(field);
            assert!(
                decode(
                    &Request::Maintenance,
                    &wire(VERSION, wrong),
                    &id(1),
                    StatusCode::OK
                )
                .is_err()
            );
        }
        let mut wrong = unknown;
        wrong["ownership"]
            .as_object_mut()
            .unwrap()
            .remove("controller_node_id");
        assert!(
            decode(
                &Request::Maintenance,
                &wire(VERSION, wrong),
                &id(1),
                StatusCode::OK
            )
            .is_err()
        );
        let mut wrong = original.clone();
        wrong["drained"] = json!(true);
        assert!(
            decode(
                &Request::Maintenance,
                &wire(VERSION, wrong),
                &id(1),
                StatusCode::OK
            )
            .is_err()
        );
        for version in 1..=4 {
            assert!(
                decode(
                    &Request::Maintenance,
                    &wire(version, original.clone()),
                    &id(1),
                    StatusCode::OK
                )
                .is_err()
            );
        }
    }

    #[test]
    fn command_replies_correlate_status_sequence_cas_and_never_carry_secret_entities() {
        let operation = Request::MaintenanceCommand(command());
        let original = reply_body();
        assert!(matches!(
            decode(
                &operation,
                &wire(VERSION, original.clone()),
                &id(1),
                StatusCode::OK
            ),
            Ok(Reply::Command(_))
        ));
        let mut saved = original.clone();
        saved["receipt"]["status"] = json!("saved");
        assert!(
            decode(
                &operation,
                &wire(VERSION, saved.clone()),
                &id(1),
                StatusCode::ACCEPTED
            )
            .is_ok()
        );
        assert!(decode(&operation, &wire(VERSION, saved), &id(1), StatusCode::OK).is_err());
        for status in [StatusCode::ACCEPTED, StatusCode::CREATED] {
            assert!(decode(&operation, &wire(VERSION, original.clone()), &id(1), status).is_err());
        }
        for (pointer, replacement) in [
            ("/receipt/controller_epoch", json!("3")),
            ("/receipt/command_id", json!("4")),
            ("/receipt/policy_revision", json!("10")),
            ("/receipt/user_id", json!(id(3))),
            ("/receipt/credential_id", json!(id(3))),
            ("/user", json!({})),
            ("/credential", json!({})),
            ("/secret", json!("must not be returned")),
            ("/secret_available", json!(true)),
        ] {
            let mut wrong = original.clone();
            *wrong.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                decode(&operation, &wire(VERSION, wrong), &id(1), StatusCode::OK).is_err(),
                "{pointer}"
            );
        }
        for field in ["routing", "presets"] {
            let mut wrong = original.clone();
            wrong[field] = json!({});
            assert!(decode(&operation, &wire(VERSION, wrong), &id(1), StatusCode::OK).is_err());
        }
        let mut replayed = original.clone();
        replayed["replayed"] = json!(true);
        assert!(decode(&operation, &wire(VERSION, replayed), &id(1), StatusCode::OK).is_ok());
        let mut rejected = original.clone();
        rejected["receipt"]["status"] = json!("rejected");
        rejected["receipt"]["policy_revision"] = Value::Null;
        rejected["receipt"]["rejection"] = json!("policy_conflict");
        assert!(decode(&operation, &wire(VERSION, rejected), &id(1), StatusCode::OK).is_ok());
        let receipt = original["receipt"].clone();
        assert!(matches!(
            client::decode(
                &Request::Receipt {
                    version: 5,
                    controller_epoch: 2,
                    command_id: 3
                },
                &wire(VERSION, receipt.clone()),
                &id(1),
                StatusCode::OK
            ),
            Ok(Reply::Receipt(_))
        ));
        for version in 1..=3 {
            assert!(
                client::decode(
                    &Request::Receipt {
                        version,
                        controller_epoch: 2,
                        command_id: 3
                    },
                    &wire(VERSION, receipt.clone()),
                    &id(1),
                    StatusCode::OK
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn actual_mtls_pause_replay_and_resume_share_policy_ownership_and_receipt_sequence()
    -> io::Result<()> {
        use crate::{
            access,
            manage::{
                controller::tests::tasks::OwnedTasks,
                node::{self, tests::Fixture},
            },
        };

        fn coordinator(path: &std::path::Path) -> io::Result<Arc<policy::Coordinator>> {
            policy::Coordinator::new(
                path.to_owned(),
                store::load_policy(path)?,
                Arc::new(store::lock(path)?),
            )
        }
        fn administrator(path: &std::path::Path) -> io::Result<String> {
            rusqlite::Connection::open(path.join("management.sqlite3"))
                .map_err(io::Error::other)?
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)
        }

        let fixture = Fixture::new(true, true)?;
        let server = coordinator(&fixture.server_state)?;
        let caller = coordinator(&fixture.client_state)?;
        let source = administrator(&fixture.client_state)?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let origin = format!("https://localhost:{}", address.port());
        let shutdown = CancellationToken::new();
        let mut tasks = OwnedTasks::new();
        tasks.insert(
            "maintenance_node",
            shutdown.clone(),
            tokio::spawn(node::serve(
                listener,
                fixture.config(address)?,
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
                call(Request::Maintenance).await.err().unwrap().kind(),
                io::ErrorKind::PermissionDenied
            );
            server
                .set_owner(
                    administrator(&fixture.server_state)?,
                    1,
                    Some(fixture.client_id.clone()),
                )
                .await?;
            let v1 = |sequence: u64, revision: u64, mutation| Command {
                version: 1,
                target_node_id: fixture.server_id.clone(),
                resource: RESOURCE.into(),
                controller_epoch: "2".into(),
                command_id: sequence.to_string(),
                expected_policy_revision: revision.to_string(),
                source_administrator_id: source.clone(),
                mutation,
            };
            let Reply::Command(mut created) = call(Request::Command(v1(
                1,
                1,
                Mutation::CreateUser {
                    name: "maintenance user".into(),
                    protocols: vec![access::Protocol::Http],
                    concurrent_limit: 2,
                },
            )))
            .await?
            else {
                return Err(invalid("expected user result"));
            };
            let user = created.user.take().unwrap().id;
            let Reply::Command(mut created) = call(Request::Command(v1(
                2,
                2,
                Mutation::CreateCredential { user_id: user },
            )))
            .await?
            else {
                return Err(invalid("expected credential result"));
            };
            let credential = created.credential.take().unwrap();
            let secret = created.secret.take().unwrap();
            let admitted = server
                .reader()
                .authenticate(&credential.login, secret.as_bytes(), access::Protocol::Http)
                .unwrap();
            let issue = MaintenanceCommand {
                version: VERSION,
                target_node_id: fixture.server_id.clone(),
                resource: RESOURCE.into(),
                controller_epoch: "2".into(),
                command_id: "3".into(),
                expected_policy_revision: "3".into(),
                source_administrator_id: source.clone(),
                mutation: MaintenanceMutation::SetAdmission { accepting: false },
            };
            let Reply::Command(changed) = call(Request::MaintenanceCommand(issue.clone())).await?
            else {
                return Err(invalid("expected maintenance result"));
            };
            assert!(changed.receipt.status == ReceiptStatus::Saved);
            assert_eq!(changed.receipt.version, VERSION);
            assert!(
                changed.user.is_none()
                    && changed.credential.is_none()
                    && changed.secret.is_none()
                    && changed.routing.is_none()
                    && changed.presets.is_none()
            );
            assert!(matches!(
                server.reader().authenticate(
                    &credential.login,
                    secret.as_bytes(),
                    access::Protocol::Http
                ),
                Err(access::Error::Unavailable)
            ));
            assert_eq!(server.reader().admission()?.active_operations, 1);
            let Reply::Command(replayed) = call(Request::MaintenanceCommand(issue)).await? else {
                return Err(invalid("expected replayed result"));
            };
            assert!(replayed.replayed && replayed.receipt.status == ReceiptStatus::Saved);
            assert_eq!(server.reader().revision()?, 4);
            for version in 1..=3 {
                let error = call(Request::Receipt {
                    version,
                    controller_epoch: 2,
                    command_id: 3,
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
            }
            let Reply::Receipt(receipt) = call(Request::Receipt {
                version: 5,
                controller_epoch: 2,
                command_id: 3,
            })
            .await?
            else {
                return Err(invalid("expected v5 receipt"));
            };
            assert_eq!(receipt.version, VERSION);
            assert_eq!(receipt.policy_revision.as_deref(), Some("4"));
            let Reply::Maintenance(status) = call(Request::Maintenance).await? else {
                return Err(invalid("expected maintenance status"));
            };
            assert!(!status.saved_accepting && !status.running);
            assert!(
                status.applied_revision.is_none()
                    && status.runtime_accepting.is_none()
                    && status.active_operations.is_none()
            );
            assert_eq!(status.saved_revision, "4");
            let Reply::Command(resumed) = call(Request::MaintenanceCommand(MaintenanceCommand {
                version: VERSION,
                target_node_id: fixture.server_id.clone(),
                resource: RESOURCE.into(),
                controller_epoch: "2".into(),
                command_id: "4".into(),
                expected_policy_revision: "4".into(),
                source_administrator_id: source,
                mutation: MaintenanceMutation::SetAdmission { accepting: true },
            }))
            .await?
            else {
                return Err(invalid("expected resume result"));
            };
            assert!(resumed.receipt.status == ReceiptStatus::Saved);
            assert_eq!(resumed.receipt.policy_revision.as_deref(), Some("5"));
            assert!(
                server
                    .reader()
                    .authenticate(&credential.login, secret.as_bytes(), access::Protocol::Http)
                    .is_ok()
            );
            drop(admitted);
            assert_eq!(server.reader().admission()?.active_operations, 0);
            Ok(())
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "maintenance node scenario timed out",
            )
        })
        .and_then(|result| result);
        tasks.finish(scenario).await
    }
}
