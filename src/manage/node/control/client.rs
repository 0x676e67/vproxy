//! One bounded request over the same explicit node trust domain as C2 probes.
//! HTTP begins only after both PKIX/SAN and the current local exact-DER binding
//! succeed. There is no redirect, environment proxy or system-root fallback.

use http_body_util::{BodyExt as _, Full};
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, ProtocolVersion};
use rustls_pki_types::ServerName;
use serde::de::DeserializeOwned;
use tokio_rustls::TlsConnector;

use super::*;

mod offline;
pub(in crate::manage) use offline::Offline;

/// Select only the local read-admission owner. Both variants share identical
/// DNS/TLS/HTTP code, response limits and before/after authorization fencing.
enum Authorization<'a> {
    Coordinator(&'a Arc<policy::Coordinator>, policy::ReadAdmission),
    Offline(&'a Arc<Offline>),
}

/// A rejected endpoint contributes only HTTP status and an allowlisted code to
/// diagnostics; its arbitrary response body never becomes an error or a log.
#[derive(Debug, thiserror::Error)]
#[error("node control request rejected ({status}, {code})")]
pub(in crate::manage) struct RemoteError {
    pub(in crate::manage) status: u16,
    pub(in crate::manage) code: &'static str,
}

/// Transport I/O is not an authenticated application rejection. Observed
/// Windows connect failures carry PermissionDenied without proving an owner
/// rejection. Retain the native code for diagnosis, but not arbitrary library
/// messages that may contain addresses, certificates, headers or body values.
#[derive(Debug, thiserror::Error)]
#[error("node control transport failed ({stage})")]
pub(in crate::manage) struct TransportError {
    stage: &'static str,
    os_error: Option<i32>,
}

fn transport(error: io::Error, stage: &'static str) -> io::Error {
    let kind = error.kind();
    let failure = TransportError {
        stage,
        os_error: error.raw_os_error(),
    };
    tracing::debug!(stage, ?kind, os_error = ?failure.os_error, "node control transport failed");
    io::Error::new(kind, failure)
}

/// Perform one fixed operation against a locally registered canonical origin.
///
/// All DNS/connect/TLS/authorization/body waits share ten seconds. Cancellation
/// drops the owned HTTP driver; it cannot cancel a command already accepted by
/// the target. Such a caller must recover with the same command/receipt ID.
pub(in crate::manage) async fn request(
    coordinator: &Arc<policy::Coordinator>,
    tls: Arc<ClientConfig>,
    endpoint: &str,
    expected_peer: &str,
    operation: Request,
) -> io::Result<Reply> {
    request_with_admission(
        coordinator,
        tls,
        endpoint,
        expected_peer,
        operation,
        policy::ReadAdmission::Immediate,
    )
    .await
}

/// Use the caller's bounded store admission within the same network deadline.
/// An admitted command may wait briefly for authorization reads so a transient
/// read overlap does not discard its first response. Both exact-DER checks and
/// the authorization revision fence remain mandatory. No read permit spans a
/// network await; ordinary remote reads keep `Immediate` admission.
pub(in crate::manage) async fn request_with_admission(
    coordinator: &Arc<policy::Coordinator>,
    tls: Arc<ClientConfig>,
    endpoint: &str,
    expected_peer: &str,
    operation: Request,
    admission: policy::ReadAdmission,
) -> io::Result<Reply> {
    coordinator.ensure_source_confirmed()?;
    request_as(
        Authorization::Coordinator(coordinator, admission),
        tls,
        endpoint,
        expected_peer,
        operation,
    )
    .await
}

async fn request_as(
    authorization: Authorization<'_>,
    tls: Arc<ClientConfig>,
    endpoint: &str,
    expected_peer: &str,
    operation: Request,
) -> io::Result<Reply> {
    let origin = PublicOrigin::parse(endpoint)?;
    if !valid_id(expected_peer) {
        return Err(invalid("invalid target node identity"));
    }
    if let Request::Witness(operation) = &operation {
        operation.validate(expected_peer)?;
    }
    if let Authorization::Offline(source) = &authorization {
        match &operation {
            Request::Witness(operation) if operation.enrollment.peer_node_id == source.node_id => {}
            _ => {
                return Err(invalid(
                    "offline operation differs from the local source identity",
                ));
            }
        }
    }
    if matches!(&operation,Request::Command(command) if command.target_node_id!=expected_peer) {
        return Err(invalid(
            "command target differs from the registered endpoint",
        ));
    }
    if matches!(&operation,Request::RoutingCommand(command) if command.target_node_id!=expected_peer)
    {
        return Err(invalid(
            "command target differs from the registered endpoint",
        ));
    }
    if matches!(&operation,Request::PresetCommand(command) if command.target_node_id!=expected_peer)
    {
        return Err(invalid(
            "command target differs from the registered endpoint",
        ));
    }
    if matches!(&operation,Request::EndpointCommand(command) if command.target_node_id!=expected_peer)
    {
        return Err(invalid(
            "endpoint command target differs from registered endpoint",
        ));
    }
    if matches!(&operation,Request::MaintenanceCommand(command) if command.target_node_id!=expected_peer)
    {
        return Err(invalid(
            "maintenance command target differs from registered endpoint",
        ));
    }
    if matches!(&operation, Request::RuntimeDrain(command) if command.request.expected_node_id != expected_peer)
    {
        return Err(invalid(
            "runtime drain target differs from registered endpoint",
        ));
    }
    if matches!(&operation, Request::CredentialSecret(input) if input.target_node_id != expected_peer)
    {
        return Err(invalid(
            "proxy secret target differs from registered endpoint",
        ));
    }
    let result = timeout(
        Duration::from_secs(10),
        once(&authorization, tls, origin, expected_peer, operation),
    )
    .await;
    result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "node control request timed out"))?
}

async fn once(
    authorization: &Authorization<'_>,
    tls: Arc<ClientConfig>,
    origin: PublicOrigin,
    expected_peer: &str,
    operation: Request,
) -> io::Result<Reply> {
    let (method, path, body) = encode(&operation)?;
    let url =
        url::Url::parse(origin.value()).map_err(|_| invalid("invalid node control endpoint"))?;
    let (host, server_name) = match url.host() {
        Some(url::Host::Domain(host)) => (
            host.to_owned(),
            ServerName::try_from(host.to_owned()).map_err(|_| invalid("invalid node hostname"))?,
        ),
        Some(url::Host::Ipv4(address)) => {
            (address.to_string(), ServerName::IpAddress(address.into()))
        }
        Some(url::Host::Ipv6(address)) => {
            (address.to_string(), ServerName::IpAddress(address.into()))
        }
        None => return Err(invalid("node control endpoint has no host")),
    };
    let port = url
        .port_or_known_default()
        .ok_or_else(|| invalid("node endpoint has no port"))?;
    let stream = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|error| transport(error, "connect"))?;
    // Short TLS/control records should not wait for a preceding record's ACK.
    // https://www.rfc-editor.org/rfc/rfc9293.html#section-3.7.4
    stream
        .set_nodelay(true)
        .map_err(|error| transport(error, "connect"))?;
    let stream = TlsConnector::from(tls)
        .connect(server_name, stream)
        .await
        .map_err(|error| transport(error, "tls"))?;
    if stream.get_ref().1.alpn_protocol() != Some(&b"http/1.1"[..])
        || stream.get_ref().1.protocol_version() != Some(ProtocolVersion::TLSv1_3)
    {
        return Err(invalid("node TLS did not negotiate TLS 1.3 and HTTP/1.1"));
    }
    let leaf: Arc<[u8]> =
        super::super::super::tls::checked_leaf(stream.get_ref().1.peer_certificates())?.into();
    let revision = authorize(authorization, leaf.clone(), expected_peer.to_owned()).await?;
    let mut builder = hyper::client::conn::http1::Builder::new();
    builder.max_buf_size(16 * 1024).max_headers(64);
    let (mut sender, connection) = builder
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|error| transport(io::Error::other(error), "http"))?;
    let mut drivers = JoinSet::new();
    drivers.spawn(connection);
    let mut request = http::Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, origin.authority())
        .header(header::ACCEPT, "application/json");
    if matches!(
        operation,
        Request::Command(_)
            | Request::RoutingCommand(_)
            | Request::PresetCommand(_)
            | Request::EndpointCommand(_)
            | Request::MaintenanceCommand(_)
            | Request::RuntimeDrain(_)
            | Request::CredentialSecret(_)
            | Request::Witness(witness::Operation {
                action: witness::Action::Reserve(_) | witness::Action::Confirm(_),
                ..
            })
    ) {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    let request = request
        .body(Full::new(bytes::Bytes::from(body)))
        .map_err(|_| invalid("cannot construct node control request"))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| transport(io::Error::other(error), "http"))?;
    let status = response.status();
    let mut types = response.headers().get_all(header::CONTENT_TYPE).iter();
    let json = types
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    if !json || types.next().is_some() || response.headers().contains_key(header::CONTENT_ENCODING)
    {
        return Err(invalid("invalid node control response representation"));
    }
    let mut body = response.into_body();
    // Reserve the whole cap once: old allocations must not retain a secret
    // during Vec growth. JSON's temporary owned String moves into Zeroizing.
    let response_limit = if matches!(operation, Request::CredentialSecret(_)) {
        secrets::RESPONSE_BYTES
    } else if matches!(operation, Request::OperationsSnapshot) {
        alerts::SNAPSHOT_RESPONSE_BYTES
    } else if matches!(operation, Request::EndpointSettings) {
        endpoints::SETTINGS_RESPONSE_BYTES
    } else if matches!(operation, Request::Witness(_)) {
        witness::MAX_RESPONSE_BYTES
    } else {
        MAX_RESPONSE_BYTES
    };
    let mut bytes = Zeroizing::new(Vec::with_capacity(response_limit));
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| transport(io::Error::other(error), "body"))?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        bytes
            .len()
            .checked_add(data.len())
            .filter(|length| *length <= response_limit)
            .ok_or_else(|| invalid("node control response exceeds its size limit"))?;
        bytes.extend_from_slice(&data);
    }
    if authorize(authorization, leaf.clone(), expected_peer.to_owned()).await? != revision {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "node authorization changed during request",
        ));
    }
    if status != StatusCode::OK
        && !(status == StatusCode::ACCEPTED
            && matches!(
                operation,
                Request::Command(_)
                    | Request::RoutingCommand(_)
                    | Request::PresetCommand(_)
                    | Request::MaintenanceCommand(_)
                    | Request::RuntimeDrain(_)
            ))
    {
        let version = match &operation {
            Request::CredentialSecret(_) => 7,
            Request::Runtime | Request::RuntimeDrain(_) | Request::RuntimeDrainStatus { .. } => 6,
            Request::Maintenance | Request::MaintenanceCommand(_) => 5,
            Request::PresetCommand(_)
            | Request::UserPresets { .. }
            | Request::PoolPreset { .. }
            | Request::PresetCatalog => 3,
            Request::RoutingCommand(_)
            | Request::PrefixesPage { .. }
            | Request::AddressesPage { .. }
            | Request::Address { .. }
            | Request::PoolsPage { .. }
            | Request::PoolMembersPage { .. }
            | Request::UserRouting { .. }
            | Request::HealthPage { .. } => 2,
            Request::Receipt { version, .. } => *version,
            Request::EndpointSettings
            | Request::EndpointCommand(_)
            | Request::EndpointReceipt { .. } => 4,
            _ => 1,
        };
        return Err(if matches!(operation, Request::OperationsSnapshot) {
            remote_error_with_snapshot(status, &bytes, true, true)
        } else if traffic::is_request(&operation)
            || matches!(
                operation,
                Request::Endpoints
                    | Request::EndpointSettings
                    | Request::UsersSearch(_)
                    | Request::EgressAlerts(_)
                    | Request::OperationsAlerts(_)
            )
        {
            remote_error_with_negotiation(status, &bytes, true)
        } else {
            remote_error(status, &bytes, version)
        });
    }
    // Construct evidence only for replies that retain it. Ordinary control
    // reads need neither another node-ID allocation nor an authorization owner.
    let proof = || store::RemoteAuthorization {
        node_id: expected_peer.to_owned(),
        authorization_revision: revision,
        leaf,
    };
    let reply = if let Request::Witness(operation) = &operation {
        let value = witness::decode(operation, &bytes, expected_peer)?;
        Reply::Witness(Box::new(Fetched {
            authorization: proof(),
            value,
        }))
    } else if matches!(operation, Request::OperationsSnapshot) {
        alerts::decode_snapshot(&bytes, expected_peer, proof())?
    } else if traffic::is_request(&operation) {
        traffic::decode(&operation, &bytes, expected_peer, proof())?
    } else {
        decode(&operation, &bytes, expected_peer, status)?
    };
    drop(sender);
    drivers.shutdown().await;
    Ok(reply)
}

async fn authorize(
    authorization: &Authorization<'_>,
    leaf: Arc<[u8]>,
    expected: String,
) -> io::Result<u64> {
    match authorization {
        Authorization::Offline(source) => source.authorize(leaf, expected).await,
        Authorization::Coordinator(coordinator, admission) => {
            coordinator.ensure_source_confirmed()?;
            let revision = coordinator
                .read_with_admission(*admission, move |directory| {
                    authorize_in(directory, &leaf, &expected)
                })
                .await?;
            coordinator.ensure_source_confirmed()?;
            Ok(revision)
        }
    }
}

fn authorize_in(directory: &std::path::Path, leaf: &[u8], expected: &str) -> io::Result<u64> {
    let peer = store::authorize_peer(directory, leaf)?
        .filter(|peer| peer.node_id == expected)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "node TLS leaf is not registered for the selected peer",
            )
        })?;
    super::super::super::tls::verify_peer_name(leaf, &peer.expected_san)?;
    Ok(peer.authorization_revision)
}

pub(super) fn encode(operation: &Request) -> io::Result<(Method, String, Vec<u8>)> {
    let convert = |_: ApiError| invalid("invalid node control operation");
    let path = match operation {
        Request::Witness(operation) => return witness::encode(operation),
        Request::Policy => format!("{PREFIX}/policy"),
        Request::Endpoints => format!("{PREFIX}/endpoints"),
        Request::EndpointSettings => "/node/v4/proxy/endpoints".into(),
        Request::EndpointReceipt {
            controller_epoch,
            command_id,
        } => {
            number(&controller_epoch.to_string(), false)?;
            number(&command_id.to_string(), false)?;
            format!("/node/v4/proxy/receipts/{controller_epoch}/{command_id}")
        }
        Request::EndpointCommand(command) => {
            command.clone().into_store().map_err(convert)?;
            let bytes = serde_json::to_vec(command)
                .map_err(|_| invalid("cannot encode endpoint command"))?;
            if bytes.len() > 4096 {
                return Err(invalid("endpoint command exceeds size limit"));
            }
            return Ok((Method::POST, "/node/v4/proxy/commands".into(), bytes));
        }
        Request::UsersPage {
            after,
            limit,
            include_deleted,
        } => {
            page_input(after, *limit, None)?;
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            query.append_pair("limit", &limit.to_string()).append_pair(
                "include_deleted",
                if *include_deleted { "true" } else { "false" },
            );
            if let Some(after) = after {
                query.append_pair("after", after);
            }
            format!("{PREFIX}/users?{}", query.finish())
        }
        Request::UsersSearch(query) => {
            let mut encoded = url::form_urlencoded::Serializer::new(String::new());
            encoded.append_pair("mode", query.mode().as_str());
            encoded.append_pair("q", query.q());
            encoded.append_pair("limit", &query.limit().to_string());
            encoded.append_pair(
                "include_deleted",
                if query.include_deleted() {
                    "true"
                } else {
                    "false"
                },
            );
            if let Some(after) = query.after() {
                encoded.append_pair("after", after);
            }
            format!("{PREFIX}/users/search?{}", encoded.finish())
        }
        Request::EgressAlerts(query) => return alerts::encode(query),
        Request::OperationsAlerts(query) => return alerts::encode_operations(query),
        Request::OperationsSnapshot => format!("{PREFIX}/operations-snapshot"),
        Request::CredentialsPage {
            after,
            limit,
            user_id,
        } => {
            page_input(after, *limit, user_id.as_deref())?;
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            query.append_pair("limit", &limit.to_string());
            if let Some(after) = after {
                query.append_pair("after", after);
            }
            if let Some(user_id) = user_id {
                query.append_pair("user_id", user_id);
            }
            format!("{PREFIX}/credentials?{}", query.finish())
        }
        Request::Receipt {
            version,
            controller_epoch,
            command_id,
        } => {
            if !matches!(version, 1..=3 | 5) {
                return Err(invalid("invalid receipt protocol version"));
            }
            decimal(&controller_epoch.to_string(), false).map_err(convert)?;
            decimal(&command_id.to_string(), false).map_err(convert)?;
            format!("/node/v{version}/proxy/receipts/{controller_epoch}/{command_id}")
        }
        Request::CredentialSecret(input) => return secrets::encode(input),
        Request::Command(command) => {
            command.clone().into_store().map_err(convert)?;
            let bytes =
                serde_json::to_vec(command).map_err(|_| invalid("cannot encode node command"))?;
            if bytes.len() > 4096 {
                return Err(invalid("node command exceeds its size limit"));
            }
            return Ok((Method::POST, format!("{PREFIX}/commands"), bytes));
        }
        Request::Maintenance | Request::MaintenanceCommand(_) => {
            return maintenance::encode(operation);
        }
        Request::Runtime | Request::RuntimeDrain(_) | Request::RuntimeDrainStatus { .. } => {
            return runtime::encode(operation);
        }
        Request::RoutingCommand(_)
        | Request::PrefixesPage { .. }
        | Request::AddressesPage { .. }
        | Request::Address { .. }
        | Request::PoolsPage { .. }
        | Request::PoolMembersPage { .. }
        | Request::UserRouting { .. }
        | Request::HealthPage { .. } => return routing::encode(operation),
        Request::PresetCommand(_)
        | Request::UserPresets { .. }
        | Request::PoolPreset { .. }
        | Request::PresetCatalog => return presets::encode(operation),
        Request::TrafficSnapshot
        | Request::TrafficTotals { .. }
        | Request::TrafficBuckets { .. } => {
            return traffic::encode(operation);
        }
    };
    Ok((Method::GET, path, Vec::new()))
}

fn page_input(after: &Option<String>, limit: u32, user: Option<&str>) -> io::Result<()> {
    if !(1..=50).contains(&limit)
        || after.as_deref().is_some_and(|id| !valid_id(id))
        || user.is_some_and(|id| !valid_id(id))
    {
        return Err(invalid("invalid node page input"));
    }
    Ok(())
}

pub(super) fn envelope<T: DeserializeOwned>(
    bytes: &[u8],
    expected: &str,
    version: u8,
) -> io::Result<T> {
    let value: Envelope<T> =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid node control response"))?;
    if value.version != version || value.node_id != expected || value.resource != RESOURCE {
        return Err(invalid(
            "node response does not match the selected identity and protocol",
        ));
    }
    Ok(value.data)
}

pub(super) fn decode(
    operation: &Request,
    bytes: &[u8],
    expected: &str,
    status: StatusCode,
) -> io::Result<Reply> {
    match operation {
        Request::CredentialSecret(input) => secrets::decode(input, bytes, expected),
        Request::Witness(_) => Err(invalid(
            "witness reply requires verified TLS authorization proof",
        )),
        Request::Runtime | Request::RuntimeDrain(_) | Request::RuntimeDrainStatus { .. } => {
            runtime::decode(operation, bytes, expected, status)
        }
        Request::Maintenance | Request::MaintenanceCommand(_) => {
            maintenance::decode(operation, bytes, expected, status)
        }
        Request::UsersSearch(query) => search::decode(query, bytes, expected),
        Request::EgressAlerts(query) => alerts::decode(query, bytes, expected),
        Request::OperationsAlerts(query) => alerts::decode_operations(query, bytes, expected),
        Request::EndpointSettings
        | Request::EndpointCommand(_)
        | Request::EndpointReceipt { .. } => endpoints::decode(operation, bytes, expected),
        Request::Endpoints => {
            let value: crate::manage::proxy::EndpointCatalog = envelope(bytes, expected, VERSION)?;
            value.validate(expected)?;
            Ok(Reply::Endpoints(value))
        }
        Request::Policy => {
            let value: Policy = envelope(bytes, expected, VERSION)?;
            let saved = number(&value.saved_revision, false)?;
            number(&value.controller_epoch, false)?;
            number(&value.last_terminal_command, true)?;
            if value
                .controller_node_id
                .as_deref()
                .is_some_and(|id| !valid_id(id))
                || !optional_revision(&value.applied_revision, saved)
                || !optional_revision(&value.durable_applied_revision, saved)
                || (!value.proxy_running && value.applied_revision.is_some())
                || value.user_count as usize > crate::access::MAX_USERS
                || value.credential_count as usize > crate::access::MAX_CREDENTIALS
            {
                return Err(invalid("invalid node policy metadata"));
            }
            Ok(Reply::Policy(value))
        }
        Request::UsersPage {
            after,
            limit,
            include_deleted,
        } => {
            let value: Page<User> = envelope(bytes, expected, VERSION)?;
            validate_page(&value, *limit)?;
            let revision = number(&value.revision, false)?;
            let mut previous = after.as_deref();
            for user in &value.items {
                validate_user(user)?;
                if number(&user.revision, false)? > revision
                    || (!include_deleted && user.deleted)
                    || previous.is_some_and(|id| user.id.as_str() <= id)
                {
                    return Err(invalid("inconsistent node user page"));
                }
                previous = Some(&user.id);
            }
            if value
                .next_cursor
                .as_deref()
                .is_some_and(|cursor| Some(cursor) != previous)
                || value.items.is_empty() && value.next_cursor.is_some()
            {
                return Err(invalid("invalid node user cursor"));
            }
            Ok(Reply::UsersPage(value))
        }
        Request::CredentialsPage {
            after,
            limit,
            user_id,
        } => {
            let value: Page<Credential> = envelope(bytes, expected, VERSION)?;
            validate_page(&value, *limit)?;
            let revision = number(&value.revision, false)?;
            let mut previous = after.as_deref();
            for credential in &value.items {
                validate_credential(credential)?;
                if number(&credential.verifier_revision, false)? > revision
                    || previous.is_some_and(|id| credential.id.as_str() <= id)
                    || user_id.as_ref().is_some_and(|id| id != &credential.user_id)
                {
                    return Err(invalid("node credential page changed its selected user"));
                }
                previous = Some(&credential.id);
            }
            if value
                .next_cursor
                .as_deref()
                .is_some_and(|cursor| Some(cursor) != previous)
                || value.items.is_empty() && value.next_cursor.is_some()
            {
                return Err(invalid("invalid node credential cursor"));
            }
            Ok(Reply::CredentialsPage(value))
        }
        Request::Receipt {
            version,
            controller_epoch,
            command_id,
        } => {
            let mut value: Receipt = envelope(bytes, expected, *version)?;
            value.version = *version;
            validate_receipt(&value)?;
            if number(&value.controller_epoch, false)? != *controller_epoch
                || number(&value.command_id, false)? != *command_id
            {
                return Err(invalid("node receipt does not match the selected command"));
            }
            Ok(Reply::Receipt(value))
        }
        Request::Command(command) => {
            let mut value: CommandReply = envelope(bytes, expected, VERSION)?;
            value.receipt.version = VERSION;
            validate_receipt(&value.receipt)?;
            if value.receipt.controller_epoch != command.controller_epoch
                || value.receipt.command_id != command.command_id
                || (status == StatusCode::ACCEPTED)
                    != (value.receipt.status == ReceiptStatus::Saved)
                || value.secret_available != value.secret.is_some()
                || value.routing.is_some()
                || value.presets.is_some()
                || value.secret.as_deref().is_some_and(|value| {
                    value.len() != 43
                        || !value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
                        })
                })
                || ((value.replayed || value.receipt.status == ReceiptStatus::Rejected)
                    && (value.secret.is_some()
                        || value.user.is_some()
                        || value.credential.is_some()))
            {
                return Err(invalid("invalid node command result"));
            }
            if let Some(user) = &value.user {
                validate_user(user)?;
                let revision = number(
                    value
                        .receipt
                        .policy_revision
                        .as_deref()
                        .ok_or_else(|| invalid("missing command revision"))?,
                    false,
                )?;
                if number(&user.revision, false)? > revision
                    || value.receipt.user_id.as_ref() != Some(&user.id)
                {
                    return Err(invalid("node command user does not match its receipt"));
                }
            }
            if let Some(credential) = &value.credential {
                validate_credential(credential)?;
                if value.receipt.credential_id.as_ref() != Some(&credential.id)
                    || value.receipt.user_id.as_ref() != Some(&credential.user_id)
                {
                    return Err(invalid(
                        "node command credential does not match its receipt",
                    ));
                }
            }
            if value.secret.is_some()
                && (!matches!(
                    command.mutation,
                    Mutation::CreateCredential { .. } | Mutation::RotateCredential { .. }
                ) || value.credential.is_none())
            {
                return Err(invalid("unexpected node command secret"));
            }
            validate_command_result(command, &value)?;
            Ok(Reply::Command(Box::new(value)))
        }
        Request::RoutingCommand(_)
        | Request::PrefixesPage { .. }
        | Request::AddressesPage { .. }
        | Request::Address { .. }
        | Request::PoolsPage { .. }
        | Request::PoolMembersPage { .. }
        | Request::UserRouting { .. }
        | Request::HealthPage { .. } => routing::decode(operation, bytes, expected, status),
        Request::PresetCommand(_)
        | Request::UserPresets { .. }
        | Request::PoolPreset { .. }
        | Request::PresetCatalog => presets::decode(operation, bytes, expected, status),
        Request::OperationsSnapshot
        | Request::TrafficSnapshot
        | Request::TrafficTotals { .. }
        | Request::TrafficBuckets { .. } => Err(invalid(
            "snapshot reply requires the verified TLS authorization proof",
        )),
    }
}

/// A syntactically valid reply can still belong to a different operation.
/// Correlate immutable command facts before exposing metadata or a secret to
/// the controller's outbox/browser bridge.
fn validate_command_result(command: &Command, value: &CommandReply) -> io::Result<()> {
    if value.receipt.status == ReceiptStatus::Rejected {
        return Ok(());
    }
    let expected = number(&command.expected_policy_revision, false)?
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| invalid("command revision is exhausted"))?;
    if value
        .receipt
        .policy_revision
        .as_deref()
        .map(|value| number(value, false))
        .transpose()?
        != Some(expected)
    {
        return Err(invalid(
            "node command revision does not match its policy CAS",
        ));
    }
    let user = value.receipt.user_id.as_deref();
    let credential = value.receipt.credential_id.as_deref();
    let (user_operation, secret_operation) = match &command.mutation {
        Mutation::CreateUser { .. } => (true, false),
        Mutation::UpdateUser { id, .. }
        | Mutation::SetUserActive { id, .. }
        | Mutation::DeleteUser { id } => {
            if user != Some(id.as_str()) {
                return Err(invalid("node command changed a different user"));
            }
            (true, false)
        }
        Mutation::CreateCredential { user_id } => {
            if user != Some(user_id.as_str()) {
                return Err(invalid("node credential changed its owning user"));
            }
            (false, true)
        }
        Mutation::SetCredentialActive { id, .. } | Mutation::RevokeCredential { id } => {
            if credential != Some(id.as_str()) {
                return Err(invalid("node command changed a different credential"));
            }
            (false, false)
        }
        Mutation::RotateCredential { id } => {
            if credential != Some(id.as_str()) {
                return Err(invalid("node command rotated a different credential"));
            }
            (false, true)
        }
    };
    if user_operation && credential.is_some() || !user_operation && credential.is_none() {
        return Err(invalid("node receipt shape differs from its mutation"));
    }
    if !value.replayed
        && (value.user.is_none()
            || value.credential.is_some() == user_operation
            || value.secret.is_some() != secret_operation)
    {
        return Err(invalid("node command omitted or added result material"));
    }
    if let Some(secret) = &value.secret {
        let mut decoded = Zeroizing::new([0; 32]);
        if !matches!(
            URL_SAFE_NO_PAD.decode_slice(secret.as_bytes(), &mut *decoded),
            Ok(32)
        ) {
            return Err(invalid("invalid generated node credential secret"));
        }
    }
    Ok(())
}

pub(super) fn number(value: &str, zero: bool) -> io::Result<u64> {
    decimal(value, zero).map_err(|_| invalid("invalid decimal in node control response"))
}
fn optional_revision(value: &Option<String>, maximum: u64) -> bool {
    value
        .as_deref()
        .is_none_or(|value| number(value, false).is_ok_and(|value| value <= maximum))
}
fn validate_page<T>(page: &Page<T>, limit: u32) -> io::Result<()> {
    number(&page.revision, false)?;
    if page.items.len() > limit as usize
        || page
            .next_cursor
            .as_deref()
            .is_some_and(|value| !valid_id(value))
    {
        return Err(invalid("invalid node control page"));
    }
    Ok(())
}
pub(super) fn validate_user(user: &User) -> io::Result<()> {
    crate::manage::views::validate_user(user)
}
fn validate_credential(credential: &Credential) -> io::Result<()> {
    number(&credential.verifier_revision, false)?;
    let mut id = [0; 16];
    if !valid_id(&credential.id)
        || !valid_id(&credential.user_id)
        || credential.syntax_version != 2
        || credential.login.len() != 36
        || !credential.login.starts_with("vp2_")
        || (credential.revoked && credential.active)
        || URL_SAFE_NO_PAD
            .decode_slice(&credential.id, &mut id)
            .is_err()
    {
        return Err(invalid("invalid node credential metadata"));
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in id.into_iter().enumerate() {
        if credential.login.as_bytes()[4 + index * 2] != HEX[usize::from(byte >> 4)]
            || credential.login.as_bytes()[5 + index * 2] != HEX[usize::from(byte & 15)]
        {
            return Err(invalid("node login does not match its credential identity"));
        }
    }
    Ok(())
}
pub(super) fn validate_receipt(receipt: &Receipt) -> io::Result<()> {
    number(&receipt.controller_epoch, false)?;
    number(&receipt.command_id, false)?;
    if let Some(revision) = &receipt.policy_revision {
        number(revision, false)?;
    }
    let rejected = receipt.status == ReceiptStatus::Rejected;
    if !matches!(receipt.version, 1..=3 | 5)
        || receipt
            .routing
            .as_ref()
            .is_some_and(|reference| !valid_id(&reference.id))
        || receipt
            .preset
            .as_ref()
            .is_some_and(|reference| !valid_id(&reference.id))
        || (receipt.version != 2 && receipt.routing.is_some())
        || (receipt.version != 3 && receipt.preset.is_some())
        || (receipt.version != 1 && (receipt.user_id.is_some() || receipt.credential_id.is_some()))
        || (rejected && receipt.routing.is_some())
        || (rejected && receipt.preset.is_some())
        || (!rejected && receipt.version == 2 && receipt.routing.is_none())
        || (!rejected && receipt.version == 3 && receipt.preset.is_none())
    {
        return Err(invalid("invalid versioned node receipt metadata"));
    }
    if receipt
        .user_id
        .as_deref()
        .is_some_and(|value| !valid_id(value))
        || receipt
            .credential_id
            .as_deref()
            .is_some_and(|value| !valid_id(value))
        || rejected != receipt.rejection.is_some()
        || rejected
            && (receipt.policy_revision.is_some()
                || receipt.user_id.is_some()
                || receipt.credential_id.is_some())
        || !rejected
            && (receipt.policy_revision.is_none()
                || (receipt.version == 1 && receipt.user_id.is_none()))
        || receipt.rejection.as_deref().is_some_and(|code| {
            !matches!(
                code,
                "invalid_policy" | "policy_conflict" | "resource_not_found" | "policy_capacity"
            )
        })
    {
        return Err(invalid("invalid node receipt metadata"));
    }
    Ok(())
}

pub(super) fn remote_error(status: StatusCode, bytes: &[u8], version: u8) -> io::Error {
    if version == 7
        && let Some(code) = secrets::rejection_code(status, bytes)
    {
        return io::Error::other(RemoteError {
            status: status.as_u16(),
            code,
        });
    }
    if version == 6
        && let Some(code) = runtime::rejection_code(status, bytes)
    {
        return io::Error::new(
            io::ErrorKind::AlreadyExists,
            RemoteError {
                status: status.as_u16(),
                code,
            },
        );
    }
    remote_error_with_negotiation(status, bytes, matches!(version, 2 | 3 | 5 | 6 | 7))
}

fn remote_error_with_negotiation(
    status: StatusCode,
    bytes: &[u8],
    allow_unsupported: bool,
) -> io::Error {
    remote_error_with_snapshot(status, bytes, allow_unsupported, false)
}

fn remote_error_with_snapshot(
    status: StatusCode,
    bytes: &[u8],
    allow_unsupported: bool,
    snapshot: bool,
) -> io::Error {
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
    let code = serde_json::from_slice::<ErrorBody>(bytes)
        .ok()
        .and_then(|body| match body.error.code.as_str() {
            "not_found" if allow_unsupported && status == StatusCode::NOT_FOUND => {
                Some("node_protocol_unsupported")
            }
            "resource_managed" => Some("resource_managed"),
            "witness_invalid" if status == StatusCode::BAD_REQUEST => Some("witness_invalid"),
            "witness_conflict" if status == StatusCode::CONFLICT => Some("witness_conflict"),
            "witness_capacity" if status == StatusCode::CONFLICT => Some("witness_capacity"),
            "witness_denied" if status == StatusCode::FORBIDDEN => Some("witness_denied"),
            "witness_upgrade_required" if status == StatusCode::SERVICE_UNAVAILABLE => {
                Some("witness_upgrade_required")
            }
            "witness_busy" if status == StatusCode::SERVICE_UNAVAILABLE => Some("witness_busy"),
            "witness_unavailable" if status == StatusCode::SERVICE_UNAVAILABLE => {
                Some("witness_unavailable")
            }
            "owner_conflict" => Some("owner_conflict"),
            "peer_not_authorized" => Some("peer_not_authorized"),
            "peer_authorization_changed" => Some("peer_authorization_changed"),
            "target_mismatch" => Some("target_mismatch"),
            "controller_epoch_changed" => Some("controller_epoch_changed"),
            "command_conflict" => Some("command_conflict"),
            "command_out_of_order" => Some("command_out_of_order"),
            "receipt_expired" => Some("receipt_expired"),
            "resource_not_found" => Some("resource_not_found"),
            "policy_busy" => Some("policy_busy"),
            "policy_unavailable" => Some("policy_unavailable"),
            "policy_publication_failed" => Some("policy_publication_failed"),
            "authorization_busy" => Some("authorization_busy"),
            "authorization_unavailable" => Some("authorization_unavailable"),
            "request_timeout" => Some("request_timeout"),
            "management_upgrade_required" => Some("management_upgrade_required"),
            "health_unavailable" => Some("health_unavailable"),
            "alerts_unavailable" if status == StatusCode::SERVICE_UNAVAILABLE => {
                Some("alerts_unavailable")
            }
            "operations_alerts_capacity"
                if snapshot && status == StatusCode::SERVICE_UNAVAILABLE =>
            {
                Some("operations_alerts_capacity")
            }
            "invalid_alert_query" if status == StatusCode::BAD_REQUEST => {
                Some("invalid_alert_query")
            }
            "alerts_changed" if status == StatusCode::CONFLICT => Some("alerts_changed"),
            "traffic_busy" => Some("traffic_busy"),
            "traffic_unavailable" => Some("traffic_unavailable"),
            "proxy_unavailable" => Some("proxy_unavailable"),
            "invalid_endpoint" => Some("invalid_endpoint"),
            "endpoint_revision_changed" => Some("endpoint_revision_changed"),
            "endpoint_configuration_changed" => Some("endpoint_configuration_changed"),
            "endpoint_capacity" => Some("endpoint_capacity"),
            "invalid_user_search" if status == StatusCode::BAD_REQUEST => {
                Some("invalid_user_search")
            }
            "invalid_user_search_cursor" if status == StatusCode::BAD_REQUEST => {
                Some("invalid_user_search_cursor")
            }
            "user_search_changed" if status == StatusCode::CONFLICT => Some("user_search_changed"),
            _ => None,
        })
        .unwrap_or("node_request_rejected");
    io::Error::new(
        if status == StatusCode::FORBIDDEN {
            io::ErrorKind::PermissionDenied
        } else if status == StatusCode::CONFLICT {
            io::ErrorKind::AlreadyExists
        } else {
            io::ErrorKind::Other
        },
        RemoteError {
            status: status.as_u16(),
            code,
        },
    )
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_errors_keep_only_fixed_codes_with_their_expected_status() {
        for (status, code) in [
            (StatusCode::BAD_REQUEST, "witness_invalid"),
            (StatusCode::CONFLICT, "witness_conflict"),
            (StatusCode::CONFLICT, "witness_capacity"),
            (StatusCode::FORBIDDEN, "witness_denied"),
            (StatusCode::SERVICE_UNAVAILABLE, "witness_upgrade_required"),
            (StatusCode::SERVICE_UNAVAILABLE, "witness_busy"),
            (StatusCode::SERVICE_UNAVAILABLE, "witness_unavailable"),
        ] {
            let body = serde_json::to_vec(&serde_json::json!({"error":{"code":code}})).unwrap();
            let error = remote_error(status, &body, 1);
            assert_eq!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<RemoteError>()
                    .unwrap()
                    .code,
                code
            );
            let mismatched = remote_error(StatusCode::UNAUTHORIZED, &body, 1);
            assert_eq!(
                mismatched
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<RemoteError>()
                    .unwrap()
                    .code,
                "node_request_rejected"
            );
        }
        let error = remote_error(
            StatusCode::SERVICE_UNAVAILABLE,
            br#"{"error":{"code":"private remote diagnostic"}}"#,
            1,
        );
        assert!(!error.to_string().contains("private"));
    }

    #[test]
    fn atomic_operations_capacity_is_fixed_and_unsupported_never_falls_back() {
        for (status, allow, expected) in [
            (
                StatusCode::SERVICE_UNAVAILABLE,
                true,
                "operations_alerts_capacity",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                false,
                "node_request_rejected",
            ),
            (StatusCode::FORBIDDEN, true, "node_request_rejected"),
        ] {
            let error = remote_error_with_snapshot(
                status,
                br#"{"error":{"code":"operations_alerts_capacity"}}"#,
                true,
                allow,
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
        }
        let unsupported = remote_error_with_snapshot(
            StatusCode::NOT_FOUND,
            br#"{"error":{"code":"not_found"}}"#,
            true,
            true,
        );
        assert_eq!(
            unsupported
                .get_ref()
                .unwrap()
                .downcast_ref::<RemoteError>()
                .unwrap()
                .code,
            "node_protocol_unsupported"
        );
        let (_, path, _) = encode(&Request::OperationsSnapshot).unwrap();
        assert_eq!(path, "/node/v1/proxy/operations-snapshot");
    }

    #[test]
    fn user_search_rejections_preserve_typed_input_and_changed_codes_only_with_their_status() {
        for (status, code, expected) in [
            (
                StatusCode::BAD_REQUEST,
                "invalid_user_search",
                "invalid_user_search",
            ),
            (
                StatusCode::BAD_REQUEST,
                "invalid_user_search_cursor",
                "invalid_user_search_cursor",
            ),
            (
                StatusCode::CONFLICT,
                "user_search_changed",
                "user_search_changed",
            ),
            (
                StatusCode::FORBIDDEN,
                "user_search_changed",
                "node_request_rejected",
            ),
            (
                StatusCode::NOT_FOUND,
                "invalid_user_search",
                "node_request_rejected",
            ),
            (
                StatusCode::NOT_FOUND,
                "not_found",
                "node_protocol_unsupported",
            ),
            (
                StatusCode::NOT_FOUND,
                "resource_not_found",
                "resource_not_found",
            ),
        ] {
            let body = serde_json::to_vec(&serde_json::json!({"error":{"code":code}})).unwrap();
            let error = remote_error_with_negotiation(status, &body, true);
            let rejected = error
                .get_ref()
                .and_then(|e| e.downcast_ref::<RemoteError>())
                .unwrap();
            assert_eq!(rejected.code, expected);
        }
        let error = remote_error_with_negotiation(
            StatusCode::NOT_FOUND,
            br#"{"error":{"code":"not_found","private":"ignored"}}"#,
            true,
        );
        assert_eq!(
            error
                .get_ref()
                .and_then(|e| e.downcast_ref::<RemoteError>())
                .unwrap()
                .code,
            "node_request_rejected"
        );
    }

    #[test]
    fn endpoint_catalog_validates_selected_identity_bounds_and_nonsecret_vocabulary() {
        use serde_json::json;
        let data = json!({"node_id":"AAAAAAAAAAAAAAAAAAAAAA","proxy_running":true,"listeners":[{"protocol":"http","bind":"0.0.0.0:8080","public_address":"proxy.example:443"}]});
        assert!(matches!(
            decode(
                &Request::Endpoints,
                &envelope(data.clone()),
                "AAAAAAAAAAAAAAAAAAAAAA",
                StatusCode::OK
            ),
            Ok(Reply::Endpoints(_))
        ));
        let mut invalid = Vec::new();
        let mut value = data.clone();
        value["node_id"] = json!("BBBBBBBBBBBBBBBBBBBBBA");
        invalid.push(value);
        let mut value = data.clone();
        value["listeners"][0]["tls_key"] = json!("private.key");
        invalid.push(value);
        for address in [
            "0.0.0.0:1080",
            "user:secret@proxy.example:443",
            "PROXY.example:443",
            "proxy.example:0",
        ] {
            let mut value = data.clone();
            value["listeners"][0]["public_address"] = json!(address);
            invalid.push(value);
        }
        let mut value = data.clone();
        value["listeners"][0]["bind"] = json!("127.0.0.1:0");
        invalid.push(value);
        let mut value = data.clone();
        value["listeners"][0]["protocol"] = json!("quic");
        invalid.push(value);
        let mut value = data.clone();
        value["listeners"] = json!(vec![data["listeners"][0].clone(); 17]);
        invalid.push(value);
        let mut value = data;
        value["listeners"] = json!([]);
        invalid.push(value);
        for value in invalid {
            assert!(
                decode(
                    &Request::Endpoints,
                    &envelope(value),
                    "AAAAAAAAAAAAAAAAAAAAAA",
                    StatusCode::OK
                )
                .is_err()
            );
        }
        let (method, path, body) = encode(&Request::Endpoints).unwrap();
        assert_eq!(method, Method::GET);
        assert_eq!(path, "/node/v1/proxy/endpoints");
        assert!(body.is_empty());
    }

    #[test]
    fn independent_traffic_routes_negotiate_support_without_downgrading_or_hiding_missing_resources()
     {
        for (status, body, expected) in [
            (
                StatusCode::NOT_FOUND,
                br#"{"error":{"code":"not_found"}}"#.as_slice(),
                "node_protocol_unsupported",
            ),
            (
                StatusCode::NOT_FOUND,
                br#"{"error":{"code":"resource_not_found"}}"#.as_slice(),
                "resource_not_found",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                br#"{"error":{"code":"management_upgrade_required"}}"#.as_slice(),
                "management_upgrade_required",
            ),
            (
                StatusCode::NOT_FOUND,
                br#"{"error":{"code":"not_found","other":true}}"#.as_slice(),
                "node_request_rejected",
            ),
        ] {
            let error = remote_error_with_negotiation(status, body, true);
            assert_eq!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<RemoteError>()
                    .unwrap()
                    .code,
                expected
            );
        }
        assert_eq!(
            remote_error(
                StatusCode::NOT_FOUND,
                br#"{"error":{"code":"not_found"}}"#,
                1
            )
            .get_ref()
            .unwrap()
            .downcast_ref::<RemoteError>()
            .unwrap()
            .code,
            "node_request_rejected"
        );
    }

    #[test]
    fn version_two_unsupported_is_not_a_missing_resource_or_upgrade_error() {
        for (version, status, body, expected) in [
            (
                2,
                StatusCode::NOT_FOUND,
                br#"{"error":{"code":"not_found"}}"#.as_slice(),
                "node_protocol_unsupported",
            ),
            (
                1,
                StatusCode::NOT_FOUND,
                br#"{"error":{"code":"not_found"}}"#.as_slice(),
                "node_request_rejected",
            ),
            (
                2,
                StatusCode::NOT_FOUND,
                br#"{"error":{"code":"resource_not_found"}}"#.as_slice(),
                "resource_not_found",
            ),
            (
                2,
                StatusCode::SERVICE_UNAVAILABLE,
                br#"{"error":{"code":"management_upgrade_required"}}"#.as_slice(),
                "management_upgrade_required",
            ),
            (
                2,
                StatusCode::NOT_FOUND,
                br#"{"error":{"code":"not_found","private":"ignored"}}"#.as_slice(),
                "node_request_rejected",
            ),
        ] {
            let error = remote_error(status, body, version);
            assert_eq!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<RemoteError>()
                    .unwrap()
                    .code,
                expected
            );
        }
    }

    #[test]
    fn receipt_version_is_internal_and_v1_rejects_routing_metadata() {
        let mut data = receipt("applied");
        data["routing"] = serde_json::json!({"kind":"pool","id":"AAAAAAAAAAAAAAAAAAAAAA"});
        assert!(
            decode(
                &Request::Receipt {
                    version: 1,
                    controller_epoch: 2,
                    command_id: 1
                },
                &envelope(data.clone()),
                "AAAAAAAAAAAAAAAAAAAAAA",
                StatusCode::OK
            )
            .is_err()
        );
        data["user_id"] = serde_json::Value::Null;
        data["credential_id"] = serde_json::Value::Null;
        let mut encoded: serde_json::Value = serde_json::from_slice(&envelope(data)).unwrap();
        encoded["version"] = serde_json::json!(2);
        let Ok(Reply::Receipt(value)) = decode(
            &Request::Receipt {
                version: 2,
                controller_epoch: 2,
                command_id: 1,
            },
            &serde_json::to_vec(&encoded).unwrap(),
            "AAAAAAAAAAAAAAAAAAAAAA",
            StatusCode::OK,
        ) else {
            panic!("matching v2 receipt")
        };
        assert_eq!(value.version, 2);
        assert!(value.routing.is_some());
        assert!(
            serde_json::to_value(value)
                .unwrap()
                .get("version")
                .is_none()
        );
    }

    #[test]
    fn transport_permission_denied_is_not_a_peer_authorization_error() {
        let error = transport(
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixture operating-system detail",
            ),
            "connect",
        );
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            error
                .get_ref()
                .is_some_and(|error| error.is::<TransportError>())
        );
        assert!(
            error
                .get_ref()
                .is_some_and(|error| !error.is::<RemoteError>())
        );
        assert!(!error.to_string().contains("operating-system detail"));
        assert!(!format!("{error:?}").contains("operating-system detail"));
        let detail = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<TransportError>())
            .unwrap();
        assert_eq!(detail.stage, "connect");
        assert_eq!(detail.os_error, None);

        // A synthetic native code proves preservation on every platform; it
        // does not claim to reproduce a Windows socket failure on this host.
        let native = io::Error::from_raw_os_error(10013);
        let original_kind = native.kind();
        let error = transport(native, "connect");
        assert_eq!(error.kind(), original_kind);
        assert_eq!(error.raw_os_error(), None);
        let detail = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<TransportError>())
            .unwrap();
        assert_eq!(detail.os_error, Some(10013));
        assert!(format!("{error:?}").contains("10013"));
        assert_eq!(error.to_string(), "node control transport failed (connect)");

        let error = remote_error(
            StatusCode::FORBIDDEN,
            br#"{"error":{"code":"peer_not_authorized"}}"#,
            1,
        );
        assert!(
            error
                .get_ref()
                .is_some_and(|error| error.is::<RemoteError>())
        );
        assert!(
            error
                .get_ref()
                .is_some_and(|error| !error.is::<TransportError>())
        );
    }

    fn receipt(status: &str) -> serde_json::Value {
        serde_json::json!({"controller_epoch":"2","command_id":"1","status":status,"policy_revision":"2","rejection":null,"user_id":"AAAAAAAAAAAAAAAAAAAAAA","credential_id":null})
    }
    fn envelope(data: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"version":1,"node_id":"AAAAAAAAAAAAAAAAAAAAAA","resource":"proxy_policy","data":data})).unwrap()
    }

    #[test]
    fn client_checks_target_identity_receipt_namespace_and_saved_http_semantics() {
        let operation = Request::Receipt {
            version: 1,
            controller_epoch: 2,
            command_id: 1,
        };
        let bytes = envelope(receipt("applied"));
        assert!(decode(&operation, &bytes, "AAAAAAAAAAAAAAAAAAAAAA", StatusCode::OK).is_ok());
        assert!(decode(&operation, &bytes, "AQEBAQEBAQEBAQEBAQEBAQ", StatusCode::OK).is_err());
        let mut wrong = receipt("applied");
        wrong["command_id"] = "2".into();
        assert!(
            decode(
                &operation,
                &envelope(wrong),
                "AAAAAAAAAAAAAAAAAAAAAA",
                StatusCode::OK
            )
            .is_err()
        );
        let command: Command = serde_json::from_value(super::super::tests::command()).unwrap();
        let data = serde_json::json!({"receipt":receipt("saved"),"replayed":true,"user":null,"credential":null,"secret":null,"secret_available":false});
        assert!(
            decode(
                &Request::Command(command.clone()),
                &envelope(data.clone()),
                "AAAAAAAAAAAAAAAAAAAAAA",
                StatusCode::ACCEPTED
            )
            .is_ok()
        );
        assert!(
            decode(
                &Request::Command(command),
                &envelope(data),
                "AAAAAAAAAAAAAAAAAAAAAA",
                StatusCode::OK
            )
            .is_err()
        );
    }

    #[test]
    fn client_rejects_secret_in_replay_and_unknown_fields_without_exposing_the_body() {
        let command: Command = serde_json::from_value(super::super::tests::command()).unwrap();
        let data = serde_json::json!({"receipt":receipt("applied"),"replayed":true,"user":null,"credential":null,"secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","secret_available":true});
        assert!(
            decode(
                &Request::Command(command),
                &envelope(data),
                "AAAAAAAAAAAAAAAAAAAAAA",
                StatusCode::OK
            )
            .is_err()
        );
        let error = remote_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            br#"{"error":{"code":"private-password-and-path"}}"#,
            1,
        );
        assert!(!error.to_string().contains("private-password"));
        assert_eq!(
            error
                .get_ref()
                .unwrap()
                .downcast_ref::<RemoteError>()
                .unwrap()
                .code,
            "node_request_rejected"
        );
    }

    #[test]
    fn client_decimals_and_credentials_preserve_precision_and_identity() {
        assert_eq!(
            number("9223372036854775807", false).unwrap(),
            i64::MAX as u64
        );
        for value in [
            "01",
            "0",
            "1e3",
            "9007199254740992.0",
            "9223372036854775808",
        ] {
            assert!(number(value, false).is_err());
        }
        let mut credential = Credential {
            id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            user_id: "AQEBAQEBAQEBAQEBAQEBAQ".into(),
            login: "vp2_00000000000000000000000000000000".into(),
            syntax_version: 2,
            active: true,
            revoked: false,
            verifier_revision: "1".into(),
        };
        validate_credential(&credential).unwrap();
        credential.login = "vp2_00000000000000000000000000000001".into();
        assert!(validate_credential(&credential).is_err());
    }

    #[test]
    fn command_replies_cannot_substitute_another_resource_or_policy_generation() {
        let mut command: Command = serde_json::from_value(super::super::tests::command()).unwrap();
        command.mutation = Mutation::SetUserActive {
            id: "AQEBAQEBAQEBAQEBAQEBAQ".into(),
            active: false,
        };
        let data = serde_json::json!({"receipt":receipt("applied"),"replayed":true,"user":null,"credential":null,"secret":null,"secret_available":false});
        assert!(
            decode(
                &Request::Command(command.clone()),
                &envelope(data.clone()),
                "AAAAAAAAAAAAAAAAAAAAAA",
                StatusCode::OK
            )
            .is_err()
        );
        command.mutation = Mutation::CreateUser {
            name: "fixture".into(),
            protocols: vec![],
            concurrent_limit: 1,
        };
        let mut wrong = data.clone();
        wrong["receipt"]["policy_revision"] = "3".into();
        assert!(
            decode(
                &Request::Command(command.clone()),
                &envelope(wrong),
                "AAAAAAAAAAAAAAAAAAAAAA",
                StatusCode::OK
            )
            .is_err()
        );
        let mut wrong = data;
        wrong["replayed"] = false.into();
        assert!(
            decode(
                &Request::Command(command),
                &envelope(wrong),
                "AAAAAAAAAAAAAAAAAAAAAA",
                StatusCode::OK
            )
            .is_err()
        );
    }
}
