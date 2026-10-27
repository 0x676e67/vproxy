//! Administrator HTTP adapter for the shared policy and ownership service.
//!
//! Session middleware supplies the real administrator identity; neither JSON
//! nor the node transport can impersonate this actor. Passwords never enter
//! audit/logs; explicit current-generation reads are separate from mutations.

use axum::extract::{Path, rejection::PathRejection};

use super::*;
use crate::access::Protocol;
use crate::manage::{
    policy::{self as service, Coordinator},
    store::{self, CredentialView, PolicyChange},
    views::{Page, User},
};

mod operations;
mod secrets;

/// Created by session middleware, never deserialized from client-supplied JSON.
#[derive(Clone)]
pub(super) struct Administrator(pub(super) String);

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .merge(operations::routes())
        .merge(secrets::routes())
        .route("/api/v1/proxy/policy", get(policy))
        .route("/api/v1/proxy/owner", get(owner).put(set_owner))
        .route("/api/v1/proxy/users", get(list_users).post(create_user))
        .route("/api/v1/proxy/users/search", get(search_users))
        .route("/api/v1/proxy/users/{id}", axum::routing::put(update_user))
        .route("/api/v1/proxy/users/{id}/state", post(user_state))
        .route("/api/v1/proxy/users/{id}/delete", post(delete_user))
        .route(
            "/api/v1/proxy/users/{id}/credentials",
            post(create_credential),
        )
        .route("/api/v1/proxy/credentials", get(list_credentials))
        .route(
            "/api/v1/proxy/credentials/{id}/state",
            post(credential_state),
        )
        .route(
            "/api/v1/proxy/credentials/{id}/rotate",
            post(rotate_credential),
        )
        .route(
            "/api/v1/proxy/credentials/{id}/revoke",
            post(revoke_credential),
        )
        .route_layer(middleware::from_fn_with_state(state, authenticated))
}

/// All new routes use the same session lifetime and mutation CSRF policy. The
/// outer API guard separately enforces Host/Origin/JSON and request deadlines.
pub(super) async fn authenticated(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    state.confirmed()?;
    // This adapter is also shared by sibling route sets. Keep its credential
    // boundary valid even if a future router omits the outer request guard.
    automation::validate_request(request.headers(), request.method(), request.uri())?;
    if let Some(key) = automation::credential(request.headers())? {
        // Only the outer guard's exact local resource allowlist can reach this path.
        // Do not insert Administrator: a machine key cannot become a form actor.
        request.extensions_mut().insert(key);
        return Ok(next.run(request).await);
    }
    let accepts_bearer = automation::enabled(request.method(), request.uri());
    let challenge = |error| {
        if accepts_bearer {
            automation::authentication_required()
        } else {
            error
        }
    };
    let token = session_cookie(request.headers())
        .map_err(challenge)?
        .ok_or_else(|| challenge(ApiError::authentication_required()))?;
    let administrator = {
        let mut security = state.security()?;
        let session = security.session(token, Instant::now()).map_err(challenge)?;
        if !matches!(*request.method(), Method::GET | Method::HEAD) {
            let csrf = single_header(
                request.headers(),
                header::HeaderName::from_static("x-csrf-token"),
            )?
            .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "invalid_csrf"))?;
            if !bool::from(session.csrf_token.as_bytes().ct_eq(csrf.as_bytes())) {
                return Err(ApiError::new(StatusCode::FORBIDDEN, "invalid_csrf"));
            }
        }
        session.administrator.id.clone()
    };
    request
        .extensions_mut()
        .insert(Administrator(administrator));
    Ok(next.run(request).await)
}

fn coordinator(state: &AppState) -> Result<Arc<Coordinator>, ApiError> {
    state.policy.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    })
}

fn busy() -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "policy_busy")
}

fn unavailable() -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable")
}

pub(super) fn storage_error(error: io::Error) -> ApiError {
    if let Some(cause) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<store::secrets::Error>())
    {
        use store::secrets::Error;
        let (status, code) = match cause {
            Error::UpgradeRequired => (
                StatusCode::SERVICE_UNAVAILABLE,
                "management_upgrade_required",
            ),
            Error::NotSaved => (StatusCode::CONFLICT, "credential_secret_not_saved"),
            Error::Changed => (StatusCode::CONFLICT, "credential_secret_changed"),
            Error::KeyUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "credential_secret_key_unavailable",
            ),
            Error::Invalid => (StatusCode::SERVICE_UNAVAILABLE, "credential_secret_invalid"),
        };
        return ApiError::new(status, code);
    }
    if let Some(search) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<crate::manage::user_search::Error>())
    {
        let status = match search {
            crate::manage::user_search::Error::Changed => StatusCode::CONFLICT,
            _ => StatusCode::BAD_REQUEST,
        };
        return ApiError::new(status, search.code());
    }
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<service::Error>())
    {
        return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error.code());
    }
    if let Some(control) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<store::ControlError>())
    {
        let status = if error.kind() == io::ErrorKind::PermissionDenied {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::CONFLICT
        };
        return ApiError::new(status, control.code());
    }
    match error.kind() {
        io::ErrorKind::InvalidInput => ApiError::new(StatusCode::BAD_REQUEST, "invalid_policy"),
        io::ErrorKind::NotFound => ApiError::new(StatusCode::NOT_FOUND, "resource_not_found"),
        io::ErrorKind::AlreadyExists => ApiError::new(StatusCode::CONFLICT, "policy_conflict"),
        io::ErrorKind::PermissionDenied => ApiError::new(StatusCode::FORBIDDEN, "policy_denied"),
        io::ErrorKind::WouldBlock => busy(),
        _ => unavailable(),
    }
}

/// Revisions use decimal strings on the wire, preserving all SQLite i64 values
/// without JavaScript Number's 53-bit precision limit. No implicit coercion.
pub(super) fn revision(value: &str) -> Result<u64, ApiError> {
    if value.is_empty()
        || value.len() > 19
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_revision"));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "invalid_revision"))
}

pub(super) fn resource_id(path: Result<Path<String>, PathRejection>) -> Result<String, ApiError> {
    let Path(id) =
        path.map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_resource_id"))?;
    let mut bytes = [0; 16];
    if id.len() != 22 || !matches!(URL_SAFE_NO_PAD.decode_slice(&id, &mut bytes), Ok(16)) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_resource_id",
        ));
    }
    Ok(id)
}

#[derive(Serialize)]
struct PolicyView {
    saved_revision: String,
    applied_revision: Option<String>,
    durable_applied_revision: Option<String>,
    proxy_running: bool,
    user_count: u32,
    credential_count: u32,
}

async fn policy(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let coordinator = coordinator(&state)?;
    let status = coordinator.status().await.map_err(storage_error)?;
    Ok(Json(PolicyView {
        saved_revision: status.saved_revision.to_string(),
        applied_revision: status.applied_revision.map(|value| value.to_string()),
        durable_applied_revision: status
            .durable_applied_revision
            .map(|value| value.to_string()),
        proxy_running: status.running,
        user_count: status.user_count,
        credential_count: status.credential_count,
    })
    .into_response())
}

#[derive(Serialize)]
struct OwnerView {
    controller_node_id: Option<String>,
    epoch: String,
    last_terminal_command: String,
}

impl From<store::Ownership> for OwnerView {
    fn from(value: store::Ownership) -> Self {
        Self {
            controller_node_id: value.controller_node_id,
            epoch: value.epoch.to_string(),
            last_terminal_command: value.last_terminal_command.to_string(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerInput {
    expected_epoch: String,
    // Missing and explicit null must not mean the same thing: a missing field
    // cannot accidentally turn a partial update into an ownership revocation.
    #[serde(deserialize_with = "required_controller")]
    controller_node_id: Option<String>,
}

fn required_controller<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

async fn owner(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let owner = coordinator(&state)?
        .ownership()
        .await
        .map_err(storage_error)?;
    Ok(Json(OwnerView::from(owner)).into_response())
}

async fn set_owner(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    request: Request,
) -> Result<Response, ApiError> {
    let input: OwnerInput = json(request).await?;
    if let Some(id) = &input.controller_node_id {
        let mut decoded = [0; 16];
        if id.len() != 22 || !matches!(URL_SAFE_NO_PAD.decode_slice(id, &mut decoded), Ok(16)) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_resource_id",
            ));
        }
    }
    let owner = coordinator(&state)?
        .set_owner(
            actor,
            revision(&input.expected_epoch)?,
            input.controller_node_id,
        )
        .await
        .map_err(storage_error)?;
    Ok(Json(OwnerView::from(owner)).into_response())
}

#[derive(Serialize)]
struct Credential {
    id: String,
    user_id: String,
    login: String,
    syntax_version: u8,
    active: bool,
    revoked: bool,
    verifier_revision: String,
}

impl From<CredentialView> for Credential {
    fn from(value: CredentialView) -> Self {
        Self {
            id: value.id,
            user_id: value.user_id,
            login: value.login,
            syntax_version: value.syntax_version,
            active: value.active,
            revoked: value.revoked,
            verifier_revision: value.verifier_revision.to_string(),
        }
    }
}

/// Small allowlisted query vocabulary. Reject duplicates and unknown fields
/// rather than silently dropping a misspelled filter in a security UI.
pub(super) struct Pagination {
    pub(super) after: Option<String>,
    pub(super) limit: u32,
    pub(super) include_deleted: bool,
    pub(super) user_id: Option<String>,
}

pub(super) fn pagination(uri: &Uri, credentials: bool) -> Result<Pagination, ApiError> {
    let query = uri.query().unwrap_or_default();
    let invalid = || ApiError::new(StatusCode::BAD_REQUEST, "invalid_pagination");
    if query.len() > 1024 {
        return Err(invalid());
    }
    let mut pagination = Pagination {
        after: None,
        limit: 25,
        include_deleted: false,
        user_id: None,
    };
    let mut seen = [false; 4];
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let index = match key.as_ref() {
            "after" => 0,
            "limit" => 1,
            "include_deleted" if !credentials => 2,
            "user_id" if credentials => 3,
            _ => return Err(invalid()),
        };
        if seen[index] {
            return Err(invalid());
        }
        seen[index] = true;
        match index {
            0 | 3 => {
                let mut decoded = [0; 16];
                if value.len() != 22
                    || !matches!(
                        URL_SAFE_NO_PAD.decode_slice(value.as_bytes(), &mut decoded),
                        Ok(16)
                    )
                {
                    return Err(invalid());
                }
                if index == 0 {
                    pagination.after = Some(value.into_owned());
                } else {
                    pagination.user_id = Some(value.into_owned());
                }
            }
            1 => {
                if value.is_empty()
                    || value.starts_with('0')
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(invalid());
                }
                pagination.limit = value
                    .parse::<u32>()
                    .ok()
                    .filter(|value| (1..=50).contains(value))
                    .ok_or_else(invalid)?;
            }
            2 => {
                pagination.include_deleted = match value.as_ref() {
                    "true" => true,
                    "false" => false,
                    _ => return Err(invalid()),
                }
            }
            _ => return Err(invalid()),
        }
    }
    Ok(pagination)
}

async fn list_users(
    State(state): State<Arc<AppState>>,
    key: Option<Extension<automation::Key>>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let pagination = pagination(&uri, false)?;
    let page = coordinator(&state)?
        .read(move |directory| {
            if let Some(Extension(key)) = key {
                store::automation::list_users(
                    directory,
                    &key,
                    pagination.include_deleted,
                    pagination.after.as_deref(),
                    pagination.limit,
                )
            } else {
                store::list_users(
                    directory,
                    pagination.include_deleted,
                    pagination.after.as_deref(),
                    pagination.limit,
                )
            }
        })
        .await
        .map_err(automation::storage_error)?;
    Ok(Json(Page {
        revision: page.revision.to_string(),
        items: page.items.into_iter().map(User::from).collect::<Vec<_>>(),
        next_cursor: page.next_cursor,
    })
    .into_response())
}

async fn list_credentials(
    State(state): State<Arc<AppState>>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let pagination = pagination(&uri, true)?;
    let page = coordinator(&state)?
        .read(move |directory| {
            store::list_credentials(
                directory,
                pagination.user_id.as_deref(),
                pagination.after.as_deref(),
                pagination.limit,
            )
        })
        .await
        .map_err(storage_error)?;
    Ok(Json(Page {
        revision: page.revision.to_string(),
        items: page
            .items
            .into_iter()
            .map(Credential::from)
            .collect::<Vec<_>>(),
        next_cursor: page.next_cursor,
    })
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserInput {
    expected_revision: String,
    name: String,
    protocols: Vec<Protocol>,
    concurrent_limit: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionInput {
    expected_revision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateInput {
    expected_revision: String,
    active: bool,
}

async fn create_user(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    request: Request,
) -> Result<Response, ApiError> {
    let input: UserInput = json(request).await?;
    let change = PolicyChange::CreateUser {
        name: input.name,
        protocols: input.protocols,
        concurrent_limit: input.concurrent_limit,
    };
    mutate(
        &state,
        actor,
        revision(&input.expected_revision)?,
        change,
        StatusCode::CREATED,
    )
    .await
}

async fn update_user(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let id = resource_id(path)?;
    let input: UserInput = json(request).await?;
    let change = PolicyChange::UpdateUser {
        id,
        name: input.name,
        protocols: input.protocols,
        concurrent_limit: input.concurrent_limit,
    };
    mutate(
        &state,
        actor,
        revision(&input.expected_revision)?,
        change,
        StatusCode::OK,
    )
    .await
}

async fn user_state(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let id = resource_id(path)?;
    let input: StateInput = json(request).await?;
    mutate(
        &state,
        actor,
        revision(&input.expected_revision)?,
        PolicyChange::SetUserActive {
            id,
            active: input.active,
        },
        StatusCode::OK,
    )
    .await
}

async fn delete_user(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let id = resource_id(path)?;
    let input: RevisionInput = json(request).await?;
    mutate(
        &state,
        actor,
        revision(&input.expected_revision)?,
        PolicyChange::DeleteUser { id },
        StatusCode::OK,
    )
    .await
}

async fn create_credential(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let user_id = resource_id(path)?;
    let input: RevisionInput = json(request).await?;
    mutate(
        &state,
        actor,
        revision(&input.expected_revision)?,
        PolicyChange::CreateCredential { user_id },
        StatusCode::CREATED,
    )
    .await
}

async fn credential_state(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let id = resource_id(path)?;
    let input: StateInput = json(request).await?;
    mutate(
        &state,
        actor,
        revision(&input.expected_revision)?,
        PolicyChange::SetCredentialActive {
            id,
            active: input.active,
        },
        StatusCode::OK,
    )
    .await
}

async fn rotate_credential(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let id = resource_id(path)?;
    let input: RevisionInput = json(request).await?;
    mutate(
        &state,
        actor,
        revision(&input.expected_revision)?,
        PolicyChange::RotateCredential { id },
        StatusCode::OK,
    )
    .await
}

async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let id = resource_id(path)?;
    let input: RevisionInput = json(request).await?;
    mutate(
        &state,
        actor,
        revision(&input.expected_revision)?,
        PolicyChange::RevokeCredential { id },
        StatusCode::OK,
    )
    .await
}

async fn mutate(
    state: &AppState,
    actor: String,
    revision: u64,
    change: PolicyChange,
    status: StatusCode,
) -> Result<Response, ApiError> {
    let result = coordinator(state)?
        .change(actor, revision, change)
        .await
        .map_err(storage_error)?;
    // Serialize the newly issued secret synchronously into this HTTPS response,
    // then drop its zeroizing owner. No list/status endpoint can recover it.
    #[derive(Serialize)]
    struct Change<'a> {
        revision: String,
        user: Option<User>,
        credential: Option<Credential>,
        secret: Option<&'a str>,
    }
    Ok((
        status,
        Json(Change {
            revision: result.revision.to_string(),
            user: result.user.map(User::from),
            credential: result.credential.map(Credential::from),
            secret: result.secret.as_deref().map(String::as_str),
        }),
    )
        .into_response())
}

async fn search_users(
    State(state): State<Arc<AppState>>,
    key: Option<Extension<automation::Key>>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let query = crate::manage::user_search::Query::parse(uri.query()).map_err(storage_error)?;
    // The ordinary coordinator moves its read permit and author into the
    // blocking worker; dropping this HTTP waiter cannot release them early.
    let page = coordinator(&state)?
        .read(move |directory| {
            if let Some(Extension(key)) = key {
                store::automation::search_users(directory, &key, &query)
            } else {
                store::search_users(directory, &query)
            }
        })
        .await
        .map_err(automation::storage_error)?;
    Ok(Json(Page {
        revision: page.revision.to_string(),
        items: page.items.into_iter().map(User::from).collect::<Vec<_>>(),
        next_cursor: page.next_cursor,
    })
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::Reader;
    use crate::manage::api::tests::{call, managed_state, request};
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};

    mod delivery {
        //! Join the Session password-read boundary to real proxy clients. Cold owners
        //! reopen the same database/key; no first-delivery password survives the setup.

        use super::*;
        use crate::manage::{
            api::tests::{fixture_session, state as empty_state},
            files,
            policy::Coordinator,
            proxy::{
                self,
                service::{Managed, Service},
            },
            traffic,
        };
        use std::{io, net::SocketAddr, time::Duration};
        use tokio::{
            io::{AsyncReadExt as _, AsyncWriteExt as _},
            net::TcpListener,
        };
        use zeroize::Zeroizing;

        fn take_password(value: &mut Value) -> io::Result<Zeroizing<String>> {
            match value["secret"].take() {
                Value::String(password) => Ok(Zeroizing::new(password)),
                _ => Err(io::Error::other("test password response missing")),
            }
        }

        /// Trust exactly this fixture's leaf with an explicit provider. Environment
        /// proxies, public roots, redirects and connection pooling cannot mask a bad
        /// listener/password or turn this test into an external request.
        fn client(
            root: &rustls_pki_types::CertificateDer<'static>,
            scheme: &str,
            address: SocketAddr,
            login: &str,
            password: &str,
        ) -> io::Result<reqwest::Client> {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(root.clone()).map_err(io::Error::other)?;
            let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots)
            .with_no_client_auth();
            reqwest::Client::builder()
                .use_preconfigured_tls(tls)
                .no_proxy()
                .proxy(
                    reqwest::Proxy::all(format!("{scheme}://{address}"))
                        .map_err(io::Error::other)?
                        .basic_auth(login, password),
                )
                .redirect(reqwest::redirect::Policy::none())
                .http1_only()
                .pool_max_idle_per_host(0)
                .timeout(Duration::from_secs(5))
                .build()
                .map_err(io::Error::other)
        }

        /// A single known origin answers the three successful clients. Its explicit
        /// abort/join below also releases the socket if a client or assertion fails.
        async fn exercise(
            root: &rustls_pki_types::CertificateDer<'static>,
            addresses: &[SocketAddr],
            login: &str,
            password: &str,
        ) -> io::Result<()> {
            assert_eq!(addresses.len(), 3);
            assert!(addresses.iter().all(|address| address.ip().is_loopback()));
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let target = listener.local_addr()?;
            let mut origin = tokio::spawn(async move {
                for _ in 0..3 {
                    let (mut stream, _) =
                        tokio::time::timeout(Duration::from_secs(5), listener.accept())
                            .await
                            .map_err(io::Error::other)??;
                    let mut headers = Vec::new();
                    while !headers.ends_with(b"\r\n\r\n") {
                        if headers.len() >= 4096 {
                            return Err(io::Error::other("test origin headers too large"));
                        }
                        let byte = tokio::time::timeout(Duration::from_secs(5), stream.read_u8())
                            .await
                            .map_err(io::Error::other)??;
                        headers.push(byte);
                    }
                    let headers = std::str::from_utf8(&headers)
                        .map_err(io::Error::other)?
                        .to_ascii_lowercase();
                    assert!(headers.starts_with("get /delivery http/1.1\r\n"));
                    assert!(!headers.contains("proxy-authorization:"));
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\npassword-delivery").await?;
                    stream.shutdown().await?;
                }
                Ok::<_, io::Error>(())
            });
            let result = async {
                // The HTTP refusal must be an authentication response, not a generic
                // network failure. The successful client immediately follows it.
                let denied = client(
                    root,
                    "http",
                    addresses[0],
                    login,
                    "not-the-current-password",
                )?
                .get(format!("http://{target}/delivery"))
                .send()
                .await
                .map_err(io::Error::other)?;
                assert_eq!(
                    denied.status(),
                    reqwest::StatusCode::PROXY_AUTHENTICATION_REQUIRED
                );
                for (scheme, address) in ["http", "https", "socks5h"].into_iter().zip(addresses) {
                    let response = client(root, scheme, *address, login, password)?
                        .get(format!("http://{target}/delivery"))
                        .send()
                        .await
                        .map_err(io::Error::other)?;
                    assert_eq!(response.status(), reqwest::StatusCode::OK);
                    assert!(
                        response.bytes().await.map_err(io::Error::other)?.as_ref()
                            == b"password-delivery"
                    );
                }
                tokio::time::timeout(Duration::from_secs(5), &mut origin)
                    .await
                    .map_err(io::Error::other)?
                    .map_err(io::Error::other)??;
                Ok::<_, io::Error>(())
            }
            .await;
            if !origin.is_finished() {
                origin.abort();
                let _ = origin.await;
            }
            result
        }

        #[test]
        fn saved_password_authenticates_three_real_proxies_after_cold_owner_reopen()
        -> io::Result<()> {
            let (_directory, state, cookie) = managed_state();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let directory = state.directory.clone();
            let node = store::inspect(&directory)?.node_id;
            let dummy_phc = state.dummy_phc.clone();
            let administrator: String =
                rusqlite::Connection::open(directory.join("management.sqlite3"))
                    .map_err(io::Error::other)?
                    .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                    .map_err(io::Error::other)?;
            let (credential, expected_digest) = runtime.block_on(async {
                let (status, user) = invoke(
                    state.clone(),
                    &cookie,
                    Method::POST,
                    "/api/v1/proxy/users",
                    user_input("1"),
                )
                .await;
                assert_eq!(status, StatusCode::CREATED);
                let user = user["user"]["id"].as_str().expect("created user");
                let (status, mut created) = invoke(
                    state.clone(),
                    &cookie,
                    Method::POST,
                    &format!("/api/v1/proxy/users/{user}/credentials"),
                    json!({"expected_revision":"2"}),
                )
                .await;
                assert_eq!(status, StatusCode::CREATED);
                let password = take_password(&mut created)?;
                let credential = created["credential"].take();
                let id = credential["id"].as_str().expect("created credential");
                let digest = crate::access::digest_secret(id, password.as_bytes());
                // Drop the only first-delivery plaintext before any proxy is started.
                drop(password);
                Ok::<_, io::Error>((credential, digest))
            })?;
            drop(state);
            let identity =
                rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                    .map_err(io::Error::other)?;
            let tls_directory = directory.join("delivery-tls");
            files::create_directory(&tls_directory)?;
            files::write(&tls_directory, "cert.pem", identity.cert.pem().as_bytes())?;
            files::write(
                &tls_directory,
                "key.pem",
                identity.signing_key.serialize_pem().as_bytes(),
            )?;
            let tls = crate::manage::tls::proxy_identity(
                &tls_directory.join("cert.pem"),
                &tls_directory.join("key.pem"),
            )?;
            let mut previous_runtime = None;
            let mut previous_cursor = 0;
            for round in 0..2 {
                // Reacquiring this lease proves the prior owner actually finished.
                let author = Arc::new(store::lock(&directory)?);
                let policy = Coordinator::new(
                    directory.clone(),
                    store::load_policy(&directory)?,
                    author.clone(),
                )?;
                let (traffic, runner) = runtime.block_on(traffic::new(policy.clone()))?;
                let mut state = empty_state();
                let mutable = Arc::get_mut(&mut state).expect("unique cold fixture state");
                mutable.directory = directory.clone();
                mutable.schema_version = store::inspect(&directory)?.schema_version;
                mutable.node.node_id = node.clone();
                mutable.dummy_phc = dummy_phc.clone();
                mutable.policy = Some(policy.clone());
                mutable.traffic = Some(traffic.clone());
                mutable._author = Some(author.clone());
                let token = if round == 0 { "u" } else { "v" }.repeat(43);
                let mut session = fixture_session(Instant::now());
                session.administrator.id = administrator.clone();
                state
                    .security()
                    .map_err(|_| io::Error::other("test security lock unavailable"))?
                    .insert_session(None, token.clone(), session)
                    .map_err(|_| io::Error::other("test session unavailable"))?;
                let cookie = format!("{COOKIE_NAME}={token}");
                let mut managed = Managed::new(
                    policy.clone(),
                    traffic.clone(),
                    proxy::settings::Tls::Manual(tls.clone()),
                    crate::ebpf::Config::default(),
                    node.clone(),
                    vec![8443],
                )?;
                managed.ephemeral = true;
                let mut owner = Service::managed(managed, author.clone())?;
                let control = owner.control();
                policy.configure_service(node.clone(), control.clone())?;
                let result = runtime.block_on(async {
            owner.ready().await?;
            let restored = control.restore().await?;
            if round == 0 {
                assert_eq!(restored.phase, proxy::service::Phase::Stopped);
                let listeners: Vec<_> = [("http",18080),("https",18443),("socks5",11080)].into_iter()
                    .map(|(protocol,port)| json!({"protocol":protocol,"bind":format!("127.0.0.1:{port}"),"public_address":format!("localhost:{port}")})).collect();
                let (status, applied) = invoke(state.clone(), &cookie, Method::PUT, "/api/v1/proxy/service",
                    json!({"expected_node_id":node,"controller_epoch":"1","expected_revision":"1",
                        "request_id":base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,[73;16]),
                        "enabled":true,"configuration":{"workers":1,"concurrent":1024,"connect_timeout":10,"listeners":listeners}})).await;
                assert_eq!(status, StatusCode::ACCEPTED);
                assert_eq!(applied["operation"]["state"], "applied");
            } else {
                assert_eq!(restored.phase, proxy::service::Phase::Running);
            }
            let running = control.snapshot()?;
            let runtime_id = running.runtime.as_ref().expect("active runtime").snapshot()?.runtime_id;
            assert_ne!(previous_runtime.as_ref(), Some(&runtime_id));
            previous_runtime = Some(runtime_id);
            let id = credential["id"].as_str().expect("selected credential");
            let (status, mut revealed) = invoke(state.clone(), &cookie, Method::POST,
                &format!("/api/v1/proxy/credentials/{id}/secret"),
                json!({"expected_node_id":node,"controller_epoch":"1","verifier_revision":"1"})).await;
            assert_eq!(status, StatusCode::OK);
            let password = take_password(&mut revealed)?;
            assert!(crate::access::digest_secret(id, password.as_bytes()) == expected_digest);
            exercise(identity.cert.der(), &running.addresses, credential["login"].as_str().expect("selected login"), &password).await?;
            assert_eq!(store::load_policy(&directory)?.revision, 3);
            assert_eq!(store::list_credentials(&directory, None, None, 50)?.items.len(), 1);
            Ok::<_, io::Error>(())
        });
                let stopped = owner.finish();
                assert!(stopped.runtime_stopped);
                stopped.result?;
                runtime.block_on(traffic.finish(stopped.runtime_stopped))?;
                result?;
                let checkpoint = store::traffic::status(&directory)?;
                assert!(
                    checkpoint.clean
                        && !checkpoint.loss_possible
                        && checkpoint.cursor > previous_cursor
                );
                previous_cursor = checkpoint.cursor;
                drop((state, control, traffic, runner, policy, author));
            }
            Ok(())
        }
    }
    mod search {
        use super::*;

        #[tokio::test]
        async fn user_search_keeps_auth_strict_query_and_public_page_contracts_separate_from_legacy_pages()
         {
            let (_directory, state, cookie) = managed_state();
            let mut input = user_input("1");
            input["name"] = json!("Research %_界");
            let (status, created) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                "/api/v1/proxy/users",
                input,
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            let path = "/api/v1/proxy/users/search?mode=name&q=research+%25_%E7%95%8C&limit=1";
            let anonymous = call(state.clone(), request(Method::GET, path, "null")).await;
            assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                anonymous.headers()[header::WWW_AUTHENTICATE],
                "Bearer realm=\"vproxy\""
            );
            assert_eq!(anonymous.headers()[header::CACHE_CONTROL], "no-store");
            let (status, page) =
                invoke(state.clone(), &cookie, Method::GET, path, Value::Null).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(page.as_object().unwrap().len(), 3);
            assert_eq!(page["revision"], "2");
            assert_eq!(page["items"].as_array().unwrap().len(), 1);
            assert_eq!(page["items"][0]["id"], created["user"]["id"]);
            assert!(page["next_cursor"].is_null());
            let encoded = page.to_string();
            for hidden in ["secret", "password", "secret_digest", "verifier_version"] {
                assert!(!encoded.contains(hidden));
            }
            for query in [
                "mode=name&q=%FF",
                "mode=name&q=%",
                "mode=name&q=a&%71=b",
                "mode=name&q=a&extra=1",
                "mode=name&q=a&limit=51",
                "mode=id&q=invalid",
            ] {
                let (status, error) = invoke(
                    state.clone(),
                    &cookie,
                    Method::GET,
                    &format!("/api/v1/proxy/users/search?{query}"),
                    Value::Null,
                )
                .await;
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert_eq!(error["error"]["code"], "invalid_user_search");
            }
            let (status, error) = invoke(
                state.clone(),
                &cookie,
                Method::GET,
                "/api/v1/proxy/users/search?mode=name&q=a&after=invalid",
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(error["error"]["code"], "invalid_user_search_cursor");
            let (status, error) = invoke(
                state,
                &cookie,
                Method::GET,
                "/api/v1/proxy/users?mode=name&q=research",
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(error["error"]["code"], "invalid_pagination");
        }

        #[tokio::test]
        async fn user_search_continuations_require_the_original_filter_and_policy_revision() {
            let (_directory, state, cookie) = managed_state();
            for revision in 1..=3 {
                let (status, _) = invoke(
                    state.clone(),
                    &cookie,
                    Method::POST,
                    "/api/v1/proxy/users",
                    user_input(&revision.to_string()),
                )
                .await;
                assert_eq!(status, StatusCode::CREATED);
            }
            let (status, first) = invoke(
                state.clone(),
                &cookie,
                Method::GET,
                "/api/v1/proxy/users/search?mode=name&q=Research&limit=1",
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let cursor = first["next_cursor"].as_str().unwrap();
            assert_eq!(cursor.len(), 102);
            let continuation =
                format!("/api/v1/proxy/users/search?mode=name&q=research&limit=1&after={cursor}");
            let (status, second) = invoke(
                state.clone(),
                &cookie,
                Method::GET,
                &continuation,
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_ne!(first["items"][0]["id"], second["items"][0]["id"]);
            let (status, error) = invoke(
                state.clone(),
                &cookie,
                Method::GET,
                &format!("/api/v1/proxy/users/search?mode=name&q=other&limit=1&after={cursor}"),
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(error["error"]["code"], "invalid_user_search_cursor");
            let (status, _) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                "/api/v1/proxy/users",
                user_input("4"),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            let (status, error) =
                invoke(state, &cookie, Method::GET, &continuation, Value::Null).await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(error["error"]["code"], "user_search_changed");
        }
    }
    mod secrets {
        use super::*;

        #[tokio::test]
        async fn explicit_secret_read_requires_session_csrf_and_exact_current_generation() {
            let (_directory, state, cookie) = managed_state();
            let (status, user) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                "/api/v1/proxy/users",
                user_input("1"),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            let user_id = user["user"]["id"].as_str().unwrap();
            let (status, created) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                &format!("/api/v1/proxy/users/{user_id}/credentials"),
                json!({"expected_revision":"2"}),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            let id = created["credential"]["id"].as_str().unwrap();
            let path = format!("/api/v1/proxy/credentials/{id}/secret");
            let node_id = store::inspect(&state.directory).unwrap().node_id;
            let body = json!({"expected_node_id":node_id, "controller_epoch":"1", "verifier_revision":"1"});
            let anonymous = call(
                state.clone(),
                request(Method::POST, &path, &body.to_string()),
            )
            .await;
            assert_eq!(anonymous.status(), StatusCode::FORBIDDEN);
            assert!(anonymous.headers().get(header::WWW_AUTHENTICATE).is_none());
            let anonymous_bytes = anonymous.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                serde_json::from_slice::<Value>(&anonymous_bytes).unwrap()["error"]["code"],
                "authentication_required"
            );
            let mut no_csrf = request(Method::POST, &path, &body.to_string());
            no_csrf
                .headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            assert_eq!(
                call(state.clone(), no_csrf).await.status(),
                StatusCode::FORBIDDEN
            );
            let (status, shown) =
                invoke(state.clone(), &cookie, Method::POST, &path, body.clone()).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(shown["secret"], created["secret"]);
            assert_eq!(shown["credential_id"], id);
            assert_eq!(shown["user_id"], user_id);
            let mut unsupported = request(Method::GET, &path, "null");
            unsupported
                .headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            assert_eq!(
                call(state.clone(), unsupported).await.status(),
                StatusCode::METHOD_NOT_ALLOWED
            );
            let (status, _) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                &format!("{path}?secret=forbidden"),
                body.clone(),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            let (status, _) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                &format!("/api/v1/proxy/credentials/{id}/rotate"),
                json!({"expected_revision":"3"}),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let (status, result) = invoke(state.clone(), &cookie, Method::POST, &path, body).await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(result["error"]["code"], "credential_secret_changed");
        }

        #[tokio::test]
        async fn missing_key_refuses_rotation_without_disabling_existing_proxy_authentication() {
            let (_directory, state, cookie) = managed_state();
            let policy = coordinator(&state).unwrap();
            policy.activate().await.unwrap();
            let (_, user) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                "/api/v1/proxy/users",
                user_input("1"),
            )
            .await;
            let id = user["user"]["id"].as_str().unwrap();
            let (status, created) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                &format!("/api/v1/proxy/users/{id}/credentials"),
                json!({"expected_revision":"2"}),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            let credential = created["credential"]["id"].as_str().unwrap();
            std::fs::rename(
                state.directory.join("secrets/proxy-secrets.key"),
                state.directory.join("retained-test-key"),
            )
            .unwrap();
            let (status, result) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                &format!("/api/v1/proxy/credentials/{credential}/rotate"),
                json!({"expected_revision":"3"}),
            )
            .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(result["error"]["code"], "credential_secret_key_unavailable");
            assert!(
                policy
                    .reader()
                    .authenticate(
                        created["credential"]["login"].as_str().unwrap(),
                        created["secret"].as_str().unwrap().as_bytes(),
                        Protocol::Http
                    )
                    .is_ok()
            );
            assert_eq!(policy.status().await.unwrap().saved_revision, 3);
        }
    }

    async fn invoke(
        state: Arc<AppState>,
        cookie: &str,
        method: Method,
        path: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut request = request(method, path, &body.to_string());
        request
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        request
            .headers_mut()
            .insert("x-csrf-token", "c".repeat(43).parse().unwrap());
        let response = call(state, request).await;
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn user_input(revision: &str) -> Value {
        json!({"expected_revision":revision, "name":"Research", "protocols":["http","socks5"],
        "concurrent_limit":2})
    }

    /// Exercise the HTTP boundary, not just the SQL mutation helpers: wire revisions
    /// stay strings, secret output is one-time, and hot publication affects admission.
    #[tokio::test]
    async fn crud_publishes_live_policy_rotates_secrets_and_preserves_tombstones() {
        let (_directory, state, cookie) = managed_state();
        let policy = coordinator(&state).unwrap();
        let (_, before) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/proxy/policy",
            Value::Null,
        )
        .await;
        assert_eq!(before["saved_revision"], "1");
        assert_eq!(before["proxy_running"], false);
        assert!(before["applied_revision"].is_null());
        policy.activate().await.unwrap();

        let (status, created) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            "/api/v1/proxy/users",
            user_input("1"),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["revision"], "2");
        let id = created["user"]["id"].as_str().unwrap();
        let credentials = format!("/api/v1/proxy/users/{id}/credentials");
        let (status, created_credential) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &credentials,
            json!({"expected_revision":"2"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let login = created_credential["credential"]["login"].as_str().unwrap();
        let secret = created_credential["secret"].as_str().unwrap();
        let credential_id = created_credential["credential"]["id"].as_str().unwrap();
        let credential_path = format!("/api/v1/proxy/credentials/{credential_id}");
        assert_eq!(secret.len(), 43);
        let flow = policy
            .reader()
            .authenticate(login, secret.as_bytes(), Protocol::Http)
            .unwrap();
        assert_eq!(
            policy
                .reader()
                .authenticate(login, secret.as_bytes(), Protocol::Masque)
                .err(),
            Some(crate::access::Error::Denied)
        );

        let (_, page) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            &format!("/api/v1/proxy/credentials?user_id={id}&limit=1"),
            Value::Null,
        )
        .await;
        assert_eq!(page["revision"], "3");
        let page = page.to_string();
        for hidden in [secret, "secret_digest", "verifier_version", "password"] {
            assert!(!page.contains(hidden));
        }

        let (status, stale) = invoke(
            state.clone(),
            &cookie,
            Method::PUT,
            &format!("/api/v1/proxy/users/{id}"),
            user_input("2"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(stale["error"]["code"], "policy_conflict");
        let (status, updated) = invoke(
            state.clone(),
            &cookie,
            Method::PUT,
            &format!("/api/v1/proxy/users/{id}"),
            user_input("3"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(updated["revision"], "4");

        let (status, rotated) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("{credential_path}/rotate"),
            json!({"expected_revision":"4"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rotated["credential"]["login"], login);
        assert_eq!(rotated["credential"]["verifier_revision"], "2");
        let next_secret = rotated["secret"].as_str().unwrap();
        assert_ne!(next_secret, secret);
        assert_eq!(
            policy
                .reader()
                .authenticate(login, secret.as_bytes(), Protocol::Http)
                .err(),
            Some(crate::access::Error::InvalidCredentials)
        );
        drop(flow);
        drop(
            policy
                .reader()
                .authenticate(login, next_secret.as_bytes(), Protocol::Socks5)
                .unwrap(),
        );

        for (suffix, active, revision) in [
            (format!("/api/v1/proxy/users/{id}/state"), false, "5"),
            (format!("/api/v1/proxy/users/{id}/state"), true, "6"),
            (format!("{credential_path}/state"), false, "7"),
            (format!("{credential_path}/state"), true, "8"),
        ] {
            let (status, changed) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                &suffix,
                json!({"expected_revision":revision,"active":active}),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(changed["secret"].is_null());
            let result =
                policy
                    .reader()
                    .authenticate(login, next_secret.as_bytes(), Protocol::Http);
            if active {
                drop(result.unwrap());
            } else {
                assert_eq!(result.err(), Some(crate::access::Error::Denied));
            }
        }
        let (status, revoked) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("{credential_path}/revoke"),
            json!({"expected_revision":"9"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(revoked["credential"]["revoked"], true);
        assert_eq!(revoked["credential"]["verifier_revision"], "2");
        for suffix in ["rotate", "state"] {
            let mut body = json!({"expected_revision":"10"});
            if suffix == "state" {
                body["active"] = true.into();
            }
            let (status, _) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                &format!("{credential_path}/{suffix}"),
                body,
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT);
        }
        let (status, _) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("/api/v1/proxy/users/{id}/delete"),
            json!({"expected_revision":"10"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, page) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/proxy/users",
            Value::Null,
        )
        .await;
        assert_eq!(page["items"].as_array().unwrap().len(), 0);
        let (_, page) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/proxy/users?include_deleted=true",
            Value::Null,
        )
        .await;
        assert_eq!(page["items"][0]["deleted"], true);
        let (_, status) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/proxy/policy",
            Value::Null,
        )
        .await;
        for key in [
            "saved_revision",
            "applied_revision",
            "durable_applied_revision",
        ] {
            assert_eq!(status[key], "11");
        }
        policy.deactivate();
        let (_, stopped) = invoke(
            state,
            &cookie,
            Method::GET,
            "/api/v1/proxy/policy",
            Value::Null,
        )
        .await;
        assert!(stopped["applied_revision"].is_null());
        assert_eq!(stopped["durable_applied_revision"], "11");
    }

    /// Session/Origin/CSRF failures and malformed wire input must not mutate storage.
    #[tokio::test]
    async fn mutation_guards_and_strict_dtos_precede_policy_writes() {
        let (_directory, state, cookie) = managed_state();
        for (with_cookie, csrf, expected) in [
            (false, None, "authentication_required"),
            (true, None, "invalid_csrf"),
            (true, Some("wrong"), "invalid_csrf"),
        ] {
            let mut req = request(
                Method::POST,
                "/api/v1/proxy/users",
                &user_input("1").to_string(),
            );
            if with_cookie {
                req.headers_mut()
                    .insert(header::COOKIE, cookie.parse().unwrap());
            }
            if let Some(csrf) = csrf {
                req.headers_mut()
                    .insert("x-csrf-token", csrf.parse().unwrap());
            }
            let response = call(state.clone(), req).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                serde_json::from_slice::<Value>(&bytes).unwrap()["error"]["code"],
                expected
            );
        }
        for invalid_revision in ["0", "01", "-1", "9223372036854775808", "1e0"] {
            let (status, body) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                "/api/v1/proxy/users",
                user_input(invalid_revision),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"]["code"], "invalid_revision");
        }
        for field in ["actor", "secret", "administrator_id"] {
            let mut body = user_input("1");
            body[field] = "forged".into();
            let (status, _) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                "/api/v1/proxy/users",
                body,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        for query in [
            "limit=0",
            "limit=51",
            "limit=01",
            "limit=1&limit=2",
            "include_deleted=yes",
            "user_id=bad",
            "after=bad",
            "unknown=1",
        ] {
            let (status, body) = invoke(
                state.clone(),
                &cookie,
                Method::GET,
                &format!("/api/v1/proxy/users?{query}"),
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"]["code"], "invalid_pagination");
        }
        let policy = coordinator(&state).unwrap();
        let permit = policy.write_work().acquire_owned().await.unwrap();
        let (status, body) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/proxy/policy",
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "policy_busy");
        drop(permit);
        assert_eq!(store::policy_status(&state.directory).unwrap().revision, 1);
    }

    /// Ownership is a separate CAS namespace. Only the authenticated local actor
    /// may grant a registered peer or explicitly take the unchanged policy back.
    #[tokio::test]
    async fn owner_grants_require_session_csrf_and_explicit_epoch_takeover() {
        let (_directory, state, cookie) = managed_state();
        let policy = coordinator(&state).unwrap();
        let peer_id = URL_SAFE_NO_PAD.encode([7; 16]);
        for with_csrf in [false, true] {
            let mut req = request(
                Method::PUT,
                "/api/v1/proxy/owner",
                r#"{"expected_epoch":"1","controller_node_id":null}"#,
            );
            if !with_csrf {
                req.headers_mut()
                    .insert(header::COOKIE, cookie.parse().unwrap());
            } else {
                req.headers_mut()
                    .insert("x-csrf-token", "c".repeat(43).parse().unwrap());
            }
            assert_eq!(
                call(state.clone(), req).await.status(),
                StatusCode::FORBIDDEN
            );
        }
        let (status, initial) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/proxy/owner",
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            initial,
            json!({"controller_node_id":null,"epoch":"1","last_terminal_command":"0"})
        );
        for invalid in [
            json!({"expected_epoch":"1"}),
            json!({"expected_epoch":"1","controller_node_id":"not-an-id"}),
            json!({"expected_epoch":"1","controller_node_id":null,"administrator_id":peer_id}),
        ] {
            let (status, _) = invoke(
                state.clone(),
                &cookie,
                Method::PUT,
                "/api/v1/proxy/owner",
                invalid,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        let grant = json!({"expected_epoch":"1","controller_node_id":peer_id});
        let (status, denied) = invoke(
            state.clone(),
            &cookie,
            Method::PUT,
            "/api/v1/proxy/owner",
            grant.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(denied["error"]["code"], "peer_not_authorized");
        store::register_peer(
            &state.directory,
            &peer_id,
            "Controller",
            b"fixture peer leaf",
            "controller.example",
            None,
        )
        .unwrap();
        let (status, granted) = invoke(
            state.clone(),
            &cookie,
            Method::PUT,
            "/api/v1/proxy/owner",
            grant,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(granted["epoch"], "2");
        assert_eq!(granted["controller_node_id"], peer_id);

        let (status, managed) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            "/api/v1/proxy/users",
            user_input("1"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(managed["error"]["code"], "resource_managed");
        assert_eq!(policy.reader().revision().unwrap(), 1);
        let (status, stale) = invoke(
            state.clone(),
            &cookie,
            Method::PUT,
            "/api/v1/proxy/owner",
            json!({"expected_epoch":"1","controller_node_id":null}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(stale["error"]["code"], "owner_conflict");
        assert_eq!(policy.reader().revision().unwrap(), 1);
        let permit = policy.write_work().acquire_owned().await.unwrap();
        let (status, busy) = invoke(
            state.clone(),
            &cookie,
            Method::PUT,
            "/api/v1/proxy/owner",
            json!({"expected_epoch":"2","controller_node_id":null}),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(busy["error"]["code"], "policy_busy");
        drop(permit);
        let (status, taken) = invoke(
            state.clone(),
            &cookie,
            Method::PUT,
            "/api/v1/proxy/owner",
            json!({"expected_epoch":"2","controller_node_id":null}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(taken["epoch"], "3");
        assert!(taken["controller_node_id"].is_null());
        let (status, _) = invoke(
            state,
            &cookie,
            Method::POST,
            "/api/v1/proxy/users",
            user_input("1"),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(policy.reader().revision().unwrap(), 2);
    }

    /// A browser ownership grant and node commands operate on the same live reader.
    /// At-most-once replay returns only durable metadata, not another credential.
    #[tokio::test]
    async fn remote_commands_share_browser_service_and_do_not_replay_secrets() {
        let (_directory, state, cookie) = managed_state();
        let policy = coordinator(&state).unwrap();
        let peer_id = URL_SAFE_NO_PAD.encode([9; 16]);
        // Store authorization repeats the registered SAN check inside its SQL
        // transaction, independently of the transport's earlier TLS handshake.
        let certificate =
            rcgen::generate_simple_self_signed(vec!["controller.example".into()]).unwrap();
        let leaf: Arc<[u8]> = Arc::from(certificate.cert.der().as_ref());
        let peer = store::register_peer(
            &state.directory,
            &peer_id,
            "Controller",
            &leaf,
            "controller.example",
            None,
        )
        .unwrap();
        let authorization = || store::RemoteAuthorization {
            node_id: peer_id.clone(),
            authorization_revision: peer.authorization_revision,
            leaf: leaf.clone(),
        };
        let target = store::inspect(&state.directory).unwrap().node_id;
        let command = |id, expected, change| store::Command {
            target_node_id: target.clone(),
            epoch: 2,
            command_id: id,
            expected_policy_revision: expected,
            source_administrator_id: URL_SAFE_NO_PAD.encode([10; 16]),
            change,
        };
        let (status, _) = invoke(
            state.clone(),
            &cookie,
            Method::PUT,
            "/api/v1/proxy/owner",
            json!({"expected_epoch":"1","controller_node_id":peer_id}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let created = policy
            .command(
                authorization(),
                command(
                    1,
                    1,
                    PolicyChange::CreateUser {
                        name: "Remote user".into(),
                        protocols: vec![Protocol::Http],
                        concurrent_limit: 1,
                    },
                ),
            )
            .await
            .unwrap();
        assert!(!created.replayed);
        assert_eq!(created.receipt.status, store::ReceiptStatus::Saved);
        let id = created.user.unwrap().id;
        assert_eq!(policy.reader().revision().unwrap(), 2);
        let credential = || PolicyChange::CreateCredential {
            user_id: id.clone(),
        };
        let created = policy
            .command(authorization(), command(2, 2, credential()))
            .await
            .unwrap();
        let login = created.credential.unwrap().login;
        let secret = created.secret.unwrap();
        drop(
            policy
                .reader()
                .authenticate(&login, secret.as_bytes(), Protocol::Http)
                .unwrap(),
        );
        let replayed = policy
            .command(authorization(), command(2, 2, credential()))
            .await
            .unwrap();
        assert!(replayed.replayed);
        assert!(replayed.user.is_none());
        assert!(replayed.credential.is_none());
        assert!(replayed.secret.is_none());
        assert_eq!(policy.reader().revision().unwrap(), 3);
        let (_, observed) = invoke(
            state,
            &cookie,
            Method::GET,
            "/api/v1/proxy/policy",
            Value::Null,
        )
        .await;
        assert_eq!(observed["saved_revision"], "3");
        assert_eq!(observed["proxy_running"], false);
        assert!(observed["applied_revision"].is_null());

        policy.activate().await.unwrap();
        let authorization = authorization();
        let receipt = policy.read(move |directory| store::receipt(directory, &authorization, 2, 2));
        // Startup repairs only the receipt for its exact actually loaded revision.
        assert_eq!(receipt.await.unwrap().status, store::ReceiptStatus::Applied);
    }

    /// A browser disconnect cannot cancel a committed change's publication or
    /// release its process author lock while the blocking writer is still running.
    #[tokio::test]
    async fn cancelled_http_writer_keeps_its_permit_and_publishes_before_release() {
        let (_directory, state, cookie) = managed_state();
        let policy = coordinator(&state).unwrap();
        let database =
            rusqlite::Connection::open(state.directory.join("management.sqlite3")).unwrap();
        database.execute_batch("BEGIN IMMEDIATE").unwrap();
        let writer_state = state.clone();
        let writer = tokio::spawn(async move {
            invoke(
                writer_state,
                &cookie,
                Method::POST,
                "/api/v1/proxy/users",
                user_input("1"),
            )
            .await
        });
        timeout(Duration::from_secs(2), async {
            while policy.write_work().available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        writer.abort();
        let _ = writer.await;
        assert_eq!(policy.write_work().available_permits(), 0);
        assert_eq!(
            store::lock(&state.directory).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        database.execute_batch("COMMIT").unwrap();
        timeout(Duration::from_secs(3), async {
            while policy.write_work().available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(policy.reader().revision().unwrap(), 2);
        assert_eq!(store::policy_status(&state.directory).unwrap().revision, 2);
    }

    /// An impossible/out-of-order in-memory publication after a real commit must
    /// close admission, not authorize from the earlier snapshot or claim application.
    #[tokio::test]
    async fn failed_publication_is_fail_closed_and_restart_uses_saved_policy() {
        let (_directory, state, cookie) = managed_state();
        let policy = coordinator(&state).unwrap();
        let mut future = store::load_policy(&state.directory).unwrap();
        future.revision = 3;
        policy.reader().publish(future).unwrap();
        let (status, body) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            "/api/v1/proxy/users",
            user_input("1"),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "policy_publication_failed");
        assert!(policy.reader().revision().is_err());
        let stored = store::policy_status(&state.directory).unwrap();
        assert_eq!(stored.revision, 2);
        assert_eq!(stored.applied_revision, None);
        let recovered = Reader::new(store::load_policy(&state.directory).unwrap()).unwrap();
        assert_eq!(recovered.revision().unwrap(), 2);
    }
}
