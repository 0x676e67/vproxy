//! Administrator HTTP adapter for the shared policy and ownership service.
//!
//! Session middleware supplies the real administrator identity; neither JSON
//! nor the node transport can impersonate this actor. Passwords never enter
//! audit/logs; explicit current-generation reads are separate from mutations.

use axum::extract::{Path, rejection::PathRejection};

use super::*;
use crate::access::Protocol;
use crate::manage::views::{RevisionInput, StateInput};
use crate::manage::{
    maintenance::Ownership as OwnerView,
    policy::{self as service, Coordinator},
    store::{self, PolicyChange},
    views::{self, Credential, Page, User, required_nullable},
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
    views::revision(value).map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_revision"))
}

pub(super) fn resource_id(path: Result<Path<String>, PathRejection>) -> Result<String, ApiError> {
    let Path(id) =
        path.map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_resource_id"))?;
    if !store::valid_id(&id) {
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerInput {
    expected_epoch: String,
    // Missing and explicit null must not mean the same thing: a missing field
    // cannot accidentally turn a partial update into an ownership revocation.
    #[serde(deserialize_with = "required_nullable")]
    controller_node_id: Option<String>,
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
    if let Some(id) = &input.controller_node_id
        && !store::valid_id(id)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_resource_id",
        ));
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

/// Small allowlisted query vocabulary. Reject duplicates and unknown fields
/// rather than silently dropping a misspelled filter in a security UI.
pub(super) struct Pagination {
    pub(super) after: Option<String>,
    pub(super) limit: u32,
    pub(super) include_deleted: bool,
    pub(super) user_id: Option<String>,
}

pub(super) fn pagination(uri: &Uri, credentials: bool) -> Result<Pagination, ApiError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Parameters {
        after: Option<String>,
        limit: Option<String>,
        include_deleted: Option<bool>,
        user_id: Option<String>,
    }
    let raw = uri.query().unwrap_or_default();
    let invalid = || ApiError::new(StatusCode::BAD_REQUEST, "invalid_pagination");
    if raw.len() > 1024 {
        return Err(invalid());
    }
    let query: Parameters = serde_urlencoded::from_str(raw).map_err(|_| invalid())?;
    if (credentials && query.include_deleted.is_some()) || (!credentials && query.user_id.is_some())
    {
        return Err(invalid());
    }
    for value in query.after.iter().chain(query.user_id.iter()) {
        if !store::valid_id(value) {
            return Err(invalid());
        }
    }
    let limit = query
        .limit
        .map(|text| {
            text.parse::<u32>()
                .ok()
                .filter(|value| (1..=50).contains(value) && value.to_string() == text)
                .ok_or_else(invalid)
        })
        .transpose()?
        .unwrap_or(25);
    Ok(Pagination {
        after: query.after,
        limit,
        include_deleted: query.include_deleted.unwrap_or(false),
        user_id: query.user_id,
    })
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
}
