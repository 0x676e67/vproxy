//! Header-only machine authentication for local users and non-secret operations.
//!
//! Parsing never creates an administrator or grants authority. The store checks
//! the key again in the same transaction that reads users or manages operations.

use super::*;
use crate::manage::store::automation::{Credential, Error};

pub(super) type Key = Arc<Credential>;

const REALM: &str = "Bearer realm=\"vproxy\"";
const INVALID_TOKEN: &str = "Bearer realm=\"vproxy\", error=\"invalid_token\"";
const INVALID_REQUEST: &str = "Bearer realm=\"vproxy\", error=\"invalid_request\"";
const WRITE_SCOPE: &str =
    "Bearer realm=\"vproxy\", error=\"insufficient_scope\", scope=\"users:write\"";

/// Exact resources, not a path prefix: target control and credential metadata
/// are deliberately outside this grant. HEAD has the same authority as GET.
pub(super) fn enabled(method: &Method, uri: &Uri) -> bool {
    let read = matches!(*method, Method::GET | Method::HEAD);
    match uri.path() {
        "/api/v1/proxy/users" | "/api/v1/proxy/users/search" => read,
        "/api/v1/proxy/user-operations" => read || *method == Method::POST,
        "/api/v1/proxy/user-operations/context" => read,
        path => path
            .strip_prefix("/api/v1/proxy/user-operations/")
            .is_some_and(|tail| {
                let (id, execute) = tail
                    .strip_suffix("/execute")
                    .map_or((tail, false), |id| (id, true));
                // Match one literal ID segment, never a prefix, encoded slash
                // or another operation subtree. Handlers still validate IDs.
                id.len() == 22
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
                    && if execute {
                        *method == Method::POST
                    } else {
                        read
                    }
            }),
    }
}

/// Run at the outer boundary, including login, session and static fallbacks.
/// An Authorization header cannot be ignored in favor of an ambient Cookie.
/// Unsupported resources are denied before identity lookup; this is a route
/// policy decision, not a claim that an unverified token has a particular scope.
pub(super) fn validate_request(
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
) -> Result<(), ApiError> {
    // Do not advertise Bearer as an authentication option on Cookie-only
    // resources. Their header-policy rejection has no HTTP challenge.
    let malformed = || {
        if enabled(method, uri) {
            invalid_request()
        } else {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_automation_authentication")
        }
    };
    if headers.contains_key(header::PROXY_AUTHORIZATION) {
        return Err(malformed());
    }
    let Some(_) = single_header(headers, header::AUTHORIZATION).map_err(|_| malformed())? else {
        return Ok(());
    };
    if headers.contains_key(header::COOKIE) || headers.contains_key("x-csrf-token") {
        return Err(malformed());
    }
    if !enabled(method, uri) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "automation_route_denied",
        ));
    }
    Ok(())
}

/// RFC 6750 section 2.1 allows one or more SP after the case-insensitive scheme.
/// Field OWS is not part of the credential; internal token bytes stay strict.
/// Unsupported schemes use a challenge without an error, while a malformed or
/// expired issued token uses invalid_token (section 3.1).
/// https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1
/// https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1
pub(super) fn credential(headers: &HeaderMap) -> Result<Option<Key>, ApiError> {
    let Some(value) =
        single_header(headers, header::AUTHORIZATION).map_err(|_| invalid_request())?
    else {
        return Ok(None);
    };
    if value.len() > 256 {
        return Err(invalid_request());
    }
    let value = value.trim_matches([' ', '\t']);
    if value.contains('\t') {
        return Err(invalid_request());
    }
    let Some((scheme, token)) = value.split_once(' ') else {
        return Err(if value.eq_ignore_ascii_case("Bearer") {
            invalid_request()
        } else {
            authentication_required()
        });
    };
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(authentication_required());
    }
    Credential::parse(token.trim_start_matches(' '))
        .map(Arc::new)
        .map(Some)
        .map_err(storage_error)
}

/// These resources now support a real HTTP challenge; Cookie-only endpoints
/// retain their separate form/session semantics. No error attribute is sent
/// when no supported HTTP credential was supplied (RFC 6750 section 3.1).
pub(super) const fn authentication_required() -> ApiError {
    ApiError {
        status: StatusCode::UNAUTHORIZED,
        code: "authentication_required",
        challenge: Some(REALM),
    }
}

fn invalid_request() -> ApiError {
    ApiError {
        status: StatusCode::BAD_REQUEST,
        code: "invalid_automation_authentication",
        challenge: Some(INVALID_REQUEST),
    }
}

pub(super) fn storage_error(error: io::Error) -> ApiError {
    if let Some(error) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<Error>())
    {
        return match error {
            Error::Unauthorized => ApiError {
                status: StatusCode::UNAUTHORIZED,
                code: "invalid_token",
                challenge: Some(INVALID_TOKEN),
            },
            // Authentication is already checked inside the store snapshot;
            // never reveal a required scope for an invalid/revoked key.
            // https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1
            Error::InsufficientScope => ApiError {
                status: StatusCode::FORBIDDEN,
                code: "insufficient_scope",
                challenge: Some(WRITE_SCOPE),
            },
            Error::UpgradeRequired => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error.code()),
            Error::InvalidInput => ApiError::new(StatusCode::BAD_REQUEST, error.code()),
            Error::Conflict | Error::Capacity => ApiError::new(StatusCode::CONFLICT, error.code()),
        };
    }
    // I/O, SQL, worker and search errors keep their original storage class;
    // they must not become a false credential rejection.
    users::storage_error(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::{
        api::tests::{call, managed_state, request},
        store,
    };
    use axum::body::Body;
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};
    use zeroize::Zeroizing;

    const USERS: &str = "/api/v1/proxy/users";

    fn issue(state: &AppState) -> (store::automation::View, Zeroizing<String>) {
        issue_scope(state, store::automation::Scope::UsersRead)
    }

    fn issue_scope(
        state: &AppState,
        scope: store::automation::Scope,
    ) -> (store::automation::View, Zeroizing<String>) {
        let mut token = Zeroizing::new(String::new());
        let view =
            store::automation::create(&state.directory, "API automation", scope, 3600, |value| {
                token.push_str(value);
                Ok(())
            })
            .unwrap();
        (view, token)
    }

    fn authorized(method: Method, path: &str, token: &str) -> Request {
        let mut input = request(method, path, "null");
        let header = Zeroizing::new(format!("Bearer {token}"));
        input.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&header).unwrap(),
        );
        input
    }

    async fn body(response: Response) -> Value {
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn the_outer_guard_never_falls_back_to_cookie_or_another_resource() {
        let (_directory, state, cookie) = managed_state();
        let (_identity, token) = issue(&state);
        for scheme in ["Bearer malformed", "Basic malformed"] {
            let mut input = request(Method::GET, USERS, "");
            input
                .headers_mut()
                .insert(header::AUTHORIZATION, scheme.parse().unwrap());
            input
                .headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            let response = call(state.clone(), input).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response.headers()[header::WWW_AUTHENTICATE],
                INVALID_REQUEST
            );
        }
        for (method, path) in [
            (Method::POST, USERS),
            (Method::GET, "/api/v1/targets"),
            (Method::GET, "/index.html"),
        ] {
            let response = call(state.clone(), authorized(method, path, &token)).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
            assert_eq!(
                body(response).await["error"]["code"],
                "automation_route_denied"
            );
        }
        for name in [header::COOKIE] {
            let mut input = authorized(Method::GET, USERS, &token);
            input
                .headers_mut()
                .insert(name, HeaderValue::from_static("ambiguous"));
            assert_eq!(
                call(state.clone(), input).await.status(),
                StatusCode::BAD_REQUEST
            );
        }
        let mut duplicate = authorized(Method::GET, USERS, &token);
        duplicate.headers_mut().append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer malformed"),
        );
        assert_eq!(
            call(state.clone(), duplicate).await.status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn write_scope_uses_canonical_operations_and_same_principal_history_after_rotation() {
        let (_directory, state, cookie) = managed_state();
        let (identity, token) = issue_scope(&state, store::automation::Scope::UsersWrite);
        const BASE: &str = "/api/v1/proxy/user-operations";
        let index = 0_usize;
        let action = "create_user";
        let change = json!({"action":action,"name":"Automation user","protocols":["http"],"concurrent_limit":2});
        let input =
            json!({"expected_revision":(index+1).to_string(),"expected_epoch":"1","change":change});
        let mut reserve_request = authorized(Method::POST, BASE, &token);
        reserve_request.headers_mut().remove(header::ORIGIN);
        *reserve_request.body_mut() = Body::from(input.to_string());
        let reserved = call(state.clone(), reserve_request).await;
        assert_eq!(reserved.status(), StatusCode::CREATED);
        let reserved = body(reserved).await;
        let id = reserved["id"].as_str().unwrap();
        let mut execute_request = authorized(Method::POST, &format!("{BASE}/{id}/execute"), &token);
        execute_request.headers_mut().remove(header::ORIGIN);
        *execute_request.body_mut() = Body::from(input.to_string());
        let saved = call(state.clone(), execute_request).await;
        assert_eq!(saved.status(), StatusCode::OK);
        let saved = body(saved).await;
        assert_eq!(saved["state"], "saved");
        assert_eq!(saved["saved_revision"], (index + 2).to_string());
        let first_id = id.to_owned();
        let first_result = saved;
        let first_input = input;

        let path = format!("{BASE}/{first_id}");
        let mut browser = request(Method::GET, &path, "null");
        browser
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(
            call(state.clone(), browser).await.status(),
            StatusCode::NOT_FOUND
        );
        let (_, other) = issue_scope(&state, store::automation::Scope::UsersWrite);
        assert_eq!(
            call(state.clone(), authorized(Method::GET, &path, &other))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        let mut current = Zeroizing::new(String::new());
        store::automation::rotate(
            &state.directory,
            &identity.id,
            identity.generation,
            3600,
            |value| {
                current.push_str(value);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            call(state.clone(), authorized(Method::GET, &path, &token))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let recovered = call(state.clone(), authorized(Method::GET, &path, &current)).await;
        assert_eq!(recovered.status(), StatusCode::OK);
        assert_eq!(body(recovered).await, first_result);
        let mut replay = authorized(Method::POST, &format!("{path}/execute"), &current);
        *replay.body_mut() = Body::from(first_input.to_string());
        let replay = call(state.clone(), replay).await;
        assert_eq!(replay.status(), StatusCode::OK);
        assert_eq!(body(replay).await, first_result);
        let read = call(state, authorized(Method::GET, USERS, &current)).await;
        assert_eq!(read.status(), StatusCode::OK);
    }

    #[test]
    fn a_queued_write_rechecks_revocation_inside_its_owned_sql_worker() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
        let (_directory, state, _cookie) = managed_state();
        let (identity, token) = issue_scope(&state, store::automation::Scope::UsersWrite);
        let (started, entered) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel::<()>();
        struct Release(std::sync::mpsc::Sender<()>);
        impl Drop for Release {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        // An assertion failure still releases the blocker before runtime drop.
        let release = Release(release);
        let worker = tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            wait.recv_timeout(Duration::from_secs(5))
        });
        entered.await.unwrap();
        let mut request = authorized(Method::POST, "/api/v1/proxy/user-operations", &token);
        *request.body_mut() = Body::from(json!({"expected_revision":"1","expected_epoch":"1","change":{
            "action":"create_user","name":"Must not be reserved","protocols":["http"],"concurrent_limit":1
        }}).to_string());
        let mut pending = Box::pin(call(state.clone(), request));
        assert!(futures_util::poll!(&mut pending).is_pending());
        store::automation::revoke(&state.directory, &identity.id, identity.generation).unwrap();
        drop(release);
        let response = tokio::time::timeout(Duration::from_secs(5), pending).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], INVALID_TOKEN);
        assert_eq!(body(response).await["error"]["code"], "invalid_token");
        worker.await.unwrap().unwrap();
        let connection = rusqlite::Connection::open(state.directory.join("management.sqlite3")).unwrap();
        let reserved: i64 = connection.query_row("SELECT count(*) FROM user_operations", [], |row| row.get(0)).unwrap();
        assert_eq!(reserved, 0);
        assert_eq!(state.policy.as_ref().unwrap().reader().revision().unwrap(), 1);
    });
    }
}
