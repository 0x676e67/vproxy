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

    #[test]
    fn scheme_and_spacing_follow_bearer_grammar_without_granting_an_identity() {
        let token = format!(
            "vpa1.{}.1.{}",
            URL_SAFE_NO_PAD.encode([1; 16]),
            URL_SAFE_NO_PAD.encode([2; 32])
        );
        for scheme in ["Bearer ", "bearer ", "BEARER   "] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                format!("{scheme}{token}").parse().unwrap(),
            );
            assert!(credential(&headers).unwrap().is_some());
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic anything"),
        );
        let rejection = credential(&headers).err().unwrap().into_response();
        assert_eq!(rejection.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(rejection.headers()[header::WWW_AUTHENTICATE], REALM);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer not-an-issued-token"),
        );
        let rejection = credential(&headers).err().unwrap().into_response();
        assert_eq!(rejection.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(rejection.headers()[header::WWW_AUTHENTICATE], INVALID_TOKEN);
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer another"),
        );
        assert_eq!(
            credential(&headers).err().unwrap().status,
            StatusCode::BAD_REQUEST
        );
        headers.clear();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer\t{token}").parse().unwrap(),
        );
        assert_eq!(
            credential(&headers).err().unwrap().status,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn machine_reads_reuse_the_user_contract_and_leave_cookie_management_intact() {
        let (_directory, state, cookie) = managed_state();
        let mut creation = request(Method::POST, USERS, &json!({
        "expected_revision":"1", "name":"Machine readable", "protocols":["http"], "concurrent_limit":2
    }).to_string());
        creation
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        creation
            .headers_mut()
            .insert("x-csrf-token", "c".repeat(43).parse().unwrap());
        let created = call(state.clone(), creation).await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let id = body(created).await["user"]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let (_identity, token) = issue(&state);
        for (label, path) in [
            ("list", USERS.to_owned()),
            ("search", format!("{USERS}/search?mode=id&q={id}&limit=1")),
        ] {
            let response = call(state.clone(), authorized(Method::GET, &path, &token)).await;
            // Classify only the fixed challenge vocabulary. Never include a raw
            // header, query, identity or response body in failure diagnostics.
            let challenges = response.headers().get_all(header::WWW_AUTHENTICATE);
            let mut challenges = challenges.iter();
            let challenge = match (challenges.next(), challenges.next()) {
                (None, _) => "absent",
                (Some(value), None) if value.as_bytes() == REALM.as_bytes() => "realm",
                (Some(value), None) if value.as_bytes() == INVALID_TOKEN.as_bytes() => {
                    "invalid_token"
                }
                (Some(value), None) if value.as_bytes() == INVALID_REQUEST.as_bytes() => {
                    "invalid_request"
                }
                _ => "other",
            };
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "automation_read={label} challenge={challenge}"
            );
            let value = body(response).await;
            assert_eq!(value["revision"], "2");
            assert_eq!(value["items"][0]["id"], id);
            assert_eq!(value["items"][0]["name"], "Machine readable");
            assert!(!value.to_string().contains(token.as_str()));
        }
        let head = call(state.clone(), authorized(Method::HEAD, USERS, &token)).await;
        assert_eq!(head.status(), StatusCode::OK);
        assert!(
            head.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        let missing = call(state.clone(), request(Method::GET, USERS, "")).await;
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(missing.headers()[header::WWW_AUTHENTICATE], REALM);
        assert_eq!(
            body(missing).await["error"]["code"],
            "authentication_required"
        );
        let legacy = call(
            state.clone(),
            request(Method::GET, "/api/v1/proxy/policy", ""),
        )
        .await;
        assert_eq!(legacy.status(), StatusCode::FORBIDDEN);
        assert!(!legacy.headers().contains_key(header::WWW_AUTHENTICATE));
        let mut browser = request(Method::GET, USERS, "");
        browser
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(call(state.clone(), browser).await.status(), StatusCode::OK);
        assert_eq!(
            state
                .policy
                .as_ref()
                .unwrap()
                .status()
                .await
                .unwrap()
                .saved_revision,
            2
        );
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
            (Method::GET, "/api/v1/proxy/credentials"),
            (Method::GET, "/api/v1/targets"),
            (Method::GET, "/api/v1/auth/session"),
            (Method::POST, "/api/v1/auth/login"),
            (Method::GET, "/unknown"),
            (Method::GET, "/index.html"),
            (Method::GET, "/api/v1/proxy/users/"),
        ] {
            let response = call(state.clone(), authorized(method, path, &token)).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
            assert_eq!(
                body(response).await["error"]["code"],
                "automation_route_denied"
            );
        }
        for name in [
            header::COOKIE,
            header::PROXY_AUTHORIZATION,
            header::HeaderName::from_static("x-csrf-token"),
        ] {
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
        let query_only = request(
            Method::GET,
            &format!("{USERS}?access_token=not-accepted"),
            "",
        );
        assert_eq!(
            call(state.clone(), query_only).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            state
                .policy
                .as_ref()
                .unwrap()
                .status()
                .await
                .unwrap()
                .saved_revision,
            1
        );
    }

    #[tokio::test]
    async fn write_scope_uses_canonical_operations_and_same_principal_history_after_rotation() {
        let (_directory, state, cookie) = managed_state();
        let (identity, token) = issue_scope(&state, store::automation::Scope::UsersWrite);
        const BASE: &str = "/api/v1/proxy/user-operations";
        let context = body(
            call(
                state.clone(),
                authorized(Method::GET, &format!("{BASE}/context"), &token),
            )
            .await,
        )
        .await;
        assert_eq!(context["policy_revision"], "1");
        assert_eq!(context["expected_epoch"], "1");
        assert_eq!(context["local"], true);
        let mut user_id = String::new();
        let mut first_id = String::new();
        let mut first_result = Value::Null;
        let mut first_input = Value::Null;
        for (index, action) in [
            "create_user",
            "update_user",
            "set_user_active",
            "delete_user",
        ]
        .into_iter()
        .enumerate()
        {
            let change = match action {
                "create_user" => {
                    json!({"action":action,"name":"Automation user","protocols":["http"],"concurrent_limit":2})
                }
                "update_user" => {
                    json!({"action":action,"id":user_id,"name":"Edited user","protocols":["http","socks5"],"concurrent_limit":3})
                }
                "set_user_active" => json!({"action":action,"id":user_id,"active":false}),
                _ => json!({"action":action,"id":user_id}),
            };
            let input = json!({"expected_revision":(index+1).to_string(),"expected_epoch":"1","change":change});
            let mut request = authorized(Method::POST, BASE, &token);
            request.headers_mut().remove(header::ORIGIN);
            *request.body_mut() = Body::from(input.to_string());
            let reserved = call(state.clone(), request).await;
            assert_eq!(reserved.status(), StatusCode::CREATED);
            let reserved = body(reserved).await;
            let id = reserved["id"].as_str().unwrap();
            let mut request = authorized(Method::POST, &format!("{BASE}/{id}/execute"), &token);
            request.headers_mut().remove(header::ORIGIN);
            *request.body_mut() = Body::from(input.to_string());
            let saved = call(state.clone(), request).await;
            assert_eq!(saved.status(), StatusCode::OK);
            let saved = body(saved).await;
            assert_eq!(saved["state"], "saved");
            assert_eq!(saved["saved_revision"], (index + 2).to_string());
            if index == 0 {
                user_id = saved["user_id"].as_str().unwrap().to_owned();
                first_id = id.to_owned();
                first_result = saved;
                first_input = input;
            }
        }
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
        assert_eq!(
            state
                .policy
                .as_ref()
                .unwrap()
                .status()
                .await
                .unwrap()
                .saved_revision,
            5
        );
        assert_eq!(
            state.policy.as_ref().unwrap().reader().revision().unwrap(),
            5
        );
        let page = body(call(state.clone(), authorized(Method::GET, BASE, &current)).await).await;
        assert_eq!(page["items"].as_array().unwrap().len(), 4);
        let read = call(state, authorized(Method::GET, USERS, &current)).await;
        assert_eq!(read.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn write_resources_distinguish_bad_keys_from_missing_scope_and_keep_http_boundaries() {
        let (_directory, state, cookie) = managed_state();
        let (identity, read) = issue(&state);
        let (_writer, write) = issue_scope(&state, store::automation::Scope::UsersWrite);
        const CONTEXT: &str = "/api/v1/proxy/user-operations/context";
        let paths = [
            (Method::GET, CONTEXT),
            (Method::GET, "/api/v1/proxy/user-operations"),
            (Method::POST, "/api/v1/proxy/user-operations"),
            (
                Method::GET,
                "/api/v1/proxy/user-operations/AAAAAAAAAAAAAAAAAAAAAA",
            ),
            (
                Method::POST,
                "/api/v1/proxy/user-operations/AAAAAAAAAAAAAAAAAAAAAA/execute",
            ),
        ];
        let node = store::inspect(&state.directory).unwrap().node_id;
        let other = if node == "AAAAAAAAAAAAAAAAAAAAAA" {
            "AQEBAQEBAQEBAQEBAQEBAQ"
        } else {
            "AAAAAAAAAAAAAAAAAAAAAA"
        };
        let input = json!({"expected_node_id":other,"expected_revision":"1","expected_epoch":"1","change":{
            "action":"create_user","name":"Not authorized","protocols":["http"],"concurrent_limit":1
        }});
        for (method, path) in &paths {
            let mut request = authorized(method.clone(), path, &read);
            *request.body_mut() = Body::from(input.to_string());
            let insufficient = call(state.clone(), request).await;
            assert_eq!(insufficient.status(), StatusCode::FORBIDDEN);
            assert_eq!(
                insufficient.headers()[header::WWW_AUTHENTICATE],
                WRITE_SCOPE
            );
            assert_eq!(
                body(insufficient).await["error"]["code"],
                "insufficient_scope"
            );
        }
        store::automation::revoke(&state.directory, &identity.id, identity.generation).unwrap();
        for (method, path) in paths {
            let mut request = authorized(method, path, &read);
            *request.body_mut() = Body::from(input.to_string());
            let invalid = call(state.clone(), request).await;
            assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(invalid.headers()[header::WWW_AUTHENTICATE], INVALID_TOKEN);
        }
        let mut mismatch = authorized(Method::POST, "/api/v1/proxy/user-operations", &write);
        *mismatch.body_mut() = Body::from(input.to_string());
        let mismatch = call(state.clone(), mismatch).await;
        assert_eq!(mismatch.status(), StatusCode::CONFLICT);
        assert_eq!(body(mismatch).await["error"]["code"], "operation_conflict");
        assert_eq!(
            state.policy.as_ref().unwrap().reader().revision().unwrap(),
            1
        );
        let head = call(state.clone(), authorized(Method::HEAD, CONTEXT, &write)).await;
        assert_eq!(head.status(), StatusCode::OK);
        assert!(
            head.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        for header in [
            header::COOKIE,
            header::HeaderName::from_static("x-csrf-token"),
        ] {
            let mut input = authorized(Method::GET, CONTEXT, &write);
            input
                .headers_mut()
                .insert(header, "ambiguous".parse().unwrap());
            assert_eq!(
                call(state.clone(), input).await.status(),
                StatusCode::BAD_REQUEST
            );
        }
        let mut wrong_origin = authorized(Method::GET, CONTEXT, &write);
        wrong_origin
            .headers_mut()
            .insert(header::ORIGIN, "https://elsewhere.invalid".parse().unwrap());
        assert_eq!(
            call(state.clone(), wrong_origin).await.status(),
            StatusCode::FORBIDDEN
        );
        let mut no_origin = authorized(Method::GET, CONTEXT, &write);
        no_origin.headers_mut().remove(header::ORIGIN);
        assert_eq!(
            call(state.clone(), no_origin).await.status(),
            StatusCode::OK
        );
        let mut wrong_host = authorized(Method::GET, CONTEXT, &write);
        wrong_host
            .headers_mut()
            .insert(header::HOST, "elsewhere.invalid".parse().unwrap());
        assert_eq!(
            call(state.clone(), wrong_host).await.status(),
            StatusCode::FORBIDDEN
        );
        let mut non_json = authorized(Method::POST, "/api/v1/proxy/user-operations", &write);
        non_json.headers_mut().remove(header::ORIGIN);
        non_json
            .headers_mut()
            .insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
        assert_eq!(
            call(state.clone(), non_json).await.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        for path in [
            "/api/v1/proxy/users",
            "/api/v1/proxy/owner",
            "/api/v1/proxy/routing",
            "/api/v1/targets",
            "/api/v1/proxy/credentials",
        ] {
            assert_eq!(
                call(state.clone(), authorized(Method::POST, path, &write))
                    .await
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        let mut browser = request(Method::POST, "/api/v1/proxy/user-operations", "null");
        browser
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        browser.headers_mut().remove(header::ORIGIN);
        assert_eq!(
            call(state.clone(), browser).await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                state,
                authorized(Method::GET, &format!("{CONTEXT}?unknown=1"), &write)
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
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

    #[tokio::test]
    async fn rotation_and_revocation_are_checked_on_each_read_not_a_session() {
        let (_directory, state, _cookie) = managed_state();
        let (identity, old) = issue(&state);
        let mut current = Zeroizing::new(String::new());
        let rotated = store::automation::rotate(
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
        let response = call(state.clone(), authorized(Method::GET, USERS, &old)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], INVALID_TOKEN);
        assert_eq!(
            call(state.clone(), authorized(Method::GET, USERS, &current))
                .await
                .status(),
            StatusCode::OK
        );
        store::automation::revoke(&state.directory, &identity.id, rotated.generation).unwrap();
        let response = call(state.clone(), authorized(Method::GET, USERS, &current)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body(response).await["error"]["code"], "invalid_token");
    }

    #[test]
    fn a_read_waiting_for_a_blocking_worker_does_not_keep_revoked_authority() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (_directory, state, _cookie) = managed_state();
            let (identity, token) = issue(&state);
            let (started, entered) = tokio::sync::oneshot::channel();
            let (release, wait) = std::sync::mpsc::channel::<()>();
            let worker = tokio::task::spawn_blocking(move || {
                let _ = started.send(());
                let _ = wait.recv();
            });
            entered.await.unwrap();
            let mut pending = Box::pin(call(state.clone(), authorized(Method::GET, USERS, &token)));
            assert!(futures_util::poll!(&mut pending).is_pending());
            store::automation::revoke(&state.directory, &identity.id, identity.generation).unwrap();
            release.send(()).unwrap();
            let response = pending.await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(body(response).await["error"]["code"], "invalid_token");
            worker.await.unwrap();
        });
    }

    #[tokio::test]
    async fn unavailable_storage_is_not_reported_as_a_wrong_secret() {
        let (_directory, state, _cookie) = managed_state();
        let (_identity, token) = issue(&state);
        let connection =
            rusqlite::Connection::open(state.directory.join("management.sqlite3")).unwrap();
        // Deliberately inconsistent private fixture, not a production repair path.
        connection.pragma_update(None, "user_version", 999).unwrap();
        let response = call(state, authorized(Method::GET, USERS, &token)).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        assert_ne!(body(response).await["error"]["code"], "invalid_token");
    }
}
