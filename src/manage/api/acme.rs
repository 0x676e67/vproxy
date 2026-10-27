//! Session-only snapshot of this process's browser HTTPS certificate state.
//!
//! Reads never inspect the ACME cache, contact a CA, or trigger an attempt. The
//! supervisor owns the bounded in-memory view; manual TLS exposes only its mode.

use super::*;
use crate::manage::acme::View;

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/tls/acme", get(status))
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

async fn status(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    if uri.query().is_some() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_query"));
    }
    let view = match &state.acme {
        Some(handle) => handle.view().map_err(|_| unavailable())?,
        None => View::manual(),
    };
    Ok(Json(view).into_response())
}

fn unavailable() -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "acme_status_unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::{
        acme::Handle,
        api::tests::{call, managed_state, request},
    };
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};
    use std::collections::BTreeSet;

    const PATH: &str = "/api/v1/tls/acme";

    fn authorized(cookie: &str, method: Method, suffix: &str) -> Request {
        let mut input = request(method, &format!("{PATH}{suffix}"), "");
        input
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        input
    }

    async fn body(response: Response, status: StatusCode) -> Value {
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.len() <= 2048);
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn empty_head(response: Response, status: StatusCode) {
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        assert!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn manual_and_cold_acme_snapshots_expose_only_their_public_wire_fields() {
        let (_directory, mut state, cookie) = managed_state();
        let value = body(
            call(state.clone(), authorized(&cookie, Method::GET, "")).await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(value, json!({ "mode": "manual" }));
        empty_head(
            call(state.clone(), authorized(&cookie, Method::HEAD, "")).await,
            StatusCode::OK,
        )
        .await;

        Arc::get_mut(&mut state).unwrap().acme = Some(Handle::testing());
        let value = body(
            call(state.clone(), authorized(&cookie, Method::GET, "")).await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "mode",
                "environment",
                "challenge",
                "certificate",
                "activity",
                "next_attempt_at_unix_s",
                "last_failure",
                "observed_at_unix_s",
            ])
        );
        assert_eq!(value["mode"], "acme");
        assert_eq!(value["environment"], "staging");
        assert_eq!(value["challenge"], "tls-alpn-01");
        assert!(value["certificate"].is_null());
        assert_eq!(value["activity"], "waiting");
        assert_eq!(value["next_attempt_at_unix_s"], "0");
        assert!(value["last_failure"].is_null());
        let observed = value["observed_at_unix_s"].as_str().unwrap();
        assert_eq!(observed.parse::<u64>().unwrap().to_string(), observed);
        // Exact keys above exclude private paths, domain/contact/account/order
        // material, CA bodies, credential tokens and raw error diagnostics.
        empty_head(
            call(state, authorized(&cookie, Method::HEAD, "")).await,
            StatusCode::OK,
        )
        .await;
    }

    #[tokio::test]
    async fn session_and_outer_guards_reject_queries_machine_credentials_and_mutations() {
        let (_directory, state, cookie) = managed_state();
        let unauthenticated = call(state.clone(), request(Method::GET, PATH, "")).await;
        assert_eq!(
            body(unauthenticated, StatusCode::FORBIDDEN).await["error"]["code"],
            "authentication_required"
        );
        empty_head(
            call(state.clone(), request(Method::HEAD, PATH, "")).await,
            StatusCode::FORBIDDEN,
        )
        .await;
        for suffix in ["?", "?domain=private.example", "?target=local", "?x=1&x=2"] {
            let value = body(
                call(state.clone(), authorized(&cookie, Method::GET, suffix)).await,
                StatusCode::BAD_REQUEST,
            )
            .await;
            assert_eq!(value["error"]["code"], "invalid_query");
            empty_head(
                call(state.clone(), authorized(&cookie, Method::HEAD, suffix)).await,
                StatusCode::BAD_REQUEST,
            )
            .await;
        }
        for method in [Method::GET, Method::HEAD] {
            let mut input = request(method.clone(), PATH, "");
            input.headers_mut().insert(
                header::AUTHORIZATION,
                format!(
                    "Bearer vpa1.{}.1.{}",
                    URL_SAFE_NO_PAD.encode([1; 16]),
                    URL_SAFE_NO_PAD.encode([2; 32]),
                )
                .parse()
                .unwrap(),
            );
            let response = call(state.clone(), input).await;
            if method == Method::HEAD {
                empty_head(response, StatusCode::FORBIDDEN).await;
            } else {
                assert_eq!(
                    body(response, StatusCode::FORBIDDEN).await["error"]["code"],
                    "automation_route_denied"
                );
            }
        }
        for name in [header::AUTHORIZATION, header::PROXY_AUTHORIZATION] {
            let mut mixed = authorized(&cookie, Method::GET, "");
            mixed
                .headers_mut()
                .insert(name, HeaderValue::from_static("Bearer synthetic-only"));
            assert_eq!(
                body(call(state.clone(), mixed).await, StatusCode::BAD_REQUEST).await["error"]["code"],
                "invalid_automation_authentication"
            );
        }
        let mut wrong_host = authorized(&cookie, Method::GET, "");
        wrong_host
            .headers_mut()
            .insert(header::HOST, "attacker.invalid".parse().unwrap());
        assert_eq!(
            body(call(state.clone(), wrong_host).await, StatusCode::FORBIDDEN).await["error"]["code"],
            "invalid_host"
        );
        let mut wrong_origin = authorized(&cookie, Method::POST, "");
        wrong_origin
            .headers_mut()
            .insert(header::ORIGIN, "https://attacker.invalid".parse().unwrap());
        assert_eq!(
            body(
                call(state.clone(), wrong_origin).await,
                StatusCode::FORBIDDEN
            )
            .await["error"]["code"],
            "invalid_origin"
        );
        for method in [Method::POST, Method::PUT, Method::DELETE] {
            let response = call(state.clone(), authorized(&cookie, method, "")).await;
            let mut allowed: Vec<_> = response.headers()[header::ALLOW]
                .to_str()
                .unwrap()
                .split(',')
                .map(str::trim)
                .collect();
            allowed.sort_unstable();
            assert_eq!(allowed, ["GET", "HEAD"]);
            assert_eq!(
                body(response, StatusCode::METHOD_NOT_ALLOWED).await["error"]["code"],
                "method_not_allowed"
            );
        }
    }

    #[tokio::test]
    async fn unavailable_error_is_fixed_and_contains_no_internal_diagnostics() {
        // Cache-Control is supplied by the outer guard, not ApiError itself.
        let response = unavailable().into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({"error": {"code": "acme_status_unavailable"}}),
        );
    }
}
