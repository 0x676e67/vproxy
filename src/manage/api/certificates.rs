//! Session-only facts from this process's actual TLS identities. Reading never
//! loads a file, probes a listener, starts issuance or changes certificate state.

use super::*;
use crate::manage::{
    certificates::{Role, Snapshot, Source, State as IdentityState},
    proxy::Protocol,
};

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/tls/status", get(status))
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

#[derive(Serialize)]
struct View {
    node_id: String,
    observed_at_unix_s: Option<String>,
    entries: Vec<Entry>,
}

#[derive(Serialize)]
struct Entry {
    role: &'static str,
    source: &'static str,
    id: Option<String>,
    protocol: Option<&'static str>,
    state: &'static str,
    certificate: Option<Certificate>,
    valid_now: Option<bool>,
}

#[derive(Serialize)]
struct Certificate {
    sha256: String,
    not_before_unix_s: String,
    not_after_unix_s: String,
}

impl From<Snapshot> for View {
    fn from(snapshot: Snapshot) -> Self {
        let entries = snapshot
            .entries
            .into_iter()
            .map(|entry| {
                let (state, certificate) = match entry.state {
                    IdentityState::Disabled => ("disabled", None),
                    IdentityState::Pending => ("pending", None),
                    IdentityState::Unavailable => ("unavailable", None),
                    IdentityState::Loaded(leaf) => (
                        "loaded",
                        Some(Certificate {
                            sha256: leaf.sha256,
                            not_before_unix_s: leaf.not_before_unix_s.to_string(),
                            not_after_unix_s: leaf.not_after_unix_s.to_string(),
                        }),
                    ),
                };
                Entry {
                    role: match entry.role {
                        Role::Management => "management",
                        Role::Node => "node",
                        Role::Proxy => "proxy",
                    },
                    source: match entry.source {
                        Source::Manual => "manual",
                        Source::Acme => "acme",
                    },
                    id: entry.id,
                    protocol: entry.protocol.map(|protocol| match protocol {
                        Protocol::Https => "https",
                        Protocol::Masque => "masque",
                        Protocol::Auto => "auto",
                        Protocol::Http => "http",
                        Protocol::Socks5 => "socks5",
                    }),
                    state,
                    certificate,
                    valid_now: entry.valid_now,
                }
            })
            .collect();
        Self {
            node_id: snapshot.node_id,
            observed_at_unix_s: snapshot.observed_at_unix_s.map(|value| value.to_string()),
            entries,
        }
    }
}

async fn status(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    if uri.query().is_some() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_query"));
    }
    let snapshot = state
        .certificates
        .as_ref()
        .ok_or_else(unavailable)?
        .snapshot()
        .map_err(|_| unavailable())?;
    Ok(Json(View::from(snapshot)).into_response())
}

fn unavailable() -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "tls_status_unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::{
        api::tests::{call, managed_state, request},
        certificates::{Descriptor, Handle, ManagementSource},
        store,
    };
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};

    const PATH: &str = "/api/v1/tls/status";

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
        assert!(bytes.len() <= 16 * 1024);
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn actual_handle_exposes_only_exact_public_metadata_and_one_local_identity() {
        let (_directory, mut state, cookie) = managed_state();
        // The shared lightweight API fixture has a display-only node label. This
        // production handle must instead use the real database's canonical ID.
        let node_id = store::inspect(&state.directory).unwrap().node_id;
        Arc::get_mut(&mut state).unwrap().node.node_id = node_id.clone();
        let handle = Handle::new(
            node_id.clone(),
            ManagementSource::Manual(IdentityState::Loaded(Descriptor {
                sha256: "a".repeat(64),
                not_before_unix_s: -100,
                not_after_unix_s: i64::MAX,
            })),
            IdentityState::Disabled,
            Default::default(),
        )
        .unwrap();
        Arc::get_mut(&mut state).unwrap().certificates = Some(handle);
        let value = body(
            call(state.clone(), authorized(&cookie, Method::GET, "")).await,
            StatusCode::OK,
        )
        .await;
        let now = value["observed_at_unix_s"]
            .as_str()
            .unwrap()
            .parse::<i64>()
            .unwrap();
        assert!(now > 0);
        assert_eq!(
            value,
            json!({"node_id":node_id, "observed_at_unix_s":now.to_string(), "entries":[
                {"role":"management", "source":"manual", "id":null, "protocol":null, "state":"loaded",
                 "certificate":{"sha256":"a".repeat(64), "not_before_unix_s":"-100", "not_after_unix_s":i64::MAX.to_string()}, "valid_now":true},
                {"role":"node", "source":"manual", "id":null, "protocol":null, "state":"disabled", "certificate":null, "valid_now":null}
            ]})
        );
        let response = call(state.clone(), authorized(&cookie, Method::HEAD, "")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        // Existing ACME clients retain their exact manual-mode representation.
        let mut input = request(Method::GET, "/api/v1/tls/acme", "");
        input
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(
            body(call(state, input).await, StatusCode::OK).await,
            json!({"mode":"manual"})
        );
    }

    #[tokio::test]
    async fn session_only_no_query_no_mutation_and_fixed_unavailable_response() {
        let (_directory, state, cookie) = managed_state();
        assert_eq!(
            body(
                call(state.clone(), request(Method::GET, PATH, "")).await,
                StatusCode::FORBIDDEN
            )
            .await["error"]["code"],
            "authentication_required"
        );
        assert_eq!(
            body(
                call(state.clone(), authorized(&cookie, Method::GET, "")).await,
                StatusCode::SERVICE_UNAVAILABLE
            )
            .await,
            json!({"error":{"code":"tls_status_unavailable"}})
        );
        for suffix in ["?", "?node_id=other", "?path=private", "?refresh=true"] {
            assert_eq!(
                body(
                    call(state.clone(), authorized(&cookie, Method::GET, suffix)).await,
                    StatusCode::BAD_REQUEST
                )
                .await["error"]["code"],
                "invalid_query"
            );
        }
        let mut bearer = request(Method::GET, PATH, "");
        bearer.headers_mut().insert(
            header::AUTHORIZATION,
            format!(
                "Bearer vpa1.{}.1.{}",
                URL_SAFE_NO_PAD.encode([1; 16]),
                URL_SAFE_NO_PAD.encode([2; 32])
            )
            .parse()
            .unwrap(),
        );
        assert_eq!(
            body(call(state.clone(), bearer).await, StatusCode::FORBIDDEN).await["error"]["code"],
            "automation_route_denied"
        );
        for method in [Method::POST, Method::PUT, Method::DELETE] {
            assert_eq!(
                body(
                    call(state.clone(), authorized(&cookie, method, "")).await,
                    StatusCode::METHOD_NOT_ALLOWED
                )
                .await["error"]["code"],
                "method_not_allowed"
            );
        }
    }
}
