//! Authenticated endpoint inventory; never a proxy probe or secret exporter.

use super::*;

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/proxy/endpoints", get(local))
        .route("/api/v1/targets/{id}/proxy/endpoints", get(remote))
        .route("/api/v1/proxy/endpoint-settings", get(settings))
        .route(
            "/api/v1/proxy/endpoint-settings/{id}",
            axum::routing::put(change),
        )
        .route(
            "/api/v1/targets/{id}/proxy/endpoint-settings",
            get(remote_settings),
        )
        .route(
            "/api/v1/targets/{id}/proxy/endpoint-commands",
            axum::routing::post(remote_change),
        )
        .route(
            "/api/v1/targets/{id}/proxy/endpoint-command/refresh",
            axum::routing::post(refresh),
        )
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

fn no_query(uri: &Uri) -> Result<(), ApiError> {
    if uri.query().is_some() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_query"));
    }
    Ok(())
}

async fn local(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let policy = state.policy.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    })?;
    Ok(Json(
        policy
            .effective_endpoints(&state.node.node_id)
            .await
            .map_err(metadata_error)?,
    )
    .into_response())
}

async fn remote(
    State(state): State<Arc<AppState>>,
    path: Result<axum::extract::Path<String>, axum::extract::rejection::PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let operation = super::super::node::control::Request::Endpoints;
    let reply = targets::service(&state)?
        .remote(users::resource_id(path)?, operation)
        .await
        .map_err(remote_error)?;
    match reply {
        super::super::node::control::Reply::Endpoints(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

fn remote_error(error: io::Error) -> ApiError {
    if error
        .get_ref()
        .and_then(|error| error.downcast_ref::<super::super::node::control::RemoteError>())
        .is_some_and(|error| error.code == "node_protocol_unsupported")
    {
        return ApiError::new(StatusCode::BAD_GATEWAY, "remote_endpoints_unsupported");
    }
    targets::remote_error(error)
}

use super::super::{node::control, store};
use serde::{Deserialize, Serialize};

fn coordinator(state: &AppState) -> Result<Arc<super::super::policy::Coordinator>, ApiError> {
    state.policy.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    })
}
fn metadata_error(error: io::Error) -> ApiError {
    control::endpoints::storage_error(error)
}
fn management_remote_error(error: io::Error) -> ApiError {
    if error
        .get_ref()
        .and_then(|e| e.downcast_ref::<control::RemoteError>())
        .is_some_and(|e| e.code == "node_protocol_unsupported")
    {
        return ApiError::new(
            StatusCode::BAD_GATEWAY,
            "remote_endpoint_management_unsupported",
        );
    }
    if error
        .get_ref()
        .is_some_and(|e| e.is::<store::endpoints::Error>())
    {
        return metadata_error(error);
    }
    targets::remote_error(error)
}
async fn settings(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    no_query(&uri)?;
    Ok(Json(
        coordinator(&state)?
            .endpoint_settings(&state.node.node_id)
            .await
            .map_err(metadata_error)?,
    )
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeInput {
    expected_revision: String,
    generation: String,
    selection: store::endpoints::AddressSelection,
}
async fn change(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    path: Result<axum::extract::Path<String>, axum::extract::rejection::PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let listener_id = users::resource_id(path)?;
    let input: ChangeInput = json(request).await?;
    let policy = coordinator(&state)?;
    let inventory = policy.endpoint_inventory().map_err(metadata_error)?;
    let saved = policy
        .endpoint_change(
            actor,
            users::revision(&input.expected_revision)?,
            input.generation,
            store::endpoints::Change {
                listener_id,
                selection: input.selection,
            },
        )
        .await
        .map_err(metadata_error)?;
    let running = policy
        .endpoints(&state.node.node_id)
        .map_err(metadata_error)?
        .proxy_running;
    Ok(Json(
        super::super::proxy::SettingsCatalog::new(&state.node.node_id, running, &inventory, saved)
            .map_err(metadata_error)?,
    )
    .into_response())
}
async fn remote_settings(
    State(state): State<Arc<AppState>>,
    path: Result<axum::extract::Path<String>, axum::extract::rejection::PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    match targets::service(&state)?
        .remote(
            users::resource_id(path)?,
            control::Request::EndpointSettings,
        )
        .await
        .map_err(management_remote_error)?
    {
        control::Reply::EndpointSettings(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteInput {
    expected_target_revision: String,
    controller_epoch: String,
    command_id: String,
    expected_metadata_revision: String,
    mutation: control::endpoints::Mutation,
}
#[derive(Serialize)]
struct Submission {
    job: targets::JobView,
    response: Option<control::endpoints::CommandReply>,
}
async fn remote_change(
    State(state): State<Arc<AppState>>,
    Extension(users::Administrator(actor)): Extension<users::Administrator>,
    path: Result<axum::extract::Path<String>, axum::extract::rejection::PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let peer = users::resource_id(path)?;
    let input: RemoteInput = json(request).await?;
    let command = store::endpoint_control::Command {
        target_node_id: peer,
        epoch: users::revision(&input.controller_epoch)?,
        command_id: users::revision(&input.command_id)?,
        expected_metadata_revision: users::revision(&input.expected_metadata_revision)?,
        source_administrator_id: actor.clone(),
        generation: input.mutation.generation,
        change: store::endpoints::Change {
            listener_id: input.mutation.listener_id,
            selection: input.mutation.selection,
        },
    };
    store::endpoint_control::validate(&command)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_endpoint"))?;
    let submitted = targets::service(&state)?
        .submit(
            actor,
            users::revision(&input.expected_target_revision)?,
            command,
        )
        .await
        .map_err(management_remote_error)?;
    let response = match timeout(Duration::from_secs(7), submitted.response).await {
        Ok(Ok(Ok(control::DeliveryReply::Endpoint(value)))) => Some(value),
        _ => None,
    };
    let status = if response.is_some() {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    let peer = submitted.job.peer_id.clone();
    let current = coordinator(&state)?
        .read(move |dir| store::targets::job(dir, &peer))
        .await
        .ok()
        .flatten();
    let job = current
        .filter(|job| job.job_id == submitted.job.job_id)
        .unwrap_or(submitted.job);
    let location = format!("/api/v1/targets/{}/command", job.peer_id);
    let mut response = (
        status,
        Json(Submission {
            job: job.into(),
            response,
        }),
    )
        .into_response();
    if status == StatusCode::ACCEPTED {
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&location).map_err(|_| ApiError::internal())?,
        );
    }
    Ok(response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshInput {
    job_id: String,
}
async fn refresh(
    State(state): State<Arc<AppState>>,
    path: Result<axum::extract::Path<String>, axum::extract::rejection::PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let input: RefreshInput = json(request).await?;
    users::resource_id(Ok(axum::extract::Path(input.job_id.clone())))?;
    let job = targets::service(&state)?
        .refresh_endpoint(users::resource_id(path)?, input.job_id)
        .await
        .map_err(management_remote_error)?;
    Ok(Json(targets::JobView::from(job)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::api::tests::{call, managed_state, request};
    use http_body_util::BodyExt as _;

    #[tokio::test]
    async fn endpoint_inventory_requires_session_rejects_queries_and_preserves_api_only_state() {
        let (_directory, mut state, cookie) = managed_state();
        let node_id = store::inspect(&state.directory).unwrap().node_id;
        Arc::get_mut(&mut state).unwrap().node.node_id = node_id;
        state
            .policy
            .as_ref()
            .unwrap()
            .configure_endpoint_settings(&state.node.node_id)
            .await
            .unwrap();
        for path in [
            "/api/v1/proxy/endpoints",
            "/api/v1/proxy/endpoint-settings",
            "/api/v1/targets/AAAAAAAAAAAAAAAAAAAAAA/proxy/endpoint-settings",
            "/api/v1/targets/AAAAAAAAAAAAAAAAAAAAAA/proxy/endpoints",
        ] {
            let response = call(state.clone(), request(Method::GET, path, "")).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let mut query = request(Method::GET, &format!("{path}?host=attacker.example"), "");
            query
                .headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            assert_eq!(
                call(state.clone(), query).await.status(),
                StatusCode::BAD_REQUEST
            );
        }
        let mut request = request(Method::GET, "/api/v1/proxy/endpoints", "");
        request
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        let response = call(state.clone(), request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let catalog: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            catalog,
            serde_json::json!({
                "node_id":state.node.node_id,
                "proxy_running":false,
                "listeners":[],
            })
        );
        let (status, settings) = authenticated(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/proxy/endpoint-settings",
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(settings["node_id"], state.node.node_id);
        assert_eq!(settings["proxy_running"], false);
        assert_eq!(settings["listeners"], serde_json::json!([]));
        assert_eq!(settings["detached"], serde_json::json!([]));
    }

    async fn authenticated(
        state: Arc<AppState>,
        cookie: &str,
        method: Method,
        path: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let mut input = request(method, path, body);
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

    #[tokio::test]
    async fn old_schema_settings_require_upgrade_without_disabling_legacy_catalog() {
        let (_directory, mut state, cookie) = managed_state();
        let node_id = store::inspect(&state.directory).unwrap().node_id;
        Arc::get_mut(&mut state).unwrap().node.node_id = node_id;
        let policy = state.policy.as_ref().unwrap();
        policy
            .configure_endpoints(vec![super::super::super::proxy::ListenerView {
                protocol: super::super::super::proxy::Protocol::Socks5,
                bind: "127.0.0.1:1080".parse().unwrap(),
                public_address: Some("startup.example:1080".into()),
            }])
            .unwrap();
        let connection =
            rusqlite::Connection::open(state.directory.join("management.sqlite3")).unwrap();
        store::recovery::remove_schema_for_test(&connection).unwrap();
        // This is a real schema-13 layout, not just a lowered user_version. A new
        // binary still serves the immutable startup catalog without migrating it.
        policy
            .configure_endpoint_settings(&state.node.node_id)
            .await
            .unwrap();
        let (status, error) = authenticated(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/proxy/endpoint-settings",
            "",
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error["error"]["code"], "management_upgrade_required");
        let (status, catalog) = authenticated(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/proxy/endpoints",
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            catalog["listeners"][0]["public_address"],
            "startup.example:1080"
        );
        assert_eq!(store::inspect(&state.directory).unwrap().schema_version, 13);
    }

    #[tokio::test]
    async fn metadata_api_hidden_inherit_conflicts_and_failures_never_publish_policy() {
        let (_directory, mut state, cookie) = managed_state();
        let node_id = store::inspect(&state.directory).unwrap().node_id;
        Arc::get_mut(&mut state).unwrap().node.node_id = node_id;
        let policy = state.policy.as_ref().unwrap();
        policy
            .configure_endpoints(vec![super::super::super::proxy::ListenerView {
                protocol: super::super::super::proxy::Protocol::Http,
                bind: "127.0.0.1:8080".parse().unwrap(),
                public_address: Some("startup.example:8080".into()),
            }])
            .unwrap();
        policy
            .configure_endpoint_settings(&state.node.node_id)
            .await
            .unwrap();
        let (status, initial) = authenticated(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/proxy/endpoint-settings",
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let id = initial["listeners"][0]["id"].as_str().unwrap();
        let path = format!("/api/v1/proxy/endpoint-settings/{id}");
        let before = policy.reader().revision().unwrap();
        let body=serde_json::json!({"expected_revision":initial["revision"],"generation":initial["generation"],"selection":{"mode":"hidden"}}).to_string();
        let mut no_csrf = request(Method::PUT, &path, &body);
        no_csrf
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(
            call(state.clone(), no_csrf).await.status(),
            StatusCode::FORBIDDEN
        );
        let (status, hidden) =
            authenticated(state.clone(), &cookie, Method::PUT, &path, &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            hidden["listeners"][0]["public_address"],
            serde_json::Value::Null
        );
        let (status, legacy) = authenticated(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/proxy/endpoints",
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(legacy.as_object().unwrap().len(), 3);
        assert_eq!(legacy["listeners"][0].as_object().unwrap().len(), 3);
        assert!(legacy["listeners"][0]["public_address"].is_null());
        let (status, error) =
            authenticated(state.clone(), &cookie, Method::PUT, &path, &body).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(error["error"]["code"], "endpoint_revision_changed");
        let invalid=serde_json::json!({"expected_revision":hidden["revision"],"generation":hidden["generation"],"selection":{"mode":"custom","public_address":"https://user:secret@invalid.example:443"}}).to_string();
        let (status, error) =
            authenticated(state.clone(), &cookie, Method::PUT, &path, &invalid).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error["error"]["code"], "invalid_endpoint");
        assert_eq!(policy.reader().revision().unwrap(), before);
        assert_eq!(
            store::policy_status(&state.directory).unwrap().revision,
            before
        );
        let body=serde_json::json!({"expected_revision":hidden["revision"],"generation":hidden["generation"],"selection":{"mode":"inherit"}}).to_string();
        let (status, inherited) =
            authenticated(state.clone(), &cookie, Method::PUT, &path, &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            inherited["listeners"][0]["public_address"],
            "startup.example:8080"
        );
        assert_eq!(policy.reader().revision().unwrap(), before);
    }

    #[test]
    fn endpoint_support_negotiation_does_not_relabel_other_remote_failures() {
        for (code, expected) in [
            ("node_protocol_unsupported", "remote_endpoints_unsupported"),
            ("resource_not_found", "resource_not_found"),
            ("management_upgrade_required", "management_upgrade_required"),
        ] {
            let error =
                io::Error::other(crate::manage::node::control::RemoteError { status: 404, code });
            assert_eq!(remote_error(error).code, expected);
        }
    }
}
