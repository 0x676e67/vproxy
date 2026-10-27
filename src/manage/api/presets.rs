//! Browser access to finite preset policy. Runtime availability and stored
//! grants are separate facts; saving a grant never loads privileged programs.

use axum::extract::{Path, rejection::PathRejection};

use super::{
    users::{Administrator, resource_id, revision, storage_error},
    *,
};
use crate::{
    access::presets::{PoolPreset, PresetEntity, UserPreset},
    manage::{
        node::control,
        policy::Coordinator,
        store::{self, PolicyChange},
    },
};

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/proxy/presets", get(catalog))
        .route("/api/v1/proxy/users/{id}/presets", get(user).put(set_user))
        .route("/api/v1/proxy/pools/{id}/presets", get(pool).put(set_pool))
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

fn coordinator(state: &AppState) -> Result<Arc<Coordinator>, ApiError> {
    state.policy.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    })
}

fn no_query(uri: &Uri) -> Result<(), ApiError> {
    if uri.query().is_some() {
        Err(bad())
    } else {
        Ok(())
    }
}

async fn catalog(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let config = state
        .policy
        .as_ref()
        .and_then(|policy| policy.preset_config());
    Ok(Json(control::preset_catalog(&state.node.node_id, config)).into_response())
}

async fn user(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let (revision, presets) = coordinator(&state)?
        .read(move |directory| store::presets::user_presets(directory, &id))
        .await
        .map_err(storage_error)?;
    Ok(Json(control::UserPresetsView {
        revision: revision.to_string(),
        presets,
    })
    .into_response())
}

async fn pool(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let (revision, preset) = coordinator(&state)?
        .read(move |directory| store::presets::pool_preset(directory, &id))
        .await
        .map_err(storage_error)?;
    Ok(Json(control::PoolPresetView {
        revision: revision.to_string(),
        preset,
    })
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserInput {
    expected_revision: String,
    presets: UserPreset,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolInput {
    expected_revision: String,
    preset: PoolPreset,
}

async fn set_user(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let input: UserInput = json(request).await?;
    if input.presets.user_id != id {
        return Err(bad());
    }
    let change = coordinator(&state)?
        .change(
            actor,
            revision(&input.expected_revision)?,
            PolicyChange::SetUserPresets {
                presets: input.presets,
            },
        )
        .await
        .map_err(storage_error)?;
    let Some(PresetEntity::User(presets)) = change.presets else {
        return Err(ApiError::internal());
    };
    Ok(Json(control::UserPresetsView {
        revision: change.revision.to_string(),
        presets,
    })
    .into_response())
}

async fn set_pool(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
    request: Request,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let input: PoolInput = json(request).await?;
    if input.preset.pool_id != id {
        return Err(bad());
    }
    let change = coordinator(&state)?
        .change(
            actor,
            revision(&input.expected_revision)?,
            PolicyChange::SetPoolPreset {
                preset: input.preset,
            },
        )
        .await
        .map_err(storage_error)?;
    let Some(PresetEntity::Pool(preset)) = change.presets else {
        return Err(ApiError::internal());
    };
    Ok(Json(control::PoolPresetView {
        revision: change.revision.to_string(),
        preset,
    })
    .into_response())
}

fn bad() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid_policy")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::api::tests::{call, managed_state, request};
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};

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

    #[tokio::test]
    async fn preset_rest_uses_global_cas_and_never_turns_catalog_into_authority() {
        let (_directory, state, cookie) = managed_state();
        let policy = coordinator(&state).unwrap();
        let (_, unavailable) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/proxy/presets",
            Value::Null,
        )
        .await;
        assert_eq!(unavailable["backend_state"], "unavailable");
        assert_eq!(unavailable["reason_code"], "proxy_unavailable");
        assert_eq!(unavailable["available_presets"], json!([]));
        policy
            .configure_presets(crate::ebpf::Config::default())
            .unwrap();
        assert!(
            policy
                .configure_presets(crate::ebpf::Config::default())
                .is_err()
        );
        let (_, catalog) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/proxy/presets",
            Value::Null,
        )
        .await;
        assert_ne!(catalog["backend_state"], "ready");
        assert_eq!(catalog["operations"], json!([]));
        assert!(catalog["abi_version"].is_null());
        let (status, created) = invoke(state.clone(), &cookie, Method::POST, "/api/v1/proxy/users", json!({"expected_revision":"1","name":"Preset user","protocols":["http","socks5","masque"],"concurrent_limit":8})).await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["user"]["id"].as_str().unwrap();
        let path = format!("/api/v1/proxy/users/{id}/presets");
        let (_, native) = invoke(state.clone(), &cookie, Method::GET, &path, Value::Null).await;
        assert_eq!(
            native,
            json!({"revision":"2","presets":{"user_id":id,"default_preset":null,"allowed_presets":[]}})
        );
        let configured =
            json!({"user_id":id,"default_preset":"linux","allowed_presets":["linux","ios"]});
        let (status, saved) = invoke(
            state.clone(),
            &cookie,
            Method::PUT,
            &path,
            json!({"expected_revision":"2","presets":configured}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(saved, json!({"revision":"3","presets":configured}));
        let (status, _) = invoke(
            state.clone(),
            &cookie,
            Method::PUT,
            &path,
            json!({"expected_revision":"2","presets":configured}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        for invalid in [
            json!({"user_id":"AAAAAAAAAAAAAAAAAAAAAA","default_preset":null,"allowed_presets":[]}),
            json!({"user_id":id,"default_preset":"native","allowed_presets":[]}),
            json!({"user_id":id,"default_preset":"linux","allowed_presets":[]}),
            json!({"user_id":id,"default_preset":null,"allowed_presets":["ios","ios"]}),
        ] {
            let (status, _) = invoke(
                state.clone(),
                &cookie,
                Method::PUT,
                &path,
                json!({"expected_revision":"3","presets":invalid}),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        let (_, unchanged) = invoke(state.clone(), &cookie, Method::GET, &path, Value::Null).await;
        assert_eq!(unchanged, saved);
        let (status, _) = invoke(
            state,
            &cookie,
            Method::GET,
            &format!("{path}?limit=1"),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn pool_preset_rest_preserves_entity_identity_and_requires_authentication() {
        let (_directory, state, cookie) = managed_state();
        let response = call(
            state.clone(),
            request(Method::GET, "/api/v1/proxy/presets", ""),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let (status, pool) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            "/api/v1/proxy/pools",
            json!({"expected_revision":"1","name":"Shared","family":"v4"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = pool["entity"]["data"]["id"].as_str().unwrap();
        let path = format!("/api/v1/proxy/pools/{id}/presets");
        let (_, native) = invoke(state.clone(), &cookie, Method::GET, &path, Value::Null).await;
        assert_eq!(native["preset"]["default_preset"], Value::Null);
        let (status, saved) = invoke(
            state.clone(),
            &cookie,
            Method::PUT,
            &path,
            json!({"expected_revision":"2","preset":{"pool_id":id,"default_preset":"ios"}}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(saved["revision"], "3");
        assert_eq!(saved["preset"]["default_preset"], "ios");
    }
}
