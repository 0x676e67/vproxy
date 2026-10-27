//! Local finite IP inventory and grants. All changes use the same policy owner,
//! global CAS, commit/publication queue and browser session/CSRF as user changes.
//! Registration never installs addresses/routes or asserts their health.

use super::{
    users::{Administrator, resource_id, revision, storage_error},
    *,
};
use crate::access::routing::{AddressFamily, ResourceState, RoutePermission, RoutingData};
use crate::manage::store::{self, PolicyChange};
use crate::manage::views::{Address, AddressView, Entity, Page, PermissionView, Pool, Prefix};
use axum::extract::{Path, rejection::PathRejection};

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/proxy/prefixes", get(prefixes).post(create_prefix))
        .route("/api/v1/proxy/prefixes/{id}/retire", post(retire_prefix))
        .route(
            "/api/v1/proxy/addresses",
            get(addresses).post(create_address),
        )
        .route("/api/v1/proxy/addresses/{id}", get(address))
        .route("/api/v1/proxy/addresses/{id}/state", post(address_state))
        .route("/api/v1/proxy/pools", get(pools).post(create_pool))
        .route("/api/v1/proxy/pools/{id}/state", post(pool_state))
        .route(
            "/api/v1/proxy/pools/{id}/members",
            get(members).post(add_member),
        )
        .route(
            "/api/v1/proxy/pools/{id}/members/remove",
            post(remove_member),
        )
        .route(
            "/api/v1/proxy/users/{id}/routing",
            get(permission).put(set_permission),
        )
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

fn coordinator(state: &AppState) -> Result<Arc<crate::manage::policy::Coordinator>, ApiError> {
    state.policy.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        )
    })
}

async fn catalog(state: &AppState) -> Result<(u64, RoutingData), ApiError> {
    coordinator(state)?
        .read(store::routing_data)
        .await
        .map_err(storage_error)
}

/// Lists return bounded metadata, not a full pool's potentially large membership.
/// Each page is a consistent snapshot; its global revision is not a multi-page
/// snapshot token. Callers must refresh before a CAS mutation after other writes.
pub(super) fn pagination(uri: &Uri) -> Result<users::Pagination, ApiError> {
    if url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
        .any(|(key, _)| !matches!(key.as_ref(), "after" | "limit"))
    {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_pagination"));
    }
    users::pagination(uri, false)
}

fn page<T>(mut items: Vec<(String, T)>, revision: u64, pagination: users::Pagination) -> Page<T> {
    items.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let mut selected = items
        .into_iter()
        .filter(|(id, _)| pagination.after.as_ref().is_none_or(|after| id > after));
    let mut items = Vec::new();
    let mut last = None;
    for _ in 0..pagination.limit {
        let Some((id, item)) = selected.next() else {
            break;
        };
        last = Some(id);
        items.push(item);
    }
    let next_cursor = if selected.next().is_some() {
        last
    } else {
        None
    };
    Page {
        revision: revision.to_string(),
        items,
        next_cursor,
    }
}

async fn prefixes(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    let pagination = pagination(&uri)?;
    let (revision, data) = catalog(&state).await?;
    Ok(Json(page(
        data.prefixes
            .into_iter()
            .map(|value| (value.id.clone(), Prefix::from(value)))
            .collect(),
        revision,
        pagination,
    ))
    .into_response())
}
async fn addresses(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    let pagination = pagination(&uri)?;
    let (revision, data) = catalog(&state).await?;
    Ok(Json(page(
        data.addresses
            .into_iter()
            .map(|value| (value.id.clone(), Address::from(value)))
            .collect(),
        revision,
        pagination,
    ))
    .into_response())
}
async fn address(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let (revision, data) = catalog(&state).await?;
    let address = data
        .addresses
        .into_iter()
        .find(|value| value.id == id)
        .ok_or_else(missing)?;
    Ok(Json(AddressView {
        revision: revision.to_string(),
        address: address.into(),
    })
    .into_response())
}

async fn pools(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    let pagination = pagination(&uri)?;
    let (revision, data) = catalog(&state).await?;
    Ok(Json(page(
        data.pools
            .into_iter()
            .map(|value| (value.id.clone(), Pool::from(value)))
            .collect(),
        revision,
        pagination,
    ))
    .into_response())
}
async fn members(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let id = resource_id(path)?;
    let pagination = pagination(&uri)?;
    let (revision, data) = catalog(&state).await?;
    let pool = data
        .pools
        .into_iter()
        .find(|pool| pool.id == id)
        .ok_or_else(missing)?;
    Ok(Json(page(
        pool.members
            .into_iter()
            .map(|id| (id.clone(), id))
            .collect(),
        revision,
        pagination,
    ))
    .into_response())
}
async fn permission(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    no_query(&uri)?;
    let id = resource_id(path)?;
    let (revision, data) = catalog(&state).await?;
    let permission = data
        .permissions
        .into_iter()
        .find(|value| value.user_id == id)
        .ok_or_else(missing)?;
    Ok(Json(PermissionView {
        revision: revision.to_string(),
        permission: permission.into(),
    })
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrefixInput {
    expected_revision: String,
    name: String,
    cidr: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddressInput {
    expected_revision: String,
    name: String,
    ip: IpAddr,
    prefix_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolInput {
    expected_revision: String,
    name: String,
    family: AddressFamily,
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
    state: ResourceState,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberInput {
    expected_revision: String,
    address_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PermissionInput {
    expected_revision: String,
    legacy_allowed: bool,
    exits: Vec<String>,
    pools: Vec<String>,
}

async fn create_prefix(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    request: Request,
) -> Result<Response, ApiError> {
    let input: PrefixInput = json(request).await?;
    let cidr: cidr::IpCidr = input.cidr.parse().map_err(|_| bad())?;
    // Display omits a host's /32 or /128. Accept the explicit mask as input,
    // while keeping the existing stored and response spelling unchanged.
    if cidr.to_string() != input.cidr && format!("{cidr:#}") != input.cidr {
        return Err(bad());
    }
    mutate(
        &state,
        actor,
        input.expected_revision,
        PolicyChange::CreatePrefix {
            name: input.name,
            cidr,
        },
        StatusCode::CREATED,
    )
    .await
}
async fn retire_prefix(
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
        input.expected_revision,
        PolicyChange::RetirePrefix { id },
        StatusCode::OK,
    )
    .await
}
async fn create_address(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    request: Request,
) -> Result<Response, ApiError> {
    let input: AddressInput = json(request).await?;
    mutate(
        &state,
        actor,
        input.expected_revision,
        PolicyChange::CreateAddress {
            name: input.name,
            ip: input.ip,
            prefix_id: input.prefix_id,
        },
        StatusCode::CREATED,
    )
    .await
}
async fn address_state(
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
        input.expected_revision,
        PolicyChange::SetAddressState {
            id,
            state: input.state,
        },
        StatusCode::OK,
    )
    .await
}
async fn create_pool(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    request: Request,
) -> Result<Response, ApiError> {
    let input: PoolInput = json(request).await?;
    mutate(
        &state,
        actor,
        input.expected_revision,
        PolicyChange::CreatePool {
            name: input.name,
            family: input.family,
        },
        StatusCode::CREATED,
    )
    .await
}
async fn pool_state(
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
        input.expected_revision,
        PolicyChange::SetPoolState {
            id,
            state: input.state,
        },
        StatusCode::OK,
    )
    .await
}
async fn add_member(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let pool_id = resource_id(path)?;
    let input: MemberInput = json(request).await?;
    mutate(
        &state,
        actor,
        input.expected_revision,
        PolicyChange::AddPoolMember {
            pool_id,
            address_id: input.address_id,
        },
        StatusCode::OK,
    )
    .await
}
async fn remove_member(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let pool_id = resource_id(path)?;
    let input: MemberInput = json(request).await?;
    mutate(
        &state,
        actor,
        input.expected_revision,
        PolicyChange::RemovePoolMember {
            pool_id,
            address_id: input.address_id,
        },
        StatusCode::OK,
    )
    .await
}
async fn set_permission(
    State(state): State<Arc<AppState>>,
    Extension(Administrator(actor)): Extension<Administrator>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let user_id = resource_id(path)?;
    let input: PermissionInput = json(request).await?;
    mutate(
        &state,
        actor,
        input.expected_revision,
        PolicyChange::SetRoutePermission {
            permission: RoutePermission {
                user_id,
                legacy_allowed: input.legacy_allowed,
                exits: input.exits,
                pools: input.pools,
            },
        },
        StatusCode::OK,
    )
    .await
}

async fn mutate(
    state: &AppState,
    actor: String,
    expected: String,
    change: PolicyChange,
    status: StatusCode,
) -> Result<Response, ApiError> {
    let result = coordinator(state)?
        .change(actor, revision(&expected)?, change)
        .await
        .map_err(storage_error)?;
    let entity = result
        .routing
        .ok_or_else(|| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable"))?;
    #[derive(Serialize)]
    struct Change {
        revision: String,
        entity: Entity,
    }
    Ok((
        status,
        Json(Change {
            revision: result.revision.to_string(),
            entity: entity.into(),
        }),
    )
        .into_response())
}
fn bad() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid_policy")
}
fn missing() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "resource_not_found")
}
fn no_query(uri: &Uri) -> Result<(), ApiError> {
    if uri.query().is_some() {
        Err(bad())
    } else {
        Ok(())
    }
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

    fn token(id: &str) -> String {
        URL_SAFE_NO_PAD
            .decode(id)
            .unwrap()
            .into_iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[tokio::test]
    async fn finite_routing_rest_updates_the_live_policy_without_legacy_escape() {
        let (_directory, state, cookie) = managed_state();
        let coordinator = coordinator(&state).unwrap();
        coordinator.activate().await.unwrap();
        let (status, prefix) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            "/api/v1/proxy/prefixes",
            json!({"expected_revision":"1","name":"Loopback inventory","cidr":"127.0.0.0/8"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(prefix["revision"], "2");
        let prefix_id = prefix["entity"]["data"]["id"].as_str().unwrap();
        let(status,address)=invoke(state.clone(),&cookie,Method::POST,"/api/v1/proxy/addresses",json!({"expected_revision":"2","name":"Loopback source","ip":"127.0.0.1","prefix_id":prefix_id})).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(address["entity"]["kind"], "address");
        let address_id = address["entity"]["data"]["id"].as_str().unwrap();
        let (status, pool) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            "/api/v1/proxy/pools",
            json!({"expected_revision":"3","name":"Shared v4","family":"v4"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let pool_id = pool["entity"]["data"]["id"].as_str().unwrap();
        let (status, changed) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("/api/v1/proxy/pools/{pool_id}/members"),
            json!({"expected_revision":"4","address_id":address_id}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(changed["revision"], "5");
        assert_eq!(changed["entity"]["data"]["member_count"], 1);
        let(status,user)=invoke(state.clone(),&cookie,Method::POST,"/api/v1/proxy/users",json!({"expected_revision":"5","name":"Restricted","protocols":["http","socks5","masque"],"concurrent_limit":8})).await;
        assert_eq!(status, StatusCode::CREATED);
        let user_id = user["user"]["id"].as_str().unwrap();
        let (status, credential) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("/api/v1/proxy/users/{user_id}/credentials"),
            json!({"expected_revision":"6"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let login = credential["credential"]["login"].as_str().unwrap();
        let secret = credential["secret"].as_str().unwrap();
        let(status,permission)=invoke(state.clone(),&cookie,Method::PUT,&format!("/api/v1/proxy/users/{user_id}/routing"),json!({"expected_revision":"7","legacy_allowed":false,"exits":[address_id],"pools":[pool_id]})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(permission["revision"], "8");
        let reader = coordinator.reader();
        assert!(matches!(
            reader.authenticate(login, secret.as_bytes(), crate::access::Protocol::Http),
            Err(crate::access::Error::Denied)
        ));
        assert!(matches!(
            reader.authenticate(
                &format!("{login}-session-id"),
                secret.as_bytes(),
                crate::access::Protocol::Http
            ),
            Err(crate::access::Error::Denied)
        ));
        let exit_login = format!("{login}-exit-{}", token(address_id));
        let pool_login = format!("{login}-pool-{}", token(pool_id));
        let retained = reader
            .authenticate(
                &exit_login,
                secret.as_bytes(),
                crate::access::Protocol::Http,
            )
            .unwrap();
        for protocol in [
            crate::access::Protocol::Http,
            crate::access::Protocol::Socks5,
            crate::access::Protocol::Masque,
        ] {
            let admitted = reader
                .authenticate(&pool_login, secret.as_bytes(), protocol)
                .unwrap();
            assert_eq!(admitted.source, Some("127.0.0.1".parse().unwrap()));
        }
        let (status, page) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            &format!("/api/v1/proxy/pools/{pool_id}/members?limit=1"),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["revision"], "8");
        assert_eq!(page["items"], json!([address_id]));
        let (status, _) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("/api/v1/proxy/addresses/{address_id}/state"),
            json!({"expected_revision":"8","state":"draining"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(matches!(
            reader.authenticate(
                &exit_login,
                secret.as_bytes(),
                crate::access::Protocol::Http
            ),
            Err(crate::access::Error::Denied)
        ));
        assert!(matches!(
            reader.authenticate(
                &pool_login,
                secret.as_bytes(),
                crate::access::Protocol::Masque
            ),
            Err(crate::access::Error::Denied)
        ));
        assert_eq!(retained.source, Some("127.0.0.1".parse().unwrap()));
        let (status, stale) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("/api/v1/proxy/addresses/{address_id}/state"),
            json!({"expected_revision":"8","state":"active"}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(stale["error"]["code"], "policy_conflict");
        let (status, page) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/proxy/addresses?limit=1",
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["items"][0]["state"], "draining");
        for hidden in [secret, "secret_digest", "verifier_version", "password"] {
            assert!(!page.to_string().contains(hidden));
        }
    }

    #[tokio::test]
    async fn host_prefix_input_preserves_legacy_views_and_duplicate_identity() {
        for (input, stored) in [("127.0.0.1/32", "127.0.0.1"), ("::1/128", "::1")] {
            let (_directory, state, cookie) = managed_state();
            let coordinator = coordinator(&state).unwrap();
            coordinator.activate().await.unwrap();
            let (status, created) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                "/api/v1/proxy/prefixes",
                json!({"expected_revision":"1","name":"Host prefix","cidr":input}),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{input}: {created}");
            assert_eq!(created["entity"]["data"]["cidr"], stored);
            let (status, duplicate) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                "/api/v1/proxy/prefixes",
                json!({"expected_revision":"2","name":"Same host","cidr":stored}),
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(duplicate["error"]["code"], "policy_conflict");
            let (status, page) = invoke(
                state.clone(),
                &cookie,
                Method::GET,
                "/api/v1/proxy/prefixes",
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(page["revision"], "2");
            assert_eq!(page["items"].as_array().unwrap().len(), 1);
            assert_eq!(page["items"][0]["cidr"], stored);
        }
    }

    #[tokio::test]
    async fn exact_address_lookup_is_session_only_and_retains_retired_metadata() {
        let (_directory, state, cookie) = managed_state();
        let (status, created) = invoke(
        state.clone(),
        &cookie,
        Method::POST,
        "/api/v1/proxy/addresses",
        json!({"expected_revision":"1","name":"Exact address","ip":"127.0.0.1","prefix_id":null}),
    )
    .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["entity"]["data"]["id"].as_str().unwrap();
        let path = format!("/api/v1/proxy/addresses/{id}");
        assert_eq!(
            call(state.clone(), request(Method::GET, &path, ""))
                .await
                .status(),
            StatusCode::FORBIDDEN,
        );
        // Route policy rejects machine access before looking up any Bearer key.
        for machine_path in [&path, &format!("/api/v1/targets/{id}/proxy/addresses/{id}")] {
            for method in [Method::GET, Method::HEAD] {
                let mut machine = request(method, machine_path, "");
                machine.headers_mut().insert(
                    header::AUTHORIZATION,
                    "Bearer fixture-no-key-lookup".parse().unwrap(),
                );
                let response = call(state.clone(), machine).await;
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
            }
        }
        let (status, view) = invoke(state.clone(), &cookie, Method::GET, &path, Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["revision"], "2");
        assert_eq!(view["address"], created["entity"]["data"]);
        for invalid in [
            format!("{path}?"),
            format!("{path}?limit=1"),
            "/api/v1/proxy/addresses/not-an-id".into(),
        ] {
            assert_eq!(
                invoke(state.clone(), &cookie, Method::GET, &invalid, Value::Null)
                    .await
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        let (status, missing) = invoke(
            state.clone(),
            &cookie,
            Method::GET,
            "/api/v1/proxy/addresses/AAAAAAAAAAAAAAAAAAAAAA",
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(missing["error"]["code"], "resource_not_found");
        let (status, _) = invoke(
            state.clone(),
            &cookie,
            Method::POST,
            &format!("{path}/state"),
            json!({"expected_revision":"2","state":"retired"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, view) = invoke(state.clone(), &cookie, Method::GET, &path, Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["revision"], "3");
        assert_eq!(view["address"]["id"], id);
        assert_eq!(view["address"]["state"], "retired");
        let mut head = request(Method::HEAD, &path, "");
        head.headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        let response = call(state, head).await;
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
    }

    #[tokio::test]
    async fn routing_routes_preserve_browser_authentication_and_strict_input_contracts() {
        let (_directory, state, cookie) = managed_state();
        let body =
            json!({"expected_revision":"1","name":"Local","ip":"127.0.0.1","prefix_id":null});
        let mut unauthenticated =
            request(Method::POST, "/api/v1/proxy/addresses", &body.to_string());
        assert_eq!(
            call(state.clone(), unauthenticated).await.status(),
            StatusCode::FORBIDDEN
        );
        unauthenticated = request(Method::POST, "/api/v1/proxy/addresses", &body.to_string());
        unauthenticated
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(
            call(state.clone(), unauthenticated).await.status(),
            StatusCode::FORBIDDEN
        );
        for path in [
            "/api/v1/proxy/addresses?limit=1&limit=2",
            "/api/v1/proxy/pools?include_deleted=true",
            "/api/v1/proxy/prefixes?limit=51",
        ] {
            assert_eq!(
                invoke(state.clone(), &cookie, Method::GET, path, Value::Null)
                    .await
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        let mut malformed = body.clone();
        malformed["health"] = json!("healthy");
        assert_eq!(
            invoke(
                state.clone(),
                &cookie,
                Method::POST,
                "/api/v1/proxy/addresses",
                malformed
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(coordinator(&state).unwrap().reader().revision().unwrap(), 1);
        for cidr in [
            "127.0.0.1/032",
            "127.0.0.1/33",
            "127.0.0.1/24",
            "127.0.0.1/32/32",
            " ::1/128",
            "::1/129",
            "2001:DB8::1/128",
            "2001:0db8::1/128",
        ] {
            let (status, _) = invoke(
                state.clone(),
                &cookie,
                Method::POST,
                "/api/v1/proxy/prefixes",
                json!({"expected_revision":"1","name":"Invalid prefix","cidr":cidr}),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{cidr}");
        }
        assert_eq!(coordinator(&state).unwrap().reader().revision().unwrap(), 1);
    }
}
