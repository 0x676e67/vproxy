//! Session-only reads of one configured target, not a global poller. Session
//! lifetime is the browser authority; remote owner/DER and registration checks
//! remain current on either side. No error falls back to local or subset data.

use super::*;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/targets/{id}/egress-alerts", get(observations))
        .route("/api/v1/targets/{id}/operations-alerts", get(operations))
}

async fn operations(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let query = crate::manage::alerts::Query::parse(uri.query())
        .map_err(super::super::alerts::page_error)?;
    let peer = resource_id(path)?;
    match service(&state)?
        .remote(peer, control::Request::OperationsAlerts(query))
        .await
        .map_err(operations_error)?
    {
        control::Reply::OperationsAlerts(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

async fn observations(
    State(state): State<Arc<AppState>>,
    path: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let query = crate::manage::alerts::Query::parse(uri.query())
        .map_err(super::super::alerts::page_error)?;
    let peer = resource_id(path)?;
    match service(&state)?
        .remote(peer, control::Request::EgressAlerts(query))
        .await
        .map_err(remote_error)?
    {
        control::Reply::EgressAlerts(value) => Ok(Json(value).into_response()),
        _ => Err(ApiError::internal()),
    }
}

fn remote_error(error: io::Error) -> ApiError {
    if let Some(remote) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<control::RemoteError>())
    {
        return match (remote.status, remote.code) {
            (404, "node_protocol_unsupported") => {
                ApiError::new(StatusCode::BAD_GATEWAY, "egress_alerts_unsupported")
            }
            (409, "alerts_changed") => ApiError::new(StatusCode::CONFLICT, "alerts_changed"),
            (400, "invalid_alert_query") => {
                ApiError::new(StatusCode::BAD_REQUEST, "invalid_alert_query")
            }
            _ => super::remote_error(error),
        };
    }
    super::remote_error(error)
}

fn operations_error(error: io::Error) -> ApiError {
    if error
        .get_ref()
        .and_then(|e| e.downcast_ref::<control::RemoteError>())
        .is_some_and(|remote| remote.status == 404 && remote.code == "node_protocol_unsupported")
    {
        ApiError::new(StatusCode::BAD_GATEWAY, "operations_alerts_unsupported")
    } else {
        remote_error(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::{
        api::tests::{call, managed_state, request},
        health, node, store,
    };
    use crate::{
        access::routing::{ResourceState, RoutingEntity},
        connect::Fallback,
    };
    use futures_util::FutureExt as _;
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    fn authorized(cookie: &str, method: Method, path: &str) -> Request {
        let mut request = request(method, path, "");
        request
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        request
    }

    async fn body(response: Response, status: StatusCode) -> Value {
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    #[tokio::test]
    async fn alert_target_routes_are_session_only_and_parse_before_network_admission() {
        let (_directory, state, cookie) = managed_state();
        for path in [
            "/api/v1/targets/AAAAAAAAAAAAAAAAAAAAAA/egress-alerts",
            "/api/v1/targets/AAAAAAAAAAAAAAAAAAAAAA/operations-alerts",
        ] {
            for method in [Method::GET, Method::HEAD] {
                assert_eq!(
                    call(state.clone(), request(method, path, ""))
                        .await
                        .status(),
                    StatusCode::FORBIDDEN
                );
            }
            for query in [
                "state=other",
                "limit=0",
                "limit=17",
                "limit=01",
                "state=active&%73tate=active",
                "scope=local",
                "target=AAAAAAAAAAAAAAAAAAAAAA",
                "after=",
                "state=%FF",
            ] {
                let response = call(
                    state.clone(),
                    authorized(&cookie, Method::GET, &format!("{path}?{query}")),
                )
                .await;
                assert_eq!(
                    body(response, StatusCode::BAD_REQUEST).await["error"]["code"],
                    "invalid_alert_query"
                );
            }
            let response = call(state.clone(), authorized(&cookie, Method::GET, path)).await;
            assert_eq!(
                body(response, StatusCode::SERVICE_UNAVAILABLE).await["error"]["code"],
                "node_control_unavailable"
            );
        }
        let path = "/api/v1/targets/AAAAAAAAAAAAAAAAAAAAAA/operations-alerts";
        let mut token = zeroize::Zeroizing::new(String::new());
        store::automation::create(
            &state.directory,
            "operations fixture",
            store::automation::Scope::UsersRead,
            3600,
            |value| {
                token.push_str(value);
                Ok(())
            },
        )
        .unwrap();
        let mut input = request(Method::GET, path, "");
        input.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {}", token.as_str()).parse().unwrap(),
        );
        let response = call(state.clone(), input).await;
        assert_eq!(
            body(response, StatusCode::FORBIDDEN).await["error"]["code"],
            "automation_route_denied"
        );
        let mut mixed = authorized(&cookie, Method::GET, path);
        mixed.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {}", token.as_str()).parse().unwrap(),
        );
        assert_eq!(
            call(state.clone(), mixed).await.status(),
            StatusCode::BAD_REQUEST
        );
        let mut cross_origin = authorized(&cookie, Method::POST, path);
        cross_origin
            .headers_mut()
            .insert(header::ORIGIN, "https://other.example".parse().unwrap());
        assert_eq!(
            body(
                call(state.clone(), cross_origin).await,
                StatusCode::FORBIDDEN
            )
            .await["error"]["code"],
            "invalid_origin"
        );
        let mut mutation = authorized(&cookie, Method::POST, path);
        mutation
            .headers_mut()
            .insert("x-csrf-token", "c".repeat(43).parse().unwrap());
        assert_eq!(
            call(state, mutation).await.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    #[test]
    fn egress_remote_errors_keep_cursor_conflicts_separate_from_auth_and_unrelated_404s() {
        for (status, code, expected_status, expected_code) in [
            (
                404,
                "node_protocol_unsupported",
                StatusCode::BAD_GATEWAY,
                "egress_alerts_unsupported",
            ),
            (
                404,
                "resource_not_found",
                StatusCode::BAD_GATEWAY,
                "resource_not_found",
            ),
            (
                403,
                "peer_not_authorized",
                StatusCode::BAD_GATEWAY,
                "peer_not_authorized",
            ),
            (
                409,
                "alerts_changed",
                StatusCode::CONFLICT,
                "alerts_changed",
            ),
            (
                503,
                "alerts_unavailable",
                StatusCode::BAD_GATEWAY,
                "alerts_unavailable",
            ),
        ] {
            let error = remote_error(io::Error::other(control::RemoteError { status, code }));
            assert_eq!((error.status, error.code), (expected_status, expected_code));
            let error = operations_error(io::Error::other(control::RemoteError { status, code }));
            assert_eq!(
                (error.status, error.code),
                (
                    expected_status,
                    if expected_code == "egress_alerts_unsupported" {
                        "operations_alerts_unsupported"
                    } else {
                        expected_code
                    }
                )
            );
        }
    }

    fn administrator(directory: &std::path::Path) -> io::Result<String> {
        rusqlite::Connection::open(directory.join("management.sqlite3"))
            .map_err(io::Error::other)?
            .query_row("SELECT id FROM administrators", [], |row| row.get(0))
            .map_err(io::Error::other)
    }

    /// Register the fixture's loopback target and create a browser session without
    /// weakening the actual node TLS/DER/owner checks or starting a second monitor.
    async fn browser(
        fixture: &node::tests::Fixture,
    ) -> io::Result<(Arc<AppState>, String, TcpListener)> {
        let mut state = crate::manage::api::initialize(
            fixture.client_state.clone(),
            PublicOrigin::parse("https://localhost:8443")?,
            Arc::new(store::lock(&fixture.client_state)?),
        )
        .await?;
        let caller = state
            .policy
            .clone()
            .ok_or_else(|| io::Error::other("fixture policy missing"))?;
        let admin = administrator(&fixture.client_state)?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        store::targets::configure(
            &fixture.client_state,
            &admin,
            &fixture.server_id,
            None,
            &format!("https://localhost:{}", address.port()),
            true,
            None,
        )?;
        let (service, _runner) = controller::Service::new(
            caller,
            fixture.client_tls.clone(),
            fixture.client_id.clone(),
        );
        Arc::get_mut(&mut state)
            .ok_or_else(|| io::Error::other("fixture state is shared"))?
            .controller = Some(service);
        let token = "t".repeat(43);
        let mut session = crate::manage::api::tests::fixture_session(std::time::Instant::now());
        session.administrator.id = admin;
        state
            .security()
            .map_err(|_| io::Error::other("fixture security missing"))?
            .insert_session(None, token.clone(), session)
            .map_err(|_| io::Error::other("fixture session failed"))?;
        let cookie = format!("{COOKIE_NAME}={token}");
        Ok((state, cookie, listener))
    }

    /// Cancel and join all owned async work before returning an I/O error or
    /// propagating an assertion panic. A listener has its own five-second drain;
    /// the outer ten-second budget leaves room to observe that result.
    async fn finish(
        shutdown: &CancellationToken,
        tasks: &mut tokio::task::JoinSet<io::Result<()>>,
        result: std::thread::Result<io::Result<()>>,
    ) -> io::Result<()> {
        shutdown.cancel();
        let mut failure = None;
        let drained = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while let Some(joined) = tasks.join_next().await {
                if let Err(error) = joined.map_err(io::Error::other).and_then(|value| value) {
                    failure.get_or_insert(error);
                }
            }
        })
        .await;
        if drained.is_err() {
            failure.get_or_insert_with(|| {
                io::Error::new(io::ErrorKind::TimedOut, "fixture tasks did not drain")
            });
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        match result {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result?,
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Real node TLS/DER and owner checks behind the browser adapter. A monitor
    /// which has never run must stay an uncollected empty snapshot, not healthy.
    #[tokio::test]
    async fn egress_target_reads_exact_mtls_source_and_rechecks_owner_without_local_fallback()
    -> io::Result<()> {
        let fixture = node::tests::Fixture::new(true, true)?;
        let child_administrator = administrator(&fixture.server_state)?;
        let child = Coordinator::new(
            fixture.server_state.clone(),
            store::load_policy(&fixture.server_state)?,
            Arc::new(store::lock(&fixture.server_state)?),
        )?;
        let (alerts, _not_started) = crate::manage::alerts::new(
            child.clone(),
            fixture.server_id.clone(),
            None,
            None,
            false,
            false,
            None,
            None,
        )?;
        let expected_boot = alerts
            .egress_page(crate::manage::alerts::Filter::Active, None, 10)
            .map_err(|_| io::Error::other("fixture alert page unavailable"))?
            .boot_id;
        let (state, cookie, listener) = browser(&fixture).await?;
        let address = listener.local_addr()?;
        let shutdown = CancellationToken::new();
        let _cancel_on_drop = shutdown.clone().drop_guard();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(node::serve(
            listener,
            fixture.config(address)?,
            fixture.server_state.clone(),
            shutdown.clone(),
            Some(child.clone()),
            None,
            Some(alerts),
        ));
        let result = std::panic::AssertUnwindSafe(async {
            let paths = [
                format!("/api/v1/targets/{}/egress-alerts", fixture.server_id),
                format!("/api/v1/targets/{}/operations-alerts", fixture.server_id),
            ];
            for path in &paths {
                let response = call(state.clone(), authorized(&cookie, Method::GET, path)).await;
                assert_eq!(
                    body(response, StatusCode::BAD_GATEWAY).await["error"]["code"],
                    "peer_not_authorized"
                );
            }
            child
                .set_owner(
                    child_administrator.clone(),
                    1,
                    Some(fixture.client_id.clone()),
                )
                .await?;
            for path in &paths {
                let response = call(state.clone(), authorized(&cookie, Method::GET, path)).await;
                let page = body(response, StatusCode::OK).await;
                assert_eq!(page["node_id"], fixture.server_id);
                assert_eq!(page["boot_id"], expected_boot);
                if path.ends_with("/egress-alerts") {
                    assert_eq!(page["monitored"], false);
                    assert!(page.get("coverage").is_none());
                } else {
                    assert!(page.get("monitored").is_none());
                    assert_eq!(
                        page["coverage"],
                        json!({"local_egress":false,"local_traffic":false,
                "local_proxy_expected":false,"local_management_https":false,
                "local_node_tls":false,"local_proxy_tls":false})
                    );
                }
                assert_eq!(page["items"], json!([]));
                assert_eq!(page["active_count"], 0);
                assert!(page["age_millis"].is_null() && page["observed_at_unix_ms"].is_null());
                let response = call(state.clone(), authorized(&cookie, Method::HEAD, path)).await;
                assert_eq!(response.status(), StatusCode::OK);
                assert!(
                    response
                        .into_body()
                        .collect()
                        .await
                        .map_err(io::Error::other)?
                        .to_bytes()
                        .is_empty()
                );
            }
            let wrong_domain = format!("{}?after={expected_boot}:1:egress-active:0", paths[1]);
            let response = call(
                state.clone(),
                authorized(&cookie, Method::GET, &wrong_domain),
            )
            .await;
            assert_eq!(
                body(response, StatusCode::BAD_REQUEST).await["error"]["code"],
                "invalid_alert_query"
            );
            let response = call(
                state.clone(),
                authorized(&cookie, Method::GET, "/api/v1/alerts"),
            )
            .await;
            assert_eq!(
                body(response, StatusCode::SERVICE_UNAVAILABLE).await["error"]["code"],
                "alerts_unavailable"
            );
            child.set_owner(child_administrator, 2, None).await?;
            for path in &paths {
                let response = call(state.clone(), authorized(&cookie, Method::GET, path)).await;
                assert_eq!(
                    body(response, StatusCode::BAD_GATEWAY).await["error"]["code"],
                    "peer_not_authorized"
                );
            }
            let response = call(
                state,
                authorized(&cookie, Method::GET, "/api/v1/auth/session"),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            io::Result::Ok(())
        })
        .catch_unwind()
        .await;
        finish(&shutdown, &mut tasks, result).await
    }

    /// Wait only for this source/target's real probe, not a global snapshot sequence
    /// which unrelated catalog refreshes or bind checks can advance.
    async fn tcp_sample(
        health: &health::Handle,
        address_id: &str,
        target: std::net::SocketAddr,
        accepts: impl Fn(health::FixedOutcome) -> bool,
    ) -> io::Result<(health::FixedOutcome, u64)> {
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let snapshot = health.snapshot()?;
                let sample = snapshot
                    .entries
                    .iter()
                    .find(|entry| entry.address_id == address_id)
                    .and_then(|entry| {
                        entry.checks.iter().find(|check| {
                            check.kind == health::CheckKind::Tcp
                                && check.target == Some(target)
                                && accepts(check.outcome)
                        })
                    });
                if let Some(check) = sample
                    && let Some(sequence) = check.sequence
                {
                    return Ok((check.outcome, sequence));
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture TCP probe did not complete",
            )
        })?
    }

    /// Exercise actual source binding and TCP failure/recovery through the fixed
    /// mTLS route and Session adapter. One bound socket retains ownership of the
    /// target port across the transition; no close/rebind race or injected health
    /// observation can fabricate recovery. The returned source identity also feeds
    /// the exact Session address read, including its retained retired record.
    #[tokio::test]
    async fn egress_target_relays_real_probe_failure_and_newer_recovery() -> io::Result<()> {
        let fixture = node::tests::Fixture::new(true, true)?;
        let admin = administrator(&fixture.server_state)?;
        let child = Coordinator::new(
            fixture.server_state.clone(),
            store::load_policy(&fixture.server_state)?,
            Arc::new(store::lock(&fixture.server_state)?),
        )?;
        let change = child
            .change(
                admin.clone(),
                1,
                store::PolicyChange::CreateAddress {
                    name: "owned loopback".into(),
                    ip: std::net::Ipv4Addr::LOCALHOST.into(),
                    prefix_id: None,
                },
            )
            .await?;
        let catalog_revision = change.revision;
        let Some(RoutingEntity::Address(address)) = change.routing else {
            return Err(io::Error::other("fixture address missing"));
        };
        child
            .set_owner(admin.clone(), 1, Some(fixture.client_id.clone()))
            .await?;
        let target_socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        target_socket.set_nonblocking(true)?;
        target_socket
            .bind(&std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)).into())?;
        let target = target_socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("fixture target missing"))?;
        let connector = crate::connect::Connector::new(
            None,
            None,
            Some(Fallback::Address(std::net::Ipv4Addr::LOCALHOST.into())),
            10,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            None,
            None,
        );
        let (health, health_runner) = health::new(
            child.clone(),
            connector,
            health::Config {
                interval_secs: 10,
                timeout_secs: 1,
                probes_per_second: 16,
                targets: vec![target],
                ..health::Config::default()
            },
        )?;
        let (alerts, mut alert_runner) = crate::manage::alerts::new(
            child.clone(),
            fixture.server_id.clone(),
            Some(health.clone()),
            None,
            false,
            false,
            None,
            None,
        )?;
        let (state, cookie, listener) = browser(&fixture).await?;
        let node_address = listener.local_addr()?;
        let config = fixture.config(node_address)?;
        let shutdown = CancellationToken::new();
        let _cancel_on_drop = shutdown.clone().drop_guard();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(node::serve(
            listener,
            config,
            fixture.server_state.clone(),
            shutdown.clone(),
            Some(child.clone()),
            None,
            Some(alerts),
        ));
        tasks.spawn(health_runner.run(shutdown.clone()));
        let result = std::panic::AssertUnwindSafe(async {
        let path = format!("/api/v1/targets/{}/egress-alerts", fixture.server_id);
        // A bound but non-listening port can reject immediately or let the
        // bounded connect expire (notably on Windows). Both are real failures;
        // unrelated outcomes must not satisfy this fixture.
        let (failure_outcome, failure_sequence) = tcp_sample(&health, &address.id, target, |value| {
            matches!(value, health::FixedOutcome::ConnectionRefused | health::FixedOutcome::TimedOut)
        }).await?;
        let failure_code = match failure_outcome {
            health::FixedOutcome::ConnectionRefused => "egress_connection_refused",
            health::FixedOutcome::TimedOut => "egress_timed_out",
            _ => return Err(io::Error::other("fixture expected a connect failure")),
        };
        alert_runner.collect_once().await?;
        let response = call(state.clone(), authorized(&cookie, Method::GET, &path)).await;
        let failure = body(response, StatusCode::OK).await;
        assert_eq!(failure["node_id"], fixture.server_id);
        assert_eq!(failure["monitored"], true);
        assert_eq!(failure["collection_error"], false);
        assert_eq!(failure["active_count"], 1);
        assert_eq!(failure["recent_count"], 0);
        assert_eq!(failure["items"].as_array().unwrap().len(), 1);
        let episode = &failure["items"][0];
        assert_eq!(episode["origin_node_id"], fixture.server_id);
        assert_eq!(episode["resource_id"], address.id);
        assert_eq!(episode["check"], "tcp");
        assert_eq!(episode["target"], target.to_string());
        assert_eq!(episode["status"], "active");
        assert_eq!(episode["code"], failure_code);
        let reported_failure = episode["evidence_sequence"].as_str().unwrap().parse::<u64>().unwrap();
        assert!(reported_failure >= failure_sequence);
        assert_eq!(episode["evidence_fresh"], true);

        // Read the wire's source and resource ID, not a local catalog or a
        // replacement ID synthesized by the controller fixture.
        let source = episode["origin_node_id"].as_str().unwrap();
        let resource_id = episode["resource_id"].as_str().unwrap();
        let address_path = format!("/api/v1/targets/{source}/proxy/addresses/{resource_id}");
        let response = call(state.clone(), authorized(&cookie, Method::GET, &address_path)).await;
        let located = body(response, StatusCode::OK).await;
        assert_eq!(located["revision"], catalog_revision.to_string());
        assert_eq!(located["address"]["id"], resource_id);
        assert_eq!(located["address"]["ip"], address.ip.to_string());
        assert_eq!(located["address"]["revision"], address.revision.to_string());
        assert_eq!(located["address"]["state"], "active");
        let response = call(
            state.clone(),
            authorized(&cookie, Method::GET, &format!("/api/v1/proxy/addresses/{resource_id}")),
        ).await;
        assert_eq!(body(response, StatusCode::NOT_FOUND).await["error"]["code"], "resource_not_found");

        target_socket.listen(1)?;
        let target_listener = TcpListener::from_std(target_socket.into())?;
        let accept_shutdown = shutdown.clone();
        let (accepted, accepted_peer) = tokio::sync::oneshot::channel();
        tasks.spawn(async move {
            let mut accepted = Some(accepted);
            // Keep accepting until teardown: dropping after the first handshake
            // could make a later scheduled probe fail before recovery is read.
            loop {
                tokio::select! {
                    biased;
                    _ = accept_shutdown.cancelled() => return Ok(()),
                    result = target_listener.accept() => {
                        let (stream, peer) = result?;
                        drop(stream);
                        if let Some(sender) = accepted.take() {
                            sender.send(peer).map_err(|_| io::Error::other("fixture peer receiver closed"))?;
                        }
                    }
                }
            }
        });
        let (_, success_sequence) = tcp_sample(&health, &address.id, target, |value| {
            value == health::FixedOutcome::Success
        }).await?;
        assert!(success_sequence > failure_sequence);
        let peer = tokio::time::timeout(std::time::Duration::from_secs(1), accepted_peer)
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        assert_eq!(peer.ip(), address.ip);
        alert_runner.collect_once().await?;
        let response = call(state.clone(), authorized(&cookie, Method::GET, &path)).await;
        let active = body(response, StatusCode::OK).await;
        assert_eq!(active["boot_id"], failure["boot_id"]);
        assert_eq!(active["active_count"], 0);
        assert_eq!(active["recent_count"], 1);
        assert_eq!(active["items"], json!([]));
        let response = call(
            state.clone(),
            authorized(&cookie, Method::GET, &format!("{path}?state=recent")),
        )
        .await;
        let recent = body(response, StatusCode::OK).await;
        assert_eq!(recent["items"].as_array().unwrap().len(), 1);
        let recovered = &recent["items"][0];
        for field in ["id", "origin_node_id", "resource_id", "check", "target", "first_observed_at_unix_ms"] {
            assert_eq!(recovered[field], episode[field], "episode field: {field}");
        }
        assert_eq!(recovered["status"], "recovered");
        assert_eq!(recovered["evidence_fresh"], true);
        let reported_recovery = recovered["evidence_sequence"].as_str().unwrap().parse::<u64>().unwrap();
        assert!(reported_recovery >= success_sequence && reported_recovery > reported_failure);
        assert!(recovered["ended_at_unix_ms"].is_string());

        // Retirement changes inventory, not the already observed recovery.
        // The same resource ID returned by the episode must locate the retained record.
        // The owner must retire this managed resource over its existing mTLS
        // command path; a local administrator change is correctly rejected.
        let caller = state.policy.as_ref().ok_or_else(|| io::Error::other("fixture policy missing"))?;
        let origin = format!("https://localhost:{}", node_address.port());
        let control::Reply::Policy(policy) = control::request(
            caller, fixture.client_tls.clone(), &origin, &fixture.server_id,
            control::Request::Policy,
        ).await? else {
            return Err(io::Error::other("fixture expected current owner policy"));
        };
        assert_eq!(policy.controller_node_id.as_deref(), Some(fixture.client_id.as_str()));
        assert_eq!(policy.saved_revision, catalog_revision.to_string());
        let command_id = policy.last_terminal_command.parse::<u64>().map_err(io::Error::other)?
            .checked_add(1).ok_or_else(|| io::Error::other("fixture command sequence exhausted"))?
            .to_string();
        let retired_revision = catalog_revision.checked_add(1)
            .ok_or_else(|| io::Error::other("fixture catalog revision exhausted"))?.to_string();
        let control::Reply::Command(retired) = control::request(
            caller, fixture.client_tls.clone(), &origin, &fixture.server_id,
            control::Request::RoutingCommand(control::RoutingCommand {
                version: 2,
                target_node_id: fixture.server_id.clone(),
                resource: "proxy_policy".into(),
                controller_epoch: policy.controller_epoch.clone(),
                command_id: command_id.clone(),
                expected_policy_revision: catalog_revision.to_string(),
                source_administrator_id: administrator(&fixture.client_state)?,
                mutation: control::RoutingMutation::SetAddressState {
                    id: resource_id.to_owned(),
                    state: ResourceState::Retired,
                },
            }),
        ).await? else {
            return Err(io::Error::other("fixture expected retirement receipt"));
        };
        assert_eq!(retired.receipt.controller_epoch, policy.controller_epoch);
        assert_eq!(retired.receipt.command_id, command_id);
        assert_eq!(retired.receipt.policy_revision.as_deref(), Some(retired_revision.as_str()));
        assert!(!retired.replayed);
        let Some(crate::manage::views::Entity::Address(retired_address)) = &retired.routing else {
            return Err(io::Error::other("fixture expected retired address receipt"));
        };
        assert_eq!(retired_address.id, resource_id);
        assert_eq!(retired_address.state, ResourceState::Retired);
        assert_eq!(retired_address.revision, retired_revision);
        let source = recovered["origin_node_id"].as_str().unwrap();
        let resource_id = recovered["resource_id"].as_str().unwrap();
        let response = call(
            state,
            authorized(&cookie, Method::GET, &format!("/api/v1/targets/{source}/proxy/addresses/{resource_id}")),
        ).await;
        let located = body(response, StatusCode::OK).await;
        assert_eq!(located["revision"], retired_revision);
        assert_eq!(located["address"]["revision"], retired_revision);
        assert_eq!(located["address"]["id"], resource_id);
        assert_eq!(located["address"]["ip"], address.ip.to_string());
        assert_eq!(located["address"]["state"], "retired");
        io::Result::Ok(())
    })
    .catch_unwind()
    .await;
        finish(&shutdown, &mut tasks, result).await?;
        assert_eq!(health.snapshot()?.in_flight, 0);
        Ok(())
    }
}
