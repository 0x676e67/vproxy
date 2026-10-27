//! Internal management preparation and the shared runtime handoff from one
//! registered capture. Preparation is inert; the separate internal run path
//! applies selected kernel inputs and starts the ordinary supervised services.
//! No public Source CLI startup or same-identity takeover is exposed here.

use super::*;
use crate::manage::{
    snapshot,
    snapshot::config::{Surface, Tls},
};

/// TLS and process-local API state use the same registered inputs. Remaining
/// node/proxy/health inputs and an optional ACME runner stay owned for the final
/// supervisor; their presence is not proof that they have started successfully.
pub(super) struct Prepared {
    pub(super) state: Arc<AppState>,
    pub(super) inputs: snapshot::inputs::Prepared,
    pub(super) acme: Option<crate::manage::acme::Prepared>,
    /// Monitoring can use the actual selected identity without parsing its old
    /// path again; the final supervisor installs the complete identity catalog.
    pub(super) certificate_source: crate::manage::certificates::ManagementSource,
    tls: Acceptor,
    reference: crate::manage::store::journal::configuration::Reference,
    key_sha256: [u8; 32],
}

/// Internal full-runtime entry using the same supervisor as ordinary serving.
/// The caller has already registered these exact choices, keeps its original
/// author, and must establish the separate activation/fencing gates before this
/// can be exposed publicly. Tests use only new loopback fixtures/no backend.
/// Kernel loading and privilege reduction precede all runtime/Source threads.
pub(super) fn run(
    directory: PathBuf,
    author: Arc<crate::manage::store::Guard>,
    registered: snapshot::Registered,
    stop: impl std::future::Future<Output = io::Result<()>> + Send + 'static,
) -> io::Result<()> {
    run_with(
        directory,
        author,
        registered,
        stop,
        snapshot::config::Configuration::load_egress,
    )
}

/// The cold backend constructor is replaceable in unit fixtures so ordering is
/// tested without attaching kernel programs. No closure enters a forwarding
/// runtime or changes the captured configuration/confirmation rules.
fn run_with(
    directory: PathBuf,
    author: Arc<crate::manage::store::Guard>,
    registered: snapshot::Registered,
    stop: impl std::future::Future<Output = io::Result<()>> + Send + 'static,
    load: impl FnOnce(&snapshot::config::Configuration) -> io::Result<crate::ebpf::Config>,
) -> io::Result<()> {
    author.ensure(&directory)?;
    registered.validate(&directory)?;
    check_surface(registered.inputs.configuration.management.surface)?;
    registered.inputs.configuration.check_egress_support()?;
    let startup = registered.preflight(&directory, author.clone())?;
    let profile_config = load(&registered.inputs.configuration)?;
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        let config = &registered.inputs.configuration;
        let acme_http = match &config.management.tls {
            Tls::Acme { options } => options.http_bind(),
            Tls::Manual { .. } => None,
        };
        profile_config.restrict_runtime_privileges(
            config.management.bind.port() < 1024
                || config.node.bind.port() < 1024
                || acme_http.is_some_and(|b| b.port() < 1024)
                || registered
                    .inputs
                    .proxy
                    .as_ref()
                    .is_some_and(crate::manage::proxy::Prepared::privileged_bind),
            registered
                .inputs
                .proxy
                .as_ref()
                .is_some_and(crate::manage::proxy::Prepared::interface_fallback),
        )?;
    }
    // The sole author survives this handoff. Release update only once kernel
    // preparation is complete so the real Source worker can acquire it and
    // repeat fresh confirmation before any listener accepts requests.
    drop(startup);
    super::run_prepared(
        async move {
            let prepared = prepare(directory, author, registered).await?;
            let mut inputs = prepared.inputs;
            Ok(super::Prepared {
                state: prepared.state,
                bind: inputs.configuration.management.bind,
                tls: prepared.tls,
                acme: prepared.acme,
                certificate_source: prepared.certificate_source,
                service_tls: None,
                node: inputs.node_listener.take(),
                prepared_proxy: inputs
                    .proxy
                    .take()
                    .map(|p| p.with_profile_config(profile_config.clone())),
                profile_config,
                health_config: inputs.health,
                health_explicit: inputs.configuration.health_config.is_some(),
                observe_target_alerts: inputs.configuration.observe_target_alerts,
                source: Some((prepared.reference, prepared.key_sha256)),
            })
        },
        stop,
    )
}

/// Original author, exact registered projection and fresh confirmation precede
/// API state. No source file is reopened; only the selected dynamic ACME cache
/// may be prepared using normal consent/configuration rules, without CA traffic.
/// Failure stops the newly-created worker; cancellation retains actual owners
/// on existing blocking/worker jobs rather than releasing their guards early.
pub(super) async fn prepare(
    directory: PathBuf,
    author: Arc<crate::manage::store::Guard>,
    registered: snapshot::Registered,
) -> io::Result<Prepared> {
    let reference = registered.reference;
    let (policy, inputs) = crate::manage::policy::Coordinator::new_registered_source(
        directory.clone(),
        author.clone(),
        registered,
    )
    .await?;
    let result = prepare_state(directory, author, policy.clone(), inputs, reference).await;
    if result.is_err()
        && let Err(error) = policy.shutdown_writer().await
    {
        tracing::error!(kind = ?error.kind(), "registered management preparation cleanup failed");
    }
    result
}

/// Reject an incompatible installed binary before any kernel/cache effects.
fn check_surface(surface: Surface) -> io::Result<()> {
    if matches!(
        (surface, cfg!(feature = "web-ui")),
        (Surface::ApiOnly, false) | (Surface::Web, true)
    ) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "registered management surface differs from this binary",
        ))
    }
}

async fn prepare_state(
    directory: PathBuf,
    author: Arc<crate::manage::store::Guard>,
    policy: Arc<crate::manage::policy::Coordinator>,
    inputs: snapshot::inputs::Prepared,
    reference: crate::manage::store::journal::configuration::Reference,
) -> io::Result<Prepared> {
    check_surface(inputs.configuration.management.surface)?;
    let key_sha256 = inputs.node.key_sha256()?;
    let overview = policy
        .source_startup(directory.clone(), reference, key_sha256)
        .await?;
    let origin = PublicOrigin::parse(&inputs.configuration.management.origin)?;
    let storage = directory.clone();
    let original = author.clone();
    let (inputs, tls, acme, certificate_source, dummy_phc) =
        tokio::task::spawn_blocking(move || {
            original.ensure(&storage)?;
            let mut inputs = inputs;
            let (tls, acme, certificate_source) = match &inputs.configuration.management.tls {
                Tls::Manual { .. } => {
                    let (tls, metadata) = inputs.management.take().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "captured management TLS required",
                        )
                    })?;
                    (
                        Acceptor::Manual(TlsAcceptor::from(tls)),
                        None,
                        crate::manage::certificates::ManagementSource::Manual(metadata),
                    )
                }
                Tls::Acme { options } => {
                    let acme = options
                        .options()
                        .prepare(&inputs.configuration.management.origin, &storage, original)?
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "explicit ACME configuration required",
                            )
                        })?;
                    let source = crate::manage::certificates::ManagementSource::Acme(acme.tls());
                    (Acceptor::Acme(acme.tls()), Some(acme), source)
                }
            };
            let dummy_phc = dummy_verifier()?;
            Ok::<_, io::Error>((inputs, tls, acme, certificate_source, dummy_phc))
        })
        .await
        .map_err(|_| io::Error::other("registered management preparation worker failed"))??;
    let mut state = initialized_state(directory, origin, overview, dummy_phc, author, Some(policy));
    Arc::get_mut(&mut state)
        .ok_or_else(|| io::Error::other("management state shared before initialization"))?
        .acme = acme.as_ref().map(crate::manage::acme::Prepared::status);
    Ok(Prepared {
        state,
        inputs,
        acme,
        certificate_source,
        tls,
        reference,
        key_sha256,
    })
}

impl Prepared {
    /// Serve only the exact declared management bind after another fresh owned
    /// startup read. The common supervisor, not this listener, owns proxy/issuer
    /// activation and shared worker shutdown. No fallback creates Native state.
    pub(super) async fn serve(
        self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> io::Result<()> {
        if listener.local_addr()? != self.inputs.configuration.management.bind {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "registered management listener differs",
            ));
        }
        self.state
            .policy
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "registered management coordinator required",
                )
            })?
            .source_startup(
                self.state.directory.clone(),
                self.reference,
                self.key_sha256,
            )
            .await?;
        // Keep unused captured inputs and the not-yet-started issuer owned for
        // the entire listener lifetime; dropping a waiter is not an activation.
        let _inputs = self.inputs;
        let _acme = self.acme;
        let _certificate_source = self.certificate_source;
        super::serve(listener, self.tls, router(self.state), shutdown).await
    }
}

#[cfg(test)]
mod tests {
    //! Strict loopback HTTPS against the real registered state/router/Source writer.
    //! Fresh unit fixtures only: no browser trust, existing credentials or CA traffic.
    use super::*;
    use crate::manage::{
        node, store,
        store::journal::{SourceExportFixture, SourceFixture},
    };
    use axum::body::Body;
    use bytes::Bytes;
    use futures_util::StreamExt as _;
    use http_body_util::BodyExt as _;
    use hyper_util::rt::TokioIo;
    use rustls::{ClientConfig, RootCertStore, crypto::aws_lc_rs};
    use rustls_pki_types::ServerName;
    use std::fs;
    use tokio_rustls::TlsConnector;

    const PASSWORD: &str = "registered management fixture passphrase";
    type Client = hyper::client::conn::http1::SendRequest<Body>;

    mod preflight {
        //! Exercise the actual run entry with an inert backend constructor. No kernel
        //! interface is touched, even on Linux builds that compile the eBPF backend.
        use super::*;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[tokio::test]
        async fn registered_run_rejects_stale_sql_before_backend_and_holds_guards_through_valid_preparation()
        -> io::Result<()> {
            for stale in [false, true] {
                let (export, listener) = fixture(Default::default()).await?;
                let result = async {
            let registered=export.register(0,false).await?;
            if stale {
                change(&export,|v|v["observe_target_alerts"]=true.into())?;
                export.register(1,false).await?;
            }
            let before=export.floor()?;
            let directory=export.fixture.client_state.clone();
            let author=Arc::new(store::lock(&directory)?);
            let calls=Arc::new(AtomicUsize::new(0));
            let observed=calls.clone();
            let checked=directory.clone();
            let result=tokio::task::spawn_blocking(move||run_with(directory,author,registered,
                std::future::pending(),move |_| {
                    observed.fetch_add(1,Ordering::AcqRel);
                    if !matches!(store::lock(&checked),Err(e) if e.kind()==io::ErrorKind::WouldBlock)
                        || !matches!(store::update_lock(&checked),Err(e) if e.kind()==io::ErrorKind::WouldBlock) {
                        return Err(io::Error::other("startup guard missing at backend preparation"));
                    }
                    Err(io::Error::new(io::ErrorKind::Interrupted,"inert backend probe reached"))
                })).await.map_err(io::Error::other)?;
            let error=result.err().ok_or_else(||io::Error::other("probe refusal expected"))?;
            assert_eq!(calls.load(Ordering::Acquire),usize::from(!stale));
            assert_eq!(error.kind(),if stale {io::ErrorKind::PermissionDenied} else {io::ErrorKind::Interrupted});
            assert_eq!(export.floor()?,before);
            store::lock(&export.fixture.client_state)?;
            store::update_lock(&export.fixture.client_state)?;
            drop(listener);
            Ok(())
        }.await;
                result.and(export.close().await)?;
            }
            Ok(())
        }

        #[tokio::test]
        async fn registered_run_refuses_an_unavailable_witness_before_backend_preparation()
        -> io::Result<()> {
            let (export, listener) = fixture(Default::default()).await?;
            let registered = export.register(0, false).await?;
            let resources = export.fixture.clone();
            let binding = registered
                .inputs
                .configuration
                .source
                .as_ref()
                .ok_or_else(|| io::Error::other("binding"))?
                .enrollment
                .binding_id
                .clone();
            let before = export.floor()?;
            // Keep the same private files/IDs alive, but really stop the witness server.
            export.close().await?;
            let directory = resources.client_state.clone();
            let author = Arc::new(store::lock(&directory)?);
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            let result = tokio::task::spawn_blocking(move || {
                run_with(
                    directory,
                    author,
                    registered,
                    std::future::pending(),
                    move |_| {
                        observed.fetch_add(1, Ordering::AcqRel);
                        Err(io::Error::other("backend must not be reached"))
                    },
                )
            })
            .await
            .map_err(io::Error::other)?;
            assert!(result.is_err());
            assert_eq!(calls.load(Ordering::Acquire), 0);
            assert_eq!(
                store::witness::inspect(&resources.server_state, &binding)?,
                before
            );
            store::lock(&resources.client_state)?;
            store::update_lock(&resources.client_state)?;
            drop(listener);
            Ok(())
        }

        #[tokio::test]
        async fn registered_preflight_keeps_pending_sql_fenced_but_reads_freshly_confirmed_original_commit()
        -> io::Result<()> {
            for reserve in [true, false] {
                let (export, listener) = fixture(node::tests::CutResponse {
                    witness_only: true,
                    witness_reserve: reserve,
                    witness_confirm: !reserve,
                    witness_sequence: Some(2),
                    ..Default::default()
                })
                .await?;
                let result = async {
                    let first = export.register(0, false).await?;
                    let original = export.register(1, false).await?;
                    let prepared = prepare(
                        export.fixture.client_state.clone(),
                        Arc::new(store::lock(&export.fixture.client_state)?),
                        first,
                    )
                    .await?;
                    let policy = prepared
                        .state
                        .policy
                        .clone()
                        .ok_or_else(|| io::Error::other("policy"))?;
                    let connection = rusqlite::Connection::open(
                        export.fixture.client_state.join("management.sqlite3"),
                    )
                    .map_err(io::Error::other)?;
                    let administrator: String = connection
                        .query_row("SELECT id FROM administrators", [], |r| r.get(0))
                        .map_err(io::Error::other)?;
                    drop(connection);
                    export.arm();
                    let changed = policy
                        .change(
                            administrator,
                            1,
                            store::PolicyChange::CreateUser {
                                name: "preflight original operation".into(),
                                protocols: vec![crate::access::Protocol::Http],
                                concurrent_limit: 1,
                            },
                        )
                        .await;
                    let stopped = policy.shutdown_writer().await;
                    drop(prepared);
                    drop(policy);
                    assert!(store::journal::is_uncertain(
                        &changed
                            .err()
                            .ok_or_else(|| io::Error::other("unknown result expected"))?
                    ));
                    stopped?;
                    let before = export.floor()?;
                    let directory = export.fixture.client_state.clone();
                    let author = Arc::new(store::lock(&directory)?);
                    let calls = Arc::new(AtomicUsize::new(0));
                    let observed = calls.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        run_with(
                            directory,
                            author,
                            original,
                            std::future::pending(),
                            move |_| {
                                observed.fetch_add(1, Ordering::AcqRel);
                                Err(io::Error::new(
                                    io::ErrorKind::Interrupted,
                                    "confirmed original reached inert backend",
                                ))
                            },
                        )
                    })
                    .await
                    .map_err(io::Error::other)?;
                    assert!(result.is_err());
                    assert_eq!(calls.load(Ordering::Acquire), usize::from(!reserve));
                    assert_eq!(export.floor()?, before);
                    let connection = rusqlite::Connection::open(
                        export.fixture.client_state.join("management.sqlite3"),
                    )
                    .map_err(io::Error::other)?;
                    let users: u32 = connection
                        .query_row("SELECT count(*) FROM proxy_users", [], |r| r.get(0))
                        .map_err(io::Error::other)?;
                    assert_eq!(users, u32::from(!reserve));
                    store::lock(&export.fixture.client_state)?;
                    store::update_lock(&export.fixture.client_state)?;
                    drop(listener);
                    Ok(())
                }
                .await;
                result.and(export.close().await)?;
            }
            Ok(())
        }

        #[tokio::test]
        async fn registered_run_refuses_pending_recovery_before_backend_or_transport_runtime()
        -> io::Result<()> {
            let (export, listener) = fixture(Default::default()).await?;
            let result=async {
        let registered=export.register(0,false).await?;
        let connection=rusqlite::Connection::open(export.fixture.client_state.join("management.sqlite3"))
            .map_err(io::Error::other)?;
        connection.execute("UPDATE recovery_state SET kind='restored',phase='pending_review',
            recovery_id=?1,source_node_id=?2,source_schema_version=26,source_database_sha256=?3,
            node_key_sha256=?4,imported_users=0,imported_prefixes=0,imported_addresses=0,imported_pools=0 WHERE singleton=1",
            rusqlite::params!["AAAAAAAAAAAAAAAAAAAAAA",export.fixture.server_id,"0".repeat(64),&[90u8;32][..]])
            .map_err(io::Error::other)?;
        drop(connection);
        assert_eq!(store::recovery::status(&export.fixture.client_state)?.recovery
            .as_ref().map(|r|r.phase),Some(store::recovery::Phase::PendingReview));
        let before=export.floor()?;
        let directory=export.fixture.client_state.clone();
        let author=Arc::new(store::lock(&directory)?);
        let calls=Arc::new(AtomicUsize::new(0));
        let observed=calls.clone();
        let result=tokio::task::spawn_blocking(move||run_with(directory,author,registered,
            std::future::pending(),move |_| {
                observed.fetch_add(1,Ordering::AcqRel);
                Err(io::Error::other("quarantine must not reach backend"))
            })).await.map_err(io::Error::other)?;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::Acquire),0);
        assert_eq!(export.floor()?,before);
        store::lock(&export.fixture.client_state)?;
        store::update_lock(&export.fixture.client_state)?;
        drop(listener);
        Ok(())
    }.await;
            result.and(export.close().await)
        }
    }
    mod runtime {
        //! The same full supervisor used by Native startup: real Source writer,
        //! management TLS, authenticated CONNECT, restart and orderly final metering.
        use super::*;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        /// Background Source checkpoints may temporarily suspend authority. Retry only
        /// a read or an explicit pre-session login refusal with no Set-Cookie. Never
        /// replay a user/credential mutation or a response with an unknown outcome.
        async fn available(
            client: &mut Client,
            mut make: impl FnMut() -> io::Result<http::Request<Body>>,
        ) -> io::Result<(StatusCode, HeaderMap, serde_json::Value)> {
            for attempt in 0..8 {
                let request = make()?;
                if request.method() != Method::GET
                    && !(request.method() == Method::POST
                        && request.uri().path() == "/api/v1/auth/login")
                {
                    return Err(io::Error::other("runtime fixture cannot retry mutations"));
                }
                let read = request.method() == Method::GET;
                let response = call(client, request).await?;
                // The same bounded GET readiness window covers policy read admission;
                // it cannot replay a mutation or turn an unrelated 503 into success.
                let retryable = response.2["error"]["code"] == "authentication_busy"
                    || read && response.2["error"]["code"] == "policy_busy";
                if response.0 != StatusCode::SERVICE_UNAVAILABLE
                    || !retryable
                    || response.1.contains_key(header::SET_COOKIE)
                    || attempt == 7
                {
                    return Ok(response);
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(io::Error::other("runtime fixture readiness exhausted"))
        }

        #[tokio::test]
        async fn registered_full_runtime_keeps_original_identity_and_credentials_across_clean_restart()
        -> io::Result<()> {
            let mut identity = None;
            let (export, listener) = fixture_with(Default::default(), |f| {
                let connection =
                    rusqlite::Connection::open(f.client_state.join("management.sqlite3"))
                        .map_err(io::Error::other)?;
                let actor: String = connection
                    .query_row("SELECT id FROM administrators", [], |r| r.get(0))
                    .map_err(io::Error::other)?;
                drop(connection);
                let gate = store::update_lock(&f.client_state)?;
                let user = store::apply_policy(
                    &f.client_state,
                    &actor,
                    1,
                    store::PolicyChange::CreateUser {
                        name: "runtime fixture".into(),
                        protocols: vec![crate::access::Protocol::Http],
                        concurrent_limit: 4,
                    },
                    &gate,
                )?;
                let credential = store::apply_policy(
                    &f.client_state,
                    &actor,
                    2,
                    store::PolicyChange::CreateCredential {
                        user_id: user.user.ok_or_else(|| io::Error::other("user"))?.id,
                    },
                    &gate,
                )?;
                identity = Some((
                    credential
                        .credential
                        .ok_or_else(|| io::Error::other("credential"))?
                        .login,
                    credential
                        .secret
                        .ok_or_else(|| io::Error::other("secret"))?,
                ));
                Ok(())
            })
            .await?;
            let result = async {
        let (login, secret) = identity.ok_or_else(|| io::Error::other("identity"))?;
        let plain = Zeroizing::new(format!("{login}:{}", secret.as_str()));
        let basic = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(plain.as_bytes()));
        let proxy_reservation = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_reservation.local_addr()?;
        let node_reservation = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let node_address = node_reservation.local_addr()?;
        let address = listener.local_addr()?;
        let tls = client_config(&export)?;
        let parent = export.configuration.parent().ok_or_else(|| io::Error::other("parent"))?;
        let proxy_file = parent.join("runtime-proxy.json");
        crate::manage::files::write(parent, "runtime-proxy.json", &serde_json::to_vec(&serde_json::json!({
            "listeners":[{"protocol":"http","bind":proxy_address}],"workers":1,"concurrent":4,
            "connect_timeout":3,"cidr":null,"cidr_range":null,"fallback":null
        })).map_err(io::Error::other)?)?;
        change(&export, |v| {
            v["proxy_config"] = proxy_file.to_string_lossy().as_ref().into();
            v["observe_target_alerts"] = true.into();
            v["node"]["bind"] = node_address.to_string().into();
            v["node"]["origin"] = format!("https://client.test:{}", node_address.port()).into();
        })?;
        let captures = [export.register(0, false).await?, export.register(1, false).await?];
        for path in [proxy_file,parent.join("admin.pem"),parent.join("admin.key"),parent.join("node.key"),
            export.configuration.clone(),export.fixture.ca.clone(),export.fixture.client_cert.clone()] {
            fs::remove_file(path)?;
        }
        drop(listener);
        drop(proxy_reservation);
        drop(node_reservation);
        let destination = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let target = destination.local_addr()?;
        let mut echoes = JoinSet::new();
        echoes.spawn(async move {
            for _ in 0..2 {
                let (mut stream,_) = destination.accept().await?;
                let mut input = [0;4]; stream.read_exact(&mut input).await?;
                assert_eq!(&input,b"ping");
                stream.write_all(b"reply").await?;
                stream.shutdown().await?;
            }
            Ok::<_,io::Error>(())
        });
        let mut previous_cursor = 0;
        for (round, registered) in captures.into_iter().enumerate() {
            let directory = export.fixture.client_state.clone();
            let author = Arc::new(store::lock(&directory)?);
            let (stop,stopping) = tokio::sync::oneshot::channel();
            let driver = tokio::task::spawn_blocking(move || run(directory, author, registered,
                async move {stopping.await.map_err(io::Error::other)}));
            let mut connections = JoinSet::new();
            let exercised = timeout(Duration::from_secs(40), async {
                // Socket readiness is not API readiness. The helper below
                // separately accepts only explicit, known pre-session refusals.
                timeout(Duration::from_secs(15), async {
                    loop {
                        match TcpStream::connect(address).await {
                            Ok(stream) => {drop(stream);break Ok::<_,io::Error>(());}
                            Err(e) if e.kind()==io::ErrorKind::ConnectionRefused => tokio::time::sleep(Duration::from_millis(10)).await,
                            Err(e) => break Err(e),
                        }
                    }
                }).await.map_err(io::Error::other)??;
                let mut client = connect(address, tls.clone(), &mut connections).await?;
                let (status,headers,session) = available(&mut client,||request(address,Method::POST,
                    "/api/v1/auth/login",login_body(PASSWORD),None,None)).await?;
                if status != StatusCode::OK {
                    return Err(io::Error::other(format!("runtime login status={status} code={}",
                        session["error"]["code"].as_str().unwrap_or("missing"))));
                }
                let cookie = Zeroizing::new(headers[header::SET_COOKIE].to_str().map_err(io::Error::other)?
                    .split(';').next().ok_or_else(|| io::Error::other("cookie"))?.to_owned());
                assert!(session["csrf_token"].is_string());
                for path in ["/api/v1/node","/api/v1/proxy/runtime","/api/v1/tls/status"] {
                    let (status,_,body) = available(&mut client,||request(address,Method::GET,path,Body::empty(),Some(&cookie),None)).await?;
                    if status != StatusCode::OK {
                        return Err(io::Error::other(format!("runtime read {path} status={status} code={}",
                            body["error"]["code"].as_str().unwrap_or("missing"))));
                    }
                    if path=="/api/v1/node" {assert_eq!(body["node_id"],export.fixture.client_id);}
                }
                let mut proxy = TcpStream::connect(proxy_address).await?;
                let request = Zeroizing::new(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {}\r\n\r\nping", basic.as_str()));
                proxy.write_all(request.as_bytes()).await?;
                let mut received=Vec::new(); proxy.read_to_end(&mut received).await?;
                assert!(received.starts_with(b"HTTP/1.1 200"));
                assert!(received.ends_with(b"reply"));
                Ok::<_,io::Error>(())
            }).await.map_err(io::Error::other).and_then(|r|r);
            let _ = stop.send(());
            connections.abort_all();
            while connections.join_next().await.is_some() {}
            let stopped = timeout(Duration::from_secs(30),driver).await.map_err(io::Error::other)?.map_err(io::Error::other)?;
            exercised?; stopped?;
            // Real shutdown has joined proxy workers, finalized the original
            // traffic run and released both author and Source update guards.
            let author = store::lock(&export.fixture.client_state)?;
            let gate = store::update_lock(&export.fixture.client_state)?;
            let traffic = store::traffic::status(&export.fixture.client_state)?;
            assert!(traffic.cursor>previous_cursor);
            assert!(traffic.run_id.is_some() && traffic.clean && !traffic.loss_possible);
            let totals=store::traffic::totals(&export.fixture.client_state, store::traffic::Scope::Node)?;
            let http=totals.items.iter().find(|v|v.protocol==crate::access::Protocol::Http)
                .ok_or_else(||io::Error::other("HTTP total missing"))?;
            assert_eq!((http.value.upload,http.value.download),(4*(round as u64+1),5*(round as u64+1)));
            previous_cursor=traffic.cursor;
            drop(gate); drop(author);
        }
        timeout(Duration::from_secs(5),echoes.join_next()).await.map_err(io::Error::other)?
            .ok_or_else(|| io::Error::other("echo missing"))?.map_err(io::Error::other)??;
        Ok(())
    }.await;
            result.and(export.close().await)
        }

        #[tokio::test]
        async fn registered_full_runtime_node_bind_failure_joins_its_writer_before_returning()
        -> io::Result<()> {
            let (export, listener) = fixture(Default::default()).await?;
            let result = async {
                let occupied = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
                let occupied_address = occupied.local_addr()?;
                change(&export, |v| {
                    v["node"]["bind"] = occupied_address.to_string().into();
                })?;
                let registered = export.register(0, false).await?;
                let before = export.floor()?;
                let directory = export.fixture.client_state.clone();
                let author = Arc::new(store::lock(&directory)?);
                let driver = tokio::task::spawn_blocking(move || {
                    run(directory, author, registered, std::future::pending())
                });
                let error = timeout(Duration::from_secs(20), driver)
                    .await
                    .map_err(io::Error::other)?
                    .map_err(io::Error::other)?
                    .err()
                    .ok_or_else(|| io::Error::other("bind refusal expected"))?;
                assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
                assert_eq!(export.floor()?, before);
                store::lock(&export.fixture.client_state)?;
                store::update_lock(&export.fixture.client_state)?;
                drop(listener);
                Ok(())
            }
            .await;
            result.and(export.close().await)
        }

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        #[tokio::test]
        async fn registered_full_runtime_refuses_a_selected_unsupported_backend_without_starting_workers()
        -> io::Result<()> {
            let (export, listener) = fixture(Default::default()).await?;
            let result = async {
                change(&export, |v| {
                    v["egress"] = serde_json::json!({
                        "interfaces":["task07-missing"], "allow_legacy_tc":false,
                        "replace_stale_legacy_tc":false, "map_capacity":64
                    })
                })?;
                let registered = export.register(0, false).await?;
                let before = export.floor()?;
                let directory = export.fixture.client_state.clone();
                let author = Arc::new(store::lock(&directory)?);
                let error = run(directory, author, registered, std::future::pending())
                    .err()
                    .ok_or_else(|| io::Error::other("backend refusal expected"))?;
                assert_eq!(error.kind(), io::ErrorKind::Unsupported);
                assert_eq!(export.floor()?, before);
                store::lock(&export.fixture.client_state)?;
                store::update_lock(&export.fixture.client_state)?;
                drop(listener);
                Ok(())
            }
            .await;
            result.and(export.close().await)
        }
    }

    async fn fixture(
        fault: node::tests::CutResponse,
    ) -> io::Result<(SourceExportFixture, TcpListener)> {
        fixture_with(fault, |_| Ok(())).await
    }

    async fn fixture_with(
        fault: node::tests::CutResponse,
        configure: impl FnOnce(&node::tests::Fixture) -> io::Result<()>,
    ) -> io::Result<(SourceExportFixture, TcpListener)> {
        let hash = tokio::task::spawn_blocking(|| {
            Argon2::default()
                .hash_password(PASSWORD.as_bytes())
                .map(|h| h.to_string())
                .map_err(io::Error::other)
        })
        .await
        .map_err(io::Error::other)??;
        let live = SourceFixture::new_with(fault, move |f| {
            let c = rusqlite::Connection::open(f.client_state.join("management.sqlite3"))
                .map_err(io::Error::other)?;
            c.execute("UPDATE administrators SET password_hash=?1", [&hash])
                .map_err(io::Error::other)?;
            configure(f)
        })
        .await?;
        let export = SourceExportFixture::from_live(live).await?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        change(&export, |v| {
            v["management"]["bind"] = address.to_string().into();
            v["management"]["origin"] = format!("https://admin.example:{}", address.port()).into();
            v["management"]["surface"] = surface().into();
        })?;
        Ok((export, listener))
    }

    fn surface() -> &'static str {
        if cfg!(feature = "web-ui") {
            "web"
        } else {
            "api_only"
        }
    }

    fn change(
        export: &SourceExportFixture,
        update: impl FnOnce(&mut serde_json::Value),
    ) -> io::Result<()> {
        let mut v: serde_json::Value =
            serde_json::from_slice(&fs::read(&export.configuration)?).map_err(io::Error::other)?;
        update(&mut v);
        fs::write(
            &export.configuration,
            serde_json::to_vec(&v).map_err(io::Error::other)?,
        )
    }

    fn client_config(export: &SourceExportFixture) -> io::Result<Arc<ClientConfig>> {
        let parent = export
            .configuration
            .parent()
            .ok_or_else(|| io::Error::other("fixture parent"))?;
        let bytes = fs::read(parent.join("admin.pem"))?;
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut bytes.as_slice()) {
            roots.add(cert?).map_err(io::Error::other)?;
        }
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(io::Error::other)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    async fn connect(
        address: SocketAddr,
        config: Arc<ClientConfig>,
        tasks: &mut JoinSet<io::Result<()>>,
    ) -> io::Result<Client> {
        let stream = TcpStream::connect(address).await?;
        let stream = TlsConnector::from(config)
            .connect(
                ServerName::try_from("admin.example").map_err(io::Error::other)?,
                stream,
            )
            .await?;
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
        let (client, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(io::Error::other)?;
        tasks.spawn(async move { connection.await.map_err(io::Error::other) });
        Ok(client)
    }

    fn request(
        address: SocketAddr,
        method: Method,
        path: &str,
        body: Body,
        cookie: Option<&str>,
        csrf: Option<&str>,
    ) -> io::Result<http::Request<Body>> {
        let mut builder = http::Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, format!("admin.example:{}", address.port()))
            .header(
                header::ORIGIN,
                format!("https://admin.example:{}", address.port()),
            )
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(value) = cookie {
            builder = builder.header(header::COOKIE, value);
        }
        if let Some(value) = csrf {
            builder = builder.header("x-csrf-token", value);
        }
        builder.body(body).map_err(io::Error::other)
    }

    async fn call(
        client: &mut Client,
        request: http::Request<Body>,
    ) -> io::Result<(StatusCode, HeaderMap, serde_json::Value)> {
        let response = client
            .send_request(request)
            .await
            .map_err(io::Error::other)?;
        let (parts, body) = response.into_parts();
        assert_eq!(parts.headers[header::CACHE_CONTROL], "no-store");
        let bytes = body.collect().await.map_err(io::Error::other)?.to_bytes();
        let body = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(io::Error::other)?
        };
        Ok((parts.status, parts.headers, body))
    }

    fn login_body(password: &str) -> Body {
        Body::from(serde_json::json!({"username":"admin", "password":password}).to_string())
    }

    fn user_body(revision: &str, name: &str) -> Body {
        Body::from(
            serde_json::json!({"expected_revision":revision,"name":name,
        "protocols":["http"],"concurrent_limit":1})
            .to_string(),
        )
    }

    #[tokio::test]
    async fn registered_https_login_csrf_users_and_original_unknown_result_keep_real_session_boundaries()
    -> io::Result<()> {
        for reserve in [true, false] {
            let (export, listener) = fixture(node::tests::CutResponse {
                witness_only: true,
                witness_reserve: reserve,
                witness_confirm: !reserve,
                witness_sequence: Some(3),
                ..Default::default()
            })
            .await?;
            let result = async {
                let address = listener.local_addr()?;
                let client_tls = client_config(&export)?;
                let registered = export.register(0, false).await?;
                // TLS and all static choices must come from the registered capture.
                let parent = export
                    .configuration
                    .parent()
                    .ok_or_else(|| io::Error::other("parent"))?;
                for path in [
                    parent.join("admin.pem"),
                    parent.join("admin.key"),
                    parent.join("node.key"),
                    export.fixture.ca.clone(),
                    export.fixture.client_cert.clone(),
                    export.configuration.clone(),
                ] {
                    fs::remove_file(path)?;
                }
                let prepared = prepare(
                    export.fixture.client_state.clone(),
                    Arc::new(store::lock(&export.fixture.client_state)?),
                    registered,
                )
                .await?;
                let state = prepared.state.clone();
                let policy = state
                    .policy
                    .clone()
                    .ok_or_else(|| io::Error::other("policy"))?;
                let shutdown = CancellationToken::new();
                let server = tokio::spawn(prepared.serve(listener, shutdown.clone()));
                let mut drivers = JoinSet::new();
                let result = timeout(Duration::from_secs(25), async {
                    let mut client = connect(address, client_tls, &mut drivers).await?;
                    let (status, headers, _) = call(
                        &mut client,
                        request(
                            address,
                            Method::POST,
                            "/api/v1/auth/login",
                            login_body("wrong"),
                            None,
                            None,
                        )?,
                    )
                    .await?;
                    assert_eq!(status, StatusCode::FORBIDDEN);
                    assert!(!headers.contains_key(header::SET_COOKIE));
                    let (status, headers, session) = call(
                        &mut client,
                        request(
                            address,
                            Method::POST,
                            "/api/v1/auth/login",
                            login_body(PASSWORD),
                            None,
                            None,
                        )?,
                    )
                    .await?;
                    assert_eq!(status, StatusCode::OK);
                    let cookie = Zeroizing::new(
                        headers
                            .get(header::SET_COOKIE)
                            .ok_or_else(|| io::Error::other("cookie"))?
                            .to_str()
                            .map_err(io::Error::other)?
                            .split(';')
                            .next()
                            .ok_or_else(|| io::Error::other("cookie pair"))?
                            .to_owned(),
                    );
                    let csrf = Zeroizing::new(
                        session["csrf_token"]
                            .as_str()
                            .ok_or_else(|| io::Error::other("csrf"))?
                            .to_owned(),
                    );
                    let (status, _, node) = call(
                        &mut client,
                        request(
                            address,
                            Method::GET,
                            "/api/v1/node",
                            Body::empty(),
                            Some(&cookie),
                            None,
                        )?,
                    )
                    .await?;
                    assert_eq!(status, StatusCode::OK);
                    assert_eq!(node["node_id"], export.fixture.client_id);
                    let (status, _, body) = call(
                        &mut client,
                        request(
                            address,
                            Method::POST,
                            "/api/v1/proxy/users",
                            user_body("1", "source HTTPS first"),
                            Some(&cookie),
                            None,
                        )?,
                    )
                    .await?;
                    assert_eq!(status, StatusCode::FORBIDDEN);
                    assert_eq!(body["error"]["code"], "invalid_csrf");
                    assert_eq!(export.floor()?.sequence, "1");
                    let (status, _, _) = call(
                        &mut client,
                        request(
                            address,
                            Method::POST,
                            "/api/v1/proxy/users",
                            user_body("1", "source HTTPS first"),
                            Some(&cookie),
                            Some(&csrf),
                        )?,
                    )
                    .await?;
                    assert_eq!(status, StatusCode::CREATED);
                    let (status, _, body) = call(
                        &mut client,
                        request(
                            address,
                            Method::GET,
                            "/api/v1/proxy/users",
                            Body::empty(),
                            Some(&cookie),
                            None,
                        )?,
                    )
                    .await?;
                    assert_eq!(status, StatusCode::OK);
                    assert_eq!(body["items"].as_array().map(Vec::len), Some(1));
                    export.arm();
                    let (status, _, body) = call(
                        &mut client,
                        request(
                            address,
                            Method::POST,
                            "/api/v1/proxy/users",
                            user_body("2", "source HTTPS unknown"),
                            Some(&cookie),
                            Some(&csrf),
                        )?,
                    )
                    .await?;
                    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                    assert_eq!(body["error"]["code"], "policy_unavailable");
                    let before = export.floor()?;
                    for path in ["/api/v1/node", "/api/v1/auth/session", "/api/v1/auth/login"] {
                        let login = path.ends_with("/login");
                        let (status, headers, body) = call(
                            &mut client,
                            request(
                                address,
                                if login { Method::POST } else { Method::GET },
                                path,
                                if login {
                                    login_body("wrong")
                                } else {
                                    Body::empty()
                                },
                                if login { None } else { Some(&cookie) },
                                None,
                            )?,
                        )
                        .await?;
                        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                        assert_eq!(body["error"]["code"], "authentication_busy");
                        assert!(!headers.contains_key(header::SET_COOKIE));
                    }
                    assert_eq!(export.floor()?, before);
                    policy.reconcile_source().await?;
                    let (status, _, body) = call(
                        &mut client,
                        request(
                            address,
                            Method::GET,
                            "/api/v1/proxy/users",
                            Body::empty(),
                            Some(&cookie),
                            None,
                        )?,
                    )
                    .await?;
                    assert_eq!(status, StatusCode::OK);
                    assert_eq!(body["items"].as_array().map(Vec::len), Some(2));
                    assert_eq!(export.floor()?.sequence, "3");
                    let (status, headers, _) = call(
                        &mut client,
                        request(
                            address,
                            Method::POST,
                            "/api/v1/auth/logout",
                            Body::from("{}"),
                            Some(&cookie),
                            Some(&csrf),
                        )?,
                    )
                    .await?;
                    assert_eq!(status, StatusCode::NO_CONTENT);
                    assert!(
                        headers
                            .get(header::SET_COOKIE)
                            .is_some_and(|v| v.to_str().is_ok_and(|v| v.contains("Max-Age=0")))
                    );
                    assert_eq!(
                        call(
                            &mut client,
                            request(
                                address,
                                Method::GET,
                                "/api/v1/auth/session",
                                Body::empty(),
                                Some(&cookie),
                                None
                            )?
                        )
                        .await?
                        .0,
                        StatusCode::FORBIDDEN
                    );
                    Ok::<_, io::Error>(())
                })
                .await
                .map_err(io::Error::other)
                .and_then(|r| r);
                shutdown.cancel();
                let served = server.await.map_err(io::Error::other);
                drivers.abort_all();
                while drivers.join_next().await.is_some() {}
                let stopped = policy.shutdown_writer().await;
                result?;
                served??;
                stopped?;
                Ok(())
            }
            .await;
            result.and(export.close().await)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn registered_login_rechecks_confirmation_after_a_body_wait_without_issuing_a_session()
    -> io::Result<()> {
        for password in [PASSWORD, "wrong"] {
            let (export, listener) = fixture(node::tests::CutResponse {
                witness_only: true,
                witness_reserve: true,
                witness_sequence: Some(2),
                ..Default::default()
            })
            .await?;
            let result = async {
                let address = listener.local_addr()?;
                let tls = client_config(&export)?;
                let registered = export.register(0, false).await?;
                let prepared = prepare(
                    export.fixture.client_state.clone(),
                    Arc::new(store::lock(&export.fixture.client_state)?),
                    registered,
                )
                .await?;
                let state = prepared.state.clone();
                let policy = state
                    .policy
                    .clone()
                    .ok_or_else(|| io::Error::other("policy"))?;
                let stop = CancellationToken::new();
                let server = tokio::spawn(prepared.serve(listener, stop.clone()));
                let mut tasks = JoinSet::new();
                let mut responses = JoinSet::new();
                let release = Arc::new(tokio::sync::Notify::new());
                let result = timeout(Duration::from_secs(20), async {
                    let mut client = connect(address, tls, &mut tasks).await?;
                    let released = release.clone();
                    let suffix = Bytes::from(format!("{password}\"}}"));
                    let body = Body::from_stream(
                        futures_util::stream::once(async {
                            Ok::<_, io::Error>(Bytes::from_static(
                                br#"{"username":"admin","password":""#,
                            ))
                        })
                        .chain(futures_util::stream::once(async move {
                            released.notified().await;
                            Ok::<_, io::Error>(suffix)
                        })),
                    );
                    let request = request(
                        address,
                        Method::POST,
                        "/api/v1/auth/login",
                        body,
                        None,
                        None,
                    )?;
                    responses.spawn(async move { call(&mut client, request).await });
                    // Observe the actual server-side entry before its JSON body
                    // completes, not merely that the client started polling a body.
                    timeout(Duration::from_secs(5), async {
                        loop {
                            if state
                                .security()
                                .map_err(|_| io::Error::other("security"))?
                                .global_rate
                                .attempts
                                == 1
                            {
                                break Ok::<_, io::Error>(());
                            }
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .map_err(io::Error::other)??;
                    let c = rusqlite::Connection::open(
                        export.fixture.client_state.join("management.sqlite3"),
                    )
                    .map_err(io::Error::other)?;
                    let actor: String = c
                        .query_row("SELECT id FROM administrators", [], |r| r.get(0))
                        .map_err(io::Error::other)?;
                    drop(c);
                    export.arm();
                    let changed = policy
                        .change(
                            actor,
                            1,
                            store::PolicyChange::CreateUser {
                                name: "delayed login source".into(),
                                protocols: vec![crate::access::Protocol::Http],
                                concurrent_limit: 1,
                            },
                        )
                        .await;
                    assert!(store::journal::is_uncertain(
                        &changed
                            .err()
                            .ok_or_else(|| io::Error::other("unknown expected"))?
                    ));
                    release.notify_one();
                    let (status, headers, body) = responses
                        .join_next()
                        .await
                        .ok_or_else(|| io::Error::other("login response task missing"))?
                        .map_err(io::Error::other)??;
                    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                    assert_eq!(body["error"]["code"], "authentication_busy");
                    assert!(!headers.contains_key(header::SET_COOKIE));
                    assert!(
                        state
                            .security()
                            .map_err(|_| io::Error::other("security"))?
                            .sessions
                            .is_empty()
                    );
                    policy.reconcile_source().await?;
                    Ok::<_, io::Error>(())
                })
                .await
                .map_err(io::Error::other)
                .and_then(|r| r);
                release.notify_one();
                stop.cancel();
                let served = server.await.map_err(io::Error::other);
                responses.abort_all();
                while responses.join_next().await.is_some() {}
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                let stopped = policy.shutdown_writer().await;
                result?;
                served??;
                stopped?;
                Ok(())
            }
            .await;
            result.and(export.close().await)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn registered_preparation_checks_surface_bind_and_native_refusal_and_prepares_acme_without_issuance()
    -> io::Result<()> {
        let (export, listener) = fixture(Default::default()).await?;
        let result = async {
        change(&export, |v| v["management"]["surface"] = if cfg!(feature="web-ui") {"api_only"} else {"web"}.into())?;
        let registered = export.register(0, false).await?;
        let before = export.floor()?;
        assert_eq!(prepare(export.fixture.client_state.clone(), Arc::new(store::lock(&export.fixture.client_state)?), registered)
            .await.err().ok_or_else(|| io::Error::other("surface refusal expected"))?.kind(), io::ErrorKind::Unsupported);
        assert_eq!(export.floor()?, before);
        let author = Arc::new(store::lock(&export.fixture.client_state)?);
        assert_eq!(initialize(export.fixture.client_state.clone(), PublicOrigin::parse("https://admin.example:24443")?, author.clone())
            .await.err().ok_or_else(|| io::Error::other("Native refusal expected"))?.kind(), io::ErrorKind::PermissionDenied);
        drop(author);
        change(&export, |v| v["management"]["surface"] = surface().into())?;
        let registered = export.register(1, false).await?;
        let prepared = prepare(export.fixture.client_state.clone(), Arc::new(store::lock(&export.fixture.client_state)?), registered).await?;
        let policy = prepared.state.policy.clone().ok_or_else(|| io::Error::other("policy"))?;
        let other = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST,0)).await?;
        let before = export.floor()?;
        let served = prepared.serve(other, CancellationToken::new()).await;
        let stopped = policy.shutdown_writer().await;
        drop(policy);
        assert_eq!(served.err().ok_or_else(|| io::Error::other("bind refusal expected"))?.kind(), io::ErrorKind::PermissionDenied);
        stopped?;
        assert_eq!(export.floor()?, before);
        change(&export, |v| v["management"]["tls"] = serde_json::json!({"mode":"acme","options":{
            "enabled":true,"accept_terms":true,"production":false,"contacts":[],"challenge":"http-01","http_bind":"127.0.0.1:24445"
        }}))?;
        let registered = export.register(2, false).await?;
        let before = export.floor()?;
        assert!(!export.fixture.client_state.join("acme").exists());
        let prepared = prepare(export.fixture.client_state.clone(), Arc::new(store::lock(&export.fixture.client_state)?), registered).await?;
        assert!(matches!(&prepared.tls, Acceptor::Acme(_)));
        assert!(prepared.acme.is_some() && prepared.state.acme.is_some());
        let policy = prepared.state.policy.clone().ok_or_else(|| io::Error::other("policy"))?;
        for namespace in fs::read_dir(export.fixture.client_state.join("acme"))? {
            assert!(fs::read_dir(namespace?.path())?.next().is_none());
        }
        drop(prepared);
        policy.shutdown_writer().await?;
        assert_eq!(export.floor()?, before);
        drop(listener);
        Ok(())
    }.await;
        result.and(export.close().await)
    }
}
